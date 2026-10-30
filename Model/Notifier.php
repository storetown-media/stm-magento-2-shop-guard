<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\AdminNotification\Model\InboxFactory;
use Magento\Framework\App\Area;
use Magento\Framework\FlagManager;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Framework\Stdlib\DateTime\TimezoneInterface;
use Magento\Store\Model\App\Emulation;
use Magento\Store\Model\Store;
use Magento\Store\Model\StoreManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Mail and admin inbox. Silent while nothing changes: the same findings are repeated once a day at most.
 */
class Notifier
{
    private const FLAG = 'storetown_shop_guard_alert';
    private const REPEAT = 86400;

    /**
     * @param Config $config
     * @param TransportBuilder $transportBuilder
     * @param InboxFactory $inboxFactory
     * @param Emulation $emulation
     * @param StoreManagerInterface $storeManager
     * @param FlagManager $flagManager
     * @param TimezoneInterface $timezone
     * @param LoggerInterface $logger
     */
    public function __construct(
        private Config $config,
        private TransportBuilder $transportBuilder,
        private InboxFactory $inboxFactory,
        private Emulation $emulation,
        private StoreManagerInterface $storeManager,
        private FlagManager $flagManager,
        private TimezoneInterface $timezone,
        private LoggerInterface $logger
    ) {
    }

    /**
     * @param array $findings from FileScanner::scan()
     * @param array $system from SystemCheck::run()
     * @param bool $force send even if nothing changed
     * @return bool true if a notification went out
     */
    public function notify(array $findings, array $system, bool $force = false): bool
    {
        $critical = array_values(array_filter($system, static fn ($row) => $row['level'] === SystemCheck::CRITICAL));
        if (!$findings && !$critical) {
            $this->flagManager->deleteFlag(self::FLAG);
            return false;
        }

        $keys = [];
        foreach ($findings as $finding) {
            $keys[] = $finding['check'] . '|' . $finding['path'];
        }
        foreach ($critical as $row) {
            $keys[] = (string)$row['label'] . '|' . $row['value'];
        }
        sort($keys);
        $hash = sha1(implode("\n", $keys));
        $last = (array)$this->flagManager->getFlagData(self::FLAG);
        if (!$force && ($last['hash'] ?? '') === $hash && (int)($last['time'] ?? 0) > time() - self::REPEAT) {
            return false;
        }

        $storeId = (int)($this->storeManager->getDefaultStoreView()?->getId() ?? Store::DEFAULT_STORE_ID);
        $this->emulation->startEnvironmentEmulation($storeId, Area::AREA_FRONTEND, true);
        try {
            $host = (string)parse_url((string)$this->storeManager->getStore($storeId)->getBaseUrl(), PHP_URL_HOST);
            $count = count($findings) + count($critical);
            $subject = (string)($count === 1
                ? __('Shop Security Guard: 1 finding on %1', $host)
                : __('Shop Security Guard: %1 findings on %2', $count, $host));
            $body = $this->body($findings, $critical, $host);
        } finally {
            $this->emulation->stopEnvironmentEmulation();
        }

        $sent = $this->mail($subject, $body);
        $isCritical = $critical || array_filter($findings, static fn ($f) => $f['level'] === FileScanner::CRITICAL);
        $this->inbox($subject, $body, (bool)$isCritical);
        $this->flagManager->saveFlag(self::FLAG, ['hash' => $hash, 'time' => time()]);
        return $sent;
    }

    /**
     * @param array $findings
     * @param array $critical
     * @param string $host
     * @return string
     */
    private function body(array $findings, array $critical, string $host): string
    {
        $now = $this->timezone->date()->format('d.m.Y H:i');
        $out = [(string)__('Shop Security Guard found the following on %1 (%2):', $host, $now), ''];
        foreach ([FileScanner::CRITICAL => __('Critical'), FileScanner::WARNING => __('Warning')] as $level => $title) {
            $group = array_filter($findings, static fn ($f) => $f['level'] === $level);
            if (!$group) {
                continue;
            }
            $out[] = mb_strtoupper((string)$title);
            $byCheck = [];
            foreach ($group as $finding) {
                $byCheck[$finding['check']][] = $finding['path'];
            }
            foreach ($byCheck as $check => $paths) {
                $out[] = '- ' . Advice::title($check);
                foreach ($paths as $path) {
                    $out[] = '    ' . $path;
                }
                $out[] = '  ' . __('What to do:') . ' ' . Advice::advice($check);
                $out[] = '';
            }
        }
        if ($critical) {
            $out[] = mb_strtoupper((string)__('System check'));
            foreach ($critical as $row) {
                $out[] = '- ' . $row['label'] . ': ' . $row['value'];
                $out[] = '  ' . $row['hint'];
            }
            $out[] = '';
        }
        $out[] = (string)__(
            'Do not delete files right away: pack them into an archive outside the web root first, '
            . 'then check how they got there (access log, time of upload).'
        );
        return implode("\n", $out);
    }

    /**
     * A message of its own, outside the finding mail: mail to the alert recipients and the admin inbox
     *
     * @param string $subject
     * @param string $body plain text
     * @param bool $critical
     * @return bool true when the mail went out
     */
    public function send(string $subject, string $body, bool $critical): bool
    {
        $sent = $this->mail($subject, $body);
        $this->inbox($subject, $body, $critical);
        return $sent;
    }

    /**
     * @param string $subject
     * @param string $body
     * @return bool
     */
    private function mail(string $subject, string $body): bool
    {
        $recipients = $this->config->recipients();
        if (!$recipients) {
            return false;
        }
        try {
            $this->transportBuilder
                ->setTemplateIdentifier('storetown_shop_guard_alert')
                ->setTemplateOptions(['area' => Area::AREA_ADMINHTML, 'store' => Store::DEFAULT_STORE_ID])
                ->setTemplateVars(['subject' => $subject, 'body' => $body])
                ->setFromByScope($this->config->value(Config::SENDER) ?: 'general');
            foreach ($recipients as $recipient) {
                $this->transportBuilder->addTo($recipient);
            }
            $this->transportBuilder->getTransport()->sendMessage();
            return true;
        } catch (\Throwable $e) {
            $this->logger->error('Shop Security Guard: alert mail failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * @param string $subject
     * @param string $body
     * @param bool $critical
     * @return void
     */
    private function inbox(string $subject, string $body, bool $critical): void
    {
        try {
            $inbox = $this->inboxFactory->create();
            $text = nl2br(htmlspecialchars($body, ENT_QUOTES));
            $critical ? $inbox->addCritical($subject, $text) : $inbox->addMajor($subject, $text);
        } catch (\Throwable $e) {
            $this->logger->error('Shop Security Guard: admin notification failed: ' . $e->getMessage());
        }
    }
}
