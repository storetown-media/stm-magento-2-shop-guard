<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Block\Adminhtml\System\Config;

use Magento\Backend\Block\Template\Context;
use Magento\Config\Block\System\Config\Form\Field;
use Magento\Framework\Data\Form\Element\AbstractElement;
use Storetown\ShopGuard\Model\Config;
use Storetown\ShopGuard\Model\FileScanner;
use Storetown\ShopGuard\Model\RuleList;
use Storetown\ShopGuard\Model\RuntimeSnapshot;
use Storetown\ShopGuard\Model\ClientIp;
use Storetown\ShopGuard\Model\SystemCheck;

/**
 * Status overview at the top of the configuration page. Rendered by PHP-FPM, so the PHP values are the real ones.
 */
class Status extends Field
{
    /**
     * @param Context $context
     * @param SystemCheck $systemCheck
     * @param FileScanner $scanner
     * @param Config $config
     * @param array $data
     */
    public function __construct(
        Context $context,
        private SystemCheck $systemCheck,
        private FileScanner $scanner,
        private Config $config,
        array $data = []
    ) {
        parent::__construct($context, $data);
    }

    /**
     * @param AbstractElement $element
     * @return string
     */
    public function render(AbstractElement $element)
    {
        $colors = [SystemCheck::OK => '#185b00', SystemCheck::WARNING => '#8a5300', SystemCheck::CRITICAL => '#b30000'];
        $html = '<tr><td colspan="4">' . $this->findingsHtml($colors)
            . '<table class="admin__table-secondary" style="width:100%"><tbody>';
        foreach ($this->systemCheck->run(RuntimeSnapshot::current()) as $row) {
            $html .= sprintf(
                '<tr><th style="width:28%%">%s</th><td style="width:22%%;color:%s;font-weight:600">%s</td><td>%s</td></tr>',
                $this->escapeHtml((string)$row['label']),
                $colors[$row['level']],
                $this->escapeHtml($row['value']),
                $this->escapeHtml((string)$row['hint'])
            );
        }

        $state = $this->scanner->state();
        $html .= sprintf(
            '<tr><th>%s</th><td>%s</td><td>%s</td></tr>',
            $this->escapeHtml(__('Last file scan')),
            empty($state['last']) ? '–' : $this->escapeHtml($this->_localeDate->date((int)$state['last'])->format('d.m.Y H:i')),
            empty($state['last']) ? $this->escapeHtml(__('Runs by cron every 30 minutes.'))
                : $this->escapeHtml((int)($state['findings'] ?? 0) === 1
                    ? __('1 finding')
                    : __('%1 findings', (int)($state['findings'] ?? 0)))
        );
        $html .= sprintf(
            '<tr><th>%s</th><td>%d / %d</td><td>%s</td></tr>',
            $this->escapeHtml(__('Automatic blocks')),
            count(RuleList::parse($this->config->value(Config::AUTO_IPS))),
            count(RuleList::parse($this->config->value(Config::AUTO_AGENTS))),
            $this->escapeHtml(__('IP addresses / user agents, see "Bot scan" below'))
        );

        $request = $this->getRequest();
        $ips = [];
        foreach (['REMOTE_ADDR', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP'] as $key) {
            $value = (string)$request->getServer($key);
            if ($value !== '') {
                $ips[] = str_replace('HTTP_', '', $key) . ' = ' . $value;
            }
        }
        $behindProxy = $this->config->value(Config::IP_SOURCE) === 'remote_addr'
            && ClientIp::isProxyAddress(
                (string)$request->getServer('REMOTE_ADDR'),
                (string)$request->getServer('SERVER_ADDR')
            );
        $html .= sprintf(
            '<tr><th>%s</th><td colspan="2"%s>%s<br><small>%s</small></td></tr>',
            $this->escapeHtml(__('Your IP as seen by the shop')),
            $behindProxy ? ' style="color:#8a5300"' : '',
            $this->escapeHtml(implode(' | ', $ips)),
            $this->escapeHtml($behindProxy
                ? __('REMOTE_ADDR is a proxy or server address. IP blocking is inactive until "Client IP from" is set.')
                : __('If REMOTE_ADDR is a server address, set "Client IP from" to the header that shows your IP.'))
        );
        return $html . '</tbody></table></td></tr>';
    }

    /**
     * Result of the last backdoor scan in plain words, with what to do per finding.
     *
     * @param array<string, string> $colors
     * @return string
     */
    private function findingsHtml(array $colors): string
    {
        $state = $this->scanner->state();
        if (empty($state['last'])) {
            return sprintf(
                '<p style="font-size:1.6rem;margin:0 0 1.5rem">%s</p>',
                $this->escapeHtml(__('No scan yet. The first backdoor scan runs with the next cron run (every 30 minutes).'))
            );
        }
        $findings = $this->scanner->lastFindings();
        $critical = (int)($state['critical'] ?? 0);
        $warnings = count($findings) - $critical;
        if (!$findings) {
            $headline = __('No dangerous files found.');
            $color = $colors[SystemCheck::OK];
        } elseif ($critical) {
            $headline = ($critical === 1 ? __('1 critical finding') : __('%1 critical findings', $critical))
                . ($warnings ? ', ' . ($warnings === 1 ? __('1 warning') : __('%1 warnings', $warnings)) : '')
                . '. ' . __('Please act now.');
            $color = $colors[SystemCheck::CRITICAL];
        } else {
            $headline = $warnings === 1 ? __('1 warning, nothing critical.') : __('%1 warnings, nothing critical.', $warnings);
            $color = $colors[SystemCheck::WARNING];
        }
        $html = sprintf(
            '<p style="font-size:1.8rem;font-weight:600;color:%s;margin:0 0 .3rem">%s</p>'
            . '<p style="margin:0 0 1.5rem;color:#666">%s</p>',
            $color,
            $this->escapeHtml($headline),
            $this->escapeHtml(__(
                'Last backdoor scan: %1',
                $this->_localeDate->date((int)$state['last'])->format('d.m.Y H:i')
            ))
        );

        $byCheck = [];
        foreach ($findings as $finding) {
            $byCheck[$finding['check']][] = $finding;
        }
        foreach ($byCheck as $check => $group) {
            $paths = array_map(fn ($f) => $this->escapeHtml($f['path']), array_slice($group, 0, 5));
            if (count($group) > 5) {
                $paths[] = $this->escapeHtml(__('and %1 more', count($group) - 5));
            }
            $html .= sprintf(
                '<div style="border-left:3px solid %s;padding:.2rem 0 .2rem 1.2rem;margin:0 0 1.5rem">'
                . '<strong>%s</strong><br><code style="font-size:1.2rem">%s</code>'
                . '<p style="margin:.5rem 0 0"><strong>%s</strong> %s</p></div>',
                $colors[$group[0]['level'] === FileScanner::CRITICAL ? SystemCheck::CRITICAL : SystemCheck::WARNING],
                $this->escapeHtml((string)$group[0]['text']),
                implode('<br>', $paths),
                $this->escapeHtml(__('What to do:')),
                $this->escapeHtml((string)$group[0]['advice'])
            );
        }
        return $html;
    }
}
