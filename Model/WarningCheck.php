<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Composer\Semver\Semver;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\App\ProductMetadataInterface;
use Magento\Framework\Locale\ResolverInterface;
use Magento\Framework\Module\ModuleListInterface;
use Magento\Store\Model\StoreManagerInterface;

/**
 * Security warnings from the signed feed of Storetown Media, checked against this shop: Magento version, PHP version
 * of the web server, installed packages and enabled modules. Critical and high warnings that affect the shop are
 * alerted once by mail and in the admin inbox. Shop Security Guard Pro alerts every level itself, two minutes earlier;
 * what it has alerted is skipped here, so a shop never gets the same warning twice.
 */
class WarningCheck
{
    public const SEVERITIES = ['critical', 'high'];

    private const STATE_FILE = 'shop_guard/warnings-alerted.json';
    private const PRO_STATE_FILE = 'shop_guard/early-warnings.json';

    /**
     * @var array<string, string>|null
     */
    private ?array $installed = null;

    /**
     * @param RuleFeed $ruleFeed
     * @param ProductMetadataInterface $productMetadata
     * @param ModuleListInterface $moduleList
     * @param RuntimeSnapshot $snapshot
     * @param DirectoryList $directoryList
     * @param ResolverInterface $localeResolver
     * @param StoreManagerInterface $storeManager
     * @param Notifier $notifier
     */
    public function __construct(
        private RuleFeed $ruleFeed,
        private ProductMetadataInterface $productMetadata,
        private ModuleListInterface $moduleList,
        private RuntimeSnapshot $snapshot,
        private DirectoryList $directoryList,
        private ResolverInterface $localeResolver,
        private StoreManagerInterface $storeManager,
        private Notifier $notifier
    ) {
    }

    /**
     * All warnings of the feed, each with "reasons": what in this shop matches, or null when it is not affected
     *
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
        return array_map(fn (array $w) => $w + ['reasons' => $this->match((array)$w['when'])], $this->ruleFeed->warnings());
    }

    /**
     * Mail for critical and high warnings that affect the shop and were not alerted yet
     *
     * @param bool $dryRun only list what would be sent
     * @return string[] ids alerted (or to be alerted)
     */
    public function alert(bool $dryRun = false): array
    {
        $state = $this->read(self::STATE_FILE);
        $byPro = $this->read(self::PRO_STATE_FILE);
        $due = array_filter($this->all(), static fn (array $w) => $w['reasons'] !== null
            && in_array($w['severity'], self::SEVERITIES, true)
            && !isset($state[$w['id']]) && !isset($byPro[$w['id']]));
        if ($dryRun) {
            return array_column($due, 'id');
        }
        foreach ($due as $warning) {
            $this->send($warning);
            $state[$warning['id']] = time();
        }
        // what Pro alerted counts as alerted here too, should Pro be removed later
        foreach (array_keys($byPro) as $id) {
            $state[$id] = $state[$id] ?? time();
        }
        if ($due || $byPro) {
            @file_put_contents($this->path(self::STATE_FILE), (string)json_encode($state), LOCK_EX);
        }
        return array_column($due, 'id');
    }

    /**
     * @param array<string, mixed> $warning
     * @return void
     */
    private function send(array $warning): void
    {
        $de = str_starts_with((string)$this->localeResolver->getLocale(), 'de');
        $text = static fn (string $field) => (string)($warning[$field][$de ? 'de' : 'en'] ?? $warning[$field]['en'] ?? '');
        $host = (string)parse_url((string)$this->storeManager->getStore()->getBaseUrl(), PHP_URL_HOST);
        $steps = (array)($warning['steps'][$de ? 'de' : 'en'] ?? $warning['steps']['en'] ?? []);
        $lines = [
            $text('what'),
            '',
            ($de ? 'Betroffen ist hier: ' : 'Affected here: ') . implode(', ', (array)$warning['reasons']),
        ];
        if ($steps) {
            $lines[] = '';
            $lines[] = $de ? 'So gehen Sie vor:' : 'What to do:';
            foreach (array_values($steps) as $i => $step) {
                $lines[] = ($i + 1) . '. ' . $step;
            }
        }
        if (!empty($warning['refs'])) {
            $lines[] = '';
            $lines[] = ($de ? 'Quellen: ' : 'Sources: ') . implode(' · ', (array)$warning['refs']);
        }
        $lines[] = '';
        $lines[] = $de
            ? 'Diese Warnung kommt von Storetown Media und wurde für Ihren Shop geprüft: Er ist betroffen.'
            : 'This warning comes from Storetown Media and was checked against your shop: it is affected.';
        $this->notifier->send(
            ($de ? 'Shop Security Guard: Frühwarnung für ' : 'Shop Security Guard: early warning for ') . $host . ' – '
                . $text('title'),
            implode("\n", $lines),
            $warning['severity'] === 'critical'
        );
    }

    /**
     * @param array<string, mixed> $when
     * @return string[]|null what matched, null when the shop is not affected
     */
    private function match(array $when): ?array
    {
        $reasons = [];
        if (($constraint = $when['magento'] ?? null) !== null) {
            $version = (string)$this->productMetadata->getVersion();
            if (!$this->satisfies($version, (string)$constraint)) {
                return null;
            }
            $reasons[] = 'Magento ' . $version;
        }
        if (($constraint = $when['php'] ?? null) !== null) {
            // the web server may run another PHP than the cron job
            $version = (string)(($this->snapshot->load() ?? [])['version'] ?? PHP_VERSION);
            if (!$this->satisfies($version, (string)$constraint)) {
                return null;
            }
            $reasons[] = 'PHP ' . $version;
        }
        if ($packages = (array)($when['packages'] ?? [])) {
            $installed = $this->installed();
            $hits = [];
            foreach ($packages as $name => $constraint) {
                if (isset($installed[$name]) && $this->satisfies($installed[$name], (string)$constraint)) {
                    $hits[] = $name . ' ' . $installed[$name];
                }
            }
            if (!$hits) {
                return null;
            }
            array_push($reasons, ...$hits);
        }
        if ($modules = (array)($when['modules'] ?? [])) {
            $hits = array_values(array_filter($modules, fn ($m) => $this->moduleList->has((string)$m)));
            if (!$hits) {
                return null;
            }
            array_push($reasons, ...$hits);
        }
        return $reasons;
    }

    /**
     * @param string $version
     * @param string $constraint
     * @return bool
     */
    private function satisfies(string $version, string $constraint): bool
    {
        if (!class_exists(Semver::class)) {
            return false;
        }
        try {
            return Semver::satisfies($version, $constraint);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * @return array<string, string> package name => version
     */
    private function installed(): array
    {
        if ($this->installed === null) {
            $this->installed = [];
            $file = $this->directoryList->getRoot() . '/vendor/composer/installed.json';
            $data = json_decode((string)@file_get_contents($file), true);
            foreach ((array)($data['packages'] ?? $data ?? []) as $p) {
                if (isset($p['name'], $p['version'])) {
                    $this->installed[(string)$p['name']] = ltrim((string)$p['version'], 'v');
                }
            }
        }
        return $this->installed;
    }

    /**
     * @param string $relative
     * @return array<string, int>
     */
    private function read(string $relative): array
    {
        $data = json_decode((string)@file_get_contents($this->path($relative)), true);
        return is_array($data) ? $data : [];
    }

    /**
     * @param string $relative
     * @return string
     */
    private function path(string $relative): string
    {
        return $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/' . $relative;
    }
}
