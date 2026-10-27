<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\FlagManager;
use Magento\Framework\Module\Manager as ModuleManager;
use Magento\Framework\Phrase;
use Magento\Framework\View\Element\BlockFactory;
use Storetown\ShopGuard\Model\Probe\NotABlock;

/**
 * Checks what a module cannot fix itself but must report: PHP version and settings, missing Magento patches.
 *
 * PHP2Shell (CVE-2026-109618/-109619) strikes while PHP parses the request body, before any Magento code
 * runs. No extension can block it. Only an updated PHP closes it; upload_progress=0 narrows the second path.
 */
class SystemCheck
{
    public const OK = 'ok';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';

    /**
     * First fixed release per branch (PHP security release of 2026-10-21)
     */
    private const PHP_FIXED = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
    private const PATCH_FLAG = 'storetown_shop_guard_patch_status';
    private const PATCH_INTERVAL = 86400;

    /**
     * @param RuntimeSnapshot $snapshot
     * @param Hardening $hardening
     * @param Config $config
     * @param BlockFactory $blockFactory
     * @param DeploymentConfig $deploymentConfig
     * @param ModuleManager $moduleManager
     * @param DirectoryList $directoryList
     * @param FlagManager $flagManager
     */
    public function __construct(
        private RuntimeSnapshot $snapshot,
        private Hardening $hardening,
        private Config $config,
        private BlockFactory $blockFactory,
        private DeploymentConfig $deploymentConfig,
        private ModuleManager $moduleManager,
        private DirectoryList $directoryList,
        private FlagManager $flagManager
    ) {
    }

    /**
     * @param array<string, mixed>|null $runtime web PHP values; null = last snapshot from a web request
     * @return array<int, array{level: string, label: Phrase, value: string, hint: Phrase|string}>
     */
    public function run(?array $runtime = null): array
    {
        $runtime = $runtime ?? $this->snapshot->load() ?? RuntimeSnapshot::current();
        $version = (string)$runtime['version'];
        $ini = (array)$runtime['ini'];
        $source = $runtime['sapi'] === 'cli' ? ' (CLI)' : '';
        $rows = [];

        $branch = implode('.', array_slice(explode('.', $version), 0, 2));
        $fixed = self::PHP_FIXED[$branch] ?? null;
        $vulnerable = $fixed === null || version_compare($version, $fixed, '<');
        if ($fixed === null && version_compare($version, '8.2', '<')) {
            $rows[] = $this->row(self::CRITICAL, __('PHP version'), $version . $source, __(
                'PHP %1 receives no security fixes. Update to a supported PHP version.',
                $branch
            ));
        } elseif ($vulnerable) {
            $rows[] = $this->row(self::CRITICAL, __('PHP version'), $version . $source, __(
                'Vulnerable to PHP2Shell (CVE-2026-109618, CVE-2026-109619). Update to %1 or later. '
                . 'Some hosters backport fixes without changing the version number, ask yours.',
                $fixed ?? '8.5.12'
            ));
        } else {
            $rows[] = $this->row(self::OK, __('PHP version'), $version . $source, __('PHP2Shell fixed.'));
        }

        $progress = $this->on($ini['session.upload_progress.enabled'] ?? null);
        $rows[] = $progress
            ? $this->row($vulnerable ? self::CRITICAL : self::WARNING, __('session.upload_progress.enabled'), 'On', __(
                'Set to 0 in php.ini or the FPM pool. Magento does not need it, it is the entry point of '
                . 'CVE-2026-109619 and CVE-2026-115560.'
            ))
            : $this->row(self::OK, __('session.upload_progress.enabled'), 'Off', '');

        if (version_compare($version, '8.5', '>=') && $this->on($ini['fatal_error_backtraces'] ?? null)) {
            $rows[] = $this->row(self::WARNING, __('fatal_error_backtraces'), 'On', __(
                'Set to 0 until PHP is updated (CVE-2026-109619).'
            ));
        }
        if ($this->on($ini['allow_url_include'] ?? null)) {
            $rows[] = $this->row(self::CRITICAL, __('allow_url_include'), 'On', __('Must be Off.'));
        }
        if ($this->on($ini['display_errors'] ?? null) && $runtime['sapi'] !== 'cli') {
            $rows[] = $this->row(self::WARNING, __('display_errors'), 'On', __('Shows paths and code to visitors.'));
        }
        if (trim((string)($ini['disable_functions'] ?? '')) === '') {
            $rows[] = $this->row(self::WARNING, __('disable_functions'), __('empty'), __(
                'A backdoor can run shell commands. For the web pool disable at least: '
                . 'system, passthru, shell_exec, popen, pcntl_exec.'
            ));
        }

        $rows[] = $this->styleSmuggler();

        $frontName = (string)$this->deploymentConfig->get('backend/frontName');
        if (in_array(strtolower($frontName), ['admin', 'backend', 'admin1'], true)) {
            $rows[] = $this->row(self::WARNING, __('Admin URL'), '/' . $frontName, __('Use a non-guessable admin path.'));
        }
        if (!$this->moduleManager->isEnabled('Magento_TwoFactorAuth')) {
            $rows[] = $this->row(self::WARNING, __('Two-factor authentication'), __('disabled'), __(
                'Admin logins are protected by password only.'
            ));
        }

        foreach ($this->hardening->check() as $file => $state) {
            $rows[] = $this->row(
                $state === 'ok' ? self::OK : self::WARNING,
                __('PHP execution in %1', basename(dirname($file))),
                $state === 'ok' ? __('blocked (.user.ini)')->render() : $state,
                $state === 'ok' ? '' : __('Enable "Write .user.ini" or create %1 with "engine = Off".', $file)
            );
        }

        $patch = $this->patchStatus(false);
        if ($patch !== null) {
            $rows[] = $patch;
        }
        return $rows;
    }

    /**
     * Adobe's patch-status tool (vendor/bin/patch-status, ships with the 2026 security patches).
     * Runs at most once a day, the result is cached.
     *
     * @param bool $refresh
     * @return array{level: string, label: Phrase, value: string, hint: Phrase|string}|null
     */
    public function patchStatus(bool $refresh): ?array
    {
        $tool = $this->directoryList->getRoot() . '/vendor/bin/patch-status';
        if (!is_file($tool)) {
            return null;
        }
        $cached = (array)$this->flagManager->getFlagData(self::PATCH_FLAG);
        if ($refresh && (empty($cached['time']) || $cached['time'] < time() - self::PATCH_INTERVAL)) {
            $cached = ['time' => time()] + $this->runPatchTool($tool);
            $this->flagManager->saveFlag(self::PATCH_FLAG, $cached);
        }
        if (empty($cached['time'])) {
            return null;
        }
        if (!empty($cached['error'])) {
            return $this->row(self::WARNING, __('Magento patches'), __('not checked')->render(), (string)$cached['error']);
        }
        $open = array_merge((array)($cached['vulnerable'] ?? []), (array)($cached['missing'] ?? []));
        return $open
            ? $this->row(self::CRITICAL, __('Magento patches'), implode(', ', $open), __('Install the missing security patches.'))
            : $this->row(self::OK, __('Magento patches'), __('all applied')->render(), '');
    }

    /**
     * APSB26-146 / CVE-2026-75650: BlockFactory must refuse non-block classes before instantiating them.
     *
     * @return array{level: string, label: Phrase, value: string, hint: Phrase|string}
     */
    private function styleSmuggler(): array
    {
        NotABlock::$constructed = false;
        try {
            $this->blockFactory->createBlock(NotABlock::class);
        } catch (\Throwable $e) {
            unset($e);
        }
        if (!NotABlock::$constructed) {
            return $this->row(self::OK, __('StyleSmuggler hotfix (APSB26-146)'), __('installed')->render(), '');
        }
        $graphqlBlocked = $this->config->flag(Config::BLOCK_GRAPHQL);
        return $this->row(self::CRITICAL, __('StyleSmuggler hotfix (APSB26-146)'), __('missing')->render(), __(
            'Install VULN-39341 or the September 2026 patch. %1',
            $graphqlBlocked ? '' : __('Until then enable "Block GraphQL" below.')
        ));
    }

    /**
     * @param string $tool
     * @return array<string, mixed>
     */
    private function runPatchTool(string $tool): array
    {
        $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
        if (!function_exists('proc_open') || in_array('proc_open', $disabled, true)) {
            return ['error' => 'proc_open is disabled'];
        }
        $proc = @proc_open(
            [PHP_BINARY, $tool, '--no-cache'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $this->directoryList->getRoot()
        );
        if (!is_resource($proc)) {
            return ['error' => 'patch-status could not be started'];
        }
        $out = (string)stream_get_contents($pipes[1]);
        $err = (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);
        $json = json_decode($out, true);
        if ($code !== 0 || !is_array($json) || !isset($json['vulnerability_status'])) {
            return ['error' => trim(substr($err . ' ' . $out, 0, 200)) ?: 'exit ' . $code];
        }
        $vulnerable = [];
        foreach ((array)$json['vulnerability_status'] as $cve => $entry) {
            if (in_array($entry['status'] ?? '', ['VULNERABLE', 'UNKNOWN'], true)) {
                $vulnerable[] = $cve;
            }
        }
        return [
            'vulnerable' => $vulnerable,
            'missing' => array_values(array_merge(
                (array)($json['missing_patches'] ?? []),
                (array)($json['unknown_patches'] ?? [])
            )),
        ];
    }

    /**
     * @param mixed $value
     * @return bool
     */
    private function on($value): bool
    {
        return in_array(strtolower(trim((string)$value)), ['1', 'on', 'true', 'yes'], true);
    }

    /**
     * @param string $level
     * @param Phrase $label
     * @param Phrase|string $value
     * @param Phrase|string $hint
     * @return array{level: string, label: Phrase, value: string, hint: Phrase|string}
     */
    private function row(string $level, Phrase $label, $value, $hint): array
    {
        return ['level' => $level, 'label' => $label, 'value' => (string)$value, 'hint' => $hint];
    }
}
