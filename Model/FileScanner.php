<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\FlagManager;
use Magento\Framework\Phrase;

/**
 * Looks for what attackers leave behind. File names are checked in full on every run,
 * file contents only for files changed since the last run (weekly in full).
 */
class FileScanner
{
    public const CRITICAL = 'critical';
    public const WARNING = 'warning';

    private const FLAG = 'storetown_shop_guard_scan';
    private const FULL_INTERVAL = 604800;
    private const DB_INTERVAL = 86400;

    private const PHP_NAME = '~\.(php\d?|phtml|phar|pht|phps)(\.|$)~i';
    private const IMAGE_NAME = '~\.(jpe?g|png|gif|webp|bmp|ico|tiff?)$~i';
    private const PUB_STANDARD = ['index.php', 'cron.php', 'get.php', 'static.php', 'health_check.php'];
    private const ERRORS_STANDARD = [
        'processor.php', 'processorFactory.php', 'report.php', '404.php', '503.php', 'noCache.php',
    ];
    private const PAYLOAD = '~X_TRACE_|eval\(base64_decode|<\?php|<\?=|cdnflare|kworker-linux~';
    private const REPORT_GUARD = '<?php exit; ?>';
    private const LOGS = ['system.log', 'exception.log', 'debug.log', 'cron.log'];
    private const LOG_TAIL = 5242880;
    private const CRON_PATTERN = '~(curl|wget)[^|\n]*\|\s*(ba)?sh|base64\s+-d|/tmp/\.|/dev/shm/|\.kw_|kworker|gs-netcat~i';
    private const DB_MARKERS = [
        'eval(atob', 'eval(function(p,a,c,k,e', 'eval(String.fromCharCode', 'document.write(unescape',
        'new WebSocket(', 'template_styles', 'rowUrl=$this',
    ];

    private const KEEP_FINDINGS = 200;
    private const NEW_ACCOUNT_DAYS = 7;

    /**
     * Name Magento gives base64 uploads from the REST API in the system temp directory (Framework\Api\ImageProcessor)
     */
    private const TMP_UPLOAD = '~^[0-9a-f]{7}\.~';
    private const KEEP_HISTORY = 1500;

    /**
     * @var array<int, array{level: string, check: string, path: string, text: Phrase, advice: Phrase}>
     */
    private array $findings = [];

    /**
     * Areas this server does not let us check (no /proc, proc_open disabled)
     *
     * @var string[]
     */
    private array $unchecked = [];

    /**
     * Findings left out because someone marked them as harmless
     */
    private int $approved = 0;

    /**
     * @param Config $config
     * @param Hardening $hardening
     * @param DirectoryList $directoryList
     * @param ResourceConnection $resource
     * @param FlagManager $flagManager
     * @param Integrity $integrity
     * @param Approvals $approvals
     */
    public function __construct(
        private Config $config,
        private Hardening $hardening,
        private DirectoryList $directoryList,
        private ResourceConnection $resource,
        private FlagManager $flagManager,
        private Integrity $integrity,
        private Approvals $approvals
    ) {
    }

    /**
     * @param bool $forceFull
     * @return array<int, array{level: string, check: string, path: string, text: Phrase, advice: Phrase}>
     */
    public function scan(bool $forceFull = false): array
    {
        $this->findings = [];
        $this->unchecked = [];
        $this->approved = 0;
        $now = time();
        $state = (array)$this->flagManager->getFlagData(self::FLAG);
        $full = $forceFull || empty($state['full']) || $state['full'] < $now - self::FULL_INTERVAL;
        // One hour overlap: a file written during the last run is checked again
        $since = $full ? 0 : (int)($state['last'] ?? 0) - 3600;

        $media = $this->directoryList->getPath(DirectoryList::MEDIA);
        $static = $this->directoryList->getPath(DirectoryList::STATIC_VIEW);

        $this->walk($media, $since, true);
        $this->walk($static, $since, false);
        $this->pubRoot();
        $this->pubTree($since, [$media, $static]);
        $this->tmpUploads();
        $this->reports($since);
        $this->logs($since);
        $this->processes();
        $this->crontab();
        if ($full || empty($state['db']) || $state['db'] < $now - self::DB_INTERVAL) {
            $this->database();
            $state['db'] = $now;
        }
        // New accounts stay reported for a week (or until marked as harmless), not only in the next run
        $this->newAdmins($now - self::NEW_ACCOUNT_DAYS * 86400);
        $this->newIntegrations($now - self::NEW_ACCOUNT_DAYS * 86400);
        foreach ($this->integrity->check($full) as $finding) {
            $this->add($finding['level'], $finding['check'], $finding['path']);
        }

        $state['last'] = $now;
        $state['approved'] = $this->approved;
        if ($full) {
            $state['full'] = $now;
        }
        $critical = count(array_filter($this->findings, static fn ($f) => $f['level'] === self::CRITICAL));
        $state['findings'] = count($this->findings);
        $state['critical'] = $critical;
        $state['unchecked'] = array_values(array_unique($this->unchecked));
        $state['list'] = array_map(
            static fn ($f) => ['level' => $f['level'], 'check' => $f['check'], 'path' => $f['path']],
            array_slice($this->findings, 0, self::KEEP_FINDINGS)
        );
        $history = (array)($state['history'] ?? []);
        $history[] = [$now, $critical, count($this->findings) - $critical];
        $state['history'] = array_slice($history, -self::KEEP_HISTORY);
        $this->flagManager->saveFlag(self::FLAG, $state);
        return $this->findings;
    }

    /**
     * @return array<string, int>
     */
    public function state(): array
    {
        return (array)$this->flagManager->getFlagData(self::FLAG);
    }

    /**
     * @param string $root
     * @param int $since
     * @param bool $isMedia
     * @return void
     */
    private function walk(string $root, int $since, bool $isMedia): void
    {
        if (!is_dir($root)) {
            return;
        }
        $ours = $this->hardening->files();
        foreach ($this->files($root, 'locked-dir') as $file) {
            $name = $file->getFilename();
            $path = $file->getPathname();

            if (preg_match(self::PHP_NAME, $name)) {
                $this->add(self::CRITICAL, 'php-in-public', $path);
                continue;
            }
            if ($isMedia && str_starts_with($name, 'sess_')) {
                $this->add(self::CRITICAL, 'session-file', $path);
                continue;
            }
            if (in_array($name, ['.user.ini', 'php.ini'], true) && !in_array($path, $ours, true)) {
                $this->add(self::CRITICAL, 'foreign-ini', $path);
                continue;
            }
            $changed = max((int)@$file->getMTime(), (int)@$file->getCTime()) >= $since;
            if (!$changed) {
                continue;
            }
            if ($name === '.htaccess' && $this->htaccessEnablesPhp($path)) {
                $this->add(self::CRITICAL, 'htaccess-php', $path);
            } elseif (preg_match(self::IMAGE_NAME, $name) && $this->imageContainsPhp($path)) {
                $this->add(self::CRITICAL, 'php-in-image', $path);
            } elseif ($this->startsWithPhp($path)) {
                $this->add(self::CRITICAL, 'php-disguised', $path);
            }
        }
    }

    /**
     * Everything in pub/ apart from media and static: Magento keeps no PHP there except the error pages.
     * The 2026 webshell campaigns drop dozens of copies with random names into new subdirectories
     * (pub/opt, pub/assets) and hide further code in .mp4, .tif or .m3u8 files.
     *
     * @param int $since
     * @param string[] $walked directories already checked by walk()
     * @return void
     */
    private function pubTree(int $since, array $walked): void
    {
        $pub = $this->directoryList->getPath(DirectoryList::PUB);
        $skip = array_map(static fn ($dir) => rtrim($dir, '/'), $walked);
        $allowed = $this->allowedPubFiles();
        foreach ($this->files($pub, 'pub-locked-dir', $skip) as $file) {
            $path = $file->getPathname();
            $relative = substr($path, strlen($pub) + 1);
            $name = $file->getFilename();
            $inErrors = str_starts_with($relative, 'errors/');
            if (!str_contains($relative, '/')) {
                // pub/ itself: PHP names are pubRoot()'s job
                if (!preg_match(self::PHP_NAME, $name)
                    && $this->changedSince($file, $since)
                    && $this->startsWithPhp($path)
                ) {
                    $this->add(self::CRITICAL, 'pub-disguised', $path);
                }
                continue;
            }
            if (preg_match(self::PHP_NAME, $name)) {
                $standard = $inErrors && (
                    in_array($relative, array_map(static fn ($n) => 'errors/' . $n, self::ERRORS_STANDARD), true)
                    || preg_match('~^errors/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+\.phtml$~', $relative)
                );
                if ($standard) {
                    continue;
                }
                if (isset($allowed[$relative])) {
                    $hash = $allowed[$relative];
                    if ($hash !== '' && !hash_equals($hash, (string)hash_file('sha256', $path))) {
                        $this->add(self::CRITICAL, 'pub-root-changed', $path);
                    }
                    continue;
                }
                $this->add(self::CRITICAL, 'pub-subdir-php', $path);
                continue;
            }
            if (in_array($name, ['.user.ini', 'php.ini'], true)) {
                $this->add(self::CRITICAL, 'foreign-ini', $path);
                continue;
            }
            if (!$this->changedSince($file, $since)) {
                continue;
            }
            if ($name === '.htaccess' && $this->htaccessEnablesPhp($path)) {
                $this->add(self::CRITICAL, 'htaccess-php', $path);
            } elseif ($this->startsWithPhp($path)) {
                $this->add(self::CRITICAL, 'pub-disguised', $path);
            }
        }
    }

    /**
     * PolyShell sends a webshell as base64 "image" to the REST API. Magento writes it to the system temp directory
     * before validating it, and the file stays there even when the upload is refused. They cannot be called from
     * the web, but an include vulnerability can load them, and their dates show when the shop was attacked.
     *
     * @return void
     */
    private function tmpUploads(): void
    {
        $dir = $this->directoryList->getPath(DirectoryList::SYS_TMP);
        if (!is_dir($dir) || !is_readable($dir)) {
            return;
        }
        $times = [];
        foreach (new \DirectoryIterator($dir) as $file) {
            if (!$file->isFile() || !preg_match(self::TMP_UPLOAD, $file->getFilename()) || $file->getSize() > 2097152) {
                continue;
            }
            $head = (string)@file_get_contents($file->getPathname(), false, null, 0, 4096);
            if (preg_match(self::PHP_NAME, $file->getFilename()) || stripos($head, '<?php') !== false
                || str_contains($head, '<?=')
            ) {
                $times[] = (int)$file->getMTime();
            }
        }
        if ($times) {
            $this->add(self::WARNING, 'tmp-upload', sprintf(
                '%s: %d (%s – %s)',
                $dir,
                count($times),
                gmdate('Y-m-d', min($times)),
                gmdate('Y-m-d', max($times))
            ));
        }
    }

    /**
     * Files below $root. Directories the shop user cannot open are reported, not skipped silently:
     * attackers lock them (chmod 000 or 444) to hide what is inside.
     *
     * @param string $root
     * @param string $lockedCheck
     * @param string[] $skip directories left out completely
     * @return \Generator<\SplFileInfo>
     */
    private function files(string $root, string $lockedCheck, array $skip = []): \Generator
    {
        if (!is_readable($root) || !is_executable($root)) {
            $this->add(self::WARNING, $lockedCheck, $root);
            return;
        }
        $filter =function (\SplFileInfo $entry) use ($lockedCheck, $skip): bool {
            if (!$entry->isDir()) {
                return true;
            }
            $path = $entry->getPathname();
            if (in_array($path, $skip, true)) {
                return false;
            }
            if (!$entry->isReadable() || !$entry->isExecutable()) {
                $this->add(self::WARNING, $lockedCheck, $path);
                return false;
            }
            return true;
        };
        $it = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                $filter
            ),
            \RecursiveIteratorIterator::LEAVES_ONLY,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        foreach ($it as $file) {
            /** @var \SplFileInfo $file */
            if ($file->isFile()) {
                yield $file;
            }
        }
    }

    /**
     * Allow list for pub/: file name (pub/ itself) or path below pub/, optionally with SHA-256
     *
     * @return array<string, string>
     */
    private function allowedPubFiles(): array
    {
        $allowed = [];
        foreach ($this->config->entries(Config::ALLOWED_PUB_FILES) as $entry) {
            $parts = preg_split('/\s+/', $entry) ?: [];
            $allowed[ltrim(preg_replace('~^pub/~', '', $parts[0]), '/')] = strtolower($parts[1] ?? '');
        }
        return $allowed;
    }

    /**
     * @param \SplFileInfo $file
     * @param int $since
     * @return bool
     */
    private function changedSince(\SplFileInfo $file, int $since): bool
    {
        return max((int)@filemtime($file->getPathname()), (int)@filectime($file->getPathname())) >= $since;
    }

    /**
     * PHP code at the start of a file whose name does not say PHP (video, archive, text)
     *
     * @param string $path
     * @return bool
     */
    private function startsWithPhp(string $path): bool
    {
        $head = ltrim((string)@file_get_contents($path, false, null, 0, 64));
        return stripos($head, '<?php') === 0 || str_starts_with($head, '<?=');
    }

    /**
     * @return void
     */
    private function pubRoot(): void
    {
        $pub = $this->directoryList->getPath(DirectoryList::PUB);
        $allowed = $this->allowedPubFiles();
        foreach (glob($pub . '/*') ?: [] as $path) {
            $name = basename($path);
            if (!is_file($path) || !preg_match(self::PHP_NAME, $name) || in_array($name, self::PUB_STANDARD, true)) {
                continue;
            }
            if (isset($allowed[$name])
                && ($allowed[$name] === '' || hash_equals($allowed[$name], (string)hash_file('sha256', $path)))
            ) {
                continue;
            }
            if (isset($allowed[$name])) {
                $this->add(self::CRITICAL, 'pub-root-changed', $path);
            } else {
                $this->add(self::WARNING, 'pub-root', $path);
            }
        }

        $index = (string)@file_get_contents($pub . '/index.php');
        if ($index !== '' && preg_match('~eval\s*\(|base64_decode|gzinflate|str_rot13|\$_(COOKIE|REQUEST)\[|assert\s*\(~i', $index)) {
            $this->add(self::CRITICAL, 'index-php', $pub . '/index.php');
        }
    }

    /**
     * StyleSmuggler writes its payload into error reports, which are later included as PHP.
     * Since the Adobe hotfix (APSB26-146) each report starts with a harmless exit line, that line is skipped.
     *
     * @param int $since
     * @return void
     */
    private function reports(int $since): void
    {
        $dir = $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/report';
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile() || max((int)$file->getMTime(), (int)$file->getCTime()) < $since) {
                continue;
            }
            $content = (string)@file_get_contents($file->getPathname(), false, null, 0, 1048576);
            if (str_starts_with($content, self::REPORT_GUARD . "\n")) {
                $content = substr($content, strlen(self::REPORT_GUARD) + 1);
            }
            if (preg_match(self::PAYLOAD, $content)) {
                $this->add(self::CRITICAL, 'report-payload', $file->getPathname());
            }
        }
    }

    /**
     * @param int $since
     * @return void
     */
    private function logs(int $since): void
    {
        $dir = $this->directoryList->getPath(DirectoryList::LOG);
        foreach (self::LOGS as $name) {
            $path = $dir . '/' . $name;
            $size = (int)@filesize($path);
            if ($size === 0 || (int)@filemtime($path) < $since) {
                continue;
            }
            $tail = (string)@file_get_contents($path, false, null, max(0, $size - self::LOG_TAIL));
            if (preg_match(self::PAYLOAD, $tail)) {
                $this->add(self::WARNING, 'log-payload', $path);
            }
        }
    }

    /**
     * Processes of the shop user. Kernel threads have no command line and belong to root,
     * so a "[kworker...]" owned by the shop user is a disguised backdoor.
     *
     * @return void
     */
    private function processes(): void
    {
        if (!@is_readable('/proc/self/cmdline')) {
            $this->unchecked[] = 'processes';
            return;
        }
        $uid = @fileowner('/proc/self');
        $self = (string)getmypid();
        foreach (glob('/proc/[0-9]*', GLOB_ONLYDIR) ?: [] as $dir) {
            $pid = basename($dir);
            if ($pid === $self || @fileowner($dir) !== $uid) {
                continue;
            }
            $cmd = trim(str_replace("\0", ' ', (string)@file_get_contents($dir . '/cmdline')));
            if ($cmd === '') {
                continue;
            }
            $exe = (string)@readlink($dir . '/exe');
            $label = 'PID ' . $pid . ': ' . substr($cmd, 0, 160);
            $runtime = preg_match('~/(php[\d.\-a-z]*|php-fpm[\d.]*|httpd|apache2|nginx|bash|sh)( \(deleted\))?$~', $exe);
            if (str_starts_with($cmd, '[')) {
                $this->add(self::CRITICAL, 'process-kthread', $label);
            } elseif (preg_match('~^/(tmp|var/tmp|dev/shm)/~', $exe) || (str_ends_with($exe, ' (deleted)') && !$runtime)) {
                $this->add(self::CRITICAL, 'process-tmp', $label);
            } elseif (preg_match('~xmrig|kdevtmpfsi|kinsing|gs-netcat|gsocket|\.kw_|/tmp/\.|/dev/shm/~i', $cmd)) {
                $this->add(self::CRITICAL, 'process-malware', $label);
            } elseif (preg_match('~(^|/)fc-cache\b~', $cmd)) {
                $this->add(self::WARNING, 'process-fccache', $label);
            }
        }
    }

    /**
     * @return void
     */
    private function crontab(): void
    {
        $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
        if (!function_exists('proc_open') || in_array('proc_open', $disabled, true)) {
            $this->unchecked[] = 'crontab';
            return;
        }
        $proc = @proc_open(['crontab', '-l'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            $this->unchecked[] = 'crontab';
            return;
        }
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);
        foreach (explode("\n", $out) as $line) {
            if (!str_starts_with(ltrim($line), '#') && preg_match(self::CRON_PATTERN, $line)) {
                $this->add(self::CRITICAL, 'crontab', substr(trim($line), 0, 200));
            }
        }
    }

    /**
     * Skimmer and StyleSmuggler markers in content that is rendered into pages and mails.
     *
     * @return void
     */
    private function database(): void
    {
        $db = $this->resource->getConnection();
        $tables = [
            'core_config_data' => ['config_id', 'path', 'value'],
            'cms_block' => ['block_id', 'identifier', 'content'],
            'cms_page' => ['page_id', 'identifier', 'content'],
            'email_template' => ['template_id', 'template_code', 'template_text'],
        ];
        foreach ($tables as $table => [$id, $name, $column]) {
            $tableName = $this->resource->getTableName($table);
            if (!$db->isTableExists($tableName)) {
                continue;
            }
            $where = [];
            foreach (self::DB_MARKERS as $marker) {
                $where[] = $db->quoteInto($column . ' LIKE ?', '%' . addcslashes($marker, '%_\\') . '%');
            }
            $rows = $db->fetchAll(
                $db->select()->from($tableName, [$id, $name])->where(implode(' OR ', $where))->limit(20)
            );
            foreach ($rows as $row) {
                $this->add(self::WARNING, 'content', $table . ' #' . $row[$id] . ' (' . $row[$name] . ')');
            }
        }
    }

    /**
     * @param int $since
     * @return void
     */
    private function newAdmins(int $since): void
    {
        $db = $this->resource->getConnection();
        $rows = $db->fetchAll(
            $db->select()
                ->from($this->resource->getTableName('admin_user'), ['username', 'email', 'created'])
                ->where('created >= ?', gmdate('Y-m-d H:i:s', $since))
        );
        foreach ($rows as $row) {
            $this->add(self::WARNING, 'admin-user', $row['username'] . ' <' . $row['email'] . '> ' . $row['created']);
        }
    }

    /**
     * Integrations get their own API token, a hidden one with full access keeps an attacker in
     *
     * @param int $since
     * @return void
     */
    private function newIntegrations(int $since): void
    {
        $db = $this->resource->getConnection();
        $table = $this->resource->getTableName('integration');
        if (!$db->isTableExists($table)) {
            return;
        }
        $rows = $db->fetchAll(
            $db->select()
                ->from($table, ['name', 'email', 'created_at'])
                ->where('created_at >= ?', gmdate('Y-m-d H:i:s', $since))
        );
        foreach ($rows as $row) {
            $this->add(self::WARNING, 'integration', $row['name'] . ' <' . $row['email'] . '> ' . $row['created_at']);
        }
    }

    /**
     * @param string $path
     * @return bool
     */
    private function imageContainsPhp(string $path): bool
    {
        // Images up to 2 MB are read completely. Larger ones only at both ends, where webshells sit
        // (behind the header or appended), so a full scan of big media directories stays fast.
        $size = (int)@filesize($path);
        $head = (string)@file_get_contents($path, false, null, 0, 2097152);
        $tail = $size > 2097152 ? (string)@file_get_contents($path, false, null, $size - 262144) : '';
        return str_starts_with($head, '<?=') || stripos($head . $tail, '<?php') !== false;
    }

    /**
     * @param string $path
     * @return bool
     */
    private function htaccessEnablesPhp(string $path): bool
    {
        $content = (string)@file_get_contents($path, false, null, 0, 65536);
        return (bool)preg_match(
            '~application/x-httpd-php|(AddHandler|SetHandler|AddType)\s+(?!cgi-script)[^\n]*php'
            . '|php_value\s+auto_(pre|ap)pend_file|php_flag\s+engine\s+(on|1)~i',
            $content
        );
    }

    /**
     * @param string $level
     * @param string $check
     * @param string $path
     * @return void
     */
    private function add(string $level, string $check, string $path): void
    {
        if ($this->approvals->covers($check, $path)) {
            $this->approved++;
            return;
        }
        $this->findings[] = self::expand(['level' => $level, 'check' => $check, 'path' => $path]);
    }

    /**
     * Adds title and advice. They stay Phrases, so they are translated where they are shown.
     *
     * @param array{level: string, check: string, path: string} $finding
     * @return array{level: string, check: string, path: string, text: Phrase, advice: Phrase}
     */
    public static function expand(array $finding): array
    {
        return $finding + ['text' => Advice::title($finding['check']), 'advice' => Advice::advice($finding['check'])];
    }

    /**
     * Findings of the last scan
     *
     * @return array<int, array{level: string, check: string, path: string, text: Phrase, advice: Phrase}>
     */
    public function lastFindings(): array
    {
        return array_map([self::class, 'expand'], (array)($this->state()['list'] ?? []));
    }
}
