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
     * @param Config $config
     * @param Hardening $hardening
     * @param DirectoryList $directoryList
     * @param ResourceConnection $resource
     * @param FlagManager $flagManager
     */
    public function __construct(
        private Config $config,
        private Hardening $hardening,
        private DirectoryList $directoryList,
        private ResourceConnection $resource,
        private FlagManager $flagManager
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
        $this->reports($since);
        $this->logs($since);
        $this->processes();
        $this->crontab();
        if ($full || empty($state['db']) || $state['db'] < $now - self::DB_INTERVAL) {
            $this->database();
            $state['db'] = $now;
        }
        $this->newAdmins((int)($state['last'] ?? $now));

        $state['last'] = $now;
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
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        foreach ($it as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }
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
            }
        }
    }

    /**
     * @return void
     */
    private function pubRoot(): void
    {
        $pub = $this->directoryList->getPath(DirectoryList::PUB);
        $allowed = [];
        foreach ($this->config->entries(Config::ALLOWED_PUB_FILES) as $entry) {
            $parts = preg_split('/\s+/', $entry) ?: [];
            $allowed[$parts[0]] = strtolower($parts[1] ?? '');
        }
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
