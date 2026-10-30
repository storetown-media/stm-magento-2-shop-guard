<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\HTTP\Client\CurlFactory;
use Magento\Framework\UrlInterface;
use Magento\Store\Model\StoreManagerInterface;

/**
 * Files anyone can download from the shop: the configuration with the database password, a git repository, database
 * dumps and backups in the web root, phpinfo or database tools, Magento logs. The shop requests itself the way an
 * attacker would, and a finding needs the content to prove it, so a "page not found" with status 200 never alerts.
 */
class LeakCheck
{
    private const AGENT = 'STM-Shop-Security-Guard-LeakCheck/1';
    private const MAX_BYTES = 4096;
    private const DUMP_NAME = '~\.(sql|sql\.gz|sql\.bz2|sql\.zip|dump|tar|tar\.gz|tgz|zip|rar|7z|bak|backup)$~i';

    /**
     * path => [check, level, pattern the first 4 KB must contain]
     */
    private const PROBES = [
        '/app/etc/env.php' => ['leak-config', FileScanner::CRITICAL, "~'(crypt|db)'\s*=>~"],
        '/.git/config' => ['leak-git', FileScanner::CRITICAL, '~\[core\]~'],
        '/.git/HEAD' => ['leak-git', FileScanner::CRITICAL, '~^ref: refs/~m'],
        '/phpinfo.php' => ['leak-tool', FileScanner::CRITICAL, '~phpinfo\(\)~'],
        '/info.php' => ['leak-tool', FileScanner::CRITICAL, '~phpinfo\(\)~'],
        '/pi.php' => ['leak-tool', FileScanner::CRITICAL, '~phpinfo\(\)~'],
        '/adminer.php' => ['leak-tool', FileScanner::CRITICAL, '~Adminer~'],
        '/adminer/' => ['leak-tool', FileScanner::CRITICAL, '~Adminer~'],
        '/phpmyadmin/' => ['leak-tool', FileScanner::CRITICAL, '~phpMyAdmin~'],
        '/pma/' => ['leak-tool', FileScanner::CRITICAL, '~phpMyAdmin~'],
        '/var/log/exception.log' => ['leak-log', FileScanner::WARNING, '~main\.(CRITICAL|ERROR)~'],
        '/var/log/system.log' => ['leak-log', FileScanner::WARNING, '~main\.(INFO|WARNING|ERROR|CRITICAL)~'],
        '/composer.json' => ['leak-docroot', FileScanner::WARNING, '~"magento/(product-|magento2-base|framework)~'],
    ];

    /**
     * @var bool false once the shop could not reach itself
     */
    private bool $reachable = true;

    /**
     * @param DirectoryList $directoryList
     * @param StoreManagerInterface $storeManager
     * @param CurlFactory $curlFactory
     */
    public function __construct(
        private DirectoryList $directoryList,
        private StoreManagerInterface $storeManager,
        private CurlFactory $curlFactory
    ) {
    }

    /**
     * @return array<int, array{level: string, check: string, path: string}>
     */
    public function run(): array
    {
        $base = rtrim((string)$this->storeManager->getStore()->getBaseUrl(UrlInterface::URL_TYPE_WEB, true), '/');
        $this->reachable = true;
        $this->request($base . '/', false);
        if (!$this->reachable) {
            // no way to ask the shop from here (firewall, no loopback): nothing can be said
            return [];
        }
        $findings = [];
        foreach (self::PROBES as $path => [$check, $level, $pattern]) {
            $body = $this->request($base . $path, false);
            if ($body !== null && preg_match($pattern, $body)) {
                $findings[] = ['level' => $level, 'check' => $check, 'path' => $base . $path];
            }
        }
        foreach ($this->dumps() as $relative => $urls) {
            $reachable = array_filter($urls, fn ($url) => $this->request($base . $url, true) !== null);
            if ($reachable) {
                $findings[] = ['level' => FileScanner::CRITICAL, 'check' => 'leak-dump', 'path' => $base . reset($reachable)];
            } elseif (str_starts_with($relative, 'pub/')) {
                $findings[] = ['level' => FileScanner::WARNING, 'check' => 'leak-dump-local', 'path' => $relative];
            }
        }
        return $findings;
    }

    /**
     * Dumps and archives in the shop root and in pub/, with the addresses they would have
     * (web root pub/ as recommended, or the shop root)
     *
     * @return array<string, string[]> relative path => candidate URL paths
     */
    private function dumps(): array
    {
        $root = $this->directoryList->getRoot();
        $found = [];
        foreach (['', 'pub/'] as $dir) {
            if (!is_dir($root . '/' . $dir)) {
                continue;
            }
            foreach (new \DirectoryIterator($root . '/' . $dir) as $file) {
                if (!$file->isFile() || !preg_match(self::DUMP_NAME, $file->getFilename()) || !$file->getSize()) {
                    continue;
                }
                $name = rawurlencode($file->getFilename());
                $found[$dir . $file->getFilename()] = $dir === 'pub/' ? ['/' . $name, '/pub/' . $name] : ['/' . $name];
            }
        }
        return $found;
    }

    /**
     * @param string $url
     * @param bool $headOnly
     * @return string|null the first bytes of a successful answer; null for an error, a redirect or an HTML page
     */
    private function request(string $url, bool $headOnly): ?string
    {
        try {
            $curl = $this->curlFactory->create();
            $curl->setTimeout(5);
            $curl->addHeader('User-Agent', self::AGENT);
            $curl->addHeader('Range', 'bytes=0-' . (self::MAX_BYTES - 1));
            $curl->setOption(CURLOPT_NOBODY, $headOnly);
            $curl->setOption(CURLOPT_MAXFILESIZE, 1048576);
            $curl->get($url);
        } catch (\Throwable $e) {
            $this->reachable = false;
            return null;
        }
        $status = $curl->getStatus();
        if ($status === 0) {
            $this->reachable = false;
        }
        if ($status !== 200 && $status !== 206) {
            return null;
        }
        $type = strtolower((string)($curl->getHeaders()['Content-Type'] ?? $curl->getHeaders()['content-type'] ?? ''));
        if ($headOnly) {
            // a dump is never served as an HTML page; an HTML answer is the shop's own page for an unknown address
            return str_contains($type, 'text/html') ? null : 'reachable';
        }
        return substr((string)$curl->getBody(), 0, self::MAX_BYTES);
    }
}
