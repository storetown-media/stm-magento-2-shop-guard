<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;

/**
 * PHP settings of the web server (PHP-FPM) as seen by a real request.
 * Cron and CLI run with a different php.ini, so their values say nothing about the web side.
 */
class RuntimeSnapshot
{
    private const FILE = 'shop_guard/runtime.json';
    private const MAX_AGE = 21600;

    public const INI_KEYS = [
        'session.upload_progress.enabled',
        'fatal_error_backtraces',
        'allow_url_include',
        'allow_url_fopen',
        'display_errors',
        'expose_php',
        'disable_functions',
        'memory_limit',
        'open_basedir',
    ];

    /**
     * @param DirectoryList $directoryList
     */
    public function __construct(private DirectoryList $directoryList)
    {
    }

    /**
     * Called from web requests, writes at most every 6 hours.
     *
     * @return void
     */
    public function refresh(): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }
        $file = $this->file();
        $mtime = @filemtime($file);
        if ($mtime !== false && $mtime > time() - self::MAX_AGE) {
            return;
        }
        if (!is_dir(dirname($file))) {
            @mkdir(dirname($file), 0770, true);
        }
        @file_put_contents($file, json_encode(self::current()), LOCK_EX);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function load(): ?array
    {
        $data = json_decode((string)@file_get_contents($this->file()), true);
        return is_array($data) ? $data : null;
    }

    /**
     * @return array<string, mixed>
     */
    public static function current(): array
    {
        $ini = [];
        foreach (self::INI_KEYS as $key) {
            $value = ini_get($key);
            $ini[$key] = $value === false ? null : (string)$value;
        }
        return ['time' => time(), 'sapi' => PHP_SAPI, 'version' => PHP_VERSION, 'ini' => $ini];
    }

    /**
     * @return string
     */
    private function file(): string
    {
        return $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/' . self::FILE;
    }
}
