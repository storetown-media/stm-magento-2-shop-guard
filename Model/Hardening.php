<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;

/**
 * "engine = Off" in pub/media and pub/static: PHP-FPM refuses to run any script there,
 * even if one gets uploaded and the web server config forwards it. nginx ignores .htaccess, .user.ini still works.
 */
class Hardening
{
    public const USER_INI = "; Storetown Shop Guard: no PHP execution below this directory\nengine = Off\n";

    /**
     * @param Config $config
     * @param DirectoryList $directoryList
     */
    public function __construct(
        private Config $config,
        private DirectoryList $directoryList
    ) {
    }

    /**
     * @return array<string, string> path => ok|written|foreign|failed|disabled
     */
    public function apply(): array
    {
        $result = [];
        foreach ($this->files() as $file) {
            $result[$file] = $this->status($file);
            if ($result[$file] === 'missing' && $this->config->flag(Config::WRITE_USER_INI)) {
                $result[$file] = @file_put_contents($file, self::USER_INI) ? 'written' : 'failed';
            }
        }
        return $result;
    }

    /**
     * @return array<string, string>
     */
    public function check(): array
    {
        $result = [];
        foreach ($this->files() as $file) {
            $result[$file] = $this->status($file);
        }
        return $result;
    }

    /**
     * @return string[]
     */
    public function files(): array
    {
        return [
            $this->directoryList->getPath(DirectoryList::MEDIA) . '/.user.ini',
            $this->directoryList->getPath(DirectoryList::STATIC_VIEW) . '/.user.ini',
        ];
    }

    /**
     * @param string $file
     * @return string
     */
    private function status(string $file): string
    {
        if (!is_file($file)) {
            return 'missing';
        }
        $content = (string)@file_get_contents($file);
        return preg_match('/^\s*engine\s*=\s*(off|0|false|no)\b/im', $content) ? 'ok' : 'foreign';
    }
}
