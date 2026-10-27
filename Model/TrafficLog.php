<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;

/**
 * Two files:
 *  var/shop_guard/traffic.log  sample of all requests, input for the hourly bot scan, emptied by it
 *  var/log/shop_guard.log      every attack, readable history for the shop owner
 *
 * Normal traffic and blocked bots are sampled (1 of N, weight N), attacks are always written.
 */
class TrafficLog
{
    public const FILE = 'shop_guard/traffic.log';
    private const ATTACK_LOG = 'log/shop_guard.log';
    private const MAX_SIZE = 50 * 1024 * 1024;

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
     * @param array<string, mixed> $facts
     * @param array{type: string, rule: string}|null $verdict
     * @return void
     */
    public function record(array $facts, ?array $verdict): void
    {
        $type = $verdict['type'] ?? 'pass';
        $rule = $verdict['rule'] ?? '-';
        $rate = $this->config->int(Config::SAMPLE_RATE, 20);

        if ($type === RequestInspector::TYPE_ATTACK) {
            $line = $this->line(1, $type, $rule, $facts);
            $this->append(self::FILE, $line);
            $this->append(self::ATTACK_LOG, $line);
            return;
        }
        if ($rate > 1 && random_int(1, $rate) !== 1) {
            return;
        }
        $this->append(self::FILE, $this->line($rate, $type, $rule, $facts));
    }

    /**
     * @param int $weight
     * @param string $type
     * @param string $rule
     * @param array<string, mixed> $facts
     * @return string
     */
    private function line(int $weight, string $type, string $rule, array $facts): string
    {
        $clean = static fn (string $value, int $max) => substr(strtr($value, "\t\r\n", '   '), 0, $max);
        return implode("\t", [
            date('c'),
            $weight,
            $type,
            $rule,
            $clean((string)$facts['ip'], 64),
            $clean((string)$facts['method'], 8),
            $clean((string)$facts['uri'], 300),
            $clean((string)$facts['ua'], 300),
            empty($facts['proxy']) ? '0' : '1',
        ]) . "\n";
    }

    /**
     * @param string $relative path below var/
     * @param string $line
     * @return void
     */
    private function append(string $relative, string $line): void
    {
        $file = $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/' . $relative;
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0770, true);
        }
        if (@filesize($file) > self::MAX_SIZE) {
            @rename($file, $file . '.1');
        }
        @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }
}
