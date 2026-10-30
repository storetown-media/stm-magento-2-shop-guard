<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;

/**
 * Card testing: someone runs stolen card numbers through the checkout, one payment attempt after the other. The
 * filter rules cannot see it, every single request looks like a customer paying. This counts payment attempts per
 * address and hour; in the mode "report" it only notes who went over the limit, in the mode "block" it refuses
 * further attempts (403) and the bot scan bans the address.
 */
class CardBrake
{
    public const RULE = 'card-testing';
    public const WINDOW = 3600;

    private const COUNTER_FILE = 'shop_guard/card-attempts.json';
    private const LOG_FILE = 'shop_guard/card-tests.log';
    private const MAX_LOG_BYTES = 1048576;

    /**
     * REST payment of guest and customer carts, any path with placeOrder (Magento ajax and many one-step checkouts)
     */
    private const PAYMENT_PATH = '~(/v1/(guest-carts|carts/mine)/[^/]+/(set-)?payment-information$|place-?order)~';

    /**
     * GraphQL mutations that pay
     */
    private const PAYMENT_MUTATION = '~\b(placeOrder|setPaymentMethodAndPlaceOrder|setPaymentMethodOnCart)\b~';

    /**
     * @param Config $config
     * @param ClientIp $clientIp
     * @param DirectoryList $directoryList
     */
    public function __construct(
        private Config $config,
        private ClientIp $clientIp,
        private DirectoryList $directoryList
    ) {
    }

    /**
     * @param array<string, mixed> $r request facts, see Plugin\RequestFilter::facts()
     * @param string $path lowercase path
     * @return string|null RULE when the request is refused
     */
    public function check(array $r, string $path): ?string
    {
        $mode = $this->config->value(Config::CARD_MODE) ?: Config::MODE_REPORT;
        if ($mode === Config::MODE_OFF || strtoupper((string)$r['method']) !== 'POST' || !$this->isPayment($r, $path)) {
            return null;
        }
        $ip = (string)$r['ip'];
        // a proxy stands for many customers; admins test their own checkout
        if (!empty($r['proxy']) || $ip === '' || isset($this->clientIp->adminIps()[$ip])) {
            return null;
        }
        $count = $this->count($ip);
        if ($count <= $this->config->int(Config::CARD_LIMIT, 8)) {
            return null;
        }
        $this->note($mode, $ip, $count, (string)$r['uri']);
        return $mode === Config::MODE_BLOCK ? self::RULE : null;
    }

    /**
     * Addresses over the limit in the last days, for the command line
     *
     * @param int $days
     * @return array<string, array{count: int, max: int, first: string, last: string, mode: string}>
     */
    public function observed(int $days = 7): array
    {
        $since = date('c', time() - $days * 86400);
        $out = [];
        foreach (array_filter(explode("\n", (string)@file_get_contents($this->path(self::LOG_FILE)))) as $line) {
            $f = explode("\t", $line);
            if (count($f) < 4 || $f[0] < $since) {
                continue;
            }
            $o = $out[$f[2]] ?? ['count' => 0, 'max' => 0, 'first' => $f[0], 'last' => $f[0], 'mode' => $f[1]];
            $o['count']++;
            $o['max'] = max($o['max'], (int)$f[3]);
            $o['last'] = $f[0];
            $o['mode'] = $f[1];
            $out[$f[2]] = $o;
        }
        uasort($out, static fn ($a, $b) => $b['max'] <=> $a['max']);
        return $out;
    }

    /**
     * @param array<string, mixed> $r
     * @param string $path
     * @return bool
     */
    private function isPayment(array $r, string $path): bool
    {
        if (preg_match(self::PAYMENT_PATH, $path)) {
            return true;
        }
        return preg_match('~(^|/)graphql/?$~', $path) === 1
            && preg_match(self::PAYMENT_MUTATION, (string)$r['body'] . "\n" . (string)$r['query']) === 1;
    }

    /**
     * @param string $ip
     * @return int attempts of the address within the last hour, this one included
     */
    private function count(string $ip): int
    {
        $file = $this->path(self::COUNTER_FILE);
        if (!is_dir(dirname($file))) {
            @mkdir(dirname($file), 0770, true);
        }
        $handle = @fopen($file, 'c+');
        if (!$handle) {
            return 0;
        }
        flock($handle, LOCK_EX);
        $data = json_decode((string)stream_get_contents($handle), true);
        $data = is_array($data) ? $data : [];
        $since = time() - self::WINDOW;
        foreach ($data as $key => $times) {
            $data[$key] = array_values(array_filter((array)$times, static fn ($t) => $t > $since));
            if (!$data[$key]) {
                unset($data[$key]);
            }
        }
        $data[$ip][] = time();
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, (string)json_encode($data));
        flock($handle, LOCK_UN);
        fclose($handle);
        return count($data[$ip]);
    }

    /**
     * @param string $mode
     * @param string $ip
     * @param int $count
     * @param string $uri
     * @return void
     */
    private function note(string $mode, string $ip, int $count, string $uri): void
    {
        $file = $this->path(self::LOG_FILE);
        if (@filesize($file) > self::MAX_LOG_BYTES) {
            @rename($file, $file . '.1');
        }
        $clean = static fn (string $value, int $max) => substr(strtr($value, "\t\r\n", '   '), 0, $max);
        @file_put_contents($file, implode("\t", [
            date('c'),
            $mode,
            $clean($ip, 64),
            $count,
            $clean($uri, 200),
        ]) . "\n", FILE_APPEND | LOCK_EX);
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
