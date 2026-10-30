<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Cache\TypeListInterface;
use Magento\Framework\App\Config\Storage\WriterInterface;
use Magento\Framework\App\Filesystem\DirectoryList;

/**
 * Stops password guessing on the admin login. Magento locks the account after a few failures, but the address keeps
 * trying other accounts; this blocks the address itself. Admin addresses, "Never block these IPs" and proxy addresses
 * are never blocked.
 */
class LoginGuard
{
    public const WINDOW = 900;

    private const FILE = 'shop_guard/login-failures.json';
    private const ATTACK_LOG = 'log/shop_guard.log';

    /**
     * @param Config $config
     * @param ClientIp $clientIp
     * @param WriterInterface $configWriter
     * @param TypeListInterface $cacheTypeList
     * @param DirectoryList $directoryList
     */
    public function __construct(
        private Config $config,
        private ClientIp $clientIp,
        private WriterInterface $configWriter,
        private TypeListInterface $cacheTypeList,
        private DirectoryList $directoryList
    ) {
    }

    /**
     * Counts a failed admin login and blocks the address when it reached the limit within 15 minutes
     *
     * @param string $ip
     * @param string $serverAddr
     * @param string $userName
     * @return bool true when the address was blocked now
     */
    public function failed(string $ip, string $serverAddr, string $userName): bool
    {
        if (!$this->config->flag(Config::ENABLED) || !$this->config->flag(Config::LOGIN_GUARD)
            || !filter_var($ip, FILTER_VALIDATE_IP) || ClientIp::isProxyAddress($ip, $serverAddr)
        ) {
            return false;
        }
        $count = $this->count($ip);
        if ($count < $this->config->int(Config::LOGIN_ATTEMPTS, 10) || $this->isProtected($ip)) {
            return false;
        }
        $entries = RuleList::parse($this->config->value(Config::AUTO_IPS));
        if (in_array($ip, array_column($entries, 'value'), true)) {
            return false;
        }
        // whole days in the list: the block ends with the next day, so it lasts 24 to 48 hours
        $entries[] = ['value' => $ip, 'until' => date('Y-m-d', time() + 86400), 'note' => 'admin-login ' . $count . ' failed'];
        $this->configWriter->save(Config::AUTO_IPS, RuleList::format($entries));
        $this->cacheTypeList->cleanType('config');
        $this->forget($ip);
        $this->logAttack($ip, $userName);
        return true;
    }

    /**
     * @param string $ip
     * @return bool
     */
    private function isProtected(string $ip): bool
    {
        return RuleList::ipMatches($ip, $this->config->entries(Config::ALLOW_IPS))
            || isset($this->clientIp->adminIps()[$ip]);
    }

    /**
     * @param string $ip
     * @return int failures of the address within the window, this one included
     */
    private function count(string $ip): int
    {
        $count = 0;
        $this->update(function (array $data) use ($ip, &$count) {
            $since = time() - self::WINDOW;
            foreach ($data as $key => $times) {
                $data[$key] = array_values(array_filter((array)$times, static fn ($t) => $t > $since));
                if (!$data[$key]) {
                    unset($data[$key]);
                }
            }
            $data[$ip][] = time();
            $count = count($data[$ip]);
            return $data;
        });
        return $count;
    }

    /**
     * @param string $ip
     * @return void
     */
    private function forget(string $ip): void
    {
        $this->update(static function (array $data) use ($ip) {
            unset($data[$ip]);
            return $data;
        });
    }

    /**
     * @param callable $change receives and returns the counter data
     * @return void
     */
    private function update(callable $change): void
    {
        $file = $this->path(self::FILE);
        if (!is_dir(dirname($file))) {
            @mkdir(dirname($file), 0770, true);
        }
        $handle = @fopen($file, 'c+');
        if (!$handle) {
            return;
        }
        flock($handle, LOCK_EX);
        $data = json_decode((string)stream_get_contents($handle), true);
        $data = $change(is_array($data) ? $data : []);
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, (string)json_encode($data));
        flock($handle, LOCK_UN);
        fclose($handle);
    }

    /**
     * The attack log only: the bot scan reads var/shop_guard/traffic.log and would turn this into a 30 day ban
     *
     * @param string $ip
     * @param string $userName
     * @return void
     */
    private function logAttack(string $ip, string $userName): void
    {
        $clean = static fn (string $value, int $max) => substr(strtr($value, "\t\r\n", '   '), 0, $max);
        @file_put_contents($this->path(self::ATTACK_LOG), implode("\t", [
            date('c'),
            1,
            RequestInspector::TYPE_ATTACK,
            'admin-login',
            $clean($ip, 64),
            'POST',
            'admin login, last user name: ' . $clean($userName, 40),
            '-',
            '0',
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
