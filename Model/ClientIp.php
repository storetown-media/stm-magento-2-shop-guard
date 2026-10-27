<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Request\Http as Request;
use Magento\Framework\FlagManager;

/**
 * Client address according to "Client IP from", and the addresses admins logged in from.
 */
class ClientIp
{
    private const ADMIN_FLAG = 'storetown_shop_guard_admin_ips';
    private const ADMIN_KEEP = 2592000;

    /**
     * @param Config $config
     * @param FlagManager $flagManager
     */
    public function __construct(
        private Config $config,
        private FlagManager $flagManager
    ) {
    }

    /**
     * Behind a proxy REMOTE_ADDR is the proxy. Only trust a header your proxy sets itself.
     *
     * @param Request $request
     * @return string
     */
    public function resolve(Request $request): string
    {
        $remote = (string)$request->getServer('REMOTE_ADDR');
        switch ($this->config->value(Config::IP_SOURCE)) {
            case 'x_real_ip':
                $candidate = (string)$request->getServer('HTTP_X_REAL_IP');
                break;
            case 'x_forwarded_for':
                $chain = explode(',', (string)$request->getServer('HTTP_X_FORWARDED_FOR'));
                $candidate = trim((string)end($chain));
                break;
            case 'cf_connecting_ip':
                $candidate = (string)$request->getServer('HTTP_CF_CONNECTING_IP');
                break;
            default:
                $candidate = '';
        }
        return filter_var($candidate, FILTER_VALIDATE_IP) ? $candidate : $remote;
    }

    /**
     * Private, loopback or the server's own address: with a wrong "Client IP from" setting
     * every visitor shares this address, it must never be banned.
     *
     * @param string $ip
     * @param string $serverAddr
     * @return bool
     */
    public static function isProxyAddress(string $ip, string $serverAddr): bool
    {
        return $ip === $serverAddr
            || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * @param string $ip
     * @return void
     */
    public function rememberAdmin(string $ip): void
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        $ips = $this->adminIps();
        $ips[$ip] = time();
        $this->flagManager->saveFlag(self::ADMIN_FLAG, $ips);
    }

    /**
     * @return array<string, int> ip => last login, last 30 days
     */
    public function adminIps(): array
    {
        $ips = (array)$this->flagManager->getFlagData(self::ADMIN_FLAG);
        return array_filter($ips, static fn ($time) => (int)$time > time() - self::ADMIN_KEEP);
    }
}
