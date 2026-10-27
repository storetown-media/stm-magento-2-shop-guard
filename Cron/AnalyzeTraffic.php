<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Cron;

use Psr\Log\LoggerInterface;
use Storetown\ShopGuard\Model\BotAnalyzer;
use Storetown\ShopGuard\Model\Config;
use Storetown\ShopGuard\Model\Hardening;

/**
 * Hourly: bot scan over the sampled traffic, repair the .user.ini files
 */
class AnalyzeTraffic
{
    /**
     * @param Config $config
     * @param BotAnalyzer $analyzer
     * @param Hardening $hardening
     * @param LoggerInterface $logger
     */
    public function __construct(
        private Config $config,
        private BotAnalyzer $analyzer,
        private Hardening $hardening,
        private LoggerInterface $logger
    ) {
    }

    /**
     * @return void
     */
    public function execute(): void
    {
        if (!$this->config->flag(Config::ENABLED)) {
            return;
        }
        $this->hardening->apply();
        $summary = $this->analyzer->run();
        if ($summary['ips'] || $summary['agents']) {
            $this->logger->info(sprintf(
                'Shop Guard bot scan (%s): %d IPs, %d user agents added, %d expired',
                $summary['mode'],
                count($summary['ips']),
                count($summary['agents']),
                $summary['expired']
            ));
        }
    }
}
