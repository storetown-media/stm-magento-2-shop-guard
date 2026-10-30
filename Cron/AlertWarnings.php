<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Cron;

use Storetown\ShopGuard\Model\Config;
use Storetown\ShopGuard\Model\WarningCheck;

/**
 * Hourly, after the feed was fetched and after Shop Security Guard Pro had its turn: critical and high warnings
 * that affect this shop
 */
class AlertWarnings
{
    /**
     * @param Config $config
     * @param WarningCheck $warningCheck
     */
    public function __construct(
        private Config $config,
        private WarningCheck $warningCheck
    ) {
    }

    /**
     * @return void
     */
    public function execute(): void
    {
        if ($this->config->flag(Config::ENABLED) && $this->config->flag(Config::FEED_ENABLED)) {
            $this->warningCheck->alert();
        }
    }
}
