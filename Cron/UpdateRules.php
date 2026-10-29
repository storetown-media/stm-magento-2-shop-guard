<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Cron;

use Storetown\ShopGuard\Model\Config;
use Storetown\ShopGuard\Model\RuleFeed;

/**
 * Fetches the signed attack patterns of Storetown Media every hour
 */
class UpdateRules
{
    /**
     * @param Config $config
     * @param RuleFeed $ruleFeed
     */
    public function __construct(
        private Config $config,
        private RuleFeed $ruleFeed
    ) {
    }

    /**
     * @return void
     */
    public function execute(): void
    {
        if ($this->config->flag(Config::ENABLED) && $this->config->flag(Config::FEED_ENABLED)) {
            $this->ruleFeed->update();
        }
    }
}
