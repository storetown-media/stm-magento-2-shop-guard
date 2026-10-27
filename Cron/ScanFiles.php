<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Cron;

use Storetown\ShopGuard\Model\Config;
use Storetown\ShopGuard\Model\FileScanner;
use Storetown\ShopGuard\Model\Hardening;
use Storetown\ShopGuard\Model\Notifier;
use Storetown\ShopGuard\Model\SystemCheck;

/**
 * Every 30 minutes: file scan, daily patch status, mail on findings
 */
class ScanFiles
{
    /**
     * @param Config $config
     * @param FileScanner $scanner
     * @param SystemCheck $systemCheck
     * @param Notifier $notifier
     * @param Hardening $hardening
     */
    public function __construct(
        private Config $config,
        private FileScanner $scanner,
        private SystemCheck $systemCheck,
        private Notifier $notifier,
        private Hardening $hardening
    ) {
    }

    /**
     * @return void
     */
    public function execute(): void
    {
        if (!$this->config->flag(Config::ENABLED) || !$this->config->flag(Config::SCAN_ENABLED)) {
            return;
        }
        $this->hardening->apply();
        $this->systemCheck->patchStatus(true);
        $this->notifier->notify($this->scanner->scan(), $this->systemCheck->run());
    }
}
