<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Observer;

use Magento\Framework\App\Request\Http as Request;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;
use Storetown\ShopGuard\Model\ClientIp;

/**
 * Admins test the shop, sometimes with attack strings. The bot scan never bans their addresses.
 */
class RememberAdminIp implements ObserverInterface
{
    /**
     * @param ClientIp $clientIp
     * @param Request $request
     */
    public function __construct(
        private ClientIp $clientIp,
        private Request $request
    ) {
    }

    /**
     * @param Observer $observer
     * @return void
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function execute(Observer $observer): void
    {
        try {
            $this->clientIp->rememberAdmin($this->clientIp->resolve($this->request));
        } catch (\Throwable $e) {
            unset($e);
        }
    }
}
