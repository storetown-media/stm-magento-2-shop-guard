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
use Storetown\ShopGuard\Model\LoginGuard;

/**
 * Every failed admin login is counted; an address that keeps guessing is blocked, see LoginGuard
 */
class BlockPasswordGuessing implements ObserverInterface
{
    /**
     * @param LoginGuard $loginGuard
     * @param ClientIp $clientIp
     * @param Request $request
     */
    public function __construct(
        private LoginGuard $loginGuard,
        private ClientIp $clientIp,
        private Request $request
    ) {
    }

    /**
     * @param Observer $observer
     * @return void
     */
    public function execute(Observer $observer): void
    {
        try {
            $this->loginGuard->failed(
                $this->clientIp->resolve($this->request),
                (string)$this->request->getServer('SERVER_ADDR'),
                (string)$observer->getEvent()->getData('user_name')
            );
        } catch (\Throwable $e) {
            // never break the login page
            unset($e);
        }
    }
}
