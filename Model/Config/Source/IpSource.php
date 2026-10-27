<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

class IpSource implements OptionSourceInterface
{
    /**
     * @return array<int, array{value: string, label: \Magento\Framework\Phrase|string}>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => 'remote_addr', 'label' => __('REMOTE_ADDR (no proxy)')],
            ['value' => 'x_real_ip', 'label' => __('X-Real-IP (nginx proxy, e.g. maxcluster)')],
            ['value' => 'x_forwarded_for', 'label' => __('X-Forwarded-For, last entry')],
            ['value' => 'cf_connecting_ip', 'label' => __('CF-Connecting-IP (Cloudflare)')],
        ];
    }
}
