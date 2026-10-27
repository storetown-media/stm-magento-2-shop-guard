<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;
use Storetown\ShopGuard\Model\Config;

class AutoMode implements OptionSourceInterface
{
    /**
     * @return array<int, array{value: string, label: \Magento\Framework\Phrase|string}>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => Config::MODE_BLOCK, 'label' => __('Block automatically')],
            ['value' => Config::MODE_REPORT, 'label' => __('Analyse only (results in var/log/system.log)')],
            ['value' => Config::MODE_OFF, 'label' => __('Off')],
        ];
    }
}
