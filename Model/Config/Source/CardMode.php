<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;
use Storetown\ShopGuard\Model\Config;

class CardMode implements OptionSourceInterface
{
    /**
     * @return array<int, array{value: string, label: \Magento\Framework\Phrase|string}>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => Config::MODE_REPORT, 'label' => __('Watch only (bin/magento shopguard:cardtests)')],
            ['value' => Config::MODE_BLOCK, 'label' => __('Refuse further payment attempts')],
            ['value' => Config::MODE_OFF, 'label' => __('Off')],
        ];
    }
}
