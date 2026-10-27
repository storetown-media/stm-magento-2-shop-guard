<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Setup\Patch\Data;

use Magento\Framework\App\Config\Storage\WriterInterface;
use Magento\Framework\Setup\ModuleDataSetupInterface;
use Magento\Framework\Setup\Patch\DataPatchInterface;
use Storetown\ShopGuard\Model\Config;

/**
 * Switches both upload blocks on, unless the shop really uses file uploads.
 */
class DetectUploadUsage implements DataPatchInterface
{
    /**
     * @param ModuleDataSetupInterface $setup
     * @param WriterInterface $configWriter
     */
    public function __construct(
        private ModuleDataSetupInterface $setup,
        private WriterInterface $configWriter
    ) {
    }

    /**
     * @inheritdoc
     */
    public function apply()
    {
        $db = $this->setup->getConnection();

        $fileOptions = (int)$db->fetchOne(
            $db->select()
                ->from($this->setup->getTable('catalog_product_option'), ['COUNT(*)'])
                ->where('type = ?', 'file')
        );
        $this->configWriter->save(Config::BLOCK_FILE_OPTIONS, $fileOptions === 0 ? '1' : '0');

        $fileAttributes = (int)$db->fetchOne(
            $db->select()
                ->from(['a' => $this->setup->getTable('eav_attribute')], ['COUNT(*)'])
                ->join(['t' => $this->setup->getTable('eav_entity_type')], 't.entity_type_id = a.entity_type_id', [])
                ->where('t.entity_type_code IN (?)', ['customer', 'customer_address'])
                ->where('a.frontend_input IN (?)', ['file', 'image'])
        );
        $this->configWriter->save(Config::BLOCK_ADDRESS_UPLOAD, $fileAttributes === 0 ? '1' : '0');

        return $this;
    }

    /**
     * @inheritdoc
     */
    public static function getDependencies()
    {
        return [];
    }

    /**
     * @inheritdoc
     */
    public function getAliases()
    {
        return [];
    }
}
