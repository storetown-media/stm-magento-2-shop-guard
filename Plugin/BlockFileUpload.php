<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Plugin;

use Magento\Catalog\Model\Product\Option\Type\File;
use Magento\Catalog\Model\Product\Option\Type\File\ValidatorFile;
use Magento\Catalog\Model\Webapi\Product\Option\Type\File\Processor;
use Magento\Framework\Exception\LocalizedException;
use Storetown\ShopGuard\Model\Config;

/**
 * PolyShell (APSB25-94): custom option files are written to pub/media/custom_options before any check.
 * Blocking the frontend validators is not enough, the REST cart API writes through the Webapi processor.
 * @SuppressWarnings(PHPMD.UnusedFormalParameter)
 */
class BlockFileUpload
{
    /**
     * @param Config $config
     */
    public function __construct(private Config $config)
    {
    }

    /**
     * @param File $subject
     * @param array $values
     * @return null
     * @throws LocalizedException
     */
    public function beforeValidateUserValue(File $subject, $values)
    {
        $this->deny();
        return null;
    }

    /**
     * @param ValidatorFile $subject
     * @param mixed $processingParams
     * @param mixed $option
     * @return null
     * @throws LocalizedException
     */
    public function beforeValidate(ValidatorFile $subject, $processingParams, $option)
    {
        $this->deny();
        return null;
    }

    /**
     * @param Processor $subject
     * @param mixed $imageContent
     * @return null
     * @throws LocalizedException
     */
    public function beforeProcessFileContent(Processor $subject, $imageContent)
    {
        $this->deny();
        return null;
    }

    /**
     * @return void
     * @throws LocalizedException
     */
    private function deny(): void
    {
        if ($this->config->flag(Config::ENABLED) && $this->config->flag(Config::BLOCK_FILE_OPTIONS)) {
            throw new LocalizedException(__('File uploads in product options are disabled for security reasons.'));
        }
    }
}
