<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model\Probe;

/**
 * Harmless class for the StyleSmuggler hotfix test. A patched BlockFactory refuses it
 * before construction, an unpatched one constructs it first and fails afterwards.
 */
class NotABlock
{
    /**
     * @var bool
     */
    public static bool $constructed = false;

    public function __construct()
    {
        self::$constructed = true;
    }
}
