<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;

/**
 * Read access to the shop_guard configuration section
 */
class Config
{
    public const ENABLED = 'shop_guard/general/enabled';
    public const IP_SOURCE = 'shop_guard/general/ip_source';
    public const ALLOW_IPS = 'shop_guard/general/allow_ips';

    public const ATTACK_RULES = 'shop_guard/filter/attack_rules';
    public const BLOCK_GRAPHQL = 'shop_guard/filter/block_graphql';
    public const BLOCK_ADDRESS_UPLOAD = 'shop_guard/filter/block_address_upload';
    public const BLOCK_FILE_OPTIONS = 'shop_guard/filter/block_file_options';
    public const BLOCK_SEO_BOTS = 'shop_guard/filter/block_seo_bots';
    public const BLOCK_AI_CRAWLERS = 'shop_guard/filter/block_ai_crawlers';
    public const BLOCKED_IPS = 'shop_guard/filter/blocked_ips';
    public const BLOCKED_AGENTS = 'shop_guard/filter/blocked_agents';
    public const FACET_PARAMS = 'shop_guard/filter/facet_params';

    public const AUTO_MODE = 'shop_guard/bots/mode';
    public const BAN_DAYS = 'shop_guard/bots/ban_days';
    public const AGENT_THRESHOLD = 'shop_guard/bots/agent_threshold';
    public const IP_THRESHOLD = 'shop_guard/bots/ip_threshold';
    public const SAMPLE_RATE = 'shop_guard/bots/sample_rate';
    public const AUTO_IPS = 'shop_guard/bots/auto_ips';
    public const AUTO_AGENTS = 'shop_guard/bots/auto_agents';

    public const SCAN_ENABLED = 'shop_guard/files/scan_enabled';
    public const WRITE_USER_INI = 'shop_guard/files/write_user_ini';
    public const ALLOWED_PUB_FILES = 'shop_guard/files/allowed_pub_files';

    public const RECIPIENTS = 'shop_guard/notify/recipients';
    public const SENDER = 'shop_guard/notify/sender';

    public const MODE_OFF = 'off';
    public const MODE_REPORT = 'report';
    public const MODE_BLOCK = 'block';

    /**
     * @var array<string, array<int, string>>
     */
    private array $lists = [];

    /**
     * @param ScopeConfigInterface $scopeConfig
     */
    public function __construct(private ScopeConfigInterface $scopeConfig)
    {
    }

    /**
     * @param string $path
     * @return bool
     */
    public function flag(string $path): bool
    {
        return $this->scopeConfig->isSetFlag($path);
    }

    /**
     * @param string $path
     * @return string
     */
    public function value(string $path): string
    {
        return trim((string)$this->scopeConfig->getValue($path));
    }

    /**
     * @param string $path
     * @param int $default
     * @return int
     */
    public function int(string $path, int $default): int
    {
        $value = $this->value($path);
        return is_numeric($value) && (int)$value > 0 ? (int)$value : $default;
    }

    /**
     * Entries of a textarea list, comments after "#" removed.
     *
     * @param string $path
     * @param bool $lowercase
     * @return string[]
     */
    public function entries(string $path, bool $lowercase = false): array
    {
        $key = $path . ($lowercase ? ':lc' : '');
        if (!isset($this->lists[$key])) {
            $entries = [];
            foreach (RuleList::parse($this->value($path)) as $line) {
                $entries[] = $lowercase ? strtolower($line['value']) : $line['value'];
            }
            $this->lists[$key] = $entries;
        }
        return $this->lists[$key];
    }

    /**
     * @return string[]
     */
    public function recipients(): array
    {
        $list = preg_split('/[\s,;]+/', $this->value(self::RECIPIENTS)) ?: [];
        return array_values(array_filter($list, static fn ($mail) => (bool)filter_var($mail, FILTER_VALIDATE_EMAIL)));
    }
}
