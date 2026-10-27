<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\Filesystem\DirectoryList;

/**
 * Decides whether a request is blocked. Works on plain request facts so it can be tested without HTTP.
 */
class RequestInspector
{
    public const TYPE_ATTACK = 'attack';
    public const TYPE_IP = 'ip';
    public const TYPE_BOT = 'bot';
    public const TYPE_POLICY = 'policy';

    public const SEO_BOTS = [
        'ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'blexbot', 'dataforseobot', 'petalbot',
        'seekport', 'serpstatbot', 'barkrowler', 'linguabot', 'megaindex', 'zoominfobot',
        'imagesiftbot', 'mauibot', 'awario', 'thinkbot',
    ];

    public const AI_CRAWLERS = [
        'gptbot', 'ccbot', 'claudebot', 'anthropic-ai', 'bytespider', 'meta-externalagent',
        'applebot-extended', 'amazonbot', 'diffbot', 'omgili', 'cohere-training-data-crawler',
        'ai2bot', 'timpibot', 'img2dataset', 'facebookbot',
    ];

    /**
     * Never blocked automatically: search engines, AI search and link previews,
     * price comparison, payment callbacks and uptime monitors.
     */
    public const FRIENDLY_AGENTS = [
        'googlebot', 'google-inspectiontool', 'googleother', 'storebot-google', 'adsbot-google',
        'mediapartners-google', 'google-read-aloud', 'feedfetcher-google', 'bingbot', 'adidxbot',
        'bingpreview', 'msnbot', 'duckduckbot', 'yandexbot', 'baiduspider', 'seznambot', 'qwantbot',
        'ecosia', 'applebot/', 'oai-searchbot', 'chatgpt-user', 'perplexitybot', 'perplexity-user',
        'claude-user', 'claude-searchbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
        'slackbot', 'whatsapp', 'telegrambot', 'pinterestbot', 'discordbot', 'idealo', 'billiger',
        'geizhals', 'guenstiger', 'check24', 'kelkoo', 'trustedshops', 'paypal', 'stripe',
        'uptimerobot', 'pingdom', 'statuscake', 'site24x7', 'better uptime', 'sansec',
    ];

    private const DIRECTIVE = '~\{\{\s*(var|block|config|template|trans|depend|if|inlinecss|media|store|'
        . 'layout|protocol|widget|customvar|css|view)\b[^}]{0,300}\}\}~i';

    /**
     * @var string|null
     */
    private ?string $adminFrontName = null;

    /**
     * @param Config $config
     * @param DeploymentConfig $deploymentConfig
     * @param DirectoryList $directoryList
     */
    public function __construct(
        private Config $config,
        private DeploymentConfig $deploymentConfig,
        private DirectoryList $directoryList
    ) {
    }

    /**
     * @param array<string, mixed> $r request facts, see Plugin\RequestFilter::facts()
     * @return array{type: string, rule: string}|null
     */
    public function inspect(array $r): ?array
    {
        // Self-test: https://shop/?shopguard-test shows the block page, also for allowed IPs
        if (in_array('shopguard-test', array_map('strtolower', (array)$r['query_keys']), true)) {
            return ['type' => self::TYPE_POLICY, 'rule' => 'test'];
        }

        // A proxy or private address stands for many visitors, IP lists never apply to it
        $ip = empty($r['proxy']) ? (string)$r['ip'] : '';
        if ($ip !== '' && RuleList::ipMatches($ip, $this->config->entries(Config::ALLOW_IPS))) {
            return null;
        }
        if ($ip !== '' && RuleList::ipMatches($ip, $this->config->entries(Config::BLOCKED_IPS))) {
            return ['type' => self::TYPE_IP, 'rule' => 'ip-manual'];
        }
        if ($ip !== '' && RuleList::ipMatches($ip, $this->config->entries(Config::AUTO_IPS))) {
            return ['type' => self::TYPE_IP, 'rule' => 'ip-auto'];
        }

        if ($this->isTrusted($r)) {
            return null;
        }
        $path = strtolower((string)$r['path']);

        if ($this->config->flag(Config::ATTACK_RULES) && ($rule = $this->attack($r, $path)) !== null) {
            return ['type' => self::TYPE_ATTACK, 'rule' => $rule];
        }
        if ($this->config->flag(Config::BLOCK_GRAPHQL) && preg_match('~(^|/)graphql/?$~', $path)) {
            return ['type' => self::TYPE_POLICY, 'rule' => 'graphql'];
        }
        if (($rule = $this->agent(strtolower((string)$r['ua']))) !== null) {
            return ['type' => self::TYPE_BOT, 'rule' => $rule];
        }
        if ($this->isFacetCrawl($r)) {
            return ['type' => self::TYPE_POLICY, 'rule' => 'facet'];
        }
        return null;
    }

    /**
     * @param array<string, mixed> $r
     * @param string $path
     * @return string|null
     */
    private function attack(array $r, string $path): ?string
    {
        $hay = (string)$r['query'] . "\n" . (string)$r['body'] . "\n" . (string)$r['post'];

        // StyleSmuggler: template_styles / styles[...] gadget chain, also via /paypal/transparent/response/
        if (stripos($hay, 'template_styles') !== false
            || stripos($hay, 'styles[with_resolved') !== false
            || (stripos($hay, 'styles[') !== false && stripos($hay, 'generatorclass') !== false)
            || preg_match('~rowUrl\s*=\s*\$this|Grid\\\\+ColumnSet~i', $hay)
        ) {
            return 'stylesmuggler';
        }
        // TrojanOrder and friends: template directives in customer input
        if (preg_match(self::DIRECTIVE, $hay)) {
            return 'template-directive';
        }
        if (preg_match('~<\?(php|=)|eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)~i', $hay)
            || preg_match('~<\?(php|=)~i', (string)$r['ua'])
        ) {
            return 'php-code';
        }
        // CosmicSting (CVE-2024-34102)
        if (preg_match('~<!ENTITY[^>]{0,200}SYSTEM~i', $hay)) {
            return 'xxe';
        }
        // PHP2Shell (CVE-2026-109619): Magento never uses upload progress fields
        $progressName = strtolower((string)ini_get('session.upload_progress.name')) ?: 'php_session_upload_progress';
        foreach ((array)$r['post_keys'] as $key) {
            if (strtolower((string)$key) === $progressName) {
                return 'php2shell';
            }
        }
        // PolyShell (APSB25-94): base64 file upload into a cart item
        if ($this->config->flag(Config::BLOCK_FILE_OPTIONS)
            && stripos((string)$r['body'], 'base64_encoded_data') !== false
            && preg_match('~/v1/(guest-)?carts/~', $path)
        ) {
            return 'polyshell';
        }
        // SessionReaper staging and the daily address upload drops seen in 2026
        if ($this->config->flag(Config::BLOCK_ADDRESS_UPLOAD) && str_contains($path, '/customer/address_file/upload')) {
            return 'address-upload';
        }
        // Scanners register with reserved domains (RFC 2606)
        if (preg_match('~[a-z0-9._%+-]+@[a-z0-9.-]*\.(invalid|test|example|localhost)(?![a-z0-9.-])~i', $hay)) {
            return 'scanner-email';
        }
        return null;
    }

    /**
     * @param string $ua lowercase
     * @return string|null
     */
    private function agent(string $ua): ?string
    {
        $tokens = array_merge(
            $this->config->entries(Config::BLOCKED_AGENTS, true),
            $this->config->entries(Config::AUTO_AGENTS, true)
        );
        if (($hit = RuleList::agentMatch($ua, $tokens)) !== null) {
            return 'ua:' . $hit;
        }
        if ($this->config->flag(Config::BLOCK_SEO_BOTS) && ($hit = RuleList::agentMatch($ua, self::SEO_BOTS))) {
            return 'ua:' . $hit;
        }
        if ($this->config->flag(Config::BLOCK_AI_CRAWLERS) && ($hit = RuleList::agentMatch($ua, self::AI_CRAWLERS))) {
            return 'ua:' . $hit;
        }
        return null;
    }

    /**
     * Layered navigation crawls: filter URLs only for visitors with a live session or an internal referrer.
     *
     * @param array<string, mixed> $r
     * @return bool
     */
    private function isFacetCrawl(array $r): bool
    {
        $params = $this->config->entries(Config::FACET_PARAMS, true);
        if (!$params || empty($r['query_keys'])) {
            return false;
        }
        if (!array_intersect($params, array_map('strtolower', (array)$r['query_keys']))) {
            return false;
        }
        $ua = strtolower((string)$r['ua']);
        if (RuleList::agentMatch($ua, self::FRIENDLY_AGENTS) !== null) {
            return false;
        }
        $referer = (string)$r['referer'];
        if ($referer !== '' && strcasecmp((string)parse_url($referer, PHP_URL_HOST), (string)$r['host']) === 0) {
            return false;
        }
        return !$this->hasLiveSession((string)$r['session']);
    }

    /**
     * A cookie alone proves nothing, crawlers send made-up ones. With file sessions the file must exist.
     *
     * @param string $sessionId
     * @return bool
     */
    private function hasLiveSession(string $sessionId): bool
    {
        if (!preg_match('/^[A-Za-z0-9,-]{16,128}$/', $sessionId)) {
            return false;
        }
        $save = (string)$this->deploymentConfig->get('session/save');
        if ($save !== '' && $save !== 'files') {
            return true;
        }
        $dir = (string)$this->deploymentConfig->get('session/save_path');
        if ($dir === '') {
            $dir = $this->directoryList->getPath(DirectoryList::SESSION);
        }
        $dir = rtrim((string)preg_replace('/^\d+;(\d+;)?/', '', $dir), '/');
        return @file_exists($dir . '/sess_' . $sessionId);
    }

    /**
     * Admin area and authenticated API calls. Integrations (ERP, PIM) may send anything, also unusual agents.
     *
     * @param array<string, mixed> $r
     * @return bool
     */
    public function isTrusted(array $r): bool
    {
        return !empty($r['auth']) || $this->isAdmin(strtolower((string)$r['path']));
    }

    /**
     * @param string $path lowercase
     * @return bool
     */
    private function isAdmin(string $path): bool
    {
        if ($this->adminFrontName === null) {
            $this->adminFrontName = strtolower((string)$this->deploymentConfig->get('backend/frontName'));
        }
        return $this->adminFrontName !== ''
            && preg_match('~^/(index\.php/)?' . preg_quote($this->adminFrontName, '~') . '(/|$)~', $path) === 1;
    }
}
