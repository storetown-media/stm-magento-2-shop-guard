<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Cache\TypeListInterface;
use Magento\Framework\App\Config\Storage\WriterInterface;
use Magento\Framework\App\Filesystem\DirectoryList;

/**
 * Hourly bot scan over the sampled traffic log. Findings go straight into the configuration
 * (shop_guard/bots/auto_ips and auto_agents), each with an expiry date, so they stay visible and editable.
 *
 *  - IPs that sent an attack pattern: banned for "ban_days"
 *  - User agents of bots and HTTP libraries above the hourly threshold
 *  - Outdated browser strings above the threshold (rotating fake agents of scraper networks)
 *  - Fake Googlebot/Bingbot: claimed crawler whose IP fails reverse and forward DNS
 *  - Single IPs above the hourly request threshold: banned for one day
 *
 * Never banned: "Never block these IPs", admin login addresses of the last 30 days, proxy addresses.
 */
class BotAnalyzer
{
    private const BOT_HINT = '~bot\b|bot/|crawl|spider|scrap|slurp|python|curl/|wget/|go-http-client|java/|okhttp|'
        . 'axios/|node-fetch|libwww|httpclient|headless|phantomjs|aiohttp|httpx~i';
    private const OUTDATED_BROWSER = '~msie [1-9]\.|trident/[4-7]\.|chrome/([1-9]|[1-6]\d)\.|firefox/([1-9]|[1-5]\d)\.~i';
    private const VERIFIABLE = [
        'googlebot' => '~\.(googlebot|google)\.com$~',
        'google-inspectiontool' => '~\.(googlebot|google)\.com$~',
        'storebot-google' => '~\.(googlebot|google)\.com$~',
        'bingbot' => '~\.search\.msn\.com$~',
        'applebot/' => '~\.applebot\.apple\.com$~',
        'yandexbot' => '~\.yandex\.(ru|net|com)$~',
        'duckduckbot' => '~\.duckduckgo\.com$~',
        'baiduspider' => '~\.baidu\.(com|jp)$~',
    ];
    private const MAX_DNS_LOOKUPS = 15;
    private const FLOOD_BAN_DAYS = 1;
    private const MAX_SHARE = 0.3;
    private const KEEP_STATS = 2592000;

    /**
     * @param Config $config
     * @param WriterInterface $configWriter
     * @param TypeListInterface $cacheTypeList
     * @param DirectoryList $directoryList
     * @param ClientIp $clientIp
     */
    public function __construct(
        private Config $config,
        private WriterInterface $configWriter,
        private TypeListInterface $cacheTypeList,
        private DirectoryList $directoryList,
        private ClientIp $clientIp
    ) {
    }

    /**
     * @param bool $dryRun
     * @return array{requests: int, hours: float, ips: array, agents: array, expired: int, mode: string}
     */
    public function run(bool $dryRun = false): array
    {
        $mode = $this->config->value(Config::AUTO_MODE) ?: Config::MODE_BLOCK;
        $lines = $this->collect($dryRun);
        $summary = [
            'requests' => 0, 'hours' => 1.0, 'ips' => [], 'agents' => [], 'expired' => 0, 'mode' => $mode, 'shared' => [],
            'types' => [], 'rules' => [],
        ];
        if ($mode === Config::MODE_OFF) {
            return $summary;
        }

        $today = date('Y-m-d');
        $autoIps = $this->current(Config::AUTO_IPS, $today, $summary['expired']);
        $autoAgents = $this->current(Config::AUTO_AGENTS, $today, $summary['expired']);

        $allow = $this->config->entries(Config::ALLOW_IPS);
        $knownIps = array_merge(array_column($autoIps, 'value'), $this->config->entries(Config::BLOCKED_IPS));
        $knownAgents = array_merge(
            array_column($autoAgents, 'value'),
            $this->config->entries(Config::BLOCKED_AGENTS, true)
        );

        $first = PHP_INT_MAX;
        $last = 0;
        $attacks = $perIp = $perAgent = $claimed = $allPerIp = $proxies = $byType = $byRule = [];
        foreach ($lines as $line) {
            $f = explode("\t", $line);
            if (count($f) < 8) {
                continue;
            }
            [$time, $weight, $type, $rule, $ip, , , $ua] = $f;
            $ts = strtotime($time) ?: time();
            $first = min($first, $ts);
            $last = max($last, $ts);
            $weight = max(1, (int)$weight);
            $summary['requests'] += $weight;
            $allPerIp[$ip] = ($allPerIp[$ip] ?? 0) + $weight;
            if (($f[8] ?? '0') === '1') {
                $proxies[$ip] = true;
            }
            $byType[$type] = ($byType[$type] ?? 0) + $weight;
            if ($type !== 'pass') {
                $byRule[$rule] = ($byRule[$rule] ?? 0) + $weight;
            }

            if ($type === RequestInspector::TYPE_ATTACK) {
                $attacks[$ip][$rule] = true;
                continue;
            }
            if ($type !== 'pass') {
                continue;
            }
            $lc = strtolower($ua);
            $perIp[$ip] = ($perIp[$ip] ?? 0) + $weight;
            $perAgent[$lc] = ($perAgent[$lc] ?? 0) + $weight;
            foreach (array_keys(self::VERIFIABLE) as $token) {
                if (str_contains($lc, $token)) {
                    $claimed[$ip] = $token;
                }
            }
        }
        $hours = max(1.0, ($last - $first) / 3600);
        $summary['hours'] = round($hours, 1);

        // Never ban admins, and never what may be the proxy in front of the shop: private and server
        // addresses, and while REMOTE_ADDR is used, any address carrying a large share of all traffic.
        $allow = array_merge(
            $allow,
            array_map('strval', array_keys($this->clientIp->adminIps())),
            array_map('strval', array_keys($proxies))
        );
        $fromRemoteAddr = in_array($this->config->value(Config::IP_SOURCE), ['', 'remote_addr'], true);
        foreach ($allPerIp as $ip => $count) {
            if ($fromRemoteAddr && $summary['requests'] >= 200 && $count > $summary['requests'] * self::MAX_SHARE) {
                $allow[] = (string)$ip;
                $summary['shared'][] = (string)$ip;
            }
        }

        $banDays = $this->config->int(Config::BAN_DAYS, 30);
        foreach ($attacks as $ip => $rules) {
            $this->addIp($summary, $knownIps, $allow, (string)$ip, $banDays, implode(',', array_keys($rules)));
        }

        $agentLimit = $this->config->int(Config::AGENT_THRESHOLD, 500);
        foreach ($perAgent as $ua => $count) {
            if ($ua === '' || $count / $hours < $agentLimit
                || RuleList::agentMatch($ua, RequestInspector::FRIENDLY_AGENTS) !== null
                || RuleList::agentMatch($ua, $knownAgents) !== null
            ) {
                continue;
            }
            $reason = null;
            if (preg_match(self::BOT_HINT, $ua)) {
                $reason = 'bot';
            } elseif (preg_match(self::OUTDATED_BROWSER, $ua)) {
                $reason = 'outdated-browser';
            }
            if ($reason === null) {
                continue;
            }
            $token = $reason === 'bot' ? $this->token($ua) : $ua;
            $knownAgents[] = $token;
            $summary['agents'][] = [
                'value' => $token,
                'until' => date('Y-m-d', strtotime('+' . $banDays . ' days')),
                'note' => $reason . ' ' . (int)round($count / $hours) . '/h',
            ];
        }

        $lookups = 0;
        $ipLimit = $this->config->int(Config::IP_THRESHOLD, 5000);
        arsort($perIp);
        foreach ($perIp as $ip => $count) {
            $rate = $count / $hours;
            $token = $claimed[$ip] ?? null;
            if ($token !== null && $rate >= 100 && $lookups < self::MAX_DNS_LOOKUPS) {
                $lookups++;
                if (!$this->verifyCrawler((string)$ip, self::VERIFIABLE[$token])) {
                    $this->addIp($summary, $knownIps, $allow, (string)$ip, $banDays, 'fake-' . rtrim($token, '/'));
                }
                continue;
            }
            if ($rate >= $ipLimit && $token === null) {
                $this->addIp($summary, $knownIps, $allow, (string)$ip, self::FLOOD_BAN_DAYS, 'flood ' . (int)$rate . '/h');
            }
        }

        $changed = $summary['ips'] || $summary['agents'] || $summary['expired'];
        if ($mode === Config::MODE_BLOCK && $changed && !$dryRun) {
            $this->configWriter->save(Config::AUTO_IPS, RuleList::format(array_merge($autoIps, $summary['ips'])));
            $this->configWriter->save(
                Config::AUTO_AGENTS,
                RuleList::format(array_merge($autoAgents, $summary['agents']))
            );
            $this->cacheTypeList->cleanType('config');
        }
        $summary['types'] = $byType;
        $summary['rules'] = $byRule;
        if (!$dryRun && $lines) {
            $this->remember($summary, $first, $last);
        }
        return $summary;
    }

    /**
     * Hourly totals of the last 30 days, oldest first
     *
     * @return array<int, array<string, mixed>>
     */
    public function history(): array
    {
        $data = json_decode((string)@file_get_contents($this->historyFile()), true);
        return is_array($data) ? $data : [];
    }

    /**
     * @param array $summary
     * @param int $first
     * @param int $last
     * @return void
     */
    private function remember(array $summary, int $first, int $last): void
    {
        $history = array_filter($this->history(), static fn ($e) => ($e['to'] ?? 0) > time() - self::KEEP_STATS);
        arsort($summary['rules']);
        $history[] = [
            'from' => $first,
            'to' => $last,
            'requests' => $summary['requests'],
            'types' => $summary['types'],
            'rules' => array_slice($summary['rules'], 0, 15, true),
            'new_ips' => count($summary['ips']),
            'new_agents' => count($summary['agents']),
        ];
        @file_put_contents($this->historyFile(), json_encode(array_values($history)), LOCK_EX);
    }

    /**
     * @return string
     */
    private function historyFile(): string
    {
        return $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/shop_guard/stats.json';
    }

    /**
     * Moves the traffic log aside and returns its lines. A dry run reads without moving.
     *
     * @param bool $dryRun
     * @return string[]
     */
    private function collect(bool $dryRun): array
    {
        $base = $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/' . TrafficLog::FILE;
        $files = array_filter([$base . '.1', $base], 'is_file');
        $lines = [];
        foreach ($files as $file) {
            $read = $file;
            if (!$dryRun) {
                $read = $file . '.work';
                if (!@rename($file, $read)) {
                    continue;
                }
            }
            foreach (file($read, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
                $lines[] = $line;
            }
            if (!$dryRun) {
                @unlink($read);
            }
        }
        return $lines;
    }

    /**
     * @param string $path
     * @param string $today
     * @param int $expired
     * @return array<int, array{value: string, until: ?string, note: string}>
     */
    private function current(string $path, string $today, int &$expired): array
    {
        $keep = [];
        foreach (RuleList::parse($this->config->value($path)) as $entry) {
            if ($entry['until'] !== null && $entry['until'] < $today) {
                $expired++;
                continue;
            }
            $keep[] = $entry;
        }
        return $keep;
    }

    /**
     * @param array $summary
     * @param string[] $known
     * @param string[] $allow
     * @param string $ip
     * @param int $days
     * @param string $reason
     * @return void
     */
    private function addIp(array &$summary, array &$known, array $allow, string $ip, int $days, string $reason): void
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)
            || RuleList::ipMatches($ip, $known)
            || RuleList::ipMatches($ip, $allow)
        ) {
            return;
        }
        $known[] = $ip;
        $summary['ips'][] = ['value' => $ip, 'until' => date('Y-m-d', strtotime('+' . $days . ' days')), 'note' => $reason];
    }

    /**
     * Shortest stable part of a bot user agent, e.g. "acmebot" instead of the full string.
     *
     * @param string $ua lowercase
     * @return string
     */
    private function token(string $ua): string
    {
        $candidates = [];
        if (preg_match_all('~[a-z0-9._-]*(bot|crawler|spider|scraper)[a-z0-9._-]*~', $ua, $m)) {
            $candidates = $m[0];
        }
        if (preg_match('~(python-requests|python-urllib|python-httpx|aiohttp|scrapy|curl|wget|go-http-client|okhttp|'
            . 'axios|node-fetch|libwww-perl|headlesschrome|phantomjs|java)/~', $ua, $m)) {
            $candidates[] = $m[1] . '/';
        }
        foreach ($candidates as $token) {
            $token = trim($token, '.-_');
            $generic = in_array($token, ['bot', 'crawler', 'spider', 'scraper', 'robot'], true);
            if (strlen($token) < 5 || $generic) {
                continue;
            }
            foreach (RequestInspector::FRIENDLY_AGENTS as $friendly) {
                if (str_contains($friendly, $token) || str_contains($token, $friendly)) {
                    continue 2;
                }
            }
            return $token;
        }
        return $ua;
    }

    /**
     * Reverse lookup must end in the crawler's domain and resolve back to the same IP.
     *
     * @param string $ip
     * @param string $hostPattern
     * @return bool
     */
    private function verifyCrawler(string $ip, string $hostPattern): bool
    {
        $host = strtolower((string)@gethostbyaddr($ip));
        if ($host === '' || $host === $ip || !preg_match($hostPattern, $host)) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                if (@inet_pton($record['ipv6'] ?? '') === @inet_pton($ip)) {
                    return true;
                }
            }
            return false;
        }
        return in_array($ip, @gethostbynamel($host) ?: [], true);
    }
}
