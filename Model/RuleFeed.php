<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\HTTP\Client\CurlFactory;

/**
 * Attack patterns published by Storetown Media between releases, so a new attack wave is filtered within the hour
 * and not only after a module update. The feed is signed with Ed25519: a file that does not verify against one of
 * the keys below is never used. Only the file is fetched, nothing about the shop is sent.
 */
class RuleFeed
{
    public const URL = 'https://www.storetown-media.de/shop-guard/rules.json';

    /**
     * Public keys that may sign the feed, by key id. Two at a time allow a key change without a gap.
     */
    public const KEYS = [
        'prod-2026-10' => 'VfHswdaf8K0L0r/OXX7tI6lyqUxFHB9Xw4UTVs60V/w=',
    ];

    public const ACTION_BLOCK = 'block';
    public const ACTION_LOG = 'log';
    // answers 403 like ?shopguard-test, but is no attack: the bot scan must not ban whoever tries it
    public const ACTION_TEST = 'test';
    public const TEST_RULE = 'feed-test';

    private const RULES_FILE = 'shop_guard/feed.json';
    private const STATE_FILE = 'shop_guard/feed-state.json';
    private const HITS_FILE = 'shop_guard/feed-hits.log';
    private const MAX_BYTES = 262144;
    private const MAX_RULES = 300;
    private const MAX_PATTERN = 1000;
    private const MAX_HITS_BYTES = 1048576;
    private const FIELDS = ['query', 'body', 'post', 'ua', 'path', 'uri'];
    private const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
    private const BACKTRACK_LIMIT = '100000';

    /**
     * Ordinary requests no rule may match. A rule that does is refused, so a faulty pattern cannot lock out customers.
     */
    private const CANARIES = [
        'start page' => ['method' => 'GET', 'path' => '/', 'query' => '', 'body' => '', 'post' => ''],
        'category with filter' => [
            'method' => 'GET', 'path' => '/sanitaer/armaturen.html', 'query' => 'color=49&price=10-100&p=2',
            'body' => '', 'post' => '',
        ],
        'search' => [
            'method' => 'GET', 'path' => '/catalogsearch/result/', 'body' => '', 'post' => '',
            'query' => 'q=Kugelhahn 3/4" Messing & Edelstahl (DN20) <neu> 100% "Angebot"',
        ],
        'product page' => [
            'method' => 'GET', 'path' => '/kugelhahn-messing-3-4-zoll.html', 'query' => 'utm_source=google&gclid=x1',
            'body' => '', 'post' => '',
        ],
        'add to cart' => [
            'method' => 'POST', 'path' => '/checkout/cart/add/uenc/aHR0cHM6Ly9zaG9w/product/12/', 'query' => '',
            'body' => '', 'post' => "12\n1\nTp2Kx9fQ3LmN8vRz\n",
        ],
        'customer account' => [
            'method' => 'POST', 'path' => '/customer/account/createpost/', 'query' => '', 'body' => '',
            'post' => "Jürgen\nO'Neil-Müller\nj.oneil@beispiel-gmbh.de\nGeheim!2026#Sommer\n1\nTp2Kx9fQ3LmN8vRz\n",
        ],
        'checkout payment' => [
            'method' => 'POST', 'path' => '/rest/default/v1/guest-carts/aBc123/payment-information', 'query' => '',
            'post' => '',
            'body' => '{"cartId":"aBc123","email":"kunde@beispiel.de","paymentMethod":{"method":"checkmo",'
                . '"po_number":null,"additional_data":null},"billingAddress":{"countryId":"DE","regionId":null,'
                . '"street":["Hauptstraße 1a","c/o Firma & Co. KG"],"company":"Müller & Söhne","telephone":"+49 40 123456",'
                . '"postcode":"25436","city":"Tornesch","firstname":"Anna","lastname":"Schmidt"}}',
        ],
        'graphql cart' => [
            'method' => 'POST', 'path' => '/graphql', 'query' => '', 'post' => '',
            'body' => '{"query":"mutation { addProductsToCart(cartId: \"x1\", cartItems: [{sku: \"KH-34\", quantity: 2}])'
                . ' { cart { total_quantity } } }"}',
        ],
        'contact form' => [
            'method' => 'POST', 'path' => '/contact/index/post/', 'query' => '', 'body' => '',
            'post' => "Peter\npeter@beispiel.de\nBitte rufen Sie an: Ist der Artikel 4711 (1/2\") lieferbar? Danke!\n",
        ],
        'image' => [
            'method' => 'GET', 'path' => '/media/catalog/product/k/u/kugelhahn.jpg', 'query' => '', 'body' => '',
            'post' => '',
        ],
    ];

    /**
     * @var array<int, array<string, mixed>>|null
     */
    private ?array $loaded = null;

    /**
     * @param CurlFactory $curlFactory
     * @param DirectoryList $directoryList
     */
    public function __construct(
        private CurlFactory $curlFactory,
        private DirectoryList $directoryList
    ) {
    }

    /**
     * Fetches the feed and its signature and takes it over if it verifies.
     *
     * @return array{status: string, message: string}
     */
    public function update(): array
    {
        try {
            $json = $this->fetch(self::URL);
            $signature = $this->fetch(self::URL . '.sig');
        } catch (\RuntimeException $e) {
            return $this->fail($e->getMessage());
        }
        return $this->import($json, $signature);
    }

    /**
     * Takes over a signed feed, from the network or from a file brought by hand.
     *
     * @param string $json
     * @param string $signature content of the .sig file: "<key id> <base64 signature>"
     * @return array{status: string, message: string}
     */
    public function import(string $json, string $signature): array
    {
        try {
            $key = $this->verify($json, $signature);
            $feed = $this->decode($json);
            $state = $this->state();
            $installed = (int)($state['serial'] ?? 0);
            if ($feed['serial'] < $installed) {
                throw new \RuntimeException(sprintf(
                    'feed %d is older than the installed feed %d, kept the installed one',
                    $feed['serial'],
                    $installed
                ));
            }
            if ($feed['serial'] === $installed && hash('sha256', $json) === ($state['hash'] ?? '')) {
                $this->writeState(['checked' => time(), 'error' => null] + $state);
                return ['status' => 'unchanged', 'message' => sprintf('feed %d is current', $installed)];
            }
            [$rules, $refused] = $this->validate($feed['rules']);
            $this->write(self::RULES_FILE, (string)json_encode(
                ['serial' => $feed['serial'], 'rules' => $rules],
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            ));
            $this->loaded = null;
            $this->writeState([
                'serial' => $feed['serial'],
                'issued' => $feed['issued'],
                'key' => $key,
                'hash' => hash('sha256', $json),
                'checked' => time(),
                'updated' => time(),
                'rules' => count($rules),
                'refused' => $refused,
                'error' => null,
            ]);
            return ['status' => 'updated', 'message' => sprintf(
                'feed %d: %d rules active, %d refused',
                $feed['serial'],
                count($rules),
                count($refused)
            )];
        } catch (\RuntimeException $e) {
            return $this->fail($e->getMessage());
        }
    }

    /**
     * Checks an unsigned feed file before it is signed and published: format, patterns, ordinary requests.
     *
     * @param string $json
     * @return array{serial: int, rules: array<int, array<string, mixed>>, refused: array<string, string>}
     */
    public function check(string $json): array
    {
        $feed = $this->decode($json);
        [$rules, $refused] = $this->validate($feed['rules']);
        return ['serial' => $feed['serial'], 'rules' => $rules, 'refused' => $refused];
    }

    /**
     * Matches a request against the active feed rules.
     *
     * @param array<string, mixed> $r request facts, see Plugin\RequestFilter::facts()
     * @param string $path lowercase path
     * @return string|null rule name "feed:<id>" when a blocking rule matched, TEST_RULE for a test rule
     */
    public function match(array $r, string $path): ?string
    {
        $rules = $this->rules();
        if (!$rules) {
            return null;
        }
        $facts = ['path' => $path] + $r;
        foreach ($rules as $rule) {
            if (!$this->matches($rule, $facts)) {
                continue;
            }
            if ($rule['action'] === self::ACTION_LOG) {
                $this->logHit($rule['id'], $facts);
                continue;
            }
            return $rule['action'] === self::ACTION_TEST ? self::TEST_RULE : 'feed:' . $rule['id'];
        }
        return null;
    }

    /**
     * @return array<string, mixed>
     */
    public function state(): array
    {
        $data = json_decode((string)@file_get_contents($this->path(self::STATE_FILE)), true);
        return is_array($data) ? $data : [];
    }

    /**
     * Active rules with id, title and action, for status pages and the command line
     *
     * @return array<int, array<string, mixed>>
     */
    public function rules(): array
    {
        if ($this->loaded === null) {
            $data = json_decode((string)@file_get_contents($this->path(self::RULES_FILE)), true);
            $this->loaded = is_array($data) && is_array($data['rules'] ?? null) ? $data['rules'] : [];
        }
        return $this->loaded;
    }

    /**
     * Hits of rules in the mode "log" over the last days, by rule id
     *
     * @param int $days
     * @return array<string, int>
     */
    public function hits(int $days = 30): array
    {
        $since = date('c', time() - $days * 86400);
        $counts = [];
        foreach (array_filter(explode("\n", (string)@file_get_contents($this->path(self::HITS_FILE)))) as $line) {
            $f = explode("\t", $line);
            if (count($f) >= 2 && $f[0] >= $since) {
                $counts[$f[1]] = ($counts[$f[1]] ?? 0) + 1;
            }
        }
        arsort($counts);
        return $counts;
    }

    /**
     * @param string $url
     * @return string
     */
    private function fetch(string $url): string
    {
        $curl = $this->curlFactory->create();
        $curl->setTimeout(10);
        $curl->addHeader('User-Agent', 'STM-Shop-Security-Guard-RuleFeed/1');
        $curl->get($url);
        $body = (string)$curl->getBody();
        if ($curl->getStatus() !== 200) {
            throw new \RuntimeException(sprintf('%s answered %d', $url, $curl->getStatus()));
        }
        if ($body === '' || strlen($body) > self::MAX_BYTES) {
            throw new \RuntimeException(sprintf('%s: unexpected size %d bytes', $url, strlen($body)));
        }
        return $body;
    }

    /**
     * @param string $json
     * @param string $signature
     * @return string key id that signed the feed
     */
    private function verify(string $json, string $signature): string
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new \RuntimeException('the PHP extension sodium is missing, the feed cannot be verified');
        }
        $parts = preg_split('/\s+/', trim($signature)) ?: [];
        if (count($parts) !== 2 || !isset(self::KEYS[$parts[0]])) {
            throw new \RuntimeException('signature from an unknown key, feed refused');
        }
        $sig = base64_decode($parts[1], true);
        $key = base64_decode(self::KEYS[$parts[0]], true);
        if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
            || $key === false || strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            || !sodium_crypto_sign_verify_detached($sig, $json, $key)
        ) {
            throw new \RuntimeException('signature does not match, feed refused');
        }
        return $parts[0];
    }

    /**
     * @param string $json
     * @return array{serial: int, issued: string, rules: array<int, mixed>}
     */
    private function decode(string $json): array
    {
        if (strlen($json) > self::MAX_BYTES) {
            throw new \RuntimeException('feed larger than 256 KB');
        }
        $feed = json_decode($json, true);
        if (!is_array($feed) || ($feed['format'] ?? null) !== 1) {
            throw new \RuntimeException('feed is not in format 1');
        }
        if (!is_int($feed['serial'] ?? null) || $feed['serial'] < 1) {
            throw new \RuntimeException('feed has no valid serial number');
        }
        if (!is_array($feed['rules'] ?? null) || count($feed['rules']) > self::MAX_RULES) {
            throw new \RuntimeException('feed has no rule list or more than 300 rules');
        }
        return ['serial' => $feed['serial'], 'issued' => (string)($feed['issued'] ?? ''), 'rules' => $feed['rules']];
    }

    /**
     * Keeps only well-formed rules whose patterns compile and match none of the ordinary requests.
     *
     * @param array<int, mixed> $input
     * @return array{0: array<int, array<string, mixed>>, 1: array<string, string>}
     */
    private function validate(array $input): array
    {
        $rules = [];
        $refused = [];
        foreach ($input as $i => $raw) {
            $id = is_array($raw) && is_string($raw['id'] ?? null) ? $raw['id'] : '#' . $i;
            try {
                $rule = $this->normalize($raw);
                if (isset($rules[$rule['id']])) {
                    throw new \RuntimeException('id used twice');
                }
                foreach (self::CANARIES as $name => $canary) {
                    if ($this->matches($rule, $canary + ['ua' => 'Mozilla/5.0', 'uri' => $canary['path']])) {
                        throw new \RuntimeException('matches an ordinary request: ' . $name);
                    }
                }
                $rules[$rule['id']] = $rule;
            } catch (\RuntimeException $e) {
                $refused[$id] = $e->getMessage();
            }
        }
        return [array_values($rules), $refused];
    }

    /**
     * @param mixed $raw
     * @return array<string, mixed>
     */
    private function normalize($raw): array
    {
        if (!is_array($raw)) {
            throw new \RuntimeException('not an object');
        }
        $id = (string)($raw['id'] ?? '');
        if (!preg_match('/^[a-z0-9][a-z0-9-]{2,40}$/', $id)) {
            throw new \RuntimeException('invalid id');
        }
        $fields = $raw['fields'] ?? null;
        if (!is_array($fields) || !$fields || array_diff($fields, self::FIELDS)) {
            throw new \RuntimeException('fields must be some of ' . implode(', ', self::FIELDS));
        }
        $methods = array_map('strtoupper', (array)($raw['methods'] ?? []));
        if (array_diff($methods, self::METHODS)) {
            throw new \RuntimeException('unknown method');
        }
        $action = (string)($raw['action'] ?? self::ACTION_LOG);
        if (!in_array($action, [self::ACTION_BLOCK, self::ACTION_LOG, self::ACTION_TEST], true)) {
            throw new \RuntimeException('action must be block, log or test');
        }
        $flags = (string)($raw['flags'] ?? 'i');
        if (!preg_match('/^[isu]{0,3}$/', $flags)) {
            throw new \RuntimeException('flags may only be i, s, u');
        }
        $rule = [
            'id' => $id,
            'title' => mb_substr(trim((string)($raw['title'] ?? $id)), 0, 200),
            'fields' => array_values(array_unique($fields)),
            'methods' => array_values(array_unique($methods)),
            'action' => $action,
            'pattern' => $this->regex((string)($raw['pattern'] ?? ''), $flags),
            'path' => isset($raw['path']) ? $this->regex((string)$raw['path'], 'i') : null,
        ];
        return $rule;
    }

    /**
     * @param string $pattern without delimiters
     * @param string $flags
     * @return string
     */
    private function regex(string $pattern, string $flags): string
    {
        if ($pattern === '' || strlen($pattern) > self::MAX_PATTERN || str_contains($pattern, '~')) {
            throw new \RuntimeException('pattern empty, longer than 1000 characters or contains ~');
        }
        $regex = '~' . $pattern . '~' . $flags;
        if ($this->safeMatch($regex, '') === null) {
            throw new \RuntimeException('pattern does not compile');
        }
        return $regex;
    }

    /**
     * @param array<string, mixed> $rule
     * @param array<string, mixed> $facts
     * @return bool
     */
    private function matches(array $rule, array $facts): bool
    {
        if ($rule['methods'] && !in_array(strtoupper((string)($facts['method'] ?? '')), $rule['methods'], true)) {
            return false;
        }
        if ($rule['path'] !== null && $this->safeMatch($rule['path'], (string)($facts['path'] ?? '')) !== true) {
            return false;
        }
        $hay = [];
        foreach ($rule['fields'] as $field) {
            $hay[] = (string)($facts[$field] ?? '');
        }
        return $this->safeMatch($rule['pattern'], implode("\n", $hay)) === true;
    }

    /**
     * A pattern from outside must never take the shop down: errors and runaway backtracking count as no match.
     *
     * @param string $regex
     * @param string $subject
     * @return bool|null null when the pattern failed
     */
    private function safeMatch(string $regex, string $subject): ?bool
    {
        $limit = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', self::BACKTRACK_LIMIT);
        set_error_handler(static fn () => true);
        try {
            $result = preg_match($regex, $subject);
        } finally {
            restore_error_handler();
            ini_set('pcre.backtrack_limit', (string)$limit);
        }
        if ($result === false || preg_last_error() !== PREG_NO_ERROR) {
            return null;
        }
        return $result === 1;
    }

    /**
     * @param string $id
     * @param array<string, mixed> $facts
     * @return void
     */
    private function logHit(string $id, array $facts): void
    {
        $file = $this->path(self::HITS_FILE);
        if (@filesize($file) > self::MAX_HITS_BYTES) {
            @rename($file, $file . '.1');
        }
        $clean = static fn (string $value, int $max) => substr(strtr($value, "\t\r\n", '   '), 0, $max);
        @file_put_contents($file, implode("\t", [
            date('c'),
            $id,
            $clean((string)($facts['ip'] ?? ''), 64),
            $clean((string)($facts['method'] ?? ''), 8),
            $clean((string)($facts['uri'] ?? ''), 300),
        ]) . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * @param string $message
     * @return array{status: string, message: string}
     */
    private function fail(string $message): array
    {
        $this->writeState(['checked' => time(), 'error' => $message] + $this->state());
        return ['status' => 'error', 'message' => $message];
    }

    /**
     * @param array<string, mixed> $state
     * @return void
     */
    private function writeState(array $state): void
    {
        $this->write(self::STATE_FILE, (string)json_encode($state, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /**
     * Writes through a temporary file, so the filter never reads a half written file.
     *
     * @param string $relative
     * @param string $content
     * @return void
     */
    private function write(string $relative, string $content): void
    {
        $file = $this->path($relative);
        if (!is_dir(dirname($file)) && !@mkdir(dirname($file), 0770, true) && !is_dir(dirname($file))) {
            throw new \RuntimeException('cannot create ' . dirname($file));
        }
        $tmp = $file . '.' . getmypid() . '.tmp';
        if (@file_put_contents($tmp, $content, LOCK_EX) === false || !@rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot write ' . $file);
        }
    }

    /**
     * @param string $relative
     * @return string
     */
    private function path(string $relative): string
    {
        return $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/' . $relative;
    }
}
