<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Plugin;

use Magento\Framework\App\Http;
use Magento\Framework\App\Request\Http as Request;
use Magento\Framework\App\Response\Http as Response;
use Magento\Framework\App\ResponseInterface;
use Storetown\ShopGuard\Model\ClientIp;
use Storetown\ShopGuard\Model\Config;
use Storetown\ShopGuard\Model\RequestInspector;
use Storetown\ShopGuard\Model\RuntimeSnapshot;
use Storetown\ShopGuard\Model\TrafficLog;

/**
 * Checks every web request before Magento routes it. Fails open: an error here never takes the shop down.
 */
class RequestFilter
{
    private const MAX_BODY = 65536;

    /**
     * @param Config $config
     * @param RequestInspector $inspector
     * @param TrafficLog $trafficLog
     * @param RuntimeSnapshot $snapshot
     * @param ClientIp $clientIp
     * @param Request $request
     * @param Response $response
     */
    public function __construct(
        private Config $config,
        private RequestInspector $inspector,
        private TrafficLog $trafficLog,
        private RuntimeSnapshot $snapshot,
        private ClientIp $clientIp,
        private Request $request,
        private Response $response
    ) {
    }

    /**
     * @param Http $subject
     * @param callable $proceed
     * @return ResponseInterface
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function aroundLaunch(Http $subject, callable $proceed)
    {
        $verdict = null;
        $facts = [];
        try {
            if ($this->config->flag(Config::ENABLED)) {
                $facts = $this->facts();
                $verdict = $this->inspector->inspect($facts);
                if ($verdict !== null || !$this->inspector->isTrusted($facts)) {
                    $this->trafficLog->record($facts, $verdict);
                }
                $this->snapshot->refresh();
            }
        } catch (\Throwable $e) {
            $verdict = null;
        }

        return $verdict === null ? $proceed() : $this->deny($verdict, $facts);
    }

    /**
     * @return array<string, mixed>
     */
    public function facts(): array
    {
        $r = $this->request;
        $type = strtolower((string)$r->getServer('CONTENT_TYPE'));
        $length = (int)$r->getServer('CONTENT_LENGTH');

        $body = '';
        if ($length > 0 && $length <= self::MAX_BODY && !str_contains($type, 'multipart/')) {
            $body = (string)$r->getContent();
            if (str_contains($type, 'x-www-form-urlencoded')) {
                $body = urldecode($body);
            }
        }
        $post = (array)$r->getPostValue();

        $uri = (string)$r->getServer('REQUEST_URI');
        $query = (string)$r->getServer('QUERY_STRING');
        parse_str($query, $queryArgs);

        $ip = $this->clientIp->resolve($r);
        return [
            'ip' => $ip,
            'proxy' => ClientIp::isProxyAddress($ip, (string)$r->getServer('SERVER_ADDR')),
            'method' => (string)$r->getMethod(),
            'uri' => $uri,
            'path' => (string)parse_url($uri, PHP_URL_PATH),
            'query' => rawurldecode($query),
            'query_keys' => array_keys($queryArgs),
            'body' => $body,
            'post' => $body === '' ? substr($this->flatten($post), 0, self::MAX_BODY) : '',
            'post_keys' => array_keys($post),
            'ua' => (string)$r->getServer('HTTP_USER_AGENT'),
            'referer' => (string)$r->getServer('HTTP_REFERER'),
            'host' => (string)$r->getHttpHost(false),
            'accept' => (string)$r->getServer('HTTP_ACCEPT'),
            'auth' => (string)$r->getServer('HTTP_AUTHORIZATION') !== ''
                || (string)$r->getServer('REDIRECT_HTTP_AUTHORIZATION') !== '',
            'session' => (string)$r->getCookie('PHPSESSID', ''),
        ];
    }

    /**
     * @param array<string, string> $verdict
     * @param array<string, mixed> $facts
     * @return Response
     */
    private function deny(array $verdict, array $facts): Response
    {
        $this->response->setHttpResponseCode(403);
        $this->response->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate', true);
        $this->response->setHeader('X-Shop-Guard', 'blocked', true);

        $test = $verdict['rule'] === 'test';
        if (!str_contains((string)$facts['accept'], 'text/html')) {
            $this->response->setHeader('Content-Type', 'text/plain; charset=utf-8', true);
            $this->response->setBody($test ? "403 Shop Guard test: the request filter is active\n" : "403 Forbidden\n");
            return $this->response;
        }
        if ($test) {
            $this->response->setHeader('Content-Type', 'text/html; charset=utf-8', true);
            $this->response->setBody(
                '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="robots" content="noindex">'
                . '<meta name="viewport" content="width=device-width"><title>Shop Guard Test</title></head>'
                . '<body style="font:16px/1.6 sans-serif;margin:3em auto;max-width:640px;padding:0 20px;color:#1f2429">'
                . '<p style="font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:#69737d">STM Shop Guard</p>'
                . '<h1 style="font-size:28px;margin:0 0 12px">Shop Guard ist aktiv.</h1>'
                . '<p>Diese Testanfrage wurde absichtlich gesperrt. Genauso antwortet der Shop auf einen erkannten '
                . 'Angriff: mit Status 403, bevor Magento die Anfrage verarbeitet.</p>'
                . '<p style="color:#69737d">Shop Guard is active. This test request was blocked on purpose, the same '
                . 'way the shop answers a detected attack: with status 403, before Magento handles the request.</p>'
                . '</body></html>'
            );
            return $this->response;
        }

        $back = '';
        if ($verdict['rule'] === 'facet') {
            $path = htmlspecialchars((string)$facts['path'], ENT_QUOTES);
            $back = '<p><a href="' . $path . '">Zur Kategorie ohne Filter / Back to the category</a></p>';
        }
        $this->response->setHeader('Content-Type', 'text/html; charset=utf-8', true);
        $this->response->setBody(
            '<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="robots" content="noindex">'
            . '<title>403</title></head><body style="font:16px/1.5 sans-serif;margin:3em">'
            . '<h1>Zugriff gesperrt</h1><p>Diese Anfrage wurde aus Sicherheitsgründen abgelehnt. '
            . 'This request was refused for security reasons.</p>' . $back . '</body></html>'
        );
        return $this->response;
    }

    /**
     * @param array<mixed> $values
     * @return string
     */
    private function flatten(array $values): string
    {
        $out = '';
        array_walk_recursive($values, static function ($value) use (&$out) {
            if (is_scalar($value)) {
                $out .= $value . "\n";
            }
        });
        return $out;
    }
}
