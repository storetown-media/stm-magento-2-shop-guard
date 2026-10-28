<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

/**
 * Patterns of webshells and loaders found in compromised Magento shops in 2026. Each rule is narrow on purpose:
 * vendor/ uses goto, zip://, hex escapes and eval too, so only combinations real libraries do not use count.
 * Plain backdoors without any trick are found by the integrity check (new or changed file), not here.
 */
class Signatures
{
    private const PATTERNS = [
        // eval/assert of decoded or request data
        'eval-decode' => '~\b(eval|assert)\s*\(\s*(@\s*)?'
            . '(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin'
            . '|\$_(GET|POST|REQUEST|COOKIE|SERVER))\b~i',
        // include of a decoded name or a hex-escaped stream wrapper (zip://, phar://, data://)
        'include-decode' => '~\b(include|require)(_once)?\s*\(?\s*(base64_decode|str_rot13|gzinflate|hex2bin)\s*\(~i',
        'include-escaped' => '~\b(include|require)(_once)?\s*\(?\s*["\'](\\\\x[0-9a-f]{2}|\\\\[0-7]{3}){4,}~i',
        // function name taken straight from a request parameter and called
        'request-call' => '~\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(~i',
        // file manager webshell of the 2026 campaign (written so this file does not match itself)
        'filemanager-shell' => '~MENU_API_PASS(?:WORD)|_ak\(200,\s*array\(\s*\'success\'~',
    ];

    /**
     * Name of the first rule that matches, or null
     *
     * @param string $code
     * @return string|null
     */
    public function match(string $code): ?string
    {
        foreach (self::PATTERNS as $name => $pattern) {
            if (preg_match($pattern, $code)) {
                return $name;
            }
        }
        $eval = (bool)preg_match('~\beval\s*\(~i', $code);
        if ($eval && preg_match('~\b(gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(~i', $code)
            && preg_match('~[A-Za-z0-9+/]{200,}~', $code)
        ) {
            return 'packed-eval';
        }
        if ($eval && preg_match('~\b(curl_exec|fsockopen)\s*\(|file_get_contents\s*\(\s*["\']https?://~i', $code)) {
            return 'remote-eval';
        }
        $escapes = preg_match_all('~\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}~', $code);
        // ${$a[0]} with escaped names: superglobals spelled as "\137\x52\x45..." (_REQUEST)
        if ($escapes >= 10 && preg_match('~\$\{\s*\$[A-Za-z_]\w*\s*\[~', $code)) {
            return 'escaped-superglobal';
        }
        // Obfuscators replace the control flow by goto jumps to random labels like "NrAxhnCEq2R0".
        // Libraries use goto rarely and with readable labels (SCANNER_END, check_duration).
        $randomGoto = '~\bgoto\s+(?=[A-Za-z_]*\d)(?=[A-Za-z0-9_]*[a-z])(?=[A-Za-z0-9_]*[A-Z])[A-Za-z0-9_]{8,};~';
        if (preg_match_all($randomGoto, $code) >= 5) {
            return 'goto-obfuscation';
        }
        // Standalone scripts (no class, no namespace) are where droppers live; templates never do this
        if (!preg_match('~^\s*(namespace|(abstract\s+|final\s+)?class|interface|trait)\s~mi', $code)) {
            if (str_contains($code, 'move_uploaded_file') && str_contains($code, '$_FILES')) {
                return 'upload-shell';
            }
            if (preg_match('~googlebot|bingbot~i', $code)
                && preg_match('~\b(file_get_contents|curl_exec)\s*\(~', $code)
                && preg_match('~https?://~', $code)
            ) {
                return 'seo-cloaking';
            }
        }
        return null;
    }
}
