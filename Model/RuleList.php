<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

/**
 * One entry per line, optional comment after "#".
 * Automatic entries carry their expiry date first: "203.0.113.5  # 2026-11-26 stylesmuggler"
 */
class RuleList
{
    /**
     * @param string $text
     * @return array<int, array{value: string, until: ?string, note: string}>
     */
    public static function parse(string $text): array
    {
        $result = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            [$value, $note] = array_pad(explode('#', $line, 2), 2, '');
            $value = trim($value);
            if ($value === '') {
                continue;
            }
            $note = trim($note);
            $until = preg_match('/^(\d{4}-\d{2}-\d{2})\b\s*(.*)$/', $note, $m) ? $m[1] : null;
            $result[] = ['value' => $value, 'until' => $until, 'note' => $until ? trim($m[2]) : $note];
        }
        return $result;
    }

    /**
     * @param array<int, array{value: string, until: ?string, note: string}> $entries
     * @return string
     */
    public static function format(array $entries): string
    {
        $width = 0;
        foreach ($entries as $entry) {
            $width = max($width, strlen($entry['value']));
        }
        $lines = [];
        foreach ($entries as $entry) {
            $comment = trim(($entry['until'] ?? '') . ' ' . $entry['note']);
            $lines[] = $comment === ''
                ? $entry['value']
                : str_pad($entry['value'], $width) . '  # ' . $comment;
        }
        return implode("\n", $lines);
    }

    /**
     * @param string $ip
     * @param string[] $entries single addresses or CIDR ranges
     * @return bool
     */
    public static function ipMatches(string $ip, array $entries): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        foreach ($entries as $entry) {
            if ($entry === $ip) {
                return true;
            }
            if (!str_contains($entry, '/')) {
                continue;
            }
            [$net, $bits] = explode('/', $entry, 2);
            $netPacked = @inet_pton($net);
            if ($netPacked === false || strlen($netPacked) !== strlen($packed) || !ctype_digit($bits)) {
                continue;
            }
            $bits = (int)$bits;
            if ($bits > strlen($packed) * 8) {
                continue;
            }
            $bytes = intdiv($bits, 8);
            if (strncmp($packed, $netPacked, $bytes) !== 0) {
                continue;
            }
            $rest = $bits % 8;
            if ($rest === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $rest)) & 0xFF;
            if ((ord($packed[$bytes]) & $mask) === (ord($netPacked[$bytes]) & $mask)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $userAgent lowercase
     * @param string[] $tokens lowercase
     * @return string|null matching token
     */
    public static function agentMatch(string $userAgent, array $tokens): ?string
    {
        if ($userAgent === '') {
            return null;
        }
        foreach ($tokens as $token) {
            if ($token !== '' && str_contains($userAgent, $token)) {
                return $token;
            }
        }
        return null;
    }
}
