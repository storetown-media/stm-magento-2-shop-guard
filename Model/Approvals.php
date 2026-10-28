<?php
/**
 * Copyright (c) Storetown Media. All rights reserved.
 * See LICENSE for license details.
 */
declare(strict_types=1);

namespace Storetown\ShopGuard\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\FlagManager;

/**
 * Findings a person checked and marked as harmless. For files the approval is bound to the content:
 * once the file changes, the finding is back. Log files, processes and records are approved by name.
 */
class Approvals
{
    public const FLAG = 'storetown_shop_guard_approvals';

    /**
     * Checks whose evidence is a file that changes on its own, so its hash cannot be pinned
     */
    private const UNPINNED = ['log-payload', 'locked-dir', 'pub-locked-dir', 'integrity-locked'];

    /**
     * @var array<string, array>|null
     */
    private ?array $list = null;

    /**
     * @param FlagManager $flagManager
     * @param DirectoryList $directoryList
     */
    public function __construct(
        private FlagManager $flagManager,
        private DirectoryList $directoryList
    ) {
    }

    /**
     * @param string $check
     * @param string $path relative to the Magento root, see relative()
     * @return string
     */
    public static function key(string $check, string $path): string
    {
        return sha1($check . '|' . $path);
    }

    /**
     * Paths below the Magento root without the root: cron, CLI and admin may see the same file under
     * different absolute paths (chroot, symlinked release directories).
     *
     * @param string $path
     * @return string
     */
    public function relative(string $path): string
    {
        $root = rtrim($this->directoryList->getRoot(), '/') . '/';
        return str_starts_with($path, $root) ? substr($path, strlen($root)) : $path;
    }

    /**
     * @return array<string, array{check: string, path: string, hash: string, reason: string, user: string, time: int}>
     */
    public function all(): array
    {
        if ($this->list === null) {
            $this->list = (array)$this->flagManager->getFlagData(self::FLAG);
        }
        return $this->list;
    }

    /**
     * @param string $check
     * @param string $path
     * @return bool
     */
    public function covers(string $check, string $path): bool
    {
        $path = $this->relative($path);
        $entry = $this->all()[self::key($check, $path)] ?? null;
        return $entry !== null
            && ($entry['hash'] === '' || hash_equals($entry['hash'], $this->fileHash($check, $path)));
    }

    /**
     * @param string $check
     * @param string $path
     * @param string $reason
     * @param string $user
     * @return array the stored entry
     */
    public function approve(string $check, string $path, string $reason, string $user): array
    {
        $path = $this->relative($path);
        $list = $this->all();
        $entry = [
            'check' => $check,
            'path' => $path,
            'hash' => $this->fileHash($check, $path),
            'reason' => mb_substr(trim($reason), 0, 500),
            'user' => $user,
            'time' => time(),
        ];
        $list[self::key($check, $path)] = $entry;
        $this->store($list);
        return $entry;
    }

    /**
     * @param string $key
     * @return array|null the removed entry
     */
    public function revoke(string $key): ?array
    {
        $list = $this->all();
        $entry = $list[$key] ?? null;
        unset($list[$key]);
        $this->store($list);
        return $entry;
    }

    /**
     * Approvals whose file changed since: they no longer apply and the finding is shown again
     *
     * @return string[] keys
     */
    public function outdated(): array
    {
        $keys = [];
        foreach ($this->all() as $key => $entry) {
            $current = $this->fileHash($entry['check'], $entry['path']);
            if ($entry['hash'] !== '' && !hash_equals($entry['hash'], $current)) {
                $keys[] = $key;
            }
        }
        return $keys;
    }

    /**
     * @param array $list
     * @return void
     */
    private function store(array $list): void
    {
        $this->flagManager->saveFlag(self::FLAG, $list);
        $this->list = $list;
    }

    /**
     * SHA-256 of the file behind a finding, '' when the finding is no file or its file changes by itself
     *
     * @param string $check
     * @param string $path
     * @return string
     */
    private function fileHash(string $check, string $path): string
    {
        if (in_array($check, self::UNPINNED, true)) {
            return '';
        }
        // Integrity findings are relative and may carry the matched rule: "vendor/a/b.php [eval-decode]"
        $file = preg_replace('~ \[[a-z-]+\]$~', '', $path);
        if (!str_starts_with($file, '/')) {
            $file = rtrim($this->directoryList->getRoot(), '/') . '/' . $file;
        }
        return is_file($file) ? (string)hash_file('sha256', $file) : '';
    }
}
