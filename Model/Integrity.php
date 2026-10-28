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
 * Compares the shop's code files with a reference state: new, changed and deleted files are reported.
 *
 * The reference is a gzipped JSON file in var/shop_guard, its SHA-256 is kept in the database, so a reference
 * rewritten by an attacker is noticed. Every run compares size, ctime and mtime and hashes only what moved
 * (ctime cannot be set back with touch), the weekly full run hashes everything again.
 * Before the first reference is written, all code passes the signature check, so an existing infection
 * is reported instead of being taken over as "known good".
 */
class Integrity
{
    public const FLAG = 'storetown_shop_guard_integrity';

    public const ROOTS = ['app/code', 'app/design', 'app/etc', 'lib', 'vendor', 'pub', 'setup', 'bin'];
    private const SKIP = '~^pub/(media|static)(/|$)~';
    private const NAME = '~\.(php\d?|phtml|phar|inc|js|html)$|^\.htaccess$|^\.user\.ini$~i';
    private const CODE = '~\.(php\d?|phtml|phar|inc)$~i';

    /**
     * Changes here are critical: nobody edits vendor/ or lib/ by hand
     */
    private const STRICT = ['vendor/', 'lib/', 'pub/', 'setup/', 'bin/'];

    /**
     * More changed files of one package than this become one finding
     */
    private const GROUP_AT = 4;
    private const MAX_READ = 8388608;
    private const FILE = 'shop_guard/integrity.json.gz';

    /**
     * Directories that could not be opened during the last collect()
     *
     * @var string[]
     */
    private array $locked = [];

    /**
     * @param DirectoryList $directoryList
     * @param FlagManager $flagManager
     * @param Signatures $signatures
     */
    public function __construct(
        private DirectoryList $directoryList,
        private FlagManager $flagManager,
        private Signatures $signatures
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function state(): array
    {
        return (array)$this->flagManager->getFlagData(self::FLAG);
    }

    /**
     * Compares the code with the reference. Without a reference, the first one is created after the signature check.
     *
     * @param bool $full hash every file, not only those whose size or times changed
     * @return array<int, array{level: string, check: string, path: string}>
     */
    public function check(bool $full): array
    {
        $state = $this->state();
        if (empty($state['hash'])) {
            $result = $this->create('auto');
            return $this->suspiciousFindings($result['suspicious']);
        }
        $reference = $this->load($state);
        if ($reference === null) {
            return [['level' => FileScanner::CRITICAL, 'check' => 'integrity-tampered', 'path' => $this->file()]];
        }

        $start = microtime(true);
        $suspicious = $full ? [] : (array)($state['suspicious'] ?? []);
        $known = $reference['files'];
        $new = $changed = [];
        foreach ($this->collect() as $path => $stat) {
            $old = $known[$path] ?? null;
            unset($known[$path]);
            if (!$full && $old !== null && array_slice($old, 0, 3) === $stat) {
                continue;
            }
            $hash = $this->hash($path, $suspicious);
            // Same hash with moved times (chmod, copy) is no change; hash() has checked the content again anyway
            if ($old === null) {
                $new[] = $path;
            } elseif ($hash !== $old[3]) {
                $changed[] = $path;
            }
        }
        $missing = array_keys($known);
        foreach (array_keys($suspicious) as $path) {
            if (!is_file($this->root() . '/' . $path)) {
                unset($suspicious[$path]);
            }
        }

        $updated = $this->updatedPackages((array)($reference['packages'] ?? []));
        $state['last'] = time();
        if ($full) {
            $state['full'] = time();
        }
        $state['duration'] = round(microtime(true) - $start, 1);
        $state['changes'] = ['new' => count($new), 'changed' => count($changed), 'missing' => count($missing)];
        $state['updated'] = $updated;
        $state['suspicious'] = $suspicious;
        $this->flagManager->saveFlag(self::FLAG, $state);

        return array_merge(
            $this->suspiciousFindings($suspicious),
            $this->group('integrity-new', $new, $updated),
            $this->group('integrity-changed', $changed, $updated),
            $this->group('integrity-missing', $missing, $updated),
            array_map(
                static fn ($dir) => ['level' => FileScanner::WARNING, 'check' => 'integrity-locked', 'path' => $dir],
                $this->locked
            )
        );
    }

    /**
     * Writes a new reference from the files as they are now. Signature hits are kept as findings.
     *
     * @param string $user who did it (admin user name, "cli" or "cron")
     * @return array{files: int, suspicious: array<string, string>}
     */
    public function create(string $user): array
    {
        $start = microtime(true);
        $files = [];
        $suspicious = [];
        foreach ($this->collect() as $path => $stat) {
            $files[$path] = array_merge($stat, [$this->hash($path, $suspicious)]);
        }
        $this->save($files, $this->installedPackages());

        $state = $this->state();
        $state['hash'] = (string)hash_file('sha256', $this->file());
        $state['files'] = count($files);
        $state['created'] = $state['created'] ?? time();
        $state['accepted'] = time();
        $state['accepted_by'] = $user;
        $state['last'] = $state['full'] = time();
        $state['duration'] = round(microtime(true) - $start, 1);
        $state['changes'] = ['new' => 0, 'changed' => 0, 'missing' => 0];
        $state['updated'] = [];
        $state['suspicious'] = $suspicious;
        $this->flagManager->saveFlag(self::FLAG, $state);
        return ['files' => count($files), 'suspicious' => $suspicious];
    }

    /**
     * Takes single files or whole package groups ("vendor/a/b/ (12)") into the reference.
     * Only the kind of change that was confirmed: accepting the new files of a package
     * leaves its changed ones reported.
     *
     * @param string[] $paths finding paths
     * @param string $user
     * @param string $check integrity-new|-changed|-missing|-updated, '' for every kind
     * @return int number of files taken over
     */
    public function accept(array $paths, string $user, string $check = ''): int
    {
        $state = $this->state();
        $reference = $this->load($state);
        if ($reference === null) {
            return 0;
        }
        $prefixes = [];
        $single = [];
        foreach ($paths as $path) {
            // Package groups look like "vendor/a/b/ (12)" or "vendor/a/b/ (12) 1.0.0 → 1.0.1"
            if (preg_match('~^(.+/) \(\d+\)~', $path, $m)) {
                $prefixes[] = $m[1];
            } else {
                $single[$path] = true;
            }
        }
        $files = $reference['files'];
        $current = $this->collect();
        $count = 0;
        $suspicious = (array)($state['suspicious'] ?? []);
        foreach (array_unique(array_merge(array_keys($files), array_keys($current))) as $path) {
            $hit = isset($single[$path]);
            foreach ($prefixes as $prefix) {
                $hit = $hit || str_starts_with($path, $prefix);
            }
            $kind = !isset($current[$path]) ? 'integrity-missing'
                : (!isset($files[$path]) ? 'integrity-new' : 'integrity-changed');
            if (!$hit || !in_array($check, ['', 'integrity-updated', $kind], true)) {
                continue;
            }
            if (!isset($current[$path])) {
                unset($files[$path]);
                $count++;
                continue;
            }
            $hash = $this->hash($path, $suspicious);
            if (($files[$path][3] ?? null) !== $hash || array_slice($files[$path] ?? [], 0, 3) !== $current[$path]) {
                $files[$path] = array_merge($current[$path], [$hash]);
                $count++;
            }
        }
        // Only the accepted packages get their new version, other updates stay visible as such
        $packages = (array)($reference['packages'] ?? []);
        foreach ($this->installedPackages() as $package => $version) {
            if (in_array($package, $prefixes, true)) {
                $packages[$package] = $version;
            }
        }
        $this->save($files, $packages);
        $state['hash'] = (string)hash_file('sha256', $this->file());
        $state['files'] = count($files);
        $state['accepted'] = time();
        $state['accepted_by'] = $user;
        $state['suspicious'] = $suspicious;
        $state['updated'] = array_diff_key((array)($state['updated'] ?? []), array_flip($prefixes));
        $this->flagManager->saveFlag(self::FLAG, $state);
        return $count;
    }

    /**
     * @param array<string, string> $suspicious
     * @return array<int, array{level: string, check: string, path: string}>
     */
    private function suspiciousFindings(array $suspicious): array
    {
        $findings = [];
        foreach ($suspicious as $path => $rule) {
            $findings[] = [
                'level' => FileScanner::CRITICAL,
                'check' => 'integrity-suspicious',
                'path' => $path . ' [' . $rule . ']',
            ];
        }
        return $findings;
    }

    /**
     * One finding per file, or per package when many files of it changed. Packages with a new version
     * since the reference are expected to change: they become one warning each.
     *
     * @param string $check
     * @param string[] $paths
     * @param array<string, string> $updated package prefix => "old → new"
     * @return array<int, array{level: string, check: string, path: string}>
     */
    private function group(string $check, array $paths, array $updated): array
    {
        $groups = [];
        foreach ($paths as $path) {
            $groups[$this->packageOf($path)][] = $path;
        }
        $findings = [];
        foreach ($groups as $package => $files) {
            if ($package !== '' && isset($updated[$package])) {
                $findings[] = [
                    'level' => FileScanner::WARNING,
                    'check' => 'integrity-updated',
                    'path' => $package . ' (' . count($files) . ') ' . $updated[$package],
                ];
                continue;
            }
            $strict = (bool)array_filter(self::STRICT, static fn ($p) => str_starts_with($files[0], $p));
            $level = $check !== 'integrity-missing' && $strict ? FileScanner::CRITICAL : FileScanner::WARNING;
            if ($package !== '' && count($files) > self::GROUP_AT) {
                $findings[] = ['level' => $level, 'check' => $check, 'path' => $package . ' (' . count($files) . ')'];
                continue;
            }
            foreach ($files as $file) {
                $findings[] = ['level' => $level, 'check' => $check, 'path' => $file];
            }
        }
        return $findings;
    }

    /**
     * Package directory a file belongs to, '' for files outside packages
     *
     * @param string $path
     * @return string
     */
    private function packageOf(string $path): string
    {
        $patterns = [
            '~^(vendor/[^/]+/[^/]+/)~',
            '~^(app/code/[^/]+/[^/]+/)~',
            '~^(app/design/[^/]+/[^/]+/[^/]+/)~',
            '~^(lib/(internal|web)/[^/]+/)~',
            '~^(setup/)~',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $path, $m)) {
                return $m[1];
            }
        }
        return '';
    }

    /**
     * Content hash. Code files are read once for hash and signature check.
     *
     * @param string $path relative to the Magento root
     * @param array<string, string> $suspicious
     * @return string
     */
    private function hash(string $path, array &$suspicious): string
    {
        $absolute = $this->root() . '/' . $path;
        if (!$this->isCode($path) || (int)@filesize($absolute) > self::MAX_READ) {
            return (string)@hash_file('sha256', $absolute);
        }
        $content = (string)@file_get_contents($absolute);
        $rule = $this->signatures->match($content);
        if ($rule !== null) {
            $suspicious[$path] = $rule;
        } else {
            unset($suspicious[$path]);
        }
        return hash('sha256', $content);
    }

    /**
     * @param string $path
     * @return bool
     */
    private function isCode(string $path): bool
    {
        return (bool)preg_match(self::CODE, basename($path));
    }

    /**
     * Code files with size, ctime and mtime
     *
     * @return array<string, array{0: int, 1: int, 2: int}>
     */
    private function collect(): array
    {
        $root = $this->root();
        $this->locked = [];
        $files = [];
        foreach (self::ROOTS as $dir) {
            if (!is_dir($root . '/' . $dir)) {
                continue;
            }
            $filter = function (\SplFileInfo $entry) use ($root): bool {
                $relative = substr($entry->getPathname(), strlen($root) + 1);
                if (preg_match(self::SKIP, $relative)) {
                    return false;
                }
                if ($entry->isDir() && (!$entry->isReadable() || !$entry->isExecutable())) {
                    $this->locked[] = $relative;
                    return false;
                }
                return true;
            };
            $it = new \RecursiveIteratorIterator(
                new \RecursiveCallbackFilterIterator(
                    new \RecursiveDirectoryIterator($root . '/' . $dir, \FilesystemIterator::SKIP_DOTS),
                    $filter
                ),
                \RecursiveIteratorIterator::LEAVES_ONLY,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($it as $file) {
                /** @var \SplFileInfo $file */
                if (!preg_match(self::NAME, $file->getFilename())) {
                    continue;
                }
                $stat = @stat($file->getPathname());
                if ($stat === false || !is_file($file->getPathname())) {
                    continue;
                }
                $files[substr($file->getPathname(), strlen($root) + 1)] = [
                    (int)$stat['size'], (int)$stat['ctime'], (int)$stat['mtime'],
                ];
            }
        }
        ksort($files);
        return $files;
    }

    /**
     * Installed package versions from vendor/composer/installed.json, keyed by package directory
     *
     * @return array<string, string>
     */
    private function installedPackages(): array
    {
        $json = json_decode((string)@file_get_contents($this->root() . '/vendor/composer/installed.json'), true);
        $list = is_array($json) ? ($json['packages'] ?? $json) : [];
        $packages = [];
        foreach ($list as $package) {
            if (isset($package['name'], $package['version'])) {
                $packages['vendor/' . $package['name'] . '/'] = (string)$package['version'];
            }
        }
        return $packages;
    }

    /**
     * @param array<string, string> $before
     * @return array<string, string> package directory => "old → new"
     */
    private function updatedPackages(array $before): array
    {
        $updated = [];
        foreach ($this->installedPackages() as $package => $version) {
            if (isset($before[$package]) && $before[$package] !== $version) {
                $updated[$package] = $before[$package] . ' → ' . $version;
            } elseif (!isset($before[$package]) && $before) {
                $updated[$package] = '→ ' . $version;
            }
        }
        return $updated;
    }

    /**
     * Reference files, or null when the file is gone or does not match the checksum in the database
     *
     * @param array<string, mixed> $state
     * @return array{files: array<string, array>, packages: array<string, string>}|null
     */
    private function load(array $state): ?array
    {
        $file = $this->file();
        if (!is_file($file) || !hash_equals((string)($state['hash'] ?? ''), (string)hash_file('sha256', $file))) {
            return null;
        }
        $data = json_decode((string)gzdecode((string)file_get_contents($file)), true);
        return is_array($data) && isset($data['files']) ? $data : null;
    }

    /**
     * @param array<string, array> $files
     * @param array<string, string> $packages
     * @return void
     */
    private function save(array $files, array $packages): void
    {
        $file = $this->file();
        if (!is_dir(dirname($file))) {
            mkdir(dirname($file), 0770, true);
        }
        $json = json_encode(['v' => 1, 'files' => $files, 'packages' => $packages], JSON_UNESCAPED_SLASHES);
        $tmp = $file . '.' . getmypid() . '.tmp';
        if (file_put_contents($tmp, gzencode((string)$json, 6), LOCK_EX) === false || !rename($tmp, $file)) {
            throw new \RuntimeException('Cannot write ' . $file);
        }
    }

    /**
     * @return string
     */
    private function file(): string
    {
        return $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/' . self::FILE;
    }

    /**
     * @return string
     */
    private function root(): string
    {
        return rtrim($this->directoryList->getRoot(), '/');
    }
}
