# Changelog

All notable changes to STM Shop Security Guard are documented in this file.

## [1.5.0] - 2026-10-29

### Added

- The signed feed can carry security warnings with the conditions under which a shop is affected; the shop checks their form and keeps them for Shop Security Guard Pro, which alerts when a warning applies. bin/magento shopguard:rules lists them

## [1.4.0] - 2026-10-29

### Added

- Attack patterns from Storetown Media: every hour the shop fetches a signed list (Ed25519) of new attack patterns, so a new attack wave is filtered before the next module update; a list that does not verify is never used, an older one never replaces a newer one
- Every pattern is checked in the shop before it becomes active: it must compile, must not match ten ordinary requests (start page, search, cart, checkout, account, contact form …) and runs with a backtracking limit, so a faulty pattern cannot lock out customers or slow the shop down
- New patterns can start in the mode "log" and only count hits; `bin/magento shopguard:rules` shows state, rules and hits, `--update` fetches now, `--check` checks a list before it is signed
- Self-test of the patterns: `?shopguard-feed-test` answers 403, without banning whoever tries it
- Setting "Load new attack patterns from Storetown Media" (on by default); only the file is fetched, nothing about the shop is sent

## [1.3.0] - 2026-10-28

### Added

- PHP code left in the system temp directory by refused REST uploads is reported (PolyShell): Magento writes base64 uploads there before checking them, the finding shows how many and from when

### Changed

- New product name: STM Shop Security Guard. Package, module and command names stay the same

## [1.2.0] - 2026-10-28

### Added

- Integrity check: every code file in vendor, app, lib, pub, setup and bin is compared with a reference state, new, changed and deleted files are reported
- The reference state is checked against its checksum in the database, a rewritten or deleted reference is reported as critical
- Before the first reference state is written, all code files are checked for webshell tricks, so an existing infection is not taken over
- Signatures for the 2026 webshells: encoded eval, hidden includes, goto obfuscation, file manager shell, upload and SEO cloaking scripts
- Package updates are read from vendor/composer/installed.json and reported as an update instead of a critical change
- New integrations with API access are reported
- Findings can be marked as harmless (STM Shop Security Guard Pro), file approvals end when the file changes
- CLI: `shopguard:integrity [--accept] [--full]`

### Changed

- New admin users and integrations stay reported for 7 days instead of one scan

## [1.1.1] - 2026-10-28

### Fixed

- The backdoor scan now checks all subdirectories of pub/, not only pub/ itself, pub/media and pub/static. Webshells dropped into new directories such as pub/opt or pub/assets were missed before
- Directories the shop user cannot open are reported as not checked instead of being skipped silently

### Added

- PHP code hidden in files with other extensions (video, archive, text) is found anywhere in pub/
- The allow list for pub/ accepts paths below pub/ (opt/file.php)

## [1.1.0] - 2026-10-27

### Added

- Every finding comes with what to do, in the admin, the alert mail, the admin inbox and on the CLI
- Status in plain words at the top of the configuration page: "No dangerous files found" or the number of critical findings
- Self-test: `?shopguard-test` shows the block page, so you can see that the request filter is active
- Findings of the last scan, scan history and hourly bot statistics are kept for STM Shop Security Guard Pro

### Changed

- Areas the server does not let us check (no /proc, proc_open disabled) are reported as such instead of passing silently
- Images up to 2 MB are checked completely, larger ones at both ends
- Configuration lives in the shared STM tab

## [1.0.0] - 2026-10-27

### Added

- Request filter: StyleSmuggler, TrojanOrder, PHP code, CosmicSting XXE, PHP2Shell upload progress, PolyShell REST uploads, address file uploads, scanner sign-ups, SEO and AI training crawlers, optional GraphQL block and filter crawl protection
- Upload block on all three custom option file paths
- Hourly bot scan with expiry dates, DNS check of search engine crawlers, proxy and admin protection
- Backdoor scan every 30 minutes with mail and admin inbox
- `.user.ini` with `engine = Off` in pub/media and pub/static
- System check: PHP2Shell, PHP settings, StyleSmuggler hotfix, admin path, 2FA, Adobe patch status
- CLI: `shopguard:scan`, `shopguard:bots`
