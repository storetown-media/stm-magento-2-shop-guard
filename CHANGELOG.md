# Changelog

All notable changes to STM Shop Security Guard are documented in this file.

## [1.7.1] - 2026-10-31

### Fixed

- On a Magento installed from source, the check "Magento patches" showed the raw answer of Adobe's tool patch-status; it now says in one sentence that the tool only reads Composer installations

## [1.7.0] - 2026-10-30

### Added

- System > Security > Shop Security Guard opens the settings, so they are found where security is looked for
- The settings start with a bar: the name, whether the request filter protects the shop, and with Shop Security Guard Pro the way to its overview and license
- With Shop Security Guard Pro the settings show its verdict in one line instead of repeating the system table (still one click away), and each settings group links to the view of the overview that shows what it does; a link to the settings with #sg-<group> opens that group

## [1.6.0] - 2026-10-30

### Added

- Password guessing on the admin login is blocked: from 10 failed logins of one address within 15 minutes (adjustable) the address is blocked until the end of the next day; addresses that logged in to the admin in the last 30 days, "Never block these IPs" and proxy addresses are never blocked
- Files anyone can download are found once a day: app/etc/env.php, a git repository, database dumps and backups in the web root, phpinfo, Adminer or phpMyAdmin, Magento logs, a web root on the Magento main folder; the shop requests itself the way an attacker would, and a finding needs the content to prove it, so a "page not found" never alerts
- Critical and high security warnings from Storetown Media are checked against the shop (Magento version, PHP version, packages, modules) and, when the shop is affected, sent once by mail and to the admin inbox; Shop Security Guard Pro alerts all levels itself, what it has sent is not sent twice; bin/magento shopguard:rules shows whether a warning affects the shop
- Card test brake: payment attempts are counted per address and hour (REST payment-information, GraphQL placeOrder, checkouts with placeOrder in the address); above 8 (adjustable) the address is noted ("Watch only", the default) or further attempts are refused and the bot scan bans the address; bin/magento shopguard:cardtests lists who went over the limit

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
