# Changelog

All notable changes to STM Shop Guard are documented in this file.

## [1.2.0] - 2026-10-28

### Added

- Integrity check: every code file in vendor, app, lib, pub, setup and bin is compared with a reference state, new, changed and deleted files are reported
- The reference state is checked against its checksum in the database, a rewritten or deleted reference is reported as critical
- Before the first reference state is written, all code files are checked for webshell tricks, so an existing infection is not taken over
- Signatures for the 2026 webshells: encoded eval, hidden includes, goto obfuscation, file manager shell, upload and SEO cloaking scripts
- Package updates are read from vendor/composer/installed.json and reported as an update instead of a critical change
- New integrations with API access are reported
- Findings can be marked as harmless (STM Shop Guard Pro), file approvals end when the file changes
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
- Findings of the last scan, scan history and hourly bot statistics are kept for STM Shop Guard Pro

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
