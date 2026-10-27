# Changelog

## 1.1.0 – 2026-10-27

- Every finding comes with what to do, in the admin, the alert mail, the admin inbox and on the CLI
- Status in plain words at the top of the configuration page: "No dangerous files found" or the number of critical findings
- Findings of the last scan, scan history and hourly bot statistics are kept for STM Shop Guard Pro
- Areas the server does not let us check (no /proc, proc_open disabled) are reported as such instead of passing silently
- Images up to 2 MB are checked completely, larger ones at both ends
- Self-test: `?shopguard-test` shows the block page, so you can see that the request filter is active
- Configuration lives in the shared STM tab

## 1.0.0 – 2026-10-27

First release.

- Request filter: StyleSmuggler, TrojanOrder, PHP code, CosmicSting XXE, PHP2Shell upload progress,
  PolyShell REST uploads, address file uploads, scanner sign-ups, SEO and AI training crawlers,
  optional GraphQL block and filter crawl protection
- Upload block on all three custom option file paths
- Hourly bot scan with expiry dates, DNS check of search engine crawlers, proxy and admin protection
- Backdoor scan every 30 minutes with mail and admin inbox
- `.user.ini` with `engine = Off` in pub/media and pub/static
- System check: PHP2Shell, PHP settings, StyleSmuggler hotfix, admin path, 2FA, Adobe patch status
- CLI: `shopguard:scan`, `shopguard:bots`
