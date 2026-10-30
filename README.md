# STM Shop Security Guard for Magento 2

![STM Shop Security Guard: free Magento 2 security extension with backdoor scan, bot protection and file integrity checks](https://raw.githubusercontent.com/storetown-media/stm-magento-2-shop-guard/main/docs/stm-shop-security-guard-free-magento-2-security-extension-en.webp)

Free hardening module for Magento Open Source and Adobe Commerce 2.4.4 or later, PHP 8.1 – 8.5
(tested on 2.4.8-p4 with PHP 8.4).
It bundles what we run on our customers' shops after the 2026 attack waves
(PolyShell, SessionReaper, StyleSmuggler, PHP2Shell) into one small module.

## What it does

**Request filter** — runs before Magento routes a request, so blocked requests cost almost nothing.

| Rule | Blocks |
|---|---|
| StyleSmuggler (APSB26-146) | `template_styles`, `styles[with_resolved]`, `styles[…generatorClass…]`, `rowUrl=$this` in query or body, also via `/paypal/transparent/response/` |
| TrojanOrder | template directives `{{var …}}`, `{{block …}}` … in customer input |
| PHP code | `<?php`, `<?=`, `eval(base64_decode(…))` in parameters, body or user agent |
| CosmicSting | XML entities with `SYSTEM` |
| PHP2Shell | upload progress fields (`PHP_SESSION_UPLOAD_PROGRESS`), never used by Magento |
| PolyShell (APSB25-94) | base64 file uploads into cart items via REST |
| Address uploads | `/customer/address_file/upload`, used to drop files for SessionReaper |
| Scanner sign-ups | e-mail addresses on reserved domains (`.invalid`, `.test`, `.example`) |
| Bots | SEO tool crawlers and AI training crawlers (two switches), your own lists |
| GraphQL | optional emergency switch |
| Filter crawls | optional: layered navigation URLs only with a live session or internal referrer |

Search engines, AI search agents, link previews, price comparison and uptime monitors are never blocked by agent.
The admin area and API calls with a token are only subject to the IP lists.

**Attack patterns from Storetown Media (hourly)** — new attack waves are filtered before the next module update.
The shop fetches `https://www.storetown-media.de/shop-guard/rules.json` with its Ed25519 signature; a list that does
not verify against a key built into the module is never used. Before a rule becomes active the shop checks it itself:
it must compile and must not match any of ten ordinary requests (start page, search, cart, checkout, account, contact
form …), and every pattern runs with a backtracking limit. New rules usually start in the mode *log*: they only count
hits, which `bin/magento shopguard:rules` shows, and block later. An older list never replaces a newer one.
Only the file is fetched, nothing about the shop is sent; storetown-media.de sees the IP address of the server.
Switch: *Load new attack patterns from Storetown Media*. Test: `https://your-shop/?shopguard-feed-test` answers 403.

**Password guessing on the admin login** — Magento locks an account after a few failures, but the address keeps
trying other accounts. From 10 failed admin logins within 15 minutes (adjustable) the address is blocked until the end
of the next day. Addresses that logged in to the admin in the last 30 days, *Never block these IPs* and proxy
addresses are never blocked. The block appears under *Automatically blocked IPs* and in `var/log/shop_guard.log`.

**Files anyone can download (daily)** — the shop requests itself the way an attacker would: `app/etc/env.php`, `.git/`, database dumps and backups found in the shop root or `pub/`, phpinfo, Adminer, phpMyAdmin, `var/log/*.log` and `composer.json` (a web root on the Magento main folder instead of `pub/`). A finding needs the content to prove it, so a "page not found" with status 200 never alerts. If the shop cannot reach itself (firewall), the check stays silent.

**Early warnings (critical and high)** — the signed feed can carry security warnings with the conditions under which a shop is affected (Magento version, PHP version of the web server, Composer packages, enabled modules). The shop checks them itself and sends critical and high warnings that apply once by mail and to the admin inbox (hourly at :41). `bin/magento shopguard:rules` shows every warning and whether it affects the shop. Shop Security Guard Pro alerts every level itself, with a task in the dashboard and the webhook; a warning Pro has sent is not sent twice.

**Card test brake** — card testers run stolen card numbers through the checkout; every single request looks like a customer paying, only the number tells. Payment attempts are counted per address and hour (REST `payment-information`, GraphQL `placeOrder`, checkouts with `placeOrder` in the address). Above the limit (8) the address is only noted in the default mode *Watch only*; `bin/magento shopguard:cardtests` lists those addresses. In the mode *Refuse further payment attempts* they get 403 and the bot scan bans them. Admin addresses and proxies are never counted.

**Upload block** — three plugins stop custom option file uploads before they reach the disk
(frontend validator, inner validator and the REST processor that PolyShell uses).
Switched on at install time only if the catalog has no options of type *File*.

**Bot scan (hourly)** — evaluates a sample of the requests and writes its results into the configuration,
each entry with an expiry date:

- IPs that sent an attack pattern
- bot and HTTP library user agents above the hourly threshold
- outdated browser strings above the threshold (rotating fake agents of scraper networks)
- fake Googlebot/Bingbot/Applebot: reverse and forward DNS must match
- single IPs above the hourly threshold (one day)

It never bans: IPs on the allow list, addresses admins logged in from (30 days),
private and server addresses, and while `REMOTE_ADDR` is used, any address carrying over 30 % of the traffic
(that is usually the proxy in front of the shop).

**Backdoor scan (every 30 minutes)** — silent while nothing changes, mail and admin inbox on findings:

- PHP files, `.user.ini`/`php.ini`, PHP-enabling `.htaccess` and session files in `pub/media` and `pub/static`
- PHP code disguised as images
- PHP code that refused REST uploads left in the system temp directory (PolyShell attempts)
- unknown PHP files in `pub/` and all its subdirectories (allow list with optional SHA-256), obfuscated code in `pub/index.php`
- PHP code hidden in files with other extensions (`.mp4`, `.tif`, `.m3u8`, ...) anywhere in `pub/`
- directories the shop user cannot open, so a locked directory is reported instead of passing as clean
- attack code in `var/report` and the main logs (StyleSmuggler stage 1), report guard line of the Adobe hotfix respected
- processes of the shop user disguised as kernel threads, started from `/tmp` or deleted files, known miners
- crontab entries that download and run code
- obfuscated scripts and template injections in CMS blocks, pages, e-mail templates and configuration
- new admin users and integrations with API access (reported for 7 days)
- every code file in `vendor`, `app`, `lib`, `pub`, `setup` and `bin` against a reference state: new, changed and
  deleted files, package updates (from `vendor/composer/installed.json`) reported as such
- webshell tricks in code files: encoded eval, hidden includes, goto obfuscation, known webshells

File names are checked on every run, file contents only if changed (weekly in full).

**Integrity check** — the first scan writes a reference state of all code files (SHA-256) to
`var/shop_guard/integrity.json.gz`, its checksum goes into the database. Before that, every code file passes the
signature check, so an infection already present is reported instead of being taken over. Later runs hash only
files whose size, ctime or mtime moved (ctime cannot be set back with `touch`), the weekly run hashes everything.
After a deployment or update take the new state with `bin/magento shopguard:integrity --accept`.
`generated/` is not covered, it changes with every compilation.

**Hardening** — writes `pub/media/.user.ini` and `pub/static/.user.ini` with `engine = Off`
(PHP-FPM then refuses to run uploaded scripts there, also on nginx). Existing files are never overwritten.

**System check** — on the configuration page and in the alert mail:

- PHP version against PHP2Shell (CVE-2026-109618, CVE-2026-109619; fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12)
- `session.upload_progress.enabled`, `fatal_error_backtraces`, `allow_url_include`, `display_errors`, `disable_functions`
  as seen by PHP-FPM, not by the CLI
- StyleSmuggler hotfix: tests whether `BlockFactory` refuses a non-block class before creating it
- admin path, two-factor authentication
- missing Adobe security patches via `vendor/bin/patch-status`, if installed (daily)

> PHP2Shell is triggered while PHP parses the request, before any Magento code runs.
> No Magento module can block it. Update PHP. Until then set `session.upload_progress.enabled = 0`.

**What to do** — every finding comes with a short, concrete instruction: in the admin, in the alert mail,
in the admin inbox and on the CLI. The configuration page starts with the result in plain words.

**STM Shop Security Guard Pro** (paid, separate module) adds a dashboard under *System › Security › Shop Security Guard*:
backdoor and bot scan at the push of a button, checked areas, findings with advice, attack and bot statistics
of the last 14 days, latest automatic blocks, findings marked as harmless with a reason, code changes accepted
per file or package, admin users and integrations with last login, 2FA and rights, and a log of who did what.

## Installation

```bash
composer require storetown-media/module-shop-guard
bin/magento module:enable Storetown_ShopGuard
bin/magento setup:upgrade
bin/magento setup:di:compile            # production mode
bin/magento setup:static-content:deploy # production mode
bin/magento cache:flush
```

Or copy the module to `app/code/Storetown/ShopGuard` and run the same commands.
Magento cron must be running.

## After installation

1. **Stores › Configuration › STM › STM Shop Security Guard**
2. Check *Your IP as seen by the shop*. Behind a proxy, Varnish or CDN set *Client IP from* to the header that shows your real IP.
   Until then IP blocking stays inactive.
3. Enter your office and ERP addresses under *Never block these IPs*.
4. Enter a recipient under *Notifications*.
5. Run the first scan: `bin/magento shopguard:scan --full`
6. Test the request filter: open `https://your-shop/?shopguard-test` — Shop Security Guard answers with status 403 and "Shop Security Guard ist aktiv".

## Commands

```bash
bin/magento shopguard:scan [--full] [--notify]   # system check and backdoor scan
bin/magento shopguard:bots [--dry-run]           # bot scan over the collected traffic
bin/magento shopguard:integrity [--accept]       # compare code with the reference state, or take the current state
bin/magento shopguard:rules [--update]           # attack patterns from Storetown Media: state, hits, fetch now
bin/magento shopguard:cardtests                  # addresses over the payment attempt limit, last 7 days
```

## Files

| Path | Content |
|---|---|
| `var/log/shop_guard.log` | every blocked attack |
| `var/shop_guard/traffic.log` | request sample, emptied by the hourly bot scan |
| `var/shop_guard/runtime.json` | PHP settings of the web server, refreshed every 6 hours |
| `var/shop_guard/integrity.json.gz` | reference state of the code files, checksum in the database |
| `var/shop_guard/feed.json`, `feed-state.json` | verified attack patterns from Storetown Media and the state of the last fetch |
| `var/shop_guard/feed-hits.log` | hits of patterns in the mode *log* |
| `var/shop_guard/login-failures.json` | failed admin logins per address in the last 15 minutes |
| `var/shop_guard/card-attempts.json`, `card-tests.log` | payment attempts per address in the last hour, addresses over the limit |

## Limits

- Pages delivered by Varnish or a CDN never reach PHP and are not filtered.
- The module complements patching and a WAF, it does not replace them.

## License

MIT, © Storetown Media, Tornesch — [storetown-media.de](https://www.storetown-media.de)
