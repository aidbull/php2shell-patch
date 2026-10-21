# php2shell-patch

Patch Linux servers against **PHP2Shell** (CVE-2026-109618, CVE-2026-109619) without breaking the
Laravel apps running on them.

One Bash script that upgrades only the PHP packages, reloads PHP-FPM / restarts Apache mod_php in
the right order, gracefully cycles Laravel queue workers / Horizon / Pulse / Reverb, and then proves
that **no process on the box still runs the old PHP**. Plus a [Claude Code](https://claude.com/claude-code)
skill (`SKILL.md`, in Russian) that walks an agent through a full server runbook: recon, compromise
check, patch, post-checks, report.

[Русская версия README](README.ru.md)

## PHP2Shell in 30 seconds

| | |
|---|---|
| CVEs | CVE-2026-109618 (RCE via OOM corruption), CVE-2026-109619 (RCE via stale global state) |
| Severity | Critical, CVSS 4.0 **9.2**, unauthenticated, runs as the web worker user |
| Fixed in | **PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12** (released 2026-10-21) |
| Affected | Every PHP serving web requests: PHP-FPM, Apache mod_php (highest risk, exploit demonstrated), php-cgi, FrankenPHP, LiteSpeed |
| EOL branches | 8.1 and older get no upstream release. Debian/Ubuntu/RHEL backport the fix into their old version numbers; the script detects that via the package changelog |
| Exploitation | Public exploit attempts reported by CDNs within hours of disclosure. Patch now |

Sources: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) (per-vendor patch status),
[Tenable FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote).

## Quick start

```bash
curl -fsSLO https://raw.githubusercontent.com/aidbull/php2shell-patch/main/scripts/php-security-update.sh
sudo bash php-security-update.sh --check /var/www/app1 /var/www/app2   # report only, changes nothing
sudo bash php-security-update.sh         /var/www/app1 /var/www/app2   # patch
```

Arguments are Laravel app roots (the directory with `artisan`). You can pass none if the host has no
Laravel apps; PHP is still patched and FPM/Apache reloaded.

Run the real thing detached from your SSH session, so a dropped connection cannot leave `dpkg`
half-way:

```bash
sudo setsid nohup bash -c 'WAIT=600 bash php-security-update.sh /var/www/app1 > /root/php2shell.log 2>&1; echo $? > /root/php2shell.exit' >/dev/null 2>&1 &
tail -f /root/php2shell.log
```

Exit code `0` means: every installed PHP branch is fixed (or backported) **and** no process still maps
the old PHP binary. Anything else is `1`, with the reason printed.

## What the script does

1. **Inventory.** Finds every installed PHP branch (`php8.2-common`, `php8.3-common`, Remi `php82-php-common`, …),
   prints installed vs. candidate version and a status: `fixed` (upstream version ≥ fixed), `backport`
   (older version number, but the CVE is in the package changelog) or `VULNERABLE`. Warns about held packages.
2. **Upgrade PHP packages only.** `apt-get install --only-upgrade` / `dnf upgrade` on the installed packages
   built from the `php8.x` source itself (`php8.x-common/-cli/-fpm/-mysql/…`, `libapache2-mod-php8.x`,
   RPM `php-*` / `php8x-php-*`). Config files you edited (`php.ini`, pools) are kept (`--force-confold`).
   PECL extension packages (`php8.x-redis`, `-igbinary`, `-xdebug`, …) and the unversioned meta packages
   (`php`, `php-cli`, `php-redis`, …) are left alone: they are not affected, and on the ondrej/sury PPA
   their meta packages are exactly what drags in the next PHP branch (`php-redis` → `php8.4-redis` →
   `php8.4-cli`, and `/usr/bin/php` flips to 8.4). On apt the upgrade is simulated first and the script
   **refuses to run if any new PHP package would be installed**.
3. **PHP-FPM reload** (`systemctl reload`, i.e. USR2: master and workers re-exec on the new binary, no dropped
   requests). Each pool config is tested with `php-fpm -t` first; a broken config is reported, not reloaded.
4. **Apache mod_php full restart** (a graceful restart keeps the old `libphp` mapped). Only after `apachectl configtest` passes.
5. **Laravel graceful cycle.** For each app, as the app's own user: `queue:restart`, `horizon:terminate`,
   `pulse:restart`, `reverb:restart`, whichever exist. Workers finish their current job and exit;
   supervisor/systemd brings them back on the new PHP.
6. **Wait** (default 300 s) until no process on the host maps a deleted PHP binary or module, then list what is left.
7. **Verify**: per-branch status again, plus `php -r 'echo PHP_VERSION;'` for every PHP binary found.

### What it never does

- `apt upgrade` / `dnf upgrade` of anything but PHP, kernel updates, reboots.
- Install a new PHP branch or touch unversioned meta packages (`php`, `php-cli`, `php-fpm`, `phpmyadmin`, …).
- Change application code, `.env`, nginx/Apache config, FPM pools.
- Run `artisan` as root. If `storage/` is owned by root it stops and asks for `APP_USER` instead of
  leaving root-owned cache and log files behind (the usual way a "harmless" restart ends in HTTP 500).
- `kill` anything. Processes that survive the wait are listed with their PID and command line; you restart
  them through their process manager.
- Roll back. Rolling back restores the vulnerability.

## Laravel notes

| Topic | Behaviour |
|---|---|
| User for `artisan` | Owner of `storage/logs` (falls back to `storage/`). Override: `APP_USER=www-data`. Never root unless you set it explicitly. |
| PHP binary for `artisan` | `PHP_BIN` (default `php`). If that fails (e.g. the app needs 8.3 but `php` is 8.1), every installed branch is tried newest-first, and the one used is printed. |
| Queue workers | `queue:restart` writes a timestamp to the cache; workers exit after the current job. Needs a working cache store and a process manager (supervisor/systemd `Restart=always`) to start them again. |
| Horizon | `horizon:terminate`, same model. |
| Octane | Not handled: with Swoole the master process *is* PHP and `octane:reload` keeps it. Restart it: `supervisorctl restart octane`. The wait step will show it as still running the old PHP until you do. |
| Scheduler (cron) | Nothing to do: every `schedule:run` is a fresh process. |
| Several PHP versions per host | Run once; all branches are upgraded. Use `PHP_BIN` per app only if the auto-detection picks the wrong one. |
| OPcache / compiled config | Lives in the FPM processes; the reload drops it. `bootstrap/cache` is plain PHP and survives a patch release. |

## Reading the output

```
==> PHP branches
    php8.3-common            branch 8.3  installed 8.3.35    VULNERABLE -> update available: 8.3.36-1+ubuntu24.04.1+deb.sury.org+1
    php8.1-common            branch 8.1  installed 8.1.2     backport (EOL branch: only distro backports, plan an upgrade)
```

| Message | Meaning / what to do |
|---|---|
| `fix is not in your repositories yet; nothing changed` | Mirror or vendor is behind. Nothing was touched. Apply the [mitigation](#no-fix-available-yet) and re-run later. Check two things first: (1) `apt-get update` output above for `Failed to fetch` / `503` (PPAs get overloaded on patch day; the lists are then stale), (2) whether your `noble-security` / `bookworm-security` comes from a hosting mirror (e.g. `mirror.hetzner.com`) that lags the official pocket. Ubuntu's own advice is to take the security pocket from `security.ubuntu.com` directly; add it as a deb822 source and re-run `--check`. |
| `upgrade would INSTALL new PHP packages` | A meta package wants to pull in another PHP branch. Script stops. Check `apt-get -s install --only-upgrade …`, usually you hold or remove the unversioned `php*` meta packages. |
| `still running old PHP after …` + PIDs | Octane, custom daemons, a worker started by hand. Restart via supervisor/systemd, then `--check`. |
| `reload of php8.3-fpm failed` / `-t failed` | Config problem in a pool. `journalctl -u php8.3-fpm`, `php-fpm8.3 -t`. FPM is still serving on the old binary. |
| `storage/ is owned by root` | Re-run that app with `APP_USER=<web user>`. |
| `artisan failed … with every PHP binary tried` | `.env` missing, `vendor/` missing, wrong `APP_USER`. Workers were not cycled; fix and re-run. |
| `another run is in progress` | Wait for the first run to finish (lock in `/run`). |

## Docker

PHP inside a container cannot be patched in place, only rebuilt. Pin the base image to the fixed tag
(`php:8.3.36-fpm`, `php:8.2.35-fpm-alpine`, …), `docker compose build --pull && docker compose up -d`,
then verify inside: `docker exec <c> php -r 'echo PHP_VERSION;'`. Derived images (`wordpress`,
`drupal`, FrankenPHP) update later than `php:`; check the version inside, not the tag.

## No fix available yet

The PHP team is explicit that config changes **do not make an installation safe**; they only reduce
exposure. When the package is not there yet, apply what is safe for virtually every app:

```ini
; /etc/php/8.x/fpm/conf.d/99-php2shell.ini  (and apache2/conf.d for mod_php)
session.upload_progress.enabled = 0
; PHP 8.5 only:
; fatal_error_backtraces = 0
```

then `systemctl reload php8.x-fpm` (mod_php: `apachectl configtest && systemctl restart apache2`).
The advisory also lists `memory_limit = -1` via `php_admin_value` and a small `post_max_size`
(`8M`, or `32M` with uploads) as the primary mitigation for CVE-2026-109618. Those change memory and
upload behaviour, so decide per application. Do not use `RLIMIT_AS` / `RLIMIT_DATA`: they trigger the
vulnerable path. Patch as soon as the package lands.

## Using the Claude Code skill

`SKILL.md` is a runbook for an agent that has shell access to the server (SSH, or Claude Code running
on the host). It covers things the script deliberately leaves to a human: fleet order (canary first),
pre-patch compromise check (children of FPM workers, new `.php` in `public/`, cron of the web user),
config backup, health baseline with `curl --resolve`, escalation rules (cPanel/Plesk/CloudLinux/LiteSpeed,
PHP ≤ 8.1 without vendor fix, low disk, broken dpkg), post-checks and a YAML report per host.

```bash
git clone https://github.com/aidbull/php2shell-patch ~/.claude/skills/php2shell-patch
# then, in Claude Code: /php2shell-patch  and name the host(s)
```

The skill text is Russian; the script and its output are English.

## Supported platforms

- Debian / Ubuntu with `apt`: distro packages, [ondrej/php PPA](https://launchpad.net/~ondrej/+archive/ubuntu/php), packages.sury.org.
- RHEL / AlmaLinux / Rocky / Fedora with `dnf`: AppStream modules, [Remi](https://rpms.remirepo.net/) (`php-*` and `php8x-php-*` SCL).
- PHP-FPM under systemd, Apache with mod_php, Laravel 9–12 with supervisor/systemd-managed workers.

Not supported (the skill escalates to a human): cPanel/EasyApache, Plesk, CloudLinux alt-php, LiteSpeed `lsphp`,
DirectAdmin, FrankenPHP outside Docker, PHP built from source, Docker containers (see above).

## Rollout advice

1. Run `--check` everywhere first; it is read-only and tells you which hosts already have the fix.
2. Patch a canary (staging or the least important production host). Watch logs for a few minutes.
3. Internet-facing hosts next, then internal ones. Behind a load balancer: one host at a time.
4. After each host: `--check` again, `systemctl --failed`, `supervisorctl status`, your health URL.

## Contributing

Issues and PRs welcome, especially: vendor-specific package names, panels, non-Laravel worker managers.
Keep the script `shellcheck`-clean and dependency-free (bash, coreutils, apt/dnf, systemd).

MIT, see [LICENSE](LICENSE).
