#!/usr/bin/env bash
# php-security-update.sh - in-place PHP security upgrade (PHP2Shell: CVE-2026-109618/109619)
# for bare-metal Laravel hosts: upgrade PHP packages, reload PHP-FPM / restart Apache mod_php,
# gracefully cycle Laravel long-running processes, verify nothing still runs the old PHP.
#
# Usage:  sudo ./php-security-update.sh [--check] /var/www/app1 [/var/www/app2 ...]
#   --check   report only: installed/candidate versions and stale processes, change nothing
# Env:    PHP_BIN  php binary for artisan (default: php; other installed branches are tried on failure)
#         APP_USER user to run artisan as (default: owner of <app>/storage; never root unless set)
#         WAIT     seconds to wait for workers to cycle (default: 300)
# Exit:   0 = all PHP branches fixed and no process runs old PHP code; 1 = otherwise.
#
# What it never does: apt/dnf upgrade of anything but PHP packages, install a new PHP branch,
# change application code/.env/web-server config, kill processes, reboot.

set -euo pipefail

declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
CVE_RE='CVE-2026-10961[89]'
PHP_BIN="${PHP_BIN:-php}"
WAIT="${WAIT:-300}"
CHECK_ONLY=0
APPS=()
RC=0

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m xx\033[0m %s\n' "$*" >&2; exit 1; }

for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) [[ -f "$a/artisan" ]] || die "$a: no artisan file, not a Laravel app"
       APPS+=("$(realpath "$a")") ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
exec 9>/run/php-security-update.lock
flock -n 9 || die "another run is in progress"

if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
else die "unsupported package manager (need apt or dnf)"; fi

# ---------- helpers ----------

ver_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }  # $1 >= $2

upstream() { local v=${1#*:}; echo "${v%%[-+~]*}"; }   # 1:8.3.36-1+deb12 -> 8.3.36

# "<pkg> <branch>" for every installed *-common package (one per PHP branch)
common_pkgs() {
  if [[ $PM == apt ]]; then
    dpkg-query -W -f='${db:Status-Abbrev}${Package}\n' 'php*-common' 2>/dev/null \
      | awk '$1=="ii" && $2 ~ /^php[0-9]+\.[0-9]+-common$/ {b=$2; sub(/^php/,"",b); sub(/-common$/,"",b); print $2, b}'
  else
    rpm -qa --qf '%{NAME} %{VERSION}\n' 'php-common' 'php[0-9][0-9]-php-common' 2>/dev/null \
      | awk '{split($2,v,"."); print $1, v[1]"."v[2]}'
  fi
}

# PHP packages we are allowed to upgrade: only binaries built from the php8.x source package itself
# (php8.x-common/-cli/-fpm/-opcache/-mysql/..., libapache2-mod-php8.x; RPM: php-*, php8x-php-*).
# That is where the vulnerable code lives. Deliberately NOT:
#  - unversioned apt meta packages (php, php-cli, php-fpm, php-redis ...): on the ondrej/sury PPA they
#    point at the newest branch and dragging them along pulls in a new PHP major/minor and flips /usr/bin/php;
#  - PECL extension packages (php8.x-redis, -igbinary, -xdebug ...): separate sources, not affected,
#    and their meta packages are exactly what triggers the branch pull above;
#  - phpmyadmin, php-pear, composer & co.
php_pkgs() {
  if [[ $PM == apt ]]; then
    dpkg-query -W -f='${db:Status-Abbrev}${Package} ${source:Package}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
      | awk '$1=="ii" && $3 ~ /^php[0-9]+\.[0-9]+$/ {print $2}'
  else
    rpm -qa --qf '%{NAME} %{SOURCERPM}\n' 'php*' 2>/dev/null \
      | awk '$2 ~ /^php-[0-9]/ || $2 ~ /^php[0-9]+-php-[0-9]/ {print $1}'
  fi
}

installed_ver() {
  if [[ $PM == apt ]]; then upstream "$(dpkg-query -W -f='${Version}' "$1")"
  else rpm -q --qf '%{VERSION}' "$1"; fi
}

candidate_ver() {
  local v
  if [[ $PM == apt ]]; then
    v=$(apt-cache policy "$1" | awk '/Candidate:/{print $2}')
    if [[ -n $v && $v != "(none)" ]]; then upstream "$v"; else installed_ver "$1"; fi
  else
    v=$(dnf -q repoquery --upgrades --qf '%{version}' "$1" 2>/dev/null | sort -V | tail -n1)
    if [[ -n $v ]]; then echo "$v"; else installed_ver "$1"; fi
  fi
}

# Distros (Ubuntu, RHEL default streams) backport into the old version number: check changelog.
declare -A CHANGELOG_CACHE
changelog_has_fix() {
  local pkg=$1 br=$2 r
  if [[ -n ${CHANGELOG_CACHE[$pkg]:-} ]]; then return "${CHANGELOG_CACHE[$pkg]}"; fi
  r=1
  if [[ $PM == apt ]]; then
    if compgen -G "/usr/share/doc/php$br-*/changelog.Debian.gz" >/dev/null; then
      zgrep -qsE "$CVE_RE" /usr/share/doc/php"$br"-*/changelog.Debian.gz && r=0
    elif [[ "$(dpkg-query -W -f='${Version}' "$pkg")" == "$(apt-cache policy "$pkg" | awk '/Candidate:/{print $2}')" ]]; then
      # minimal images strip /usr/share/doc: ask the archive (only valid when installed == candidate)
      timeout 30 apt-get -qq changelog "$pkg" 2>/dev/null | grep -qE "$CVE_RE" && r=0
    fi
  else
    rpm -q --changelog "$pkg" 2>/dev/null | grep -qE "$CVE_RE" && r=0
  fi
  CHANGELOG_CACHE[$pkg]=$r
  return "$r"
}

installed_status() {   # pkg branch -> fixed | backport | VULNERABLE
  local pkg=$1 br=$2 v fixed
  v=$(installed_ver "$pkg"); fixed=${FIXED[$br]:-}
  if [[ -n $fixed ]] && ver_ge "$v" "$fixed"; then echo fixed
  elif changelog_has_fix "$pkg" "$br"; then echo backport
  else echo VULNERABLE; fi
}

# PIDs whose memory still maps a replaced (deleted) PHP binary/module
stale_pids() {
  { grep -lE ' /[^ ]*(php|libphp)[^ ]* \(deleted\)$' /proc/[0-9]*/maps 2>/dev/null || true; } \
    | sed -E 's#^/proc/([0-9]+)/maps$#\1#'
}

show_pids() { local p; for p in "$@"; do ps -o pid=,user=,etime=,args= -p "$p" 2>/dev/null || true; done; }

# ---------- 1. inventory ----------

mapfile -t COMMONS < <(common_pkgs)
[[ ${#COMMONS[@]} -gt 0 ]] || die "no PHP packages found via $PM"

log "Refreshing package metadata ($PM)"
if [[ $PM == apt ]]; then apt-get update -qq || warn "apt-get update reported errors, continuing with cached lists"
else dnf -q makecache --refresh >/dev/null || warn "dnf makecache reported errors, continuing with cached metadata"; fi

if [[ $PM == apt ]]; then
  held=$(apt-mark showhold | grep -E '^(php|libapache2-mod-php)' || true)
  [[ -z $held ]] || warn "held packages will NOT be upgraded: $(echo "$held" | tr '\n' ' ')"
fi

mapfile -t PKGS < <(php_pkgs)

UPDATES=0
log "PHP branches"
for line in "${COMMONS[@]}"; do
  read -r pkg br <<<"$line"
  inst=$(installed_ver "$pkg"); cand=$(candidate_ver "$pkg"); st=$(installed_status "$pkg" "$br")
  note=""
  [[ -z ${FIXED[$br]:-} ]] && note=" (EOL branch: only distro backports, plan an upgrade)"
  if [[ $cand != "$inst" ]] || { [[ $PM == apt ]] && apt-get -s install --only-upgrade "$pkg" 2>/dev/null | grep -q '^Inst '; }; then
    [[ $PM == apt ]] && cand=$(apt-cache policy "$pkg" | awk '/Candidate:/{print $2}')
    UPDATES=1; note+=" -> update available: $cand"
  fi
  printf '    %-24s branch %-4s installed %-10s %s%s\n' "$pkg" "$br" "$inst" "$st" "$note"
done

# apt: make sure the upgrade stays inside the installed branches (no new PHP packages)
if [[ $PM == apt && $UPDATES -eq 1 ]]; then
  sim=$(apt-get -s install --only-upgrade "${PKGS[@]}" 2>/dev/null | grep -E '^Inst ' || true)
  new_pkgs=$(awk '$3 !~ /^\[/ {print $2}' <<<"$sim")           # "Inst pkg (ver ...)" = new install, "[old]" = upgrade
  new_php=$(grep -E '^(php|libapache2-mod-php)' <<<"$new_pkgs" || true)
  if [[ -n $new_php ]]; then
    warn "upgrade would INSTALL new PHP packages (branch switch?): $(echo "$new_php" | tr '\n' ' ')"
    [[ $CHECK_ONLY -eq 1 ]] || die "refusing to change the set of PHP branches; investigate with: apt-get -s install --only-upgrade ${PKGS[*]}"
  elif [[ -n $new_pkgs ]]; then
    warn "upgrade pulls in new non-PHP dependencies: $(echo "$new_pkgs" | tr '\n' ' ')"
  fi
fi

mapfile -t STALE < <(stale_pids)
if [[ ${#STALE[@]} -gt 0 ]]; then
  warn "${#STALE[@]} process(es) still run replaced PHP code:"; show_pids "${STALE[@]}"
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
  log "--check: nothing changed"; exit 0
fi

ALL_FIXED=1
for line in "${COMMONS[@]}"; do
  read -r pkg br <<<"$line"
  [[ $(installed_status "$pkg" "$br") == VULNERABLE ]] && ALL_FIXED=0
done
if [[ $UPDATES -eq 0 && $ALL_FIXED -eq 0 ]]; then
  die "fix is not in your repositories yet; nothing changed. Re-run later."
fi

# ---------- 2. upgrade PHP packages only ----------

if [[ $UPDATES -eq 1 ]]; then
  log "Upgrading ${#PKGS[@]} PHP packages"
  if [[ $PM == apt ]]; then
    # --only-upgrade: never installs the listed packages fresh; --force-confold: keep admin's php.ini/pools
    # NEEDRESTART_SUSPEND: restarts are done below, in a controlled order
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 \
      apt-get install -y -q --only-upgrade -o Dpkg::Options::=--force-confold "${PKGS[@]}"
  else
    dnf upgrade -y -q "${PKGS[@]}"
  fi
fi

# ---------- 3. PHP-FPM: reload (USR2 re-execs master + workers, no dropped requests) ----------

mapfile -t FPM_UNITS < <(systemctl list-units --type=service --state=running --no-legend --plain '*php*fpm*' 2>/dev/null | awk '{print $1}')
for u in "${FPM_UNITS[@]}"; do
  bin=$(systemctl show -p ExecStart --value "$u" 2>/dev/null | sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -n1)
  if [[ -x ${bin:-} ]] && ! "$bin" -t >/dev/null 2>&1; then
    warn "$bin -t failed: config error, $u NOT reloaded (still on old PHP). Check: $bin -t"; RC=1; continue
  fi
  if systemctl reload "$u"; then ok "reloaded $u"
  else warn "reload of $u failed, check: journalctl -u $u"; RC=1; fi
done
[[ ${#FPM_UNITS[@]} -gt 0 ]] || log "no running PHP-FPM units"

# ---------- 4. Apache with mod_php: full restart (graceful keeps the old libphp) ----------

for svc in apache2 httpd; do
  systemctl is-active -q "$svc" 2>/dev/null || continue
  pid=$(systemctl show -p MainPID --value "$svc")
  if [[ $pid != 0 ]] && grep -q libphp "/proc/$pid/maps" 2>/dev/null; then
    if apachectl configtest >/dev/null 2>&1; then systemctl restart "$svc"; ok "restarted $svc (mod_php)"
    else warn "apachectl configtest failed, $svc NOT restarted"; RC=1; fi
  fi
done

# ---------- 5. Laravel: graceful cycle of long-running processes ----------
# Workers finish the current job and exit; supervisor/systemd starts them on the new PHP.
# queue:restart / horizon:terminate / pulse:restart / reverb:restart only set a flag or signal -
# they do not change files. Octane is not covered: restart it via its process manager.

php_candidates() {   # PHP_BIN first, then every installed branch newest-first
  local f
  echo "$PHP_BIN"
  for f in /usr/bin/php[0-9].[0-9] /usr/bin/php[0-9].[0-9][0-9] /opt/remi/php*/root/usr/bin/php; do
    [[ -x $f ]] && echo "$f"
  done | sort -rV
}

for app in "${APPS[@]}"; do
  if [[ -n ${APP_USER:-} ]]; then user=$APP_USER
  else
    user=$(stat -c %U "$app/storage/logs" 2>/dev/null || stat -c %U "$app/storage")
    if [[ $user == root ]]; then
      warn "$app: storage/ is owned by root; refusing to run artisan as root (it would leave root-owned cache/log files)."
      warn "   re-run with APP_USER=<web user> $0 $app   (workers of this app were NOT cycled)"
      RC=1; continue
    fi
  fi
  id -u "$user" >/dev/null 2>&1 || { warn "$app: user $user does not exist (set APP_USER)"; RC=1; continue; }
  log "Laravel $app (as $user)"

  cmds=""; used=""
  while read -r bin; do
    [[ -n $bin ]] || continue
    command -v "$bin" >/dev/null 2>&1 || continue
    if cmds=$(cd "$app" && timeout 120 runuser -u "$user" -- "$bin" artisan list --raw --no-interaction 2>/dev/null | awk '{print $1}') && [[ -n $cmds ]]; then
      used=$bin; break
    fi
  done < <(php_candidates | awk '!seen[$0]++')
  if [[ -z $used ]]; then
    warn "artisan failed in $app with every PHP binary tried (set PHP_BIN / APP_USER, check .env and storage permissions)"; RC=1; continue
  fi
  [[ $used == "$PHP_BIN" ]] || warn "$app: $PHP_BIN could not run artisan, used $used instead"

  ran=0
  for c in queue:restart horizon:terminate pulse:restart reverb:restart; do
    grep -qx "$c" <<<"$cmds" || continue
    ran=1
    if out=$(cd "$app" && timeout 120 runuser -u "$user" -- "$used" artisan "$c" --no-interaction 2>&1); then ok "$c"
    else warn "$c failed in $app:"; grep -v '^PHP Warning' <<<"$out" | grep -v '^\s*$' | head -n 4 | sed 's/^/      /' >&2; RC=1; fi
  done
  [[ $ran -eq 1 ]] || warn "no restart commands found in $app (artisan list empty?)"
done

# ---------- 6. wait until no process runs the old PHP ----------

deadline=$((SECONDS + WAIT))
while :; do
  mapfile -t STALE < <(stale_pids)
  [[ ${#STALE[@]} -eq 0 || $SECONDS -ge $deadline ]] && break
  printf '\r    waiting for %d process(es) on old PHP, %ds left ' "${#STALE[@]}" $((deadline - SECONDS))
  sleep 5
done
echo
if [[ ${#STALE[@]} -gt 0 ]]; then
  warn "still running old PHP after ${WAIT}s (Octane, custom daemons, long jobs, workers without a process manager):"
  show_pids "${STALE[@]}"
  warn "restart them via their process manager (e.g. supervisorctl restart <program>)"
  RC=1
else
  ok "no process runs replaced PHP code"
fi

# ---------- 7. final verification ----------

log "Result"
for line in "${COMMONS[@]}"; do
  read -r pkg br <<<"$line"
  st=$(installed_status "$pkg" "$br")
  printf '    %-24s %-10s %s\n' "$pkg" "$(installed_ver "$pkg")" "$st"
  [[ $st == VULNERABLE ]] && RC=1
done
for b in /usr/bin/php /usr/bin/php[0-9]*.[0-9]* /opt/remi/php*/root/usr/bin/php; do
  [[ -x $b ]] && printf '    %-34s %s\n' "$b" "$("$b" -r 'echo PHP_VERSION;' 2>/dev/null)"
done

if [[ $RC -eq 0 ]]; then ok "done"; else warn "finished with problems, see above"; fi
exit "$RC"
