---
name: php2shell-patch
description: Патч PHP на Linux-сервере от PHP2Shell (CVE-2026-109618, CVE-2026-109619) — разведка, проверка на компрометацию, обновление PHP-пакетов, перезапуск FPM/Apache/Laravel-воркеров, пост-проверки и отчёт. Использовать на каждом сервере из списка, по одному за раз.
---

# PHP2Shell: патч одного сервера

Ты работаешь на одном сервере. Цель: PHP закрыт от CVE-2026-109618 и CVE-2026-109619, сайты и воркеры работают как до патча. В конце — отчёт по шаблону из раздела 10.

Фикс: **8.2.35, 8.3.36, 8.4.27, 8.5.12** (релиз 2026-10-21). Ubuntu и RHEL бэкпортят фикс в старую версию (например `8.3.6-0ubuntu0.24.04.13`) — тогда признак фикса это CVE в changelog пакета, а не `php -v`. Скрипт это учитывает.

Скрипт: `scripts/php-security-update.sh` (рядом с этим файлом).

## 1. Жёсткие правила

Запрещено:
- `apt upgrade` / `apt full-upgrade` / `dnf upgrade` без аргументов, обновление ядра, reboot.
- Менять код приложений, `.env`, конфиги nginx/apache, пулы FPM (кроме митигации из раздела 8).
- Удалять файлы, чистить логи, убивать процессы `kill -9`.
- Собирать PHP из исходников, подключать новые репозитории, менять источник PHP (ondrej → distro и т.п.).
- Трогать серверы вне выданного списка.
- Повторно запускать скрипт, если предыдущий запуск ещё идёт.

Стоп и эскалация человеку (ничего не менять, сразу отчёт со статусом `ESCALATED`):
- Признаки компрометации (раздел 4).
- Хостинг-панель: cPanel/EasyApache, Plesk, CloudLinux alt-php, LiteSpeed (`lsphp`), DirectAdmin.
- PHP 8.1 и старше без фикса от дистрибутива (только митигация из раздела 8 — затем `ESCALATED`).
- Свободно меньше 1 ГБ на `/` или `/var`.
- `dpkg`/`dnf` заблокирован другим процессом дольше 10 минут, или dpkg в сломанном состоянии (`dpkg --audit` не пустой).
- Пост-проверки (раздел 9) хуже базовой линии.
- Что-то не описано здесь.

## 2. Порядок по флоту

1. Первый сервер — канарейка (staging или наименее важный prod). Если на нём что-то пошло не так — остановить весь rollout.
2. Дальше internet-facing серверы, потом внутренние.
3. В кластере за балансировщиком — по одному серверу, следующий только после зелёных пост-проверок предыдущего.

## 3. Разведка

```bash
hostname; . /etc/os-release; echo "$PRETTY_NAME"
command -v apt-get dnf docker 2>/dev/null
dpkg -l 'php*' 2>/dev/null | awk '/^ii/{print $2,$3}'; rpm -qa 'php*' 2>/dev/null | sort
grep -rlE 'ondrej|sury' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
dnf repolist 2>/dev/null | grep -iE 'remi|appstream'
systemctl list-units --type=service --state=running --no-legend --plain \
  '*php*' 'apache2*' 'httpd*' 'nginx*' 'lsws*' 'supervisor*' 'frankenphp*' 'laravel*' 2>/dev/null
docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null
ls -d /usr/local/cpanel /usr/local/psa /opt/cpanel/ea-php* /opt/alt/php* /usr/local/lsws /usr/local/directadmin 2>/dev/null
dpkg --audit 2>/dev/null; df -h / /var
```

Laravel-приложения: корни из веб-сервера, приложение — родитель `public/` с файлом `artisan`.

```bash
{ grep -rhoE '^\s*root\s+[^;]+' /etc/nginx/ 2>/dev/null | awk '{print $2}'
  grep -rhoiE '^\s*DocumentRoot\s+\S+' /etc/apache2/ /etc/httpd/ 2>/dev/null | awk '{print $2}' | tr -d '"'
} | sort -u | while read -r r; do d=$(dirname "$r"); [ -f "$d/artisan" ] && echo "$d"; done | sort -u
grep -rhE 'artisan (queue:work|horizon|octane|reverb|pulse)' /etc/supervisor* /etc/systemd/system 2>/dev/null
```

Какая версия PHP у приложения: по `fastcgi_pass` (например `unix:/run/php/php8.2-fpm.sock` → `PHP_BIN=php8.2`). Если приложения на разных версиях — запускай скрипт отдельно на каждую группу со своим `PHP_BIN`.

Классификация:

| Что нашёл | Что делать |
|---|---|
| apt/dnf, PHP из дистрибутива, ondrej/sury или Remi; FPM и/или mod_php | Разделы 4 → 5 → 6 → 9 |
| PHP только в Docker | Раздел 7 |
| И то и другое | Оба пути |
| Панель, LiteSpeed, FrankenPHP вне Docker | `ESCALATED` |
| Ветка 8.1 и ниже | Разделы 4, 5, 6 (`--check`); фикса нет → раздел 8 и `ESCALATED` |

## 4. Проверка на компрометацию (до патча)

Перезапуск FPM уничтожит следы в памяти, поэтому сначала смотрим.

```bash
# дочерние процессы веб-воркеров, которые не являются самими воркерами
pids=$(pgrep -d, -f '^(php-fpm|lsphp|/usr/sbin/(apache2|httpd))')
[ -n "$pids" ] && ps --ppid "$pids" -o pid=,user=,etime=,comm=,args= | awk '$4 !~ /^(php-fpm|apache2|httpd|lsphp)/'

# новые/неотслеживаемые php-файлы в приложениях (для каждого APP)
git -C "$APP" status --porcelain --untracked-files=all -- public 2>/dev/null | grep '\.php'
find "$APP/public" -name '*.php' -newermt 2026-10-20 2>/dev/null | head -50

# исполняемые файлы во временных каталогах, cron веб-пользователя
find /tmp /var/tmp /dev/shm -type f -newermt 2026-10-20 -perm -u+x 2>/dev/null | head -50
for u in www-data apache nginx; do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
```

Подозрительно: шелл, `curl`/`wget`, `nc`, `python`/`perl` — дети воркеров; новые `.php` в `public/`, не объяснимые деплоем; исполняемые файлы в `/tmp`; cron у веб-пользователя, которого не было. Легитимные исключения бывают (imagemagick, git, `ffmpeg` из приложения) — опиши, что видишь, не делай вывода сам. При любом подозрении — стоп, `ESCALATED`, приложи вывод.

## 5. Пре-флайт

```bash
TS=$(date +%Y%m%d-%H%M%S)
tar czf /root/php-config-$TS.tgz $(ls -d /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.d /etc/php-fpm.conf /etc/opt/remi 2>/dev/null)
systemctl --failed --no-legend
supervisorctl status 2>/dev/null
```

Базовая линия здоровья: для каждого `server_name` приложения запиши код ответа и время. Запросы локальные, через `--resolve`:

```bash
curl -sk -o /dev/null -w '%{http_code} %{time_total}\n' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/"
```

Если сайт уже отдаёт 5xx до патча — зафиксируй в отчёте, это не повод останавливаться.

## 6. Патч

Скопируй скрипт на сервер и сначала прогоняй только отчёт:

```bash
scp scripts/php-security-update.sh HOST:/root/
sudo bash /root/php-security-update.sh --check /var/www/app1 /var/www/app2
```

Если `--check` показывает `fixed`/`backport` для всех веток и нет процессов на старом PHP — патч уже стоит, переходи к разделу 9.

Если в выводе `VULNERABLE` без `update available` — фикса в репозитории ещё нет: раздел 8, статус `NO_FIX_YET`, вернуться к серверу позже.

Боевой запуск — отвязанно от SSH, чтобы обрыв соединения не оставил dpkg в полуустановленном состоянии:

```bash
sudo setsid nohup bash -c '
  date "+%F %T" > /root/php2shell.start
  WAIT=600 bash /root/php-security-update.sh /var/www/app1 /var/www/app2 > /root/php2shell.log 2>&1
  echo $? > /root/php2shell.exit' >/dev/null 2>&1 &
```

Опрашивай раз в 15–30 с, пока не появится `/root/php2shell.exit`:

```bash
tail -n 20 /root/php2shell.log; cat /root/php2shell.exit 2>/dev/null
```

Переменные: `PHP_BIN` (php для artisan, по умолчанию `php`; если им artisan не запускается, скрипт сам перебирает остальные установленные ветки и пишет, какую взял), `APP_USER` (по умолчанию владелец `storage/logs`; если это root — скрипт не запускает artisan от root и просит задать `APP_USER`), `WAIT` (сек на перезапуск воркеров).

Скрипт обновляет только уже установленные версионные пакеты (`php8.3-*`, `libapache2-mod-php8.3`, `php-common`), безверсионные мета-пакеты (`php`, `php-cli`, `php-fpm`) не трогает, и перед `apt-get install` делает симуляцию: если она показывает установку пакетов новой ветки PHP — останавливается с `refusing to change the set of PHP branches`.

Разбор результата:

| В логе | Действие |
|---|---|
| exit 0, `ok done` | Раздел 9 |
| `fix is not in your repositories yet` | Ничего не изменено. Раздел 8, `NO_FIX_YET` |
| `still running old PHP after …` + список PID | Найди, кто управляет процессом (`systemctl status <PID>`, `supervisorctl status`), перезапусти через него: `supervisorctl restart <program>` / `systemctl restart <unit>`. Не `kill`. Для Octane — `supervisorctl restart`. Затем снова `--check` |
| `reload of … failed` | `journalctl -u <unit> -n 50`, `php-fpm<ver> -t`. Не правь конфиг — `ESCALATED` |
| `apachectl configtest failed` | `ESCALATED`, Apache работает на старом PHP |
| `refusing to change the set of PHP branches` | Ничего не изменено. Какой-то пакет тянет новую ветку PHP. Покажи вывод `apt-get -s install --only-upgrade …` из лога, `ESCALATED` |
| `storage/ is owned by root` | Воркеры этого приложения не перезапущены. Определи веб-пользователя (по пулу FPM: `grep -h '^user' /etc/php/*/fpm/pool.d/*.conf`) и повтори только для него: `APP_USER=<user> bash /root/php-security-update.sh <app>` |
| `artisan failed in …` | Проверь `PHP_BIN`/`APP_USER`, `.env` и `vendor/`, повтори только для этого приложения |
| `VULNERABLE` в Result | Пакет не обновился (hold, pin, зеркало отстаёт). Покажи `apt-cache policy php<ver>-common` / `dnf info php-common`, `ESCALATED` |
| `another run is in progress` | Подожди завершения первого запуска |

## 7. Docker-хосты

Скрипт для контейнеров не используется. PHP в образе меняется только пересборкой.

```bash
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project.working_dir"}}'
docker exec <container> php -r 'echo PHP_VERSION, PHP_EOL;'
```

- Образ собирается на этом сервере (в compose есть `build:`): в `Dockerfile` замени базовый тег на точный фиксированный (`php:8.3.36-fpm`, `php:8.2.35-fpm-alpine` и т.д., вариант сохранить), затем `docker compose build --pull && docker compose up -d`. Изменение Dockerfile — единственная разрешённая правка в проекте; покажи diff в отчёте.
- Образ приходит из registry/CI: на сервере ничего не собирать. Статус `NEEDS_CI_REBUILD`, укажи образ и текущую версию PHP.
- Производные образы (`wordpress`, `drupal`, FrankenPHP и др.) обновляются позже официального `php:` — проверь версию внутри после `pull`, а не тег.
- Если точного тега ещё нет на Docker Hub — `NO_FIX_YET`.

Проверка: `docker exec <container> php -r 'echo PHP_VERSION;'` ≥ фиксированной версии для ветки; воркеры в контейнерах перезапущены вместе с `up -d`.

## 8. Нет фикса: митигация

Частичная защита, сервер остаётся уязвимым (так говорит сам advisory PHP). Применяй только `session.upload_progress.enabled=0` (закрывает путь CVE-2026-109619) — это безопасно для почти всех приложений; на ветке 8.5 дополнительно `fatal_error_backtraces=0`. Остальные меры из advisory для CVE-2026-109618 (`memory_limit=-1` через `php_admin_value`, `post_max_size` 8M/32M, лимиты на multipart на фронте) меняют поведение памяти и загрузок — не применяй, перечисли в отчёте для человека. `RLIMIT_AS`/`RLIMIT_DATA` не ставить: они сами приводят на уязвимый путь.

Каталог доп. ini для каждого FPM-бинарника и для mod_php:

```bash
for b in /usr/sbin/php-fpm* /opt/remi/php*/root/usr/sbin/php-fpm; do
  [ -x "$b" ] && echo "$b: $("$b" -i 2>/dev/null | awk -F'=> ' '/Scan this dir/{print $2}')"
done
ls -d /etc/php/*/apache2/conf.d 2>/dev/null
```

В каждый найденный каталог:

```bash
printf '; PHP2Shell partial mitigation %s\nsession.upload_progress.enabled = 0\n' "$(date -I)" > "$DIR/99-php2shell.ini"
# только для каталогов ветки 8.5:
# printf 'fatal_error_backtraces = 0\n' >> "$DIR/99-php2shell.ini"
```

Затем `systemctl reload <fpm-unit>` (для mod_php — `apachectl configtest && systemctl restart apache2`) и проверка:

```bash
"$b" -i | grep 'session.upload_progress.enabled'   # должно быть Off
```

Файл `99-php2shell.ini` после установки фикса не удалять.

## 9. Пост-проверки

```bash
sudo bash /root/php-security-update.sh --check <apps>        # все ветки fixed/backport, нет процессов на старом PHP
systemctl --failed --no-legend
supervisorctl status 2>/dev/null                              # всё RUNNING, uptime свежий у воркеров
curl ... (те же запросы, что в разделе 5)                     # коды как в базовой линии
```

Ошибки после старта патча:

```bash
START=$(cat /root/php2shell.start)
for a in <apps>; do find "$a/storage/logs" -name '*.log' -newermt "$START" -exec grep -hE 'ERROR|CRITICAL|EMERGENCY' {} + 2>/dev/null | tail -20; done
journalctl -u 'php*-fpm*' --since "$START" -p warning --no-pager | tail -20
```

Если в приложении Horizon — `php artisan horizon:status` должно быть `running`.

Регресс относительно базовой линии (новые 5xx, упавшие юниты, воркеры не RUNNING, новые CRITICAL в логах) → не откатывать пакеты (откат возвращает уязвимость), `ESCALATED` с выводом.

## 10. Отчёт

Один блок на сервер:

```yaml
host:
status: PATCHED | MITIGATED_NO_FIX | NO_FIX_YET | NEEDS_CI_REBUILD | ESCALATED
os:
php_source: distro | ondrej | sury | remi | docker | panel
php_branches:            # ветка: пакет и версия до -> после, fixed|backport|VULNERABLE
  - "8.3: php8.3-common 8.3.35-1+... -> 8.3.36-1+... fixed"
sapi: [fpm, mod_php, docker]
apps: [/var/www/app1]
restarted: [php8.3-fpm (reload), queue:restart app1, supervisor laravel-worker]
stale_processes_left: none | <pid comm args>
compromise_check: clean | suspicious: <что именно>
health: before -> after (по каждому домену: код, время)
mitigation_applied: none | upload_progress off в <каталоги>
config_backup: /root/php-config-<TS>.tgz
log: /root/php2shell.log
notes:
```

Статус `PATCHED` только если: все ветки `fixed`/`backport`, ни одного процесса на старом PHP, пост-проверки не хуже базовой линии.
