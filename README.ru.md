# php2shell-patch

Патч Linux-серверов от **PHP2Shell** (CVE-2026-109618, CVE-2026-109619) так, чтобы Laravel-приложения
на них не сломались.

Один Bash-скрипт: обновляет только PHP-пакеты, перезагружает PHP-FPM / перезапускает Apache mod_php
в правильном порядке, мягко перезапускает воркеры очередей / Horizon / Pulse / Reverb и в конце
доказывает, что **ни один процесс на сервере больше не выполняет старый PHP**. Плюс скилл для
[Claude Code](https://claude.com/claude-code) (`SKILL.md`) — полный ранбук для агента: разведка,
проверка на компрометацию, патч, пост-проверки, отчёт.

[English README](README.md)

## PHP2Shell за 30 секунд

| | |
|---|---|
| CVE | CVE-2026-109618 (RCE через OOM corruption), CVE-2026-109619 (RCE через stale global state) |
| Критичность | Critical, CVSS 4.0 **9.2**, без аутентификации, выполнение от пользователя веб-воркера |
| Исправлено в | **PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12** (релиз 2026-10-21) |
| Уязвимо | Любой PHP, обслуживающий веб-запросы: PHP-FPM, Apache mod_php (максимальный риск, эксплойт показан), php-cgi, FrankenPHP, LiteSpeed |
| EOL-ветки | 8.1 и старше релиза не получат. Debian/Ubuntu/RHEL бэкпортят фикс в старый номер версии — скрипт определяет это по changelog пакета |
| Эксплуатация | CDN-провайдеры сообщили о попытках атак через несколько часов после раскрытия. Патчить сейчас |

Источники: [advisory PHP](https://www.php.net/archive/2026.php#2026-10-21-5),
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) (статус патчей по вендорам).

## Быстрый старт

```bash
curl -fsSLO https://raw.githubusercontent.com/aidbull/php2shell-patch/main/scripts/php-security-update.sh
sudo bash php-security-update.sh --check /var/www/app1 /var/www/app2   # только отчёт, ничего не меняет
sudo bash php-security-update.sh         /var/www/app1 /var/www/app2   # патч
```

Аргументы — корни Laravel-приложений (каталог с `artisan`). Без аргументов тоже работает: PHP
обновится, FPM/Apache перезагрузятся, воркеры не трогаются.

Боевой запуск — отвязанно от SSH, чтобы обрыв соединения не оставил `dpkg` на полпути:

```bash
sudo setsid nohup bash -c 'WAIT=600 bash php-security-update.sh /var/www/app1 > /root/php2shell.log 2>&1; echo $? > /root/php2shell.exit' >/dev/null 2>&1 &
tail -f /root/php2shell.log
```

Код выхода `0` означает: все установленные ветки PHP исправлены (или бэкпортированы) **и** ни один
процесс не держит старый бинарник PHP. Иначе `1` с причиной в выводе.

## Что делает скрипт

1. **Инвентаризация.** Находит все установленные ветки PHP (`php8.2-common`, `php8.3-common`, Remi
   `php82-php-common`, …), печатает установленную и доступную версии и статус: `fixed` (версия ≥
   исправленной), `backport` (номер старый, но CVE есть в changelog пакета) или `VULNERABLE`.
   Предупреждает о пакетах на hold.
2. **Обновление только PHP-пакетов.** `apt-get install --only-upgrade` / `dnf upgrade` для установленных
   пакетов, собранных из исходника `php8.x` (`php8.x-common/-cli/-fpm/-mysql/…`, `libapache2-mod-php8.x`,
   RPM `php-*` / `php8x-php-*`). Ваши `php.ini` и пулы сохраняются (`--force-confold`).
   PECL-расширения (`php8.x-redis`, `-igbinary`, `-xdebug`, …) и безверсионные мета-пакеты (`php`,
   `php-cli`, `php-redis`, …) не трогаются: они не затронуты, а на ondrej/sury PPA именно их
   мета-пакеты тянут следующую ветку PHP (`php-redis` → `php8.4-redis` → `php8.4-cli`, и `/usr/bin/php`
   переключается на 8.4). На apt обновление сначала симулируется, и скрипт **отказывается работать,
   если установился бы хоть один новый PHP-пакет**.
3. **Reload PHP-FPM** (`systemctl reload` = USR2: мастер и воркеры перезапускаются на новом бинарнике
   без потери запросов). Перед этим `php-fpm -t`; сломанный конфиг — предупреждение, а не reload.
4. **Полный restart Apache mod_php** (graceful оставляет старый `libphp` в памяти). Только после
   `apachectl configtest`.
5. **Мягкий перезапуск Laravel.** Для каждого приложения от его пользователя: `queue:restart`,
   `horizon:terminate`, `pulse:restart`, `reverb:restart` — те, что есть. Воркеры дорабатывают текущую
   задачу и выходят; supervisor/systemd поднимает их на новом PHP.
6. **Ожидание** (по умолчанию 300 с), пока ни один процесс не держит удалённый бинарник/модуль PHP;
   остаток печатается списком.
7. **Проверка**: статус по веткам ещё раз и `php -r 'echo PHP_VERSION;'` для каждого найденного бинарника.

### Чего скрипт не делает никогда

- `apt upgrade` / `dnf upgrade` чего-либо кроме PHP, обновления ядра, reboot.
- Не ставит новую ветку PHP и не трогает безверсионные мета-пакеты (`php`, `php-cli`, `php-fpm`, `phpmyadmin`, …).
- Не меняет код приложений, `.env`, конфиги nginx/Apache, пулы FPM.
- Не запускает `artisan` от root. Если `storage/` принадлежит root — останавливается и просит `APP_USER`,
  вместо того чтобы оставить root-овые файлы кэша и логов (обычный путь от «безобидного» перезапуска к HTTP 500).
- Не делает `kill`. Процессы, пережившие ожидание, печатаются с PID и командной строкой; перезапускаете
  их через их менеджер процессов.
- Не откатывает. Откат возвращает уязвимость.

## Особенности для Laravel

| Тема | Поведение |
|---|---|
| Пользователь для `artisan` | Владелец `storage/logs` (иначе `storage/`). Переопределить: `APP_USER=www-data`. Root — только если задан явно. |
| Бинарник PHP для `artisan` | `PHP_BIN` (по умолчанию `php`). Если не подходит (приложению нужен 8.3, а `php` — 8.1), перебираются все установленные ветки от новой к старой; выбранный печатается. |
| Воркеры очередей | `queue:restart` пишет метку в кэш; воркер выходит после текущей задачи. Нужен рабочий кэш и менеджер процессов (supervisor / systemd `Restart=always`), который поднимет их заново. |
| Horizon | `horizon:terminate`, та же модель. |
| Octane | Не обрабатывается: со Swoole мастер-процесс и есть PHP, `octane:reload` его не меняет. Перезапуск: `supervisorctl restart octane`. Шаг ожидания будет показывать его как процесс на старом PHP, пока вы это не сделаете. |
| Планировщик (cron) | Ничего не нужно: каждый `schedule:run` — новый процесс. |
| Несколько версий PHP на хосте | Один запуск обновляет все ветки. `PHP_BIN` указывайте только если автоопределение выбрало не то. |
| OPcache / закэшированный конфиг | Живёт в процессах FPM, reload его сбрасывает. `bootstrap/cache` — обычный PHP, патч-релиз его не ломает. |

## Как читать вывод

```
==> PHP branches
    php8.3-common            branch 8.3  installed 8.3.35    VULNERABLE -> update available: 8.3.36-1+ubuntu24.04.1+deb.sury.org+1
    php8.1-common            branch 8.1  installed 8.1.2     backport (EOL branch: only distro backports, plan an upgrade)
```

| Сообщение | Что значит / что делать |
|---|---|
| `fix is not in your repositories yet; nothing changed` | Зеркало или вендор отстают. Ничего не тронуто. Примените [митигацию](#фикса-ещё-нет) и повторите позже. |
| `upgrade would INSTALL new PHP packages` | Мета-пакет тянет другую ветку PHP. Скрипт остановился. Смотрите `apt-get -s install --only-upgrade …`; обычно помогает hold/удаление безверсионных `php*` мета-пакетов. |
| `still running old PHP after …` + PID | Octane, свои демоны, воркер, запущенный руками. Перезапустить через supervisor/systemd, затем `--check`. |
| `reload of php8.3-fpm failed` / `-t failed` | Проблема в конфиге пула. `journalctl -u php8.3-fpm`, `php-fpm8.3 -t`. FPM продолжает работать на старом бинарнике. |
| `storage/ is owned by root` | Повторить для этого приложения с `APP_USER=<веб-пользователь>`. |
| `artisan failed … with every PHP binary tried` | Нет `.env`, нет `vendor/`, неверный `APP_USER`. Воркеры не перезапущены; исправить и повторить. |
| `another run is in progress` | Дождаться первого запуска (лок в `/run`). |

## Docker

PHP в контейнере не патчится на месте — только пересборкой. Закрепите базовый образ на исправленном теге
(`php:8.3.36-fpm`, `php:8.2.35-fpm-alpine`, …), `docker compose build --pull && docker compose up -d`,
затем проверьте внутри: `docker exec <c> php -r 'echo PHP_VERSION;'`. Производные образы (`wordpress`,
`drupal`, FrankenPHP) обновляются позже официального `php:`; проверяйте версию внутри, а не тег.

## Фикса ещё нет

Команда PHP прямо говорит, что настройки **не делают установку безопасной**, а лишь снижают
экспозицию. Пока пакета нет, примените то, что безопасно почти для любого приложения:

```ini
; /etc/php/8.x/fpm/conf.d/99-php2shell.ini  (и apache2/conf.d для mod_php)
session.upload_progress.enabled = 0
; только PHP 8.5:
; fatal_error_backtraces = 0
```

затем `systemctl reload php8.x-fpm` (mod_php: `apachectl configtest && systemctl restart apache2`).
Advisory также называет `memory_limit = -1` через `php_admin_value` и маленький `post_max_size`
(`8M`, или `32M` с загрузками) основной митигацией для CVE-2026-109618. Это меняет поведение памяти
и загрузок — решайте по каждому приложению. Не используйте `RLIMIT_AS` / `RLIMIT_DATA`: они сами
приводят на уязвимый путь. Патчите, как только пакет появится.

## Скилл для Claude Code

`SKILL.md` — ранбук для агента с shell-доступом к серверу (SSH или Claude Code прямо на хосте).
Покрывает то, что скрипт намеренно оставляет человеку: порядок по флоту (сначала канарейка),
проверка на компрометацию до патча (дети FPM-воркеров, новые `.php` в `public/`, cron веб-пользователя),
бэкап конфигов, базовая линия здоровья через `curl --resolve`, правила эскалации (cPanel/Plesk/CloudLinux/
LiteSpeed, PHP ≤ 8.1 без фикса от вендора, мало места, сломанный dpkg), пост-проверки и YAML-отчёт по хосту.

```bash
git clone https://github.com/aidbull/php2shell-patch ~/.claude/skills/php2shell-patch
# затем в Claude Code: /php2shell-patch  и назвать хост(ы)
```

## Поддерживаемые платформы

- Debian / Ubuntu с `apt`: пакеты дистрибутива, [ondrej/php PPA](https://launchpad.net/~ondrej/+archive/ubuntu/php), packages.sury.org.
- RHEL / AlmaLinux / Rocky / Fedora с `dnf`: модули AppStream, [Remi](https://rpms.remirepo.net/) (`php-*` и SCL `php8x-php-*`).
- PHP-FPM под systemd, Apache с mod_php, Laravel 9–12 с воркерами под supervisor/systemd.

Не поддерживается (скилл эскалирует человеку): cPanel/EasyApache, Plesk, CloudLinux alt-php, LiteSpeed `lsphp`,
DirectAdmin, FrankenPHP вне Docker, PHP из исходников, Docker-контейнеры (см. выше).

## Порядок по флоту

1. Сначала `--check` везде: он read-only и покажет, где фикс уже стоит.
2. Канарейка (staging или наименее важный прод). Несколько минут смотреть логи.
3. Потом internet-facing хосты, потом внутренние. За балансировщиком — по одному.
4. После каждого хоста: снова `--check`, `systemctl --failed`, `supervisorctl status`, health-URL.

## Участие

Issues и PR приветствуются, особенно: имена пакетов у вендоров, панели, менеджеры воркеров не для Laravel.
Скрипт должен оставаться `shellcheck`-чистым и без зависимостей (bash, coreutils, apt/dnf, systemd).

MIT, см. [LICENSE](LICENSE).
