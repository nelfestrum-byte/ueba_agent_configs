# UEBA Agent Bundle (offline, Debian 12)

Самодостаточный набор для развёртывания UEBA-агентов на хостах **Debian 12 (bookworm)** без доступа в интернет одним плейбуком Ansible.

Устанавливает и настраивает:

- **osquery 5.22.1** — телеметрия процессов, портов, сокетов, модулей ядра, cron, SSH-ключей и т.д.
- **fluent-bit 5.0.4** — сбор логов osquery / auditd / sshd и отправка в Logstash по TCP.
- **auditd 3.0.9** + audispd-plugins — расширенные правила аудита для аналитики ИБ.

## Структура

```
_offline-bundle/
├── ansible.cfg
├── inventory.ini              # список целевых хостов
├── deploy.yml                 # единый плейбук
├── group_vars/all.yml         # logstash_host и пр.
├── files/
│   ├── packages/              # .deb-пакеты (38 файлов, ~100 MB)
│   ├── osquery/osquery.conf
│   ├── fluent-bit/{fluent-bit.conf,parsers.conf,flatten.lua}
│   └── auditd/audit.rules
└── README.md
```

## Содержимое `files/packages/`

Полный транзитивный набор зависимостей для чистой `debian:12-slim`:

- `osquery_5.22.1-1.linux_amd64.deb`
- `fluent-bit_5.0.4_amd64.deb`
- `auditd`, `audispd-plugins`, `libauparse0`
- криптостек: `libssl3`, `libgnutls30`, `libnettle8`, `libhogweed6`, `libgmp10`, `libtasn1-6`, `libp11-kit0`, `libffi8`, `libidn2-0`, `libunistring2`, `libcom-err2`, `libkrb5-3`, `libkrb5support0`, `libk5crypto3`, `libgssapi-krb5-2`, `libkeyutils1`
- сетевой стек: `libcurl4`, `libcurl3-gnutls`, `libldap-2.5-0`, `libssh2-1`, `libnghttp2-14`, `libpsl5`, `librtmp1`, `libbrotli1`
- SASL: `libsasl2-2`, `libsasl2-modules`, `libsasl2-modules-db`
- прочее: `libpq5`, `libwrap0`, `libyaml-0-2`, `libnsl2`, `libtirpc3`, `libtirpc-common`

Если на целевых хостах базовая Debian 12 уже содержит часть библиотек — лишние пакеты просто не переустановятся (apt установит из локальных файлов только нужное).

## Запуск

1. Скопируйте каталог `_offline-bundle/` на машину с установленным Ansible (control node), у которой есть SSH-доступ к целевым хостам.

2. Заполните `inventory.ini` адресами хостов и `group_vars/all.yml` — `logstash_host`.

3. Запустите:

   ```bash
   cd _offline-bundle
   ansible-playbook deploy.yml
   ```

   Если sudo с паролем: добавьте `--ask-become-pass`.

## Что делает плейбук

1. Проверяет, что хост — Debian 12.
2. Копирует все `.deb` в `/opt/ueba-bundle/packages/` на целевом хосте.
3. Ставит пакеты через `apt deb=...` (offline — apt сам выберет порядок зависимостей внутри переданного набора).
4. Кладёт конфиги:
   - `/etc/audit/rules.d/ueba.rules`
   - `/etc/osquery/osquery.conf`
   - `/etc/fluent-bit/{fluent-bit.conf,parsers.conf,flatten.lua}`
   - `/etc/default/fluent-bit` — `LOGSTASH_HOST`, `HOSTNAME`
   - systemd drop-in для подгрузки `EnvironmentFile` в fluent-bit.
5. Проверяет конфиги (`osqueryd --config_check`, `fluent-bit --dry-run`).
6. Включает и стартует `auditd`, `osqueryd`, `fluent-bit`.

## auditd — что добавлено сверх исходных правил

Сверх изначального файла добавлено покрытие типичных для UEBA событий:

- privileged-команды (`su`, `sudo`, `passwd`, `chage`, `usermod`, `useradd`, `userdel`, `groupadd`, `visudo`, `chsh`, `gpasswd`, `newgrp`)
- ssh-конфиг (`/etc/ssh/sshd_config*`)
- cron.allow/cron.deny + cron.hourly/.weekly/.monthly + systemd-юниты (`/etc/systemd/`, `/lib/systemd/system/`, `/usr/lib/systemd/system/`) + `init.d`/`rc.local`
- сеть/DNS: `sethostname`/`setdomainname`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/network/`, `/etc/netplan/`, iptables/nftables/ufw
- модули и параметры ядра: `/etc/modules*`, `/etc/sysctl.conf`, `/etc/sysctl.d/`
- file integrity: chmod/chown/fchmod/fchown/lchown, unlink/rename (только для AUID≥1000), setxattr/removexattr
- ptrace, mount/umount, chroot/pivot_root (с прицелом на container-escape)
- изменения системного времени (adjtimex/settimeofday/clock_settime), `/etc/localtime`, `/etc/timezone`
- целостность журналов входов: `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`
- целостность самого аудита: `/etc/audit/`, `/etc/audisp/`, `/var/log/audit/`, бинари `auditctl`/`auditd`
- MAC: AppArmor/SELinux каталоги
- shell-конфиги: `/etc/bash.bashrc`, `/etc/profile`, `/etc/profile.d/`, `/etc/shells`, `/etc/environment`, `/etc/skel/`
- supply-chain пакетного менеджера: `/etc/apt/`, `/etc/dpkg/`
- буфер увеличен с 8192 до 16384, добавлены `never,exit` для самого `auditd`, чтобы не зацикливать

В проде рекомендуется раскомментировать `-e 2` (immutable mode) в конце правил.

## Логика подбора пакетов

`.deb`-файлы получены так: запущен временный `debian:12-slim` контейнер, в нём добавлены официальные репозитории osquery и fluent-bit, выполнен `apt-get install --download-only --reinstall --no-install-recommends osquery fluent-bit auditd audispd-plugins ...` со всеми ключевыми библиотеками, скачанные `.deb` извлечены через `docker cp`. Это даёт минимально достаточный набор для чистой Debian 12.

## Известные ограничения

- Если у вас Debian 11/13 — версии библиотек не совпадут; нужно пересобрать bundle для соответствующего релиза.
- Если на целевом хосте установлена другая версия `auditd`/`fluent-bit`/`osquery` — задача `apt deb=...` обновит/откатит её до версии из bundle. Файлы конфигов перезапишутся.
- fluent-bit ходит по TCP на logstash; убедитесь, что порты 5045/5047/5048 открыты с агента в logstash.
- Плейбук рассчитан на оффлайн: `apt update` нигде не вызывается. Если apt в процессе попытается достучаться в сеть — это значит в bundle не хватает зависимости.
