# README_FOR_AI — Справочник по данным для AI-агентов

Этот документ предназначен для AI-агентов, использующих данный стенд как основу
для надпроектов — прежде всего **UEBA-системы со скорингом поведения пользователей и сущностей**.

Содержит точные описания: какие данные собираются, в каком формате хранятся,
какие ECS-поля гарантированы, и как интерпретировать каждый тип события.

**Версия стенда:** 0.9. История изменений и человеко-читаемое описание возможностей: [docs/RELEASE_NOTES_0.9.md](docs/RELEASE_NOTES_0.9.md).

---

## 1. Назначение стенда в UEBA-контексте

Стенд собирает сырые события безопасности с Linux-хостов и нормализует их в **ECS 8.11**.
Нормализованные события — входные данные для UEBA-скоринга:

- **Базовые линии**: osquery diff позволяет строить baseline (типичные процессы, соединения, пользователи)
- **Аномалии**: auditd execve + syscall-трассировка — основа для детектирования аномального поведения
- **Идентичность**: user.id / user.name сквозные через все источники (auditd auid, osquery uid)
- **Граф сущностей**: host.name + process.pid + user.name + destination.ip → граф для UEBA

---

## 2. Архитектура пайплайна (с точки зрения данных)

```
Источник   Транспорт              Хранилище
────────────────────────────────────────────────────────────────
auditd     fluent-bit TCP 5045    fluent-audit-YYYY.MM.dd
osquery    fluent-bit TCP 5047    fluent-osquery-YYYY.MM.dd
```

Все события проходят через **Logstash** (маршрутизация + type-cast) до записи в OpenSearch.

---

## 3. Источник: auditd (индекс `fluent-audit-*`)

### 3.1 Что собирается

auditd перехватывает системные вызовы на уровне ядра. Правила в `agents/configs/auditd/audit.rules`:
- **execve / execveat** — запуск любого процесса (кроме системных путей)
- **sudo / su** — привилегированное выполнение (USER_CMD, USER_AUTH)
- **setuid / setreuid / setresuid** — смена UID (privilege escalation)
- **connect / bind / accept** — сетевые соединения
- **openat / open / creat** — открытие файлов в критичных директориях
- **unlink / unlinkat** — удаление файлов
- **SSH auth events** — USER_LOGIN, USER_LOGOUT, LOGIN
- **io_uring_setup** — инициализация io_uring ring (RingReaper-class bypass; auid≥1000)
- **ptrace / process_vm_readv / process_vm_writev** — process injection (T1055; auid≥1000)
- **memfd_create** — fileless execution через анонимный fd (T1620; auid≥1000)
- **bpf** — загрузка eBPF-программы (rootkit/backdoor вектор; auid≥1000; whitelist osqueryd потребуется при включении P2-01)
- **Tier A (P1-01): anti-forensics + persistence + container escape** — watch на `/var/log/audit/`, `/etc/ld.so.preload`, `/etc/ld.so.conf*`; syscalls: `reboot`, `acct`, `utimensat/utimes/futimesat` (timestomp), `unshare/setns/pivot_root` (container escape), `mount/umount2/move_mount/...` (mount-based escape), `kexec_file_load/kexec_load` (kernel hot-replace), `userfaultfd` (exploitation primitive), `socket a0=38` (AF_ALG crypto bypass), `swapon/swapoff`
- **Tier B (P1-01): extended persistence + network config + package mgmt** — watch на env, MAC-политики (selinux/apparmor), shell-профили, init/rc.local, fstab, udev, apt/dnf/yum, firewall (nftables/iptables), /etc/ssh (только sshd_config), SSSD/LDAP/Kerberos, polkit, issue; syscalls: `sethostname/setdomainname`, `mknod/mknodat`

### 3.2 Обработка в fluent-bit

1. **auditd_merge.lua** — объединяет строки одного события по `serial` number.
   auditd пишет одно событие несколькими строками (SYSCALL + EXECVE + PATH + CWD).
   Merge флашит по timeout (~2 сек wall clock), **не** по EOE (auditd 4.x EOE не пишет в лог).

2. **auditd_enrich.lua** — нормализует объединённую запись в ECS:
   - syscall number → имя (`SYSCALLS` таблица, x86_64)
   - `event.category`, `event.type`, `event.action` по типу события
   - `process.*` из полей pid/ppid/comm/exe/proctitle/_execve_args; `process.parent.name` и `process.parent.command_line` из кэшей `pid→name`/`pid→cmdline` или `/proc/<ppid>/comm` и `/proc/<ppid>/cmdline`
   - `user.id` из uid, `user.effective.id` из auid (login UID — реальный пользователь до sudo)
   - `source.*` / `destination.*` из SOCKADDR-записей auditd (decode_saddr: AF_INET / AF_INET6)
   - `file.*` из PATH-записей auditd
   - `event.outcome`: success / failure из syscall_success

3. **proc_common.lua** — общий модуль (импортируется всеми тремя enrich-скриптами):
   - `short_id()` — FNV-1a 64-bit → 16 hex символов (для entity_id и session.id)
   - `/proc/<pid>/stat` чтение и кэш `pid → start_time` (epoch seconds)
   - `/proc/<pid>/comm`, `/proc/<pid>/cmdline` чтение и кэши имён/cmdline
   - `/proc/<pid>/sessionid` чтение для `user.session.id`
   - `to_iso(ts)` — конвертирует epoch seconds → ISO 8601 строку (тип `date` в OpenSearch)

### 3.3 Гарантированные ECS-поля

| Поле | Тип | Условие | Описание |
|------|-----|---------|---------|
| `ecs.version` | keyword | всегда | `"8.11"` |
| `event.kind` | keyword | всегда | `"event"` |
| `event.dataset` | keyword | всегда | `"auditd"` |
| `event.module` | keyword | всегда | `"auditd"` |
| `event.category` | keyword | всегда | process / network / file / authentication / iam |
| `event.type` | keyword | всегда | start / end / access / deletion / creation / change / info |
| `event.action` | keyword | при syscall | имя syscall (execve, connect, openat, ...) |
| `event.outcome` | keyword | при наличии | success / failure |
| `host.name` | keyword | всегда | FQDN агентского хоста |
| `host.os.type` | keyword | всегда | `"linux"` |
| `host.os.family` | keyword | всегда | `"linux"` |
| `process.pid` | integer | при syscall | PID процесса |
| `process.parent.pid` | integer | при syscall | PPID |
| `process.parent.name` | keyword | если ppid жив или в кэше | Имя родительского процесса (comm, max 15 символов). Из кэша `pid→name`, при miss — из `/proc/<ppid>/comm`. Отсутствует если родитель завершился до enrich и не попал в кэш. |
| `process.parent.command_line` | keyword | если ppid жив или в кэше | Командная строка родителя. Из кэша `pid→cmdline`, при miss — из `/proc/<ppid>/cmdline`. |
| `process.entity_id` | keyword | если pid > 0 | Стабильный ID процесса: FNV-1a hash(host.name:pid:start_time), 16 hex. Одинаков для всех событий одного процесса; переключается при PID reuse. Источник: `/proc/<pid>/stat` field 22 + btime. |
| `process.parent.entity_id` | keyword | если ppid резолвирован | ID родительского процесса. Может отсутствовать сразу после рестарта fluent-bit пока родитель не появится в `/proc` или кэше. |
| `process.start` | date | если pid > 0 | Время старта процесса, ISO 8601. Вычисляется как btime + floor(starttime_ticks / CLK_TCK), конвертируется в ISO строку через `to_iso()`. Совпадает по значению с `osquery.processes.start_time`. |
| `process.parent.start` | date | если ppid резолвирован | Время старта родительского процесса, ISO 8601. Из кэша или `/proc/<ppid>/stat`. |
| `process.name` | keyword | при syscall | имя процесса (comm) |
| `process.executable` | keyword | при syscall | полный путь (exe) |
| `process.title` | keyword | при syscall | Сырой proctitle (полная командная строка из `/proc/<pid>/comm`-поля auditd PROCTITLE). |
| `process.command_line` | keyword | при execve или proctitle | Нормализованная командная строка: preferably из EXECVE-аргументов, иначе proctitle. |
| `process.args` | keyword[] | при execve | аргументы (массив) |
| `process.args_count` | integer | при execve | количество аргументов |
| `process.working_directory` | keyword | при CWD | рабочая директория |
| `labels.entity_id_source` | keyword | при fallback | `event_timestamp_fallback` — процесс исчез из `/proc` до enrich (exit-событие короткоживущего); entity_id такого события **не совпадёт** с osquery. |
| `user.id` | keyword | всегда | UID процесса (uid из auditd) |
| `user.name` | keyword | если известен | Имя пользователя, соответствующее `user.id` (из поля auditd `uid_name`). Для PAM/sudo событий — имя вызывающего процесса, **не** target. |
| `user.target.name` | keyword | при PAM/sudo | Целевая учётная запись (`acct` / `user_acct` / `cred_*_acct` поле auditd). `"root"` при `sudo`, имя пользователя при прямом логине. |
| `user.effective.id` | keyword | если auid ≠ -1 | Login UID (auid) — реальный пользователь до sudo. При `sudo cmd` process uid=0, auid = залогинившийся. |
| `user.effective.name` | keyword | если известен | имя login-пользователя |
| `source.ip` | ip | при accept/accept4 | IP подключившегося клиента (из SOCKADDR-записи auditd, AF_INET/AF_INET6). |
| `source.port` | integer | при accept/accept4 | Порт подключившегося клиента. |
| `destination.ip` | ip | при connect/bind | IP назначения или адрес привязки. |
| `destination.port` | integer | при connect/bind | Порт назначения или bind-порт. |
| `network.type` | keyword | при сетевых syscall | `"ipv4"` / `"ipv6"` — определяется из SOCKADDR family (AF_INET=2, AF_INET6=10). |
| `file.path` | keyword | при PATH | полный путь файла |
| `file.name` | keyword | при PATH | имя файла |
| `file.extension` | keyword | при PATH | Расширение файла (из имени, после последней точки). |
| `file.mode` | keyword | при PATH | права (rwxr-xr-x) |
| `file.inode` | keyword | при PATH | inode файла |
| `file.device` | keyword | при PATH | номер устройства |
| `file.uid` | keyword | при PATH | UID владельца файла (ouid из auditd) |
| `file.gid` | keyword | при PATH | GID владельца файла (ogid из auditd) |
| `auditd.paths` | keyword[] | при > 1 PATH записи | Список всех путей из PATH-записей события (например, rename: source + destination). |
| `auditd.data.syscall` | keyword | при SYSCALL | имя syscall |
| `auditd.session` | integer | если ses > 0 | номер сессии auditd |
| `user.session.id` | keyword | если ses > 0 и ses ≠ 0xFFFFFFFF | Стабильный ID сессии: FNV-1a hash(host.name:btime:ses), 16 hex. Одинаков для всех событий одной пользовательской сессии (auditd + osquery). Переключается при новом логине. |
| `tags` | keyword[] | всегда | `["auditd","security","linux"]` |
| `@timestamp` | date | всегда | время события |

### 3.4 Типичные event.action значения для UEBA

| action | Сценарий UEBA |
|--------|--------------|
| `execve` | Базовая линия процессов; аномальный execve → подозрение |
| `execveat` | Запуск процесса через fd (memfd + execveat = fileless без memfd_create отдельно) |
| `connect` | Граф сетевых соединений; новый destination → скоринг |
| `setuid` | Privilege escalation; редко в baseline → высокий скор |
| `openat` | Доступ к чувствительным файлам (/etc/passwd, ~/.ssh/) |
| `unlink` | Удаление файлов; anti-forensics паттерн |
| `memfd_create` | Fileless execution; в baseline почти нет → высокий скор |
| `ptrace` | Process injection; редко вне debugger'ов → подозрение |
| `process_vm_readv` | Чтение чужой памяти; дамп credentials из памяти процесса |
| `process_vm_writev` | Memory injection; критичный сигнал |
| `bpf` | Загрузка eBPF-программы; rootkit-индикатор |
| `io_uring_setup` | Использование io_uring; редко на prod-серверах → flag |
| `sudo` / `privilege_use` | Выполнение с повышенными правами |
| `mount_action` (mount/move_mount/...) | Mount-based escape: монтирование поверх /etc или /proc — container escape сигнал |
| `container_escape` (unshare/setns/pivot_root) | Namespace escape / pivot root: выход из контейнера или создание нового namespace |
| `preload_inject` | Запись /etc/ld.so.preload — классическая LD_PRELOAD persistence |
| `pkg_mgmt_change` | Изменение apt/dnf/yum репозиториев — supply-chain вектор |
| `firewall_change` | Изменение nftables/iptables — попытка открыть/закрыть порты скрытно |
| `timestomp` (utimensat/utimes/futimesat) | Подмена mtime/atime файлов — T1070.006 anti-forensics |
| `kexec_hot_replace` | kexec_file_load/kexec_load — горячая замена ядра |
| `audit_log_tamper` | Запись в /var/log/audit/ — попытка затереть audit-логи |

---

## 4. Источник: osquery (индекс `fluent-osquery-*`)

### 4.1 Принцип работы (diff-режим)

osquery работает в **differential mode**: каждые N секунд выполняет SQL-запрос к системным таблицам.
Если результат изменился — пишет события `action: "added"` (новая строка) или `action: "removed"` (исчезла).

Это делает osquery идеальным для детектирования изменений состояния системы,
а не потока syscall (auditd). Вместе они дают полную картину.

### 4.2 Обработка в fluent-bit

**osquery_enrich.lua** читает `osqueryd.results.log` (JSON Lines) и:
- Маппирует `name` запроса на `event.category` / `event.action` / `event.type`
- Копирует все `columns.*` → `osquery.<column>` (flat namespace)
- Добавляет ECS `process.*`, `user.*`, `network.*`, `file.*` для релевантных запросов
- Импортирует `proc_common.lua` для entity_id, session.id и кэшей

### 4.3 Запросы osquery и их ECS-маппинг

#### `processes` (интервал: 30 сек)
Мониторинг запущенных процессов. Фильтр: исключает системные бинари (`/usr/`, `/bin/`, `/sbin/`).

```sql
SELECT p.pid, p.name, p.path, p.cmdline, p.uid, p.parent, u.username,
       parent_name, hostname FROM processes p LEFT JOIN users u ...
WHERE p.path NOT LIKE '/usr/%' AND p.path NOT LIKE '/bin/%' ...
```

- `action: added` → `event.action: process_started` → новый нестандартный процесс
- `action: removed` → `event.action: process_stopped`
- ECS: `process.pid`, `process.parent.pid`, `process.name`, `process.executable`, `process.command_line`, `user.name`, `user.id`
- **UEBA**: базовая линия процессов; появление нового path — сигнал

#### `listening_ports` (интервал: 60 сек)
Открытые сетевые порты, привязанные к ним процессы и владельцы процессов.

```sql
SELECT l.pid, p.name AS process_name, l.port, l.protocol, l.address,
       p.uid, u.username,
       (SELECT hostname FROM system_info) AS hostname
FROM listening_ports l
LEFT JOIN processes p ON l.pid = p.pid
LEFT JOIN users u ON p.uid = u.uid
```

- `action: added` → `event.action: port_listening` → новый прослушивающий порт
- ECS: `destination.port`, `destination.ip`, `network.transport`, `network.iana_number`, `process.pid`, `process.name`, `process.entity_id`, `user.name`, `user.id`
- **UEBA**: появление нового порта у хоста — потенциальный backdoor / lateral movement; `user.name` позволяет связать порт с конкретным пользователем

#### `process_connections` (интервал: 30 сек)
Активные сетевые соединения процессов (только с внешними IP, без loopback).

```sql
SELECT pos.pid, pos.remote_address, pos.remote_port, pos.local_address, pos.local_port,
       pos.protocol, pos.state, p.name, p.path, u.username, hostname
FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid
WHERE pos.remote_address NOT IN ('0.0.0.0', '::', '127.0.0.1', '::1')
```

- `action: added` → `event.action: network_connection`
- ECS: `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport`, `network.iana_number`, `process.*`, `user.name`
- **UEBA**: граф process→IP; новый destination для процесса → аномалия

#### `logged_in_users` (интервал: 30 сек)
Активные сессии (wtmp, pts, tty).

- `action: added` → `event.action: user_login`
- `action: removed` → `event.action: user_logout`
- ECS: `user.name`, `source.ip` (host колонка), `event.category: authentication`
- **UEBA**: временной паттерн логинов; нетипичное время → скоринг

#### `users` (интервал: 120 сек)
Список системных пользователей (`/etc/passwd`).

- `action: added` → `event.action: user_created` → новый пользователь в системе
- `action: removed` → `event.action: user_deleted`
- ECS: `user.id`, `user.name`, `event.category: iam`
- **UEBA**: создание пользователя вне change management → высокий скор

#### `ssh_authorized_keys` (интервал: 60 сек)
SSH authorized_keys всех пользователей.

- `action: added` → `event.action: ssh_key_added`
- ECS: `user.name`, `user.id`, `file.path` (key_file), `event.category: iam`
- **UEBA**: добавление нового SSH-ключа — критичное событие

#### `kernel_modules` (интервал: 60 сек)
Загруженные модули ядра.

- `action: added` → `event.action: kernel_module_loaded`
- `action: removed` → `event.action: kernel_module_unloaded`
- **UEBA**: нестандартный модуль — rootkit-индикатор

#### `services` (интервал: 60 сек)
Системные сервисы (systemd).

- `action: added/removed` → `event.action: service_modified`
- `event.category: configuration`
- **UEBA**: новый сервис → persistence механизм

#### `crontabs` (интервал: 60 сек)
Cron-задачи (system + user crontabs) с привязкой к пользователю.

```sql
-- username: для /var/spool/cron/crontabs/<user> — извлекается из path; для /etc/cron.d/ — 'root'
-- uid: subquery к таблице users по username
```

- `action: added` → `event.action: cron_modified`
- ECS: `user.name`, `user.id` (через path-экстракцию + JOIN users)
- **UEBA**: новая cron-задача → persistence; `user.name` позволяет атрибутировать задачу конкретному пользователю

#### `sudoers` (интервал: 120 сек)
Правила `/etc/sudoers`.

- `action: added/removed` → `event.action: sudoers_modified`
- **UEBA**: изменение sudoers → privilege escalation подготовка

#### `user_groups` (интервал: 120 сек)
Членство пользователей в группах.

- `action: added` → `event.action: user_group_modified`
- **UEBA**: добавление в sudo/docker/adm группу → эскалация

#### `groups` (интервал: 120 сек)
Список системных групп.

- `event.action: group_modified`

#### `suid_bins` (интервал: 3600 сек)
Бинари с SUID-битом.

- `action: added` → `event.action: suid_binary_added`
- **UEBA**: новый SUID-бинарь → privilege escalation вектор

#### `startup_items` (интервал: 300 сек)
Автозагрузка (systemd + init).

- `event.action: startup_item_modified`
- **UEBA**: persistence через autostart

#### `mounts` (интервал: 120 сек)
Смонтированные файловые системы (без виртуальных).

- `action: added` → `event.action: mount_added`
- **UEBA**: нестандартный mount — боковое перемещение данных

#### `iptables` (интервал: 300 сек)
Правила netfilter.

- `event.action: firewall_rule_added / firewall_rule_removed`
- **UEBA**: изменение firewall → подготовка к exfiltration

#### `routes` (интервал: 120 сек)
Таблица маршрутизации (без local/broadcast).

- `event.action: route_added / route_removed`

#### `arp_cache` (интервал: 60 сек)
ARP-таблица (без loopback).

- `event.action: arp_entry_added / arp_entry_removed`
- **UEBA**: новый MAC в сети → обнаружение хоста / ARP-spoofing

#### `dns_resolvers` (интервал: 120 сек)
Настройки DNS (`/etc/resolv.conf`).

- `event.action: dns_resolver_modified`
- **UEBA**: смена DNS → потенциальный hijack

#### `usb_devices` (интервал: 30 сек)
Подключённые USB-устройства.

- `action: added` → `event.action: usb_connected`
- **UEBA**: USB-носитель → DLP-событие

#### `pci_devices` (интервал: 300 сек)
PCI-устройства (базовый инвентарь, редко меняется).

#### `process_open_files` (интервал: 60 сек)
Открытые файлы нестандартных процессов (без /proc, /dev, /sys, /usr).

- `action: added` → `event.action: file_opened`
- ECS: `file.path`, `file.name`, `process.*`, `user.name`
- **UEBA**: нестандартный процесс читает sensitive-файлы

#### `certificates` (интервал: 3600 сек)
CA и self-signed сертификаты из системного хранилища.

- `action: added` → `event.action: certificate_added`
- **UEBA**: добавление нового CA → MitM подготовка

---

### 4.3-P2 Запросы P2-02 (добавлены 2026-05-21)

#### `shell_history` (интервал: 300 сек, профиль: both)

```sql
SELECT uid, username, command, history_file FROM shell_history;
```

- `removed: false` — только `action: added` (новые строки истории)
- `event.action: shell_command`, `event.category: process`, `event.type: info`
- `event.dataset: osquery.shell_history`
- ECS: `process.command_line` (command), `file.path` (history_file), `user.name`, `user.id`
- **UEBA**: последовательности команд — основа скоринга по поведению CLI; отклонения от baseline → сигнал

#### `last_logins` (интервал: 300 сек, профиль: both)

```sql
SELECT username, tty, host AS source_host, time, type FROM last WHERE type IN (7,8);
```

- `event.dataset: osquery.last`
- `type=7` → `event.action: user_login`, `event.type: start`
- `type=8` → `event.action: user_logout`, `event.type: end`
- ECS: `user.name`, `source.ip` (source_host), `user.terminal` (tty)
- **UEBA**: кросс-сверка с auditd USER_LOGIN; выявление сессий без auditd-записи

#### `preload_envs` (интервал: 60 сек, профиль: both)

```sql
SELECT pe.pid, pe.key, pe.value, p.name, p.path, p.cmdline
FROM process_envs pe JOIN processes p ON p.pid = pe.pid
WHERE pe.key IN ('LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH') AND pe.value != '';
```

- `event.action: preload_env_set`, `event.category: process`
- `event.dataset: osquery.process_envs`
- ECS: `process.pid`, `process.name`, `process.executable`, `process.command_line`, `process.env.key`, `process.env.value`
- **УЯЗВИМОСТЬ**: без WHERE-фильтра → десятки тысяч строк/ч. Фильтр обязателен.
- **UEBA**: ненулевой LD_PRELOAD у нестандартного бинаря → preload injection

#### `python_packages_diff` / `npm_packages_diff` / `pip_packages_diff` (интервал: 7200 сек, профиль: both)

```sql
SELECT name, version, path FROM python_packages;  -- аналогично npm_packages, pip_packages
```

- `action: added` → `event.action: package_installed`, `event.type: installation`
- `action: removed` → `event.action: package_removed`, `event.type: deletion`
- `event.category: package`
- ECS: `package.name`, `package.version`, `package.path`
- `event.dataset`: `osquery.python_packages` / `osquery.npm_packages` / `osquery.pip_packages`
- **UEBA**: supply-chain — новый пакет вне change management → скоринг; typosquatting-детект по имени

#### `deb_packages_diff` (интервал: 3600 сек, профиль: both)

```sql
SELECT name, version, arch FROM deb_packages;
```

- `event.action: package_installed / package_removed`, `event.category: package`
- `event.dataset: osquery.deb_packages`
- ECS: `package.name`, `package.version`, `package.architecture`
- **UEBA**: неавторизованная установка deb-пакета → риск persistence

#### `kernel_keys_diff` (интервал: 600 сек, профиль: both)

```sql
SELECT * FROM kernel_keys;
```

- Колонки osquery: `serial`, `type`, `description`, `uid`, `gid`
- `event.action: kernel_key_added / kernel_key_removed`, `event.category: iam`
- `event.dataset: osquery.kernel_keys`
- ECS: `user.name` (generic extractor), `user.id`
- **UEBA**: нестандартный ключ в keyring → Kerberos-атака / credential caching

#### `sudoers_diff` (интервал: 1800 сек, профиль: both)

```sql
SELECT * FROM sudoers;
```

- `event.action: sudoers_modified`, `event.category: iam`, `event.type: change`
- `event.dataset: osquery.sudoers`
- **Замечание**: существующий запрос `sudoers` (120 сек) продолжает работать. `sudoers_diff` — более редкий diff с `removed: false` отключённым.
- **UEBA**: изменение sudoers → privilege escalation подготовка

#### `acpi_tables_diff` (интервал: 86400 сек, профиль: both)

```sql
SELECT * FROM acpi_tables;
```

- `event.action: acpi_table_added / acpi_table_removed`, `event.category: host`, `event.type: change`
- `event.dataset: osquery.acpi_tables`
- **UEBA**: низкочастотный детект firmware tamper; изменение ACPI-таблицы → буткит-индикатор

#### `suspicious_mmap` (интервал: 300 сек, профиль: both)

```sql
SELECT pmm.pid, pmm.path, pmm.start, pmm.end, p.name AS process_name
FROM process_memory_map pmm JOIN processes p ON p.pid = pmm.pid
WHERE pmm.path != ''
  AND pmm.path NOT LIKE '/usr/%'
  AND pmm.path NOT LIKE '/lib/%'
  AND pmm.path NOT LIKE '/lib64/%'
  AND pmm.path NOT LIKE '[%';
```

- `event.action: non_standard_mmap`, `event.category: process`, `event.type: info`
- `event.dataset: osquery.process_memory_map`
- ECS: `process.pid`, `process.name`, `file.path` (pmm.path)
- **UEBA**: не-стандартный .so в адресном пространстве → инъекция / reflective loading

#### `chrome_extensions_diff` (интервал: 3600 сек, профиль: workstation only)

```sql
SELECT uid, name, version, identifier, path FROM users CROSS JOIN chrome_extensions USING (uid);
```

- `event.action: extension_installed / extension_removed`, `event.category: configuration`
- `event.dataset: osquery.chrome_extensions`
- ECS: `package.name`, `package.version`, `package.identifier`, `user.id`
- **UEBA**: новое расширение без IT-авторизации → информационный хищник / infostealer

#### `firefox_addons_diff` (интервал: 3600 сек, профиль: workstation only)

```sql
SELECT uid, name, version, identifier, path FROM users CROSS JOIN firefox_addons USING (uid);
```

- `event.action: addon_installed / addon_removed`, `event.category: configuration`
- `event.dataset: osquery.firefox_addons`
- ECS: `package.name`, `package.version`, `package.identifier`, `user.id`
- **UEBA**: аналогично chrome_extensions_diff

---

### 4.4 Гарантированные ECS-поля (все osquery события)

| Поле | Описание |
|------|---------|
| `ecs.version` | `"8.11"` |
| `event.kind` | `"event"` |
| `event.dataset` | `"osquery"` для базовых запросов; специфичный для P2-02 и BPF — см. таблицу event.dataset ниже |
| `event.module` | `"osquery"` |
| `event.category` | process / network / iam / configuration / file / host / authentication / **package** |
| `event.action` | специфично для запроса (см. таблицы выше) |
| `event.type` | start / end / change / creation / deletion / access / info / installation |
| `host.name` | hostname хоста (из `hostname -f`, FQDN) |
| `host.os.type` | `"linux"` |
| `host.os.family` | `"linux"` |
| `process.pid` | PID (для запросов processes, process_connections, process_open_files, listening_ports, preload_envs, suspicious_mmap) |
| `process.entity_id` | Стабильный ID процесса, 16 hex. **Совпадает** с `process.entity_id` в auditd для того же процесса — одинаковая формула FNV-1a(host.name:pid:start_time). Источник start_time: `processes.start_time` (epoch seconds из osquery) или `/proc/<pid>/stat` на cache miss. Только для процессных запросов с PID. |
| `process.parent.entity_id` | ID родительского процесса; отсутствует если родитель не резолвирован. |
| `process.start` | Старт процесса, ISO 8601 строка (через `to_iso()`). Для таблицы `processes` = `to_iso(cols.start_time)`. Для остальных — из кэша или `/proc`. Только для запросов с PID. |
| `process.parent.start` | Старт родительского процесса, ISO 8601. Только для запросов с parent PID. |
| `process.exit_code` | Exit code процесса. Только для `bpf_processes` (из `cols.exit_code`). |
| `user.session.id` | Стабильный ID сессии: FNV-1a hash(host.name:btime:ses), 16 hex. Читается из `/proc/<pid>/sessionid`. Присутствует для запросов: **processes**, **process_connections**, **process_open_files**, **listening_ports**, **logged_in_users** (где доступен PID). Отсутствует для остальных (users, ssh_authorized_keys, crontabs и др.). **Совпадает** с `user.session.id` в auditd для той же сессии. |
| `user.name` | Имя пользователя (для запросов: processes, process_connections, process_open_files, logged_in_users, users, ssh_authorized_keys, user_groups, startup_items, suid_bins, listening_ports, crontabs) |
| `user.id` | UID пользователя (для тех же запросов, где доступен uid) |
| `user.group.id` | GID процесса. Только для `bpf_processes` (из `cols.gid`). |
| `user.terminal` | Имя tty/pts. Только для `last_logins` (из `cols.tty`). |
| `network.transport` | tcp / udp / icmp (из IANA protocol number). Для process_connections и listening_ports. |
| `network.iana_number` | Числовой IANA protocol number (строка). Для process_connections и listening_ports. |
| `osquery.result.name` | имя запроса (processes, listening_ports, ...) |
| `osquery.result.action` | added / removed |
| `osquery.result.host_identifier` | hostname из osquery |
| `osquery.result.unix_time` | unix timestamp события из osquery (числовая строка) |
| `osquery.<column>` | все колонки запроса в flat-namespace |
| `tags` | `["osquery","security","linux"]` |

#### Сводная таблица event.dataset по запросам

| Запрос | event.dataset |
|--------|--------------|
| processes, listening_ports, process_connections, logged_in_users, users, ssh_authorized_keys, kernel_modules, services, crontabs, sudoers, user_groups, groups, suid_bins, startup_items, mounts, iptables, routes, arp_cache, dns_resolvers, usb_devices, pci_devices, process_open_files, certificates, etc_hosts | `"osquery"` |
| shell_history | `"osquery.shell_history"` |
| last_logins | `"osquery.last"` |
| preload_envs | `"osquery.process_envs"` |
| python_packages_diff | `"osquery.python_packages"` |
| npm_packages_diff | `"osquery.npm_packages"` |
| pip_packages_diff | `"osquery.pip_packages"` |
| deb_packages_diff | `"osquery.deb_packages"` |
| kernel_keys_diff | `"osquery.kernel_keys"` |
| sudoers_diff | `"osquery.sudoers"` |
| acpi_tables_diff | `"osquery.acpi_tables"` |
| suspicious_mmap | `"osquery.process_memory_map"` |
| chrome_extensions_diff | `"osquery.chrome_extensions"` |
| firefox_addons_diff | `"osquery.firefox_addons"` |
| bpf_processes | `"osquery.bpf_process_events"` |
| bpf_sockets | `"osquery.bpf_socket_events"` |
| docker_containers | `"osquery.docker_containers"` |

**Namespace'ы P2-02 (присутствуют только для соответствующих запросов):**

| Поле | Запросы |
|------|---------|
| `package.name` | python/npm/pip/deb_packages_diff, chrome_extensions_diff, firefox_addons_diff |
| `package.version` | те же |
| `package.path` | python/npm/pip_packages_diff |
| `package.architecture` | deb_packages_diff |
| `package.identifier` | chrome_extensions_diff, firefox_addons_diff |
| `process.env.key` | preload_envs (LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH) |
| `process.env.value` | preload_envs |

### 4.5 BPF backend — event-driven таблицы (только docker-хосты)

**Требования к хосту:** ядро ≥ 5.10 (рекомендуется ≥ 5.15), `/sys/kernel/btf/vmlinux` (CONFIG_DEBUG_INFO_BTF=y), osquery ≥ 4.6.  
**Toggle:** `osquery_bpf_events_enabled: true` в `agents/deploy/group_vars/docker_hosts.yml`.  
На workstations и servers без контейнеров BPF backend выключен (дефолт false).

#### `bpf_processes` (интервал: 10 сек, event-driven через eBPF)

Каждый `execve` в реальном времени. Поля osquery: `tid, pid, parent, path, cmdline, uid, gid, ntime, exit_code, probe_error, cgroup, cid`.

- `action: added` → `event.action: process_started`, `event.dataset: osquery.bpf_process_events`
- `action: removed` → `event.action: process_stopped`
- ECS: `process.pid`, `process.parent.pid`, `process.executable`, `process.command_line`, `user.id`, `user.group.id`, `process.exit_code`
- `container.id` — резолвится из `/proc/<pid>/cgroup` путём парсинга Docker container ID из cgroup-пути (cgroup v2: `docker-<hex>.scope`, cgroup v1: `/docker/<hex>`). Первые 12 hex символов. Поле `cid` из osquery является cgroup namespace inode (числовой ID) на cgroup v2 хостах и **не используется** для резолвинга.
- `container.name`, `container.image.name`, `container.entity_id` — резолвятся из `container_cache` по `container.id`. Кэш заполняется из `docker_containers` событий. **Если fluent-bit перезапущен** — первые события после рестарта не получат container-атрибуцию до прихода следующего `docker_containers` diff (≤30 сек).
- `process.entity_id`: FNV-1a(host.name:pid:ntime) — ntime является kernel monotonic nanoseconds, поэтому **НЕ совпадает** с auditd/processes (те используют epoch seconds). Known limitation до унификации через P0-01.
- **UEBA**: event-driven (без polling gap); container-aware видимость через `/proc/<pid>/cgroup` lookup

#### `bpf_sockets` (интервал: 10 сек, event-driven через eBPF)

Каждый `connect` / `bind` / `accept`. Поля osquery: `pid, family, protocol, local_address, local_port, remote_address, remote_port, syscall, cid`.

> **Важно:** колонка в osquery называется `syscall` (не `action`) — это системный вызов eBPF-пробы. Enrich-скрипт читает `cols["syscall"] or cols["action"]` для совместимости.

- `event.action: socket_<syscall>` → `socket_connect`, `socket_bind`, `socket_accept`
- `event.dataset: osquery.bpf_socket_events`
- ECS: `process.pid`, `network.type` (ipv4/ipv6 из family AF_INET=2/AF_INET6=10), `network.transport` (tcp/udp из protocol IANA), `source.ip`, `source.port`, `destination.ip`, `destination.port`
- `container.id`, `container.name`, `container.image.name`, `container.entity_id` — резолвятся аналогично bpf_processes через `/proc/<pid>/cgroup` + `container_cache`
- **UEBA**: второй независимый источник сетевых соединений — кросс-верификация с auditd `connect`

#### `docker_containers` (интервал: 30 сек, diff)

Инвентарь запущенных контейнеров. Заполняет `container_cache` для резолвинга в bpf_*.

> **Важно:** фильтрация по `state = 'running'` (машиночитаемый статус), не по `status` (человекочитаемый: "Up 2 hours").

- `action: added` → `event.action: container_started`, `event.dataset: osquery.docker_containers`
- `action: removed` → `event.action: container_stopped`
- ECS: `container.id` (первые 12 hex из `id`), `container.name`, `container.image.name` (ECS 8.x: не `container.image`), `container.runtime: "docker"`
- **ECS-extension:** `container.entity_id = host.name:container.name` — кастомное расширение ECS (аналог `process.entity_id`). Стабильный ключ сущности, переживающий рестарты контейнера. Задокументирован здесь как extension.
- **UEBA**: появление нового контейнера вне baseline → потенциальное shadow deployment

## 5. Сквозные идентификаторы для UEBA

Для построения графа пользователь→хост→процесс→сеть используйте:

| Цель | Поле | Источники |
|------|------|-----------|
| Идентификатор пользователя | `user.id` (UID) | auditd, osquery |
| Имя пользователя | `user.name` | все источники |
| Реальный пользователь (до sudo) | `user.effective.id` | auditd (auid — login UID, сохраняется через sudo) |
| Хост | `host.name` | все источники |
| Сессия пользователя | `user.session.id` | auditd, osquery (processes/connections/files/logged_in_users) — **join корректен**: одинаковая формула FNV-1a(host.name:btime:ses); объединяет все события от логина до выхода |
| Процесс (рекомендуется) | `process.entity_id` | auditd, osquery — **join корректен**: одинаковая формула, одинаковый seed (epoch seconds) |
| Процесс BPF (изолировано) | `process.entity_id` | osquery bpf_processes — **НЕ совпадает** с auditd/processes (seed: ntime в monotonic ns, не epoch) |
| Процесс (устаревший) | `process.pid` + `host.name` | auditd, osquery — ненадёжен при PID reuse |
| Исходный IP (SSH) | `source.ip` | osquery logged_in_users |
| Внешний IP | `destination.ip` | osquery process_connections, auditd connect/bind |
| Команда | `process.command_line` | auditd (execve), osquery processes |
| Контейнер | `container.id` | osquery bpf_processes, bpf_sockets, docker_containers — Docker short ID (12 hex), резолвится из `/proc/<pid>/cgroup` |
| Контейнер (стабильный) | `container.entity_id` | osquery bpf_* и docker_containers — `host.name:container.name`, переживает рестарты контейнера |
| Образ контейнера | `container.image.name` | osquery bpf_* и docker_containers |

> **Кросс-источниковый join по `user.session.id` корректен**: одна формула `FNV-1a(host.name + ":" + btime + ":" + ses)` в обоих enrich-скриптах. Для auditd `ses` берётся из каждого события напрямую; для osquery — из `/proc/<pid>/sessionid`. Поле отсутствует если `ses = 0` (kernel) или `ses = 0xFFFFFFFF` (unset), либо если процесс завершился до enrich osquery, либо для запросов osquery без PID.

> **Кросс-источниковый join auditd ↔ osquery по `process.entity_id` корректен** при условии, что оба enrich-скрипта используют одинаковую формулу: `FNV-1a(host.name + ":" + pid + ":" + start_time)`, где `start_time` берётся из `/proc/<pid>/stat field 22 + btime` (целое число, epoch seconds). Для exit-событий короткоживущих процессов поле `labels.entity_id_source = "event_timestamp_fallback"` сигнализирует, что entity_id в этом документе **не совпадёт** с osquery.

> **BPF process.entity_id исключение**: для таблицы `bpf_processes` seed = `host.name:pid:ntime` (ntime — kernel monotonic nanoseconds, не epoch). Join с auditd/processes по `process.entity_id` для bpf_processes **некорректен**.

---

## 6. Что НЕ входит в текущий стенд

- MITRE ATT&CK аннотация событий (отключена в `auditd_enrich.lua` — теги предназначены для scoring, не для raw-событий)
- GeoIP обогащение (не настроено в Logstash)
- Агрегация / базовые линии (должны строиться на уровне надпроекта)

---

## 7. Файлы, критичные для AI-агентов надпроекта

| Файл | Зачем |
|------|-------|
| `agents/configs/osquery/osquery.conf.j2` | Jinja2-шаблон конфига osquery. Содержит полный список запросов и их SQL — источник schema. BPF-блоки (`bpf_processes`, `bpf_sockets`, `docker_containers`) включаются при `osquery_bpf_events_enabled: true` (группа `[docker_hosts]`). |
| `agents/configs/fluent-bit/scripts/proc_common.lua` | Общая библиотека (shared module): `short_id()` (FNV-1a hash), кэши `pid→start_time/name/cmdline`, `read_proc_start()`, `get_sessionid()`, `make_session_id()`, `to_iso()`. Импортируется всеми тремя enrich-скриптами — изменение меняет behavior во всех пайплайнах. |
| `agents/configs/fluent-bit/scripts/osquery_enrich.lua` | Маппинг запросов → ECS категории/действия; table `QUERY_META` — истина о категоризации всех osquery событий |
| `agents/configs/fluent-bit/scripts/auditd_enrich.lua` | ECS-нормализация auditd, syscall→action маппинг; таблица `SYSCALLS` — истина о поддерживаемых syscall номерах |
| `logstash/configs/pipeline/ueba-main.conf` | Входящие порты, type-cast, индексы |
| `agents/configs/auditd/audit.rules` | Что именно перехватывает auditd (фильтр событий) |
| `opensearch/templates/fluent-audit.json` | Точные типы ECS-полей в auditd-индексе (`wildcard`, `ip`, `date`, `integer`) |
| `opensearch/templates/fluent-osquery.json` | Типы полей osquery-индекса + `osquery.result.*` namespace |

---

## 8. OpenSearch маппинги — что важно для запросов

При построении UEBA-запросов учитывать типы полей из шаблонов (`opensearch/templates/`):

- `source.ip`, `destination.ip`, `related.ip` → тип `ip`: поддерживают CIDR (`source.ip: 10.0.0.0/8`)
- `process.command_line`, `process.executable`, `file.path` → тип `wildcard`: glob-поиск (`*bash -c*`)
- `process.start`, `process.parent.start` → тип `date` (ISO 8601 строки через `to_iso()`): date range и date math работают корректно
- `process.pid`, `destination.port`, `auditd.session`, `process.exit_code` → тип `integer` / `long`: числовые range-запросы
- `network.iana_number` → тип `keyword`: строковое значение IANA-номера протокола (не число)
- `user.terminal` → тип `keyword`: имя tty/pts
- все прочие строки → тип `keyword`: точный match и `terms` aggregation, без full-text поиска

Для cross-index join auditd ↔ osquery использовать `process.entity_id` (keyword) и `user.session.id` (keyword) — оба поля одинаково заполняются в обоих источниках (кроме bpf_processes — см. раздел 6).
