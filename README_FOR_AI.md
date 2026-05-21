# README_FOR_AI — Справочник по данным для AI-агентов

Этот документ предназначен для AI-агентов, использующих данный стенд как основу
для надпроектов — прежде всего **UEBA-системы со скорингом поведения пользователей и сущностей**.

Содержит точные описания: какие данные собираются, в каком формате хранятся,
какие ECS-поля гарантированы, и как интерпретировать каждый тип события.

---

## 1. Назначение стенда в UEBA-контексте

Стенд собирает сырые события безопасности с Linux-хостов и нормализует их в **ECS 8.11**.
Нормализованные события — входные данные для UEBA-скоринга:

- **Базовые линии**: osquery diff позволяет строить baseline (типичные процессы, соединения, пользователи)
- **Аномалии**: auditd execve + syscall-трассировка — основа для детектирования аномального поведения
- **Идентичность**: user.id / user.name сквозные через все источники (auditd auid, osquery uid, filebeat auth)
- **Граф сущностей**: host.name + process.pid + user.name + destination.ip → граф для UEBA

---

## 2. Архитектура пайплайна (с точки зрения данных)

```
Источник          Транспорт              Хранилище
─────────────────────────────────────────────────────────────────
auditd            fluent-bit TCP 5045    fluent-audit-YYYY.MM.dd
osquery           fluent-bit TCP 5047    fluent-osquery-YYYY.MM.dd
filebeat [врем.]  beats TCP 5044         filebeat-{ver}-YYYY.MM.dd
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

### 3.2 Обработка в fluent-bit

1. **auditd_merge.lua** — объединяет строки одного события по `serial` number.
   auditd пишет одно событие несколькими строками (SYSCALL + EXECVE + PATH + CWD).
   Merge флашит по timeout (~2 сек wall clock), **не** по EOE (auditd 4.x EOE не пишет в лог).

2. **auditd_enrich.lua** — нормализует объединённую запись в ECS:
   - syscall number → имя (`SYSCALLS` таблица, x86_64)
   - `event.category`, `event.type`, `event.action` по типу события
   - `process.*` из полей pid/ppid/comm/exe/proctitle/_execve_args; `process.parent.name` и `process.parent.command_line` из кэшей `pid→name`/`pid→cmdline` или `/proc/<ppid>/comm` и `/proc/<ppid>/cmdline`
   - `user.id` из uid, `user.effective.id` из auid (реальный пользователь до sudo)
   - `file.*` из PATH-записей auditd
   - `event.outcome`: success / failure из syscall_success

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
| `process.pid` | integer | при syscall | PID процесса |
| `process.parent.pid` | integer | при syscall | PPID |
| `process.parent.name` | keyword | если ppid жив или в кэше | Имя родительского процесса (comm, max 15 символов). Берётся из кэша `pid→name` (заполняется при обработке событий родителя), при cache miss — из `/proc/<ppid>/comm`. Отсутствует если родитель завершился до enrich и не попал в кэш. |
| `process.parent.command_line` | keyword | если ppid жив или в кэше | Командная строка родительского процесса. Берётся из кэша `pid→cmdline` (заполняется из `process.command_line` текущего процесса после обработки execve-аргументов), при cache miss — из `/proc/<ppid>/cmdline` (null-байты заменены пробелами). Отсутствует если родитель завершился до enrich и не попал в кэш. |
| `process.entity_id` | keyword | если pid > 0 | Стабильный ID процесса: FNV-1a hash(host.name:pid:start_time), 16 hex. Одинаков для всех событий одного процесса; переключается при PID reuse. Источник: `/proc/<pid>/stat` field 22 + btime. |
| `process.parent.entity_id` | keyword | если ppid резолвирован | ID родительского процесса. Может отсутствовать сразу после рестарта fluent-bit пока родитель не появится в `/proc` или кэше. |
| `process.start` | long | если pid > 0 | Время старта процесса, epoch seconds (btime + floor(starttime_ticks / CLK_TCK)). Совпадает с `osquery.processes.start_time`. |
| `process.name` | keyword | при syscall | имя процесса (comm) |
| `process.executable` | keyword | при syscall | полный путь (exe) |
| `process.command_line` | keyword | при execve | командная строка |
| `process.args` | keyword[] | при execve | аргументы (массив) |
| `process.args_count` | integer | при execve | количество аргументов |
| `process.working_directory` | keyword | при CWD | рабочая директория |
| `labels.entity_id_source` | keyword | при fallback | `event_timestamp_fallback` — процесс исчез из `/proc` до enrich (exit-событие короткоживущего); entity_id такого события **не совпадёт** с osquery. |
| `user.id` | keyword | всегда | UID процесса |
| `user.name` | keyword | если известен | имя пользователя (uid_name или user_acct) |
| `user.effective.id` | keyword | если auid ≠ -1 | audit UID (реальный до sudo) |
| `user.effective.name` | keyword | если известен | имя audit-пользователя |
| `file.path` | keyword | при PATH | полный путь файла |
| `file.name` | keyword | при PATH | имя файла |
| `file.mode` | keyword | при PATH | права (rwxr-xr-x) |
| `auditd.data.syscall` | keyword | при SYSCALL | имя syscall |
| `auditd.session` | integer | если ses > 0 | номер сессии auditd |
| `user.session.id` | keyword | если ses > 0 и ses ≠ 0xFFFFFFFF | Стабильный ID сессии: FNV-1a hash(host.name:btime:ses), 16 hex. Одинаков для всех событий одной пользовательской сессии (auditd + osquery). Переключается при новом логине. |
| `tags` | keyword[] | всегда | `["auditd","security","linux"]` |
| `@timestamp` | date | всегда | время события |

### 3.4 Типичные event.action значения для UEBA

| action | Сценарий UEBA |
|--------|--------------|
| `execve` | Базовая линия процессов; аномальный execve → подозрение |
| `connect` | Граф сетевых соединений; новый destination → скоринг |
| `setuid` | Privilege escalation; редко в baseline → высокий скор |
| `openat` | Доступ к чувствительным файлам (/etc/passwd, ~/.ssh/) |
| `unlink` | Удаление файлов; anti-forensics паттерн |
| `sudo` / `privilege_use` | Выполнение с повышенными правами |

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
- ECS: `destination.port`, `destination.ip`, `network.transport`, `process.pid`, `process.name`, `process.entity_id`, `user.name`, `user.id`
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
- ECS: `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport`, `process.*`, `user.name`
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

### 4.4 Гарантированные ECS-поля (все osquery события)

| Поле | Описание |
|------|---------|
| `ecs.version` | `"8.11"` |
| `event.kind` | `"event"` |
| `event.dataset` | `"osquery"` |
| `event.module` | `"osquery"` |
| `event.category` | process / network / iam / configuration / file / host / authentication |
| `event.action` | специфично для запроса (см. таблицы выше) |
| `event.type` | start / end / change / creation / deletion / access / info |
| `host.name` | hostname хоста |
| `host.os.type` | `"linux"` |
| `process.pid` | PID (для запросов processes, process_connections, process_open_files, listening_ports) |
| `process.entity_id` | Стабильный ID процесса, 16 hex. **Совпадает** с `process.entity_id` в auditd для того же процесса — одинаковая формула FNV-1a(host.name:pid:start_time). Источник start_time: `processes.start_time` (epoch seconds из osquery) или `/proc/<pid>/stat` на cache miss. |
| `process.parent.entity_id` | ID родительского процесса; отсутствует если родитель не резолвирован. |
| `process.start` | Старт процесса, epoch seconds. Для таблицы `processes` = `cols.start_time`. Для остальных — из кэша или `/proc`. |
| `process.parent.start` | Старт родительского процесса, epoch seconds. |
| `user.session.id` | Стабильный ID сессии: FNV-1a hash(host.name:btime:ses), 16 hex. Читается из `/proc/<pid>/sessionid`. Отсутствует если процесс завершился до enrich. **Совпадает** с `user.session.id` в auditd для той же сессии. |
| `user.name` | Имя пользователя (для запросов: processes, process_connections, process_open_files, logged_in_users, users, ssh_authorized_keys, user_groups, startup_items, suid_bins, listening_ports, crontabs) |
| `user.id` | UID пользователя (для тех же запросов, где доступен uid) |
| `osquery.result.name` | имя запроса (processes, listening_ports, ...) |
| `osquery.result.action` | added / removed |
| `osquery.result.host_identifier` | hostname из osquery |
| `osquery.<column>` | все колонки запроса в flat-namespace |
| `tags` | `["osquery","security","linux"]` |

---

## 5. Источник: filebeat — SSH auth *(временный компонент)*

> **Статус: временный.** filebeat используется только для `/var/log/auth.log` (SSH аутентификация).
> Планируется замена на fluent-bit pipeline с Lua-нормализацией для единообразия стека.

### 5.1 Что собирается

Модуль `system/auth` filebeat читает `/var/log/auth.log` и нормализует в ECS:
- SSH successful login / failed login
- sudo events (дублирует часть auditd, но с parsed message)
- PAM authentication events

### 5.2 Ключевые ECS-поля (filebeat system/auth)

| Поле | Описание |
|------|---------|
| `event.dataset` | `"system.auth"` |
| `event.outcome` | success / failure |
| `user.name` | имя пользователя |
| `source.ip` | IP источника подключения (SSH) |
| `source.geo.*` | геолокация (если настроен GeoIP) |
| `host.name` | имя хоста |

### 5.3 Индекс

`filebeat-{version}-YYYY.MM.dd` — стандартная схема filebeat.

---

## 6. Сквозные идентификаторы для UEBA

Для построения графа пользователь→хост→процесс→сеть используйте:

| Цель | Поле | Источники |
|------|------|-----------|
| Идентификатор пользователя | `user.id` (UID) | auditd, osquery |
| Имя пользователя | `user.name` | все источники |
| Реальный пользователь (до sudo) | `user.effective.id` | auditd (auid) |
| Хост | `host.name` | все источники |
| Сессия пользователя | `user.session.id` | auditd, osquery — **join корректен**: одинаковая формула FNV-1a(host.name:btime:ses); объединяет все события от логина до выхода |
| Процесс (рекомендуется) | `process.entity_id` | auditd, osquery — **join корректен**: одинаковая формула, одинаковый seed |
| Процесс (устаревший) | `process.pid` + `host.name` | auditd, osquery — ненадёжен при PID reuse |
| Исходный IP (SSH) | `source.ip` | filebeat, osquery logged_in_users |
| Внешний IP | `destination.ip` | osquery process_connections |
| Команда | `process.command_line` | auditd (execve), osquery processes |

> **Кросс-источниковый join по `user.session.id` корректен**: одна формула `FNV-1a(host.name + ":" + btime + ":" + ses)` в обоих enrich-скриптах. Для auditd `ses` берётся из каждого события напрямую; для osquery — из `/proc/<pid>/sessionid`. Поле отсутствует если `ses = 0` (kernel) или `ses = 0xFFFFFFFF` (unset), либо если процесс завершился до enrich osquery.

> **Кросс-источниковый join auditd ↔ osquery по `process.entity_id` корректен** при условии, что оба enrich-скрипта используют одинаковую формулу: `FNV-1a(host.name + ":" + pid + ":" + start_time)`, где `start_time` берётся из `/proc/<pid>/stat field 22 + btime` (целое число, epoch seconds). Для exit-событий короткоживущих процессов поле `labels.entity_id_source = "event_timestamp_fallback"` сигнализирует, что entity_id в этом документе **не совпадёт** с osquery.

---

## 7. Что НЕ входит в текущий стенд

- Windows события (stub в Logstash на TCP 5046, не развёрнут)
- Suricata IDS (stub на TCP 5049)
- MITRE ATT&CK аннотация событий (отключена в `auditd_enrich.lua` — теги предназначены для scoring, не для raw-событий)
- GeoIP обогащение (не настроено в Logstash)
- Агрегация / базовые линии (должны строиться на уровне надпроекта)

---

## 8. Файлы, критичные для AI-агентов надпроекта

| Файл | Зачем |
|------|-------|
| `agents/configs/osquery/osquery.conf` | Полный список запросов и их SQL — источник schema |
| `agents/configs/fluent-bit/scripts/osquery_enrich.lua` | Маппинг запросов → ECS категории/действия |
| `agents/configs/fluent-bit/scripts/auditd_enrich.lua` | ECS-нормализация auditd, syscall→action маппинг |
| `logstash/configs/pipeline/ueba-main.conf` | Входящие порты, type-cast, индексы |
| `agents/configs/auditd/audit.rules` | Что именно перехватывает auditd (фильтр событий) |
| `opensearch/templates/fluent-audit.json` | Точные типы ECS-полей в auditd-индексе (`wildcard`, `ip`, `date`, `integer`) |
| `opensearch/templates/fluent-osquery.json` | Типы полей osquery-индекса + `osquery.result.*` namespace |

---

## 9. OpenSearch маппинги — что важно для запросов

При построении UEBA-запросов учитывать типы полей из шаблонов (`opensearch/templates/`):

- `source.ip`, `destination.ip` → тип `ip`: поддерживают CIDR (`source.ip: 10.0.0.0/8`)
- `process.command_line`, `process.executable`, `file.path` → тип `wildcard`: glob-поиск (`*bash -c*`)
- `process.start`, `process.parent.start` → тип `date` (ISO 8601 строки): date range и date math работают корректно
- `process.pid`, `destination.port`, `auditd.session` → тип `integer`: числовые range-запросы
- все прочие строки → тип `keyword`: точный match и `terms` aggregation, без full-text поиска

Для cross-index join auditd ↔ osquery использовать `process.entity_id` (keyword) и `user.session.id` (keyword) — оба поля одинаково заполняются в обоих источниках.
