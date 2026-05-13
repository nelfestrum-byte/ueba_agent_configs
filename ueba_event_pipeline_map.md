# UEBA — карта событий: агент → пайплайн → OpenSearch → тип правила

## Легенда типов правил

| Тип | Описание |
|-----|----------|
| **AD** | Числовой ряд → OpenSearch RCF → `anomaly_grade` → webhook → scoring |
| **Детерм. правило** | Фильтр события → Painless → webhook → scoring |
| **first_seen** | Детерм. правило с composite aggr + `historical_count = 0` за N дней |

---

## Процессы

| Тип события | ОС | Агент | Источник | Пайплайн → OpenSearch | Индекс | Тип правила | Что даёт |
|---|---|---|---|---|---|---|---|
| `process_start` | Windows | fluent-bit `winevtlog` | Sysmon EID 1 | winevtlog JSON → beats:5044 → Logstash: `Image→process.executable`, `CommandLine`, `User`, `Hashes` → enrich: `entity_id=host.name`, `from_suspicious_path` | `process-events-*` | **first_seen**, suspicious path | Новый exe path, запуск из `/tmp`, `AppData` |
| `process_start` | Linux | fluent-bit `systemd` | auditd `execve syscall=59` | journald MESSAGE → tcp:5045 → Logstash grok SYSCALL: `exe`, `comm`, `auid`, `uid`, `ppid` → normalize: `exe→process.executable`, `comm→process.name` → enrich: `entity_id=host.name` | `process-events-*` | **first_seen**, suspicious path | Тот же индекс — правило единое для Win+Linux |
| `process_start` | Linux | osquery `diff` | `processes` table | osqueryd results.log → fluent-bit tail → Lua `flatten_diff`: `action=added`, `name`, `path`, `cmdline`, `uid`, `parent`, `username`, `parent_name` → tcp:5048 → Logstash → normalize: `name→process.name`, `path→process.executable`, `cmdline→process.command_line`, `username→user.name`, `uid→user.id`, `parent→process.parent.pid`, `parent_name→process.parent.name` | `process-events-*` | **first_seen** | Тот же индекс: кто запустил, с каким cmdline, родительский процесс |
| `process_start` (cmdline) | Linux | fluent-bit `systemd` | auditd `PROCTITLE` | journald PROCTITLE record → tcp:5045 → Logstash: grok `proctitle=<hex|str>` → Ruby: hex декод + `\x00→пробел` → `process.command_line`; `event.category=process`, `event.action=process_start` | `process-events-*` | **first_seen** | Полная командная строка из PROCTITLE (дополняет SYSCALL execve, у которого нет cmdline) |

---

## Аутентификация

| Тип события | ОС | Агент | Источник | Пайплайн → OpenSearch | Индекс | Тип правила | Что даёт |
|---|---|---|---|---|---|---|---|
| `login` / `login_failed` | Windows | fluent-bit `winevtlog` | Security EID 4624 / 4625 | Security channel JSON → tcp:5046 → Logstash: `event_id→action`, `TargetUserName→user.name`, `IpAddress→source.ip` → enrich: `hour_of_day`, `day_of_week`, `is_offhours` | `auth-events-*` | **AD** (logins_per_hour через Transform), **offhours**, **brute force** | AD: `logins_per_hour`; правило: `is_offhours=true`; правило: `failed > N/мин` |
| `login` / `login_failed` | Linux | fluent-bit `systemd` | sshd journald / auditd `USER_AUTH` | journald sshd MESSAGE → tcp:5047 → Logstash grok: `user`, `src_ip`, `auth_method`, `Accepted/Failed` → enrich: `hour_of_day`, `is_offhours` | `auth-events-*` | **AD**, **offhours**, **brute force** | Тот же индекс — правило единое Win+Linux |
| `session_change` | Linux | osquery `diff` | `logged_in_users` table | osqueryd results.log → fluent-bit tail → Lua `flatten_diff`: `action=added/removed`, `user`, `type`, `host`, `time`, `pid` → tcp:5048 → Logstash → normalize: `user→user.name`, `host→session_host`, `pid→process.pid` | `auth-events-*` | **AD**, **first_seen** | Активные сессии: TTY/SSH, появление/закрытие; корреляция с login/logout |
| `privilege_use` | Windows | fluent-bit `winevtlog` | Security EID 4648 (runas) | Security channel → tcp:5046 → Logstash: `action=privilege_use`, `user.name`, `target_user` | `auth-events-*` | **Детерм. правило** | Любой runas → webhook немедленно |
| `privilege_use` | Linux | fluent-bit `systemd` | auditd `execve` + `-F path=/usr/bin/sudo` / `/usr/bin/su` (key=sudo_exec) | journald SYSCALL record → tcp:5045 → Logstash: grok SYSCALL → key extraction grok (`key="sudo_exec"`) → `event.category=authentication`, `event.action=privilege_use`, `process.executable`, `process.name`, `user.id`, `user.audit_id`; rule.id=5402, level=8 | `auth-events-*` | **Детерм. правило** | Любой sudo/su → auth-events; MITRE T1548 Privilege Escalation |

---

## Сетевые события

| Тип события | ОС | Агент | Источник | Пайплайн → OpenSearch | Индекс | Тип правила | Что даёт |
|---|---|---|---|---|---|---|---|
| `network_connection` | Windows | fluent-bit `winevtlog` | Sysmon EID 3 | Sysmon/Operational → beats:5044 → Logstash: `Image→process.executable`, `DestinationIp/Port`, `SourceIp/Port` → normalize: `destination.ip`, `destination.port` | `network-events-*` | **AD** (unique_dst_ip через Transform), **first_seen** | AD: `unique_dst_ip_1h`; правило: новый `(entity, dst_ip, dst_port)` за 30 дней |
| `network_connection` | Windows + Linux | Suricata | NetFlow / eve.json | eve.json → fluent-bit tail → tcp:5049 → Logstash: `src_ip→source.ip`, `dest_ip→destination.ip`, `dest_port` → inventory lookup: `src_ip→entity_id` | `network-events-*` | **AD**, **first_seen** | Основной источник сетевых аномалий |
| `network_connection` | Linux | osquery `diff` | `process_open_sockets` table (`process_connections` query) | osqueryd results.log added → fluent-bit tail → Lua `flatten_diff`: `pid`, `remote_address`, `remote_port`, `local_address`, `local_port`, `protocol`, `state`, `process_name`, `process_path`, `username` → tcp:5048 → Logstash → normalize: `remote_address→destination.ip`, `remote_port→destination.port`, `local_address→source.ip`, `local_port→source.port`, `process_name→process.name`, `process_path→process.executable`, `protocol→network.transport`, `state→network.state`; rule.id=99020, level=3 | `network-events-*` | **AD** (unique_dst_ip), **first_seen** | Исходящие соединения с привязкой к процессу; AD: `unique_dst_ip_per_process_15m`; MITRE T1071 C&C |
| `open_sockets` (метрика) | Windows | osquery `snapshot` | `process_open_sockets` | results.log → fluent-bit tail → Lua `flatten_snapshot` → `{metric_name, value, entity_id}` | `host-metrics-*` | **AD** | RCF на числовой ряд `open_sockets_count` |

---

## Конфигурация и персистентность

| Тип события | ОС | Агент | Источник | Пайплайн → OpenSearch | Индекс | Тип правила | Что даёт |
|---|---|---|---|---|---|---|---|
| `service_installed` | Windows | fluent-bit `winevtlog` | System EID 7045 | System channel → tcp:5046 → Logstash: `ServiceName→service.name`, `ImagePath→service.executable` → `action=service_installed` | `config-events-*` | **Детерм. правило** | Любой новый сервис → webhook немедленно |
| `service_change` | Windows + Linux | osquery `diff` | `services` / `drivers` | results.log added/removed → fluent-bit tail → Lua `flatten_diff` → tcp:5048 → Logstash normalize | `config-events-*` | **first_seen**, **AD** (count) | Новый сервис/драйвер; AD на `drivers_count` |
| `scheduled_task` | Windows | osquery `diff` + fluent-bit `winevtlog` | `scheduled_tasks` / EID 106 / 200 | osquery diff: added task → `config-events-*`; winevtlog EID 106 (task registered) → `config-events-*` | `config-events-*` | **first_seen**, **AD** (count) | Новая задача; AD на `scheduled_tasks_count` |
| `autorun_registry` | Windows | osquery `diff` | registry Run keys | results.log added Run key → fluent-bit tail → tcp:5048 → Logstash: `action=autorun_added`, `registry.path`, `registry.data` | `config-events-*` | **Детерм. правило** | Любой новый Run key → webhook немедленно |
| `startup_items` | Linux | osquery `diff` | `startup_items` / `/etc/cron*` | results.log added → fluent-bit tail → tcp:5048 → Logstash normalize | `config-events-*` | **first_seen**, **AD** (count) | Новый элемент автозапуска; AD на `cronjobs_count` |

---

## Файловые события

| Тип события | ОС | Агент | Источник | Пайплайн → OpenSearch | Индекс | Тип правила | Что даёт |
|---|---|---|---|---|---|---|---|
| `file_create` | Windows | fluent-bit `winevtlog` | Sysmon EID 11 | Sysmon/Operational → beats:5044 → Logstash: `TargetFilename→file.path`, `Image→process.executable` → `action=file_create` | `file-events-*` | **Детерм. правило** | Создание `.exe` / `.ps1` в `AppData` / `Temp` |
| `registry_change` | Windows | fluent-bit `winevtlog` | Sysmon EID 12 / 13 | Sysmon/Operational → beats:5044 → Logstash: `TargetObject→registry.path`, `Details→registry.data` → `action=registry_set / registry_delete` | `file-events-*` | **first_seen** | Новый ключ реестра за 30 дней |

---

## Системные метрики — числовые ряды для AD

| Тип события | ОС | Агент / Источник | Пайплайн → OpenSearch | Индекс | Тип правила | Что даёт |
|---|---|---|---|---|---|---|
| Метрики хоста (11 штук) | Windows + Linux | osquery `snapshot`: `processes`, `listening_ports`, `drivers`, `routes`, `scheduled_tasks`, `services`, `users`, `logon_sessions`, `startup_items`, `open_sockets`, `routes` | results.log snapshot → fluent-bit tail → Lua `flatten_snapshot` → `{metric_name, value, entity_id}` → tcp:5048 → Logstash | `host-metrics-*` | **AD** | RCF на 11 метрик; `category_field=entity_id` |
| `logins_per_hour` (агрегат) | Windows + Linux | OpenSearch Transform Job из `auth-events-*` каждые 15 мин | `auth-events-*` GROUP BY `entity_id`, `hour_bucket` → COUNT(*) → запись в `host-metrics-*` | `host-metrics-*` | **AD** | RCF на `logins_per_hour` — паттерн времени входа |
| `unique_dst_ip_15m` (агрегат) | Windows + Linux | OpenSearch Transform Job из `network-events-*` каждые 15 мин | `network-events-*` GROUP BY `entity_id`, `time_bucket` → CARDINALITY(`destination.ip`), CARDINALITY(`destination.port`) → запись в `host-metrics-*` | `host-metrics-*` | **AD** | RCF на `unique_dst_ip_15m` — аномалия сетевой активности |

---

## Common Schema — ключевые поля после нормализации Logstash

| Поле | Тип | Источник Windows | Источник Linux |
|------|-----|-----------------|----------------|
| `process.executable` | keyword | Sysmon `Image` | auditd `exe`; osquery `path` |
| `process.name` | keyword | basename(Image) | auditd `comm`; osquery `name` |
| `process.command_line` | text | Sysmon `CommandLine` | osquery `cmdline` |
| `process.pid` | integer | Sysmon `ProcessId` | auditd `pid`; osquery `pid` |
| `process.parent.pid` | integer | Sysmon `ParentProcessId` | auditd `ppid`; osquery `parent` |
| `process.parent.name` | keyword | Sysmon `ParentImage` (basename) | osquery `parent_name` (subquery) |
| `process.from_suspicious_path` | boolean | вычисляется из `process.executable` | вычисляется из `process.executable` |
| `user.name` | keyword | EventLog `TargetUserName` | sshd grok `user`; osquery `username` |
| `user.id` | integer | EventLog `TargetUserSid` | auditd `uid`; osquery `uid` |
| `user.audit_id` | integer | — | auditd `auid` (сохраняется при sudo/su) |
| `source.ip` | ip | EventLog `IpAddress` | sshd grok `src_ip` |
| `destination.ip` | ip | Sysmon EID 3 `DestinationIp` | Suricata `dest_ip` |
| `destination.port` | integer | Sysmon EID 3 `DestinationPort` | Suricata `dest_port` |
| `file.hash.sha256` | keyword | Sysmon `Hashes` (SHA256=…) | — |
| `session_host` | keyword | — | osquery `logged_in_users.host` (tty или remote host) |
| `event.is_offhours` | boolean | все события, из `@timestamp` | все события, из `@timestamp` |
| `event.hour_of_day` | integer | все события, из `@timestamp` | все события, из `@timestamp` |
| `agent.name` | keyword | `host.name` | `host.name` (из `hostname` fluent-bit) |
| `decoder.name` | keyword | `sysmon` / `winevtlog` | `auditd` / `sshd` / `osquery` |
| `location` | keyword | `eventlog` | `/var/log/audit/audit.log`, `journald`, `/var/log/osquery/*.log` |
| `rule.id` | keyword | Wazuh rule ID | Wazuh rule ID |
| `rule.level` | integer | 1–15 (Wazuh severity) | 1–15 (Wazuh severity) |
| `rule.description` | keyword | Wazuh rule text | Wazuh rule text |
| `rule.groups` | keyword[] | `["authentication_success", ...]` | `["audit_command", ...]` |
| `rule.mitre.id` | keyword[] | `["T1078"]` | `["T1059"]` |
| `rule.mitre.tactic` | keyword[] | `["Initial Access"]` | `["Execution"]` |
| `rule.mitre.technique` | keyword[] | `["Valid Accounts"]` | `["Command and Scripting Interpreter"]` |

---

## Индексы OpenSearch

| Индекс | `event.category` | Источники |
|--------|-----------------|-----------|
| `process-events-*` | `process` | Sysmon EID 1, auditd execve, osquery processes diff |
| `auth-events-*` | `authentication` | EventLog 4624/4625/4648, sshd journald, auditd USER_AUTH, auditd sudo_exec (privilege_use), osquery logged_in_users diff |
| `network-events-*` | `network` | Sysmon EID 3, Suricata NetFlow, osquery process_connections diff |
| `config-events-*` | `configuration` | EventLog 7045, Sysmon EID 12/13, osquery diff (services, drivers, tasks, registry) |
| `file-events-*` | `file` | Sysmon EID 11 |
| `host-metrics-*` | `metric` | osquery snapshot (11 метрик) + Transform Jobs (logins_per_hour, unique_dst_ip_15m) |
