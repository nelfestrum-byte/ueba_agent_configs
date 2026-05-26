# UEBA-stand v0.9 — Release Notes

**Версия:** 0.9  
**Дата:** 2026-05-22  
**Стек:** auditd + fluent-bit + osquery → Logstash → OpenSearch

---

## Что такое UEBA-stand

UEBA-stand — инфраструктурная основа для систем User and Entity Behavior Analytics (UEBA).
Стенд собирает события безопасности с Linux-хостов, нормализует их в **ECS 8.11** (Elastic Common Schema) и пишет в OpenSearch.

Нормализованные данные служат входом для UEBA-скоринга: построения базовых линий поведения пользователей и сущностей, обнаружения аномалий, атрибуции инцидентов.

Совместимость с Elastic ECS 8.x обеспечивает готовность данных к Elastic Security, Kibana SIEM и любой системе, понимающей ECS — без дополнительных преобразований.

---

## Архитектура пайплайна

```
Linux-хост
  ├── auditd (kernel subsystem)
  │     └── /var/log/audit/audit.log
  │               └── fluent-bit
  │                     ├── auditd_merge.lua    — объединение записей по serial
  │                     ├── auditd_enrich.lua   — ECS 8.11 нормализация
  │                     └── TCP 5045 ──────────────────────┐
  │                                                        │
  └── osquery (diff-мониторинг)                           │
        └── /var/log/osquery/osqueryd.results.log         │
                  └── fluent-bit                          │
                        ├── osquery_enrich.lua — ECS 8.11  │
                        └── TCP 5047 ──────────────────────┤
                                                           │
                                                      Logstash
                                                           │
                                                     OpenSearch
                                               ├── fluent-audit-YYYY.MM.dd
                                               └── fluent-osquery-YYYY.MM.dd
```

На **BPF-хостах** (группа `[bpf_hosts]`, ядро ≥ 5.10, osquery ≥ 4.6) дополнительно активируется osquery BPF backend: event-driven таблицы `bpf_process_events`, `bpf_socket_events`, diff-инвентарь `docker_containers` с нативным container attribution.

---

## Компоненты стека

| Компонент | Версия | Роль |
|-----------|--------|------|
| **auditd** | 4.x | Kernel-level audit: execve, syscalls, auth, file integrity |
| **fluent-bit** | 3.x | Сбор, merge, ECS-обогащение, отправка в Logstash |
| **osquery** | 5.23.0 | Diff-мониторинг: процессы, сети, пользователи, пакеты, BPF |
| **Logstash** | 8.x | Маршрутизация, type-cast, запись в OpenSearch |
| **OpenSearch** | 2.x | Хранение событий, index templates, Anomaly Detection |

**auditbeat не используется** — конфликтует с auditd за audit netlink-сокет.

---

## Возможности v0.9

### Сбор событий безопасности (auditd → fluent-audit-*)

auditd перехватывает системные вызовы на уровне ядра. В v0.9 покрыты следующие вектора:

**Базовые события процессов и идентичности:**
- `execve / execveat` — запуск любого процесса (кроме системных путей)
- `sudo / su` — привилегированное выполнение (USER_CMD, USER_AUTH)
- `setuid / setreuid / setresuid` — смена UID (privilege escalation)
- SSH auth events: USER_LOGIN, USER_LOGOUT, LOGIN

**Сетевые события:**
- `connect / bind / accept` — все сетевые соединения (IPv4/IPv6)

**Файловая активность:**
- `openat / open / creat` — доступ к файлам в критичных директориях
- `unlink / unlinkat` — удаление файлов

**Современные bypass-векторы (добавлены в v0.9, P0-04):**
- `io_uring_setup` — инициализация io_uring ring (RingReaper-класс, auid≥1000)
- `ptrace` + `process_vm_readv/writev` — process injection (T1055)
- `memfd_create` — fileless execution через анонимный fd (T1620)
- `bpf` — загрузка eBPF-программ (rootkit-вектор, с whitelist osqueryd)

**Tier A — anti-forensics, persistence, container escape (добавлены в v0.9, P1-01):**
- Watch на `/var/log/audit/` — попытки чистить audit-логи
- Watch на `/etc/ld.so.preload`, `/etc/ld.so.conf*` — LD_PRELOAD persistence
- `reboot` — преднамеренный ребут (anti-forensics)
- `acct` — отключение/включение process accounting
- `utimensat / utimes / futimesat` — timestomping (T1070.006)
- `unshare / setns / pivot_root` — container/namespace escape
- `mount / umount2 / move_mount / fsopen / fsconfig / fsmount / open_tree` — mount-based escapes
- `kexec_file_load / kexec_load` — горячая замена ядра
- `userfaultfd` — exploitation primitive для kernel race conditions
- `socket a0=38` (AF_ALG) — crypto-bypass вектор
- `swapon / swapoff` — подготовка LD_PRELOAD через swap

**Tier B — extended persistence, network config, package management (добавлены в v0.9, P1-01):**
- Watch на `/etc/environment`, MAC-политики (selinux/apparmor), shell-профили (`/etc/profile.d/`, `/etc/bashrc`)
- Watch на init-файлы (`/etc/inittab`, `/etc/init.d/`, `/etc/rc.local`), fstab, udev rules
- Watch на pkg-репозитории (`/etc/apt/`, `/etc/yum.repos.d/`) — supply chain
- Watch на firewall-конфиги (nftables, iptables), `/etc/ssh/sshd_config`
- Watch на SSSD, LDAP, Kerberos, Polkit
- `sethostname / setdomainname` — DNS spoofing prep
- `mknod / mknodat` — создание device-файлов

### Diff-мониторинг состояния (osquery → fluent-osquery-*)

osquery работает в diff-режиме: фиксирует изменения состояния (появление/исчезновение строк) с интервальным опросом. В v0.9 покрыто:

**Базовые таблицы:**
- `processes` — новые/завершённые процессы (30 сек)
- `listening_ports` — открытые/закрытые порты (60 сек)
- `process_connections` — активные соединения (30 сек)
- `logged_in_users` — входы/выходы пользователей (60 сек)
- `users` — изменения в /etc/passwd (300 сек)
- `ssh_authorized_keys` — изменения авторизованных ключей (300 сек)
- `kernel_modules` — загрузка/выгрузка модулей (120 сек)
- `services` — изменения в systemd-юнитах (300 сек)
- `crontabs` — изменения задач cron (300 сек)
- `sudoers` — изменения sudo-политики (1800 сек)
- `user_groups` / `groups` — изменения групп
- `suid_bins` — SUID-бинари (600 сек)
- `startup_items` — элементы автозапуска (300 сек)
- `mounts` — изменения точек монтирования (300 сек)
- `iptables` / `routes` / `arp_cache` / `dns_resolvers` — сетевая конфигурация
- `usb_devices` / `pci_devices` — подключение устройств
- `process_open_files` — открытые файловые дескрипторы (60 сек)
- `certificates` — изменения сертификатов (3600 сек)

**Расширенные таблицы (добавлены в v0.9, P2-02):**
- `shell_history` — история команд bash/zsh (300 сек; server+workstation)
- `last_logins` (utmp/wtmp) — login/logout sessions с источником (300 сек)
- `preload_envs` — процессы с LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH (60 сек)
- `python_packages` / `npm_packages` / `pip_packages` — diff установленных пакетов (7200 сек)
- `deb_packages_diff` — новые/удалённые deb-пакеты (3600 сек)
- `kernel_keys_diff` — изменения в kernel keyrings (600 сек)
- `sudoers_diff` — изменения sudo policy (1800 сек)
- `acpi_tables_diff` — firmware tampering (86400 сек)
- `suspicious_mmap` (process_memory_map вне /usr/) — shared object hijack (300 сек)
- `chrome_extensions_diff` / `firefox_addons_diff` — расширения браузеров (3600 сек; **только workstation-профиль**)

**BPF backend (только docker-хосты, добавлен в v0.9, P2-01):**
- `bpf_process_events` — event-driven execve (нет polling gap, 10 сек интервал)
- `bpf_socket_events` — event-driven connect/bind/accept
- `docker_containers` — diff запущенных контейнеров (30 сек)

### ECS-нормализация

Все события нормализованы в ECS 8.11. Ключевые гарантированные поля:

| Поле | Примечание |
|------|-----------|
| `process.entity_id` | Стабильный хэш (FNV-1a: host+pid+start_time). Одинаков для всех событий одного процесса, переключается при PID reuse. Совпадает между auditd и osquery. |
| `process.parent.entity_id` | ID родительского процесса — основа для построения process tree |
| `user.session.id` | Глобально уникальный ID сессии (FNV-1a: host+btime+ses). Один логин = один session.id в auditd и osquery |
| `user.effective.id` | auid (реальный пользователь до sudo) |
| `container.entity_id` | `host.name:container.name` — стабильный ключ контейнера для UEBA |
| `source.ip` / `destination.ip` | Тип `ip` в OpenSearch (CIDR-фильтры, geo-enrich) |
| `process.command_line` | Тип `wildcard` (substring-поиск) |

Подробная спецификация всех ECS-полей: [README_FOR_AI.md](../README_FOR_AI.md).

---

## Что было реализовано в v0.9 (Hardening P0–P2)

### P0-01 — process.entity_id и process.parent.entity_id (2026-05-18)

PID переиспользуются ядром — без стабильного entity_id скоринговые фичи "process tree depth", "необычный родитель", "PID reuse" деградируют при первой коллизии. Реализован стабильный `process.entity_id = FNV-1a(host.name:pid:start_time)` — одинаков для всех событий одного процесса, уникален после PID reuse. Работает в auditd (из `/proc/<pid>/stat`) и osquery (из родного `start_time`). LRU-кэш pid→start_time на 10 000 записей обеспечивает заполнение `process.parent.entity_id` без повторного обращения к /proc.

### P0-02 — user.session.id (2026-05-18)

UEBA-скоринг требует единого идентификатора сессии для корреляции всех действий одного логина. Linux audit session number (`ses`) наследуется всеми дочерними процессами сессии. `user.session.id = FNV-1a(host.name:btime:ses)` — глобально уникален, совпадает между auditd и osquery для одного логина. Позволяет строить baseline сессии и группировать инциденты "от логина до выхода".

### P0-04 — Auditd syscall rules: modern bypass vectors (2026-05-22)

Добавлены правила для 5 современных техник обхода: io_uring (RingReaper), ptrace+process_vm (T1055 process injection), memfd_create (T1620 fileless execution), bpf (rootkit-вектор). Расширена таблица SYSCALLS в auditd_enrich.lua (x86_64 номера), добавлена ECS-категоризация событий.

### P1-01 — Neo23x0 gap-analysis: Tier A + Tier B (2026-05-22)

Сверка текущего ruleset с референсом Neo23x0/auditd (Florian Roth, MIT). Cherry-pick: Tier A (12 правил высокого сигнала) + Tier B (~16 правил/watch, средняя ценность). Закрытые слепые зоны: anti-forensics, LD_PRELOAD persistence, container/namespace escape, mount-based escapes, kexec, timestomping, supply chain (pkg repos). Tier C (bin_writes, delete без фильтра, IPC) отвергнут как шумный.

### P1-02 — ECS Index Templates для OpenSearch (2026-05-22)

Два шаблона v2.0 (`fluent-audit-*`, `fluent-osquery-*`) фиксируют типы всех ECS-полей до создания первого документа: `source.ip`/`destination.ip` как `ip` (CIDR-фильтры), `process.command_line` как `wildcard` (substring-поиск), `event.module` как `constant_keyword` (экономия диска). Шаблоны применяются автоматически при деплое Logstash через Ansible.

### P2-01 — osquery BPF backend + container.entity_id (2026-05-21)

Активирован eBPF backend osquery на BPF-хостах (группа `[bpf_hosts]`, ядро ≥ 5.10). Event-driven таблицы `bpf_process_events` и `bpf_socket_events` дают container-aware видимость без polling gap. Нативное поле `cid` (container ID из cgroup) → `container.id`. Добавлен diff-запрос `docker_containers` + кэш `container_id → {name, image}` в osquery_enrich.lua. `container.entity_id = host.name:container.name` — стабильный ключ для поведенческой модели.

### P2-02 — Расширение osquery-запросов (2026-05-21)

Добавлены 10 высокосигнальных таблиц: shell_history (sequence-аномалии), last_logins (login sessions), preload_envs (LD_PRELOAD injection), python/npm/pip/deb пакеты (supply chain), kernel_keys, acpi_tables (firmware tampering), suspicious_mmap (shared object hijack), chrome/firefox extensions (workstation only). Переменная `osquery_profile` (server/workstation) управляет профилем запросов.

---

## Профили развёртывания

| Группа Ansible | Профиль osquery | BPF backend | Дополнительные таблицы |
|----------------|-----------------|-------------|----------------------|
| `[servers]` | `server` | нет | shell_history, packages, kernel_keys, acpi, suspicious_mmap |
| `[workstations]` | `workstation` | нет | +chrome/firefox extensions |
| `[bpf_hosts]` | `server` | **да** | +bpf_process_events, bpf_socket_events, docker_containers |

---

## Хранение в OpenSearch

| Индекс | Источник | Размер (ориентир) |
|--------|---------|------------------|
| `fluent-audit-YYYY.MM.dd` | auditd → fluent-bit | ~50–200 MB/день на активный хост |
| `fluent-osquery-YYYY.MM.dd` | osquery → fluent-bit | ~20–80 MB/день на активный хост |

Шаблоны индексов: `opensearch/templates/fluent-audit.json`, `opensearch/templates/fluent-osquery.json` (v2.0, project v0.9).

---

## Развёртывание

### Предварительные требования

| Компонент | Требования |
|-----------|-----------|
| Logstash-хост | Debian/Ubuntu, Docker 24+, Docker Compose v2 |
| Агентские хосты | Debian/Ubuntu, пользователь с sudo |
| Docker-хосты (опц.) | Ядро ≥ 5.10, `/sys/kernel/btf/vmlinux`, osquery ≥ 4.6 |
| Ansible (control node) | Ansible 2.14+, SSH-доступ к хостам |

### Быстрый старт

```bash
# 1. Logstash
cd logstash/deploy
cp inventory.ini.example inventory.ini        # указать IP хоста
cp group_vars/all.yml.example group_vars/all.yml
# заполнить opensearch_url + opensearch_user
cp /path/to/ca.pem files/opensearch-ca.pem
ansible-vault create host_vars/<hostname>.yml  # opensearch_password
ansible-playbook logstash-deploy.yml --ask-vault-pass

# 2. Агенты
cd agents/deploy
cp inventory.ini.example inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
# заполнить logstash_host; для BPF-хостов — group_vars/bpf_hosts.yml
.\fetch-packages\fetch.ps1                     # скачать .deb офлайн (Windows)
ansible-playbook agents-deploy.yml --ask-become-pass
```

Подробные инструкции по развёртыванию: [README.md](../README.md).

---

## Известные ограничения

| Ограничение | Описание | Статус |
|-------------|----------|--------|
| **TLS не настроен** | fluent-bit → Logstash по plaintext TCP (5045, 5047). Допустимо в изолированных сегментах | P1-03 в roadmap |
| **auditd 4.x: нет EOE** | `type=EOE` не пишется в лог. `auditd_merge.lua` использует wall-clock timeout (2 сек) — не EOE | Known limitation, задокументировано |
| **Холодный старт enrich** | `process.parent.entity_id` и `user.session.id` могут отсутствовать сразу после рестарта fluent-bit (кэш pid→start_time пустой). Лейбл `labels.entity_id_source=event_timestamp_fallback` сигнализирует о fallback | Known limitation |
| **BPF process.entity_id** | На BPF-событиях `process.entity_id` вычисляется из kernel monotonic clock (`ntime`), а не из `start_time` как у auditd/osquery. Не совпадает для одного процесса между источниками | Known limitation |
| **CA-сертификат не в git** | `logstash/deploy/files/opensearch-ca.pem` — положить вручную перед деплоем | Намеренно (безопасность) |
| **Офлайн-пакеты не в git** | `*.deb` — перезапустить `fetch.ps1` при смене версий | Намеренно (размер репо) |
| **Index templates не ретроактивны** | Существующие индексы сохраняют старые маппинги до истечения retention | Known limitation |
| **osquery BPF: buffer overflow** | На нагруженных хостах perf-ring буфер может переполняться → `probe_error=1`. Диагностика и параметры в [README.md](../README.md) | Параметры задокументированы |
| **bpf audit-правило + osqueryd** | Правило `-S bpf` триггерится самим osqueryd при загрузке BPF-программ → feedback loop. Нужен whitelist `-F exe!=/usr/bin/osqueryd` до включения P2-01 | Cross-task, задокументировано в CLAUDE.md |
| **shell_history: raw command lines** | `shell_history` пишет команды пользователей без маскирования секретов (--password=, --token=). Политика принята намеренно; при изменении — добавить gsub в osquery_enrich.lua | Known limitation |



## Ключевые файлы

| Файл | Назначение |
|------|-----------|
| [README.md](../README.md) | Инструкция по развёртыванию для оператора |
| [README_FOR_AI.md](../README_FOR_AI.md) | Детальная спецификация ECS-схемы для AI-агентов надпроектов |
| [HARDENING/HARDENING_PLAN.md](../HARDENING/HARDENING_PLAN.md) | Оставшиеся задачи: P1-03, P1-04, P3-01, P3-02, P3-03 |
| [agents/configs/auditd/audit.rules](../agents/configs/auditd/audit.rules) | Правила auditd |
| [agents/configs/fluent-bit/fluent-bit.conf](../agents/configs/fluent-bit/fluent-bit.conf) | Конфигурация fluent-bit |
| [agents/configs/fluent-bit/scripts/](../agents/configs/fluent-bit/scripts/) | Lua-скрипты: merge + enrich |
| [agents/configs/osquery/osquery.conf.j2](../agents/configs/osquery/osquery.conf.j2) | Jinja2-шаблон конфигурации osquery |
| [opensearch/templates/](../opensearch/templates/) | Index templates ECS 8.11 v2.0 |
| [logstash/configs/pipeline/ueba-main.conf](../logstash/configs/pipeline/ueba-main.conf) | Logstash pipeline |
