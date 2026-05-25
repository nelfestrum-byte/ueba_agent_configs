# Деплой UEBA-агентов

Ansible-плейбук для установки и настройки агентов сбора событий на Linux-хостах (Debian/Ubuntu).

**Стек:** auditd + fluent-bit + osquery → Logstash → OpenSearch

---

## Содержание

1. [Предварительные требования](#предварительные-требования)
2. [Структура директории](#структура-директории)
3. [Первоначальная настройка](#первоначальная-настройка)
4. [Инвентарь и группы хостов](#инвентарь-и-группы-хостов)
5. [Переменные деплоя](#переменные-деплоя)
6. [Режим офлайн-установки](#режим-офлайн-установки)
7. [Деплой](#деплой)
8. [Групповые конфигурации](#групповые-конфигурации)
9. [Проверка после деплоя](#проверка-после-деплоя)
10. [Диагностика](#диагностика)

---

## Предварительные требования

| Компонент | Требования |
|-----------|-----------|
| Агентские хосты | Debian/Ubuntu, пользователь с sudo |
| Docker-хосты (опц.) | Ядро ≥ 5.10, `/sys/kernel/btf/vmlinux`, osquery ≥ 4.6 |
| Ansible (control node) | Ansible 2.14+, SSH-доступ к целевым хостам |
| Logstash | Запущен и доступен (TCP 5045, 5047; опционально 5044) |

---

## Структура директории

```
agents/
├── configs/
│   ├── auditd/
│   │   └── audit.rules              — правила auditd (execve, sudo, auth, сеть, файлы)
│   ├── fluent-bit/
│   │   ├── fluent-bit.conf.j2       — шаблон конфига fluent-bit (Jinja2)
│   │   ├── parsers.conf.j2          — шаблон парсеров (Jinja2)
│   │   ├── fluent-bit.env.j2        — шаблон /etc/default/fluent-bit
│   │   └── scripts/                 — Lua-скрипты обработки событий
│   │       ├── auditd_merge.lua     — объединение auditd записей по serial
│   │       ├── auditd_enrich.lua    — ECS-обогащение auditd событий
│   │       ├── osquery_enrich.lua   — ECS-обогащение osquery событий
│   │       ├── proc_common.lua      — общие утилиты (process.entity_id)
│   │       ├── freeipa.lua          — нормализация FreeIPA событий
│   │       ├── docker_events.lua    — санитизация Docker Events API
│   │       └── remove_commas.lua    — препроцессинг Keycloak logfmt
│   └── osquery/
│       └── osquery.conf.j2          — шаблон конфига osquery (BPF per-group)
└── deploy/
    ├── agents-deploy.yml            — основной Ansible-плейбук
    ├── ansible.cfg
    ├── inventory.ini                — хосты (скопировать из inventory.ini.example)
    ├── inventory.ini.example        — шаблон инвентаря
    ├── group_vars/
    │   ├── all.yml                  — глобальные переменные (скопировать из all.yml.example)
    │   ├── all.yml.example          — шаблон переменных
    │   ├── docker_hosts.yml.example — пример для docker-хостов (BPF backend)
    │   ├── workstations.yml         — профиль workstation для osquery
    │   ├── freeipa_hosts.yml        — base_stack для FreeIPA-хостов
    │   ├── keycloak_hosts.yml       — base_stack для Keycloak-хостов
    │   └── docker_event_hosts.yml   — base_stack для Docker event-хостов
    └── fetch-packages/
        ├── fetch.ps1                — скачать .deb для офлайн-деплоя (Windows)
        └── Dockerfile
```

---

## Первоначальная настройка

```bash
cd agents/deploy

# 1. Скопировать шаблоны
cp inventory.ini.example inventory.ini
cp group_vars/all.yml.example group_vars/all.yml

# 2. Заполнить переменные (см. раздел ниже)
$EDITOR group_vars/all.yml

# 3. Заполнить инвентарь
$EDITOR inventory.ini
```

---

## Инвентарь и группы хостов

Файл `inventory.ini` определяет иерархию групп. Группа `[ueba_agents]` — родитель всех остальных.

| Группа | Описание | Особенности |
|--------|----------|-------------|
| `[pure_ueba]` | Только auditd + osquery ECS | `base_stack: []` |
| `[docker_hosts]` | pure_ueba + BPF backend | ядро ≥ 5.10, BTF, `osquery_bpf_events_enabled: true` |
| `[workstations]` | pure_ueba + профиль workstation | добавляет chrome/firefox в osquery |
| `[freeipa_hosts]` | + FreeIPA / Docker / Suricata / WAF | `base_stack: [freeipa, docker_events, suricata, waf]` |
| `[keycloak_hosts]` | + Keycloak container logs | `base_stack: [keycloak]` |
| `[docker_event_hosts]` | + Docker events / Suricata / WAF | `base_stack: [docker_events, suricata, waf]` |

Пример `inventory.ini`:

```ini
[ueba_agents:children]
pure_ueba
docker_hosts
workstations
freeipa_hosts
keycloak_hosts
docker_event_hosts

[pure_ueba]
server01.example.com  ansible_host=10.0.0.11
server02.example.com  ansible_host=10.0.0.12

[docker_hosts]
docker-node-1.example.com  ansible_host=10.0.0.21

[workstations]
ws-alice.example.com  ansible_host=10.0.0.31

[freeipa_hosts]
freeipa.example.com  ansible_host=10.0.0.51

[keycloak_hosts]
keycloak.example.com  ansible_host=10.0.0.52

[docker_event_hosts]
docker-events-1.example.com  ansible_host=10.0.0.53

[ueba_agents:vars]
ansible_user=deploy
ansible_become=true
ansible_python_interpreter=/usr/bin/python3
```

---

## Переменные деплоя

Все параметры задаются в `deploy/group_vars/all.yml`. Скопировать из `all.yml.example`.

### Logstash — эндпоинты

```yaml
logstash_security_host:         10.0.0.5    # UEBA Logstash (auditd + osquery)
logstash_security_audit_port:   5045        # auditd → fluent-audit-*
logstash_security_osquery_port: 5047        # osquery → fluent-osquery-*

logstash_common_host:  10.0.0.10            # общий Logstash (только если base_stack непустой)
logstash_common_port:  5044
```

### Базовый pipeline

```yaml
base_stack: []   # [] = pure UEBA; переопределяется через group_vars/<группа>.yml
```

### Режим установки пакетов

```yaml
use_local_packages: true   # true = офлайн (.deb из deploy/files/), false = онлайн (apt-репо)

fluent_bit_version:   "5.0.5"
fluent_bit_local_deb: "fluent-bit_{{ fluent_bit_version }}_amd64.deb"

osquery_version:   "5.23.0"
osquery_local_deb: "osquery_{{ osquery_version }}-1.linux_amd64.deb"
```

### BPF backend (docker-хосты)

```yaml
osquery_bpf_events_enabled: false   # переопределяется в group_vars/docker_hosts.yml
osquery_bpf_interval: 10
```

### osquery профиль

```yaml
osquery_profile: server   # "server" или "workstation"; переопределяется в group_vars/workstations.yml
```

---

## Режим офлайн-установки

Если целевые хосты не имеют доступа в интернет — скачайте `.deb`-пакеты на control node заранее (требуется Docker Desktop):

```powershell
# Windows (PowerShell)
.\agents\deploy\fetch-packages\fetch.ps1

# Указать конкретные версии:
.\agents\deploy\fetch-packages\fetch.ps1 -FluentBitVersion 5.0.5 -OsqueryVersion 5.23.0
```

Пакеты сохраняются в `agents/deploy/files/`. После этого убедитесь, что в `all.yml` задано:

```yaml
use_local_packages: true
fluent_bit_version: "5.0.5"
osquery_version: "5.23.0"
```

---

## Деплой

```bash
cd agents/deploy

# Деплой всех агентов
ansible-playbook agents-deploy.yml --ask-become-pass

# Только определённая группа хостов
ansible-playbook agents-deploy.yml --limit docker_hosts --ask-become-pass

# Только определённые задачи (теги)
ansible-playbook agents-deploy.yml --tags osquery --ask-become-pass

# Проверить синтаксис без выполнения
ansible-playbook --syntax-check agents-deploy.yml

# Dry-run (check mode)
ansible-playbook agents-deploy.yml --check --ask-become-pass
```

Плейбук выполняет:
1. Проверяет ОС (только Debian/Ubuntu)
2. Устанавливает `auditd`, `fluent-bit`, `osquery`, `acl`
3. Настраивает `auditd.conf` и разворачивает `audit.rules`
4. Разворачивает конфиги и Lua-скрипты fluent-bit; настраивает ACL на `/var/log/audit` и `/var/log/osquery`
5. Рендерит и валидирует конфиг osquery (pre-flight BTF/kernel на docker-хостах)
6. Запускает и включает в автозагрузку `auditd`, `fluent-bit`, `osqueryd`

---

## Групповые конфигурации

### docker_hosts — BPF backend

Для хостов с Docker и ядром ≥ 5.10 создать `group_vars/docker_hosts.yml`:

```bash
cp group_vars/docker_hosts.yml.example group_vars/docker_hosts.yml
```

Содержимое:
```yaml
osquery_bpf_events_enabled: true
```

Плейбук автоматически проверит версию ядра и наличие `/sys/kernel/btf/vmlinux` перед включением BPF-таблиц.

> **Важно:** на docker-хостах auditd-правило `-S bpf` будет срабатывать при загрузке BPF-программ osquery.
> Добавьте whitelist: `-F exe!=/usr/bin/osqueryd` в `configs/auditd/audit.rules`, чтобы избежать feedback loop.

### workstations — профиль рабочих станций

Файл `group_vars/workstations.yml` уже готов:
```yaml
osquery_profile: workstation
```

Добавляет запросы `chrome_extensions_diff` и `firefox_addons_diff` в osquery schedule.

### freeipa_hosts / keycloak_hosts / docker_event_hosts

Готовые `group_vars` файлы задают `base_stack` — fluent-bit добавляет соответствующие pipeline-ы:

| Группа | base_stack |
|--------|------------|
| `freeipa_hosts` | `[freeipa, docker_events, suricata, waf]` |
| `keycloak_hosts` | `[keycloak]` |
| `docker_event_hosts` | `[docker_events, suricata, waf]` |

При непустом `base_stack` обязателен `logstash_common_host` в `all.yml`.

---

## Проверка после деплоя

```bash
# Статус сервисов на агенте
systemctl status auditd fluent-bit osqueryd

# Метрики fluent-bit — pipeline health, состояние Lua-скриптов
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool

# Проверить правила auditd
auditctl -l | head -20

# Ожидаемые события в OpenSearch после запуска:
# sudo <cmd>     → fluent-audit-*   (event.action: privilege_use)
# любой execve   → fluent-audit-*   (event.category: process)
# ssh user@host  → fluent-audit-*   (event.action: session_opened)
# osquery diff   → fluent-osquery-* (event.dataset: osquery.processes и пр.)
```

---

## Диагностика

### fluent-bit не отправляет события

```bash
# Проверить, что filter.lua добавляет записи (должно быть > 0):
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool | grep -A3 '"filter"'

# Проверить права на audit.log:
getfacl /var/log/audit/audit.log
# fluent-bit должен иметь: user:fluent-bit:r--

# Проверить переменные окружения:
cat /etc/default/fluent-bit
```

### auditd_merge.lua не флашит буфер (auditd 4.x)

auditd 4.x не пишет `type=EOE` в файл лога. Merge-скрипт флашит по wall-clock timeout (2 сек по умолчанию). Если `filter.lua.0.add_records = 0` при ненулевом `input.tail.0.records`:

```bash
# Проверить метрики:
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool | grep -E 'add_records|records'

# Перезапустить fluent-bit:
systemctl restart fluent-bit
```

### osquery BPF: переполнение буфера

```bash
# Количество событий с probe_error (=drop на уровне eBPF):
grep '"probe_error":"1"' /var/log/osquery/osqueryd.results.log | wc -l

# Предупреждения о переполнении в логе osquery:
grep -iE 'lost|overflow|drop' /var/log/osquery/osqueryd.WARNING 2>/dev/null | tail -20
```

Если `probe_error > 1%` от `bpf_process_events` — увеличить буфер в `configs/osquery/osquery.conf.j2`:
```json
"bpf_perf_event_array_exp": "15",
"bpf_buffer_storage_size": "2048"
```
> `exp=15` потребляет ~512 МБ RAM на 4-ядерном хосте (128 МБ × 4 CPU).

### Конфигурация osquery не применилась

```bash
# Валидация конфига вручную:
osqueryd --config_path=/etc/osquery/osquery.conf --config_check --database_path=/tmp/check
rm -rf /tmp/check

# Просмотр текущего конфига:
cat /etc/osquery/osquery.conf | python3 -m json.tool | head -40
```
