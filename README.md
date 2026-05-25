# UEBA — стенд сбора событий безопасности

**Версия:** 0.9 · [Release Notes](docs/RELEASE_NOTES_0.9.md)

Инфраструктурная основа для UEBA-системы (User and Entity Behavior Analytics) со скорингом.
Собирает события с Linux-хостов, нормализует в **ECS 8.x** (Elastic Common Schema) и пишет в OpenSearch.

> **Совместимость с ECS:** все события нормализованы по ECS 8.11 — поля `event.*`, `process.*`, `user.*`, `network.*`, `file.*`, `host.*`. Индексы совместимы с Elastic Security и Kibana SIEM без дополнительных преобразований.

---

## Архитектура пайплайна

```
Linux-хост
  ├── auditd (kernel)
  │     └── /var/log/audit/audit.log
  │               └── fluent-bit
  │                     ├── auditd_merge.lua   — объединение по serial
  │                     ├── auditd_enrich.lua  — ECS 8.11 + process.entity_id
  │                     └── TCP 5045 ──────────────────────────────────┐
  │                                                                     │
  ├── osquery (diff-мониторинг)                                        │
  │     └── /var/log/osquery/osqueryd.results.log                      │
  │               └── fluent-bit                                       │
  │                     ├── osquery_enrich.lua — ECS 8.11              │
  │                     └── TCP 5047 ──────────────────────────────────┤
  │                                                                     │
  └── [опц.] клиентские источники (freeipa / keycloak / docker / ...)  │
        └── fluent-bit (тот же процесс, base_stack в group_vars)     │
              └── TCP 5044 → Logstash-клиента → data_* (без изменений) │
                                                                        │
                                                              Logstash (UEBA)
                                                                        │
                                                                  OpenSearch
                                                         ├── fluent-audit-YYYY.MM.dd
                                                         └── fluent-osquery-YYYY.MM.dd
```

На **docker-хостах** (группа `[docker_hosts]`, ядро ≥ 5.10) osquery дополнительно использует BPF backend — таблицы `bpf_process_events`, `bpf_socket_events`, `docker_containers` с container-aware видимостью.

## Стек агентов

| Сервис | Роль | Индекс |
|--------|------|--------|
| **auditd** + **fluent-bit** | Kernel audit: execve, sudo, auth, network, file integrity; syscall-правила (io_uring, ptrace, memfd_create, bpf, process_vm) | `fluent-audit-*` |
| **osquery** + **fluent-bit** | Diff-мониторинг: процессы, соединения, пользователи, модули, cron, SSH-ключи, shell_history, пакеты; BPF events на docker-хостах | `fluent-osquery-*` |

**auditbeat не используется** — конфликтует с auditd за audit netlink-сокет.

---

## Развёртывание

### Предварительные требования

| Компонент | Требования |
|-----------|-----------|
| Logstash-хост | Debian/Ubuntu, Docker 24+, Docker Compose v2, пользователь в группе `docker` |
| Агентские хосты | Debian/Ubuntu, пользователь с sudo |
| Docker-хосты (опц.) | Ядро ≥ 5.10, `/sys/kernel/btf/vmlinux`, osquery ≥ 4.6 (для BPF backend) |
| Ansible (control node) | Ansible 2.14+, SSH-доступ к целевым хостам |

---

### 1. Logstash (Docker)

Logstash разворачивается в Docker на выделенном хосте и принимает события от всех агентов.
Деплой также автоматически применяет index templates в OpenSearch.

**Первоначальная настройка:**

```bash
cd logstash/deploy
cp inventory.ini.example inventory.ini           # указать IP хоста
cp group_vars/all.yml.example group_vars/all.yml  # указать URL OpenSearch
```

`group_vars/all.yml` — обязательные параметры:
```yaml
opensearch_url:  "https://opensearch.prod.example.com:9200"
opensearch_user: "logstash_writer"
```

CA-сертификат OpenSearch (не хранится в git):
```bash
cp /path/to/opensearch-ca.pem logstash/deploy/files/opensearch-ca.pem
```

Пароль через ansible-vault:
```bash
ansible-vault create logstash/deploy/host_vars/<hostname>.yml
# содержимое: opensearch_password: "<пароль>"
```

**Деплой:**
```bash
cd logstash/deploy
ansible-playbook logstash-deploy.yml --ask-vault-pass
```

Плейбук разворачивает Logstash и сразу применяет index templates (`fluent-audit`, `fluent-osquery`) через OpenSearch REST API.

**Проверка:**
```bash
# На Logstash-хосте:
docker ps --filter name=ueba-logstash
curl -sf http://localhost:9600/_node/stats | python3 -m json.tool | grep -A2 '"events"'
```

---

### 2. Агенты (auditd + fluent-bit + osquery)

**Первоначальная настройка:**

```bash
cd agents/deploy
cp inventory.ini.example inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
```

`group_vars/all.yml`:
```yaml
logstash_security_host: 10.0.0.5   # UEBA Logstash (порты 5045/5047)
logstash_common_host:   10.0.0.10  # Клиентский Logstash (порт 5044) — нужен если base_stack непустой
base_stack: []                   # [] = pure UEBA; [freeipa, docker_events, suricata, waf] — FreeIPA-хост и т.п.
osquery_version: "5.23.0"
fluent_bit_version: "5.x.x"
```

Для docker-хостов (BPF backend) создать `group_vars/docker_hosts.yml`:
```yaml
osquery_bpf_events_enabled: true
```

Для хостов с клиентскими источниками используются готовые group_vars:
- `group_vars/freeipa_hosts.yml` — FreeIPA + docker + suricata + waf
- `group_vars/keycloak_hosts.yml` — Keycloak container logs
- `group_vars/docker_event_hosts.yml` — Docker events + suricata + waf

**Подготовка пакетов (офлайн):**
```powershell
.\agents\deploy\fetch-packages\fetch.ps1
```

**Деплой:**
```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass
```

Плейбук устанавливает auditd, fluent-bit, osquery; раскладывает конфиги и Lua-скрипты; запускает сервисы.

**Проверка на агенте:**
```bash
systemctl status auditd fluent-bit osqueryd

# Метрики fluent-bit (pipeline health, состояние Lua-скриптов):
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool
```

---

## Проверка данных в OpenSearch

```bash
# Список индексов:
curl -s 'http://opensearch:9200/_cat/indices?v&index=fluent-*' | sort

# Первые события после запуска агентов:
# sudo <cmd>          → fluent-audit-*  (event.action: privilege_use)
# любой execve        → fluent-audit-*  (event.category: process)
# ssh user@host       → fluent-audit-*  (event.action: session_opened, event.module: auditd)
# osquery diff ~30с   → fluent-osquery-* (event.dataset: osquery.processes и пр.)
```

---

## OpenSearch Index Templates

Шаблоны индексов в [`opensearch/templates/`](opensearch/templates/) применяются автоматически при деплое Logstash (`logstash-deploy.yml`).

| Шаблон | Index Pattern | Версия |
|--------|---------------|--------|
| `fluent-audit.json` | `fluent-audit-*` | 2.0 |
| `fluent-osquery.json` | `fluent-osquery-*` | 2.0 |

Шаблоны фиксируют типы всех ECS-полей: `source.ip`/`destination.ip` как `ip`, `process.command_line` как `wildcard`, `event.module` как `constant_keyword`. Без шаблона OpenSearch угадывает типы по первому документу, что ломает CIDR-фильтры и агрегации.

Инструкция по ручному применению: [`opensearch/templates/README.md`](opensearch/templates/README.md).

---

## Известные ограничения

- **auditd 4.x**: не пишет `type=EOE` в audit.log. `auditd_merge.lua` использует wall-clock timeout для флаша буфера — не EOE.
- **TLS не настроен**: fluent-bit → Logstash по plaintext TCP. Задача P1-03 (mTLS) запланирована.
- **CA-сертификат** не хранится в git — положить вручную перед деплоем Logstash.
- **Офлайн-пакеты** (`*.deb`) не хранятся в git — перезапустить `fetch.ps1` при смене версий.
- **Index templates не применяются ретроактивно** — существующие индексы сохраняют старые маппинги до истечения retention.

### osquery BPF backend: переполнение буфера (docker-хосты)

На нагруженных docker-хостах eBPF perf-ring-буфер может переполняться, что приводит к **молчаливой потере событий** в `bpf_process_events` и `bpf_socket_events`.

**Диагностика:**

```bash
# probe_error=1 означает drop на уровне eBPF:
grep '"probe_error":"1"' /var/log/osquery/osqueryd.results.log | wc -l

# Сообщения о переполнении в логе osquery:
grep -iE 'lost|overflow|drop' /var/log/osquery/osqueryd.WARNING 2>/dev/null | tail -20

# В OpenSearch: фильтр osquery.probe_error:1
# Если > 1% от bpf_process_events — буфер мал.
```

**Параметры** (`agents/configs/osquery/osquery.conf.j2`, блок `{% if osquery_bpf_events_enabled %}`):

| Параметр | Значение | Описание |
|---|---|---|
| `bpf_perf_event_array_exp` | `14` | Размер perf ring-буфера: 2^N страниц × 4 КБ на каждое CPU (14 → 64 МБ/CPU) |
| `bpf_buffer_storage_size` | `1024` | Внутренний буфер osquery в МБ |

Рекомендуемые значения для busy-хостов: `bpf_perf_event_array_exp: 15`, `bpf_buffer_storage_size: 2048`.

> **Память:** `bpf_perf_event_array_exp=15` на 4-ядерном хосте потребляет ~512 МБ RAM под perf-буферы.
