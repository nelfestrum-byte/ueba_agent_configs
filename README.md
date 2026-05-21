# UEBA — стенд сбора событий безопасности

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
  │                     ├── auditd_enrich.lua  — ECS 8.x нормализация
  │                     └── TCP 5045 ──────────────────────┐
  │                                                         │
  ├── osquery (diff-мониторинг)                             │
  │     └── /var/log/osquery/osqueryd.results.log           │
  │               └── fluent-bit                            │
  │                     ├── osquery_enrich.lua — ECS 8.x    │
  │                     └── TCP 5047 ──────────────────────┤
  │                                                         │
  └── filebeat [временный, будет заменён на fluent-bit]     │
        └── /var/log/auth.log (SSH)                         │
              └── beats 5044 ──────────────────────────────┤
                                                            │
                                                     Logstash
                                                            │
                                                      OpenSearch
                                                 ├── fluent-audit-YYYY.MM.dd
                                                 ├── fluent-osquery-YYYY.MM.dd
                                                 └── filebeat-{ver}-YYYY.MM.dd
```

## Стек агентов

| Сервис | Роль | Индекс |
|--------|------|--------|
| **auditd** + **fluent-bit** | Kernel audit: execve, sudo, auth, файловые события | `fluent-audit-*` |
| **osquery** + **fluent-bit** | Diff-мониторинг: процессы, соединения, пользователи, модули, cron, SSH-ключи | `fluent-osquery-*` |
| **fluent-bit** | SSH auth.log → sshd_enrich.lua | `system-auth-*` |

---

## Развёртывание

### Предварительные требования

| Компонент | Требования |
|-----------|-----------|
| Logstash-хост | Debian/Ubuntu, Docker 24+, Docker Compose v2, пользователь `installer` в группе `docker` |
| Агентские хосты | Debian/Ubuntu, пользователь с sudo |
| Ansible (control node) | Ansible 2.14+, доступ по SSH к целевым хостам |

---

### 1. Logstash (Docker)

Logstash разворачивается в Docker на выделенном хосте и принимает события от всех агентов.

**Первоначальная настройка:**

```bash
cd logstash/deploy
cp inventory.ini.example inventory.ini     # указать IP хоста
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

**Проверка:**
```bash
# На Logstash-хосте:
docker ps --filter name=ueba-logstash
curl -sf http://localhost:9600/_node/stats | python3 -m json.tool | grep -A2 '"events"'
```

---

### 2. Агенты (auditd + fluent-bit + filebeat + osquery)

**Первоначальная настройка:**

```bash
cd agents/deploy
cp inventory.ini.example inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
```

`group_vars/all.yml`:
```yaml
logstash_host:    10.0.0.5      # IP/hostname Logstash
elastic_version:  "9.4.1"
filebeat_arch:    "amd64"       # или arm64
osquery_version:  "5.23.0"
```

**Подготовка пакетов (офлайн):**
```powershell
.\agents\deploy\fetch-packages\fetch.ps1
```

**Деплой:**
```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass
```

Плейбук: устанавливает и настраивает auditd, fluent-bit, filebeat, osquery; раскладывает конфиги и Lua-скрипты; запускает сервисы.

**Проверка на агенте:**
```bash
systemctl status auditd fluent-bit filebeat osqueryd

# Метрики fluent-bit (включая состояние Lua-скриптов):
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool

# Диагностика: если filter.lua.0.add_records = 0 при ненулевом input.tail.0.records
# — merge-скрипт не флашит буфер. Проверить auditd_merge.lua timeout.
```

---

### 3. Dev-стенд (OpenSearch + Logstash локально)

Для разработки и тестирования пайплайна без реальных агентов:

```bash
cd dev_stand
docker compose up -d
docker compose logs -f logstash
```

OpenSearch Dashboards: http://localhost:5601

Тестовые события можно отправить скриптами из `dev_stand/scripts/`.

---

## Проверка данных в OpenSearch

```bash
# Список индексов:
curl -s 'http://opensearch:9200/_cat/indices?v&index=fluent-*,filebeat-*' | sort

# Первые события после запуска:
# ssh <host>         → filebeat-* (system.auth)
# sudo <cmd>         → fluent-audit-* (event.action: sudo / privilege_use)
# любой execve       → fluent-audit-* (event.category: process)
# osquery diff ~30с  → fluent-osquery-* (event.dataset: osquery)
```

---

## OpenSearch Index Templates

Готовые шаблоны индексов лежат в [`opensearch/templates/`](opensearch/templates/):

| Шаблон | Index Pattern |
|--------|---------------|
| `fluent-audit.json` | `fluent-audit-*` |
| `fluent-osquery.json` | `fluent-osquery-*` |
| `filebeat-auth.json` | `filebeat-*` |

Применяются вручную через OpenSearch REST API. Инструкция: [`opensearch/templates/README.md`](opensearch/templates/README.md).

```bash
# Пример применения одного шаблона:
curl -u admin:password -X PUT "https://opensearch:9200/_index_template/fluent-audit" \
  -H "Content-Type: application/json" --data-binary @opensearch/templates/fluent-audit.json
```

---

## Известные ограничения

- **auditd 4.x**: не пишет `type=EOE` в audit.log. `auditd_merge.lua` использует wall-clock timeout (не EOE) для флаша буфера.
- **TLS не настроен**: fluent-bit → Logstash по TCP без шифрования. Для прода использовать beats-протокол с mTLS.
- **CA-сертификат** не хранится в git — положить вручную перед деплоем Logstash.
- **Офлайн-пакеты** (`*.deb`) не хранятся в git — перезапустить `fetch.ps1` при смене версий.

### ⚠️ osquery BPF backend: переполнение буфера (docker-хосты)

На нагруженных docker-хостах eBPF perf-ring-буфер может переполняться, что приводит к **молчаливой потере событий** в `bpf_process_events` и `bpf_socket_events`.

**Диагностика:**

```bash
# 1. События с ошибкой пробы — probe_error=1 означает drop на уровне eBPF:
grep '"probe_error":"1"' /var/log/osquery/osqueryd.results.log | wc -l

# 2. Сообщения о переполнении в логе osquery:
grep -iE 'lost|overflow|drop' /var/log/osquery/osqueryd.WARNING 2>/dev/null | tail -20

# 3. В OpenSearch Dashboards: фильтр osquery.probe_error:1
#    Если таких событий > 1% от bpf_process_events — буфер мал.
```

**Параметры и где менять:**

Файл: `agents/configs/osquery/osquery.conf.j2`, блок `{% if osquery_bpf_events_enabled %}` в секции `options`:

| Параметр | Текущее значение | Описание | Когда увеличить |
|---|---|---|---|
| `bpf_perf_event_array_exp` | `14` | Размер perf ring-буфера: 2^N страниц × 4 КБ **на каждое CPU**. Значение 14 → 64 МБ/CPU | Много короткоживущих процессов (CI/CD), `probe_error` > 0 |
| `bpf_buffer_storage_size` | `1024` | Внутренний буфер osquery в МБ для BPF-событий до их записи в лог | Высокий throughput сокет-событий |

```jsonc
// agents/configs/osquery/osquery.conf.j2 — рекомендуемые значения для busy-хостов:
"bpf_perf_event_array_exp": "15",   // 128 МБ/CPU (было 14 → 64 МБ/CPU)
"bpf_buffer_storage_size": "2048",  // 2 ГБ (было 1024)
```

После изменения — раскатить и перезапустить osqueryd:

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass --limit=<docker-host> --tags=osquery
```

> **Память:** `bpf_perf_event_array_exp=15` на 4-ядерном хосте потребляет ~512 МБ RAM только под perf-буферы. Увеличивать осторожно на хостах с ограниченной памятью.
