# QA-01. Аудит полей OpenSearch — проверка качества данных

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор по проекту и стеку агентов.
- [README_FOR_AI.md](../README_FOR_AI.md) — источник истины по ECS-схеме.
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — все поля, которые должен проставить enrich.
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) — то же для osquery.

Инструмент для HTTP-запросов — **Bash + curl** (OpenSearch без TLS, без auth).

## Цель

Последовательно обойти индексы `fluent-audit-*` и `fluent-osquery-*`. Для каждой уникальной пары **`event.dataset` + `event.category`** взять 3–5 реальных документов и проверить каждое поле на адекватность. Зафиксировать все аномалии.

Пара `event.dataset + event.category` — единица наблюдения: именно она определяет, какой источник (`auditd` / `osquery.shell_history` / `osquery.bpf_process_events` и т.д.) и какой тип события (`process` / `network` / `iam` и т.д.) сгенерировал документ.

Результат итерации — письменный отчёт прямо в диалоге: по одной секции на каждую пару с оценкой **OK / WARN / FAIL** для каждого поля.

---

## Шаг 0. Параметры

Уточнить у пользователя:

1. **URL OpenSearch** — по умолчанию `http://localhost:9200`. Если другой — спросить явно.
2. **Дата индекса** — обычно сегодняшняя (`YYYY.MM.dd`), но может быть несколько дней. Сначала проверить, какие индексы существуют.

Далее используй переменную `OS` для URL, например `OS=http://localhost:9200`.

---

## Шаг 1. Проверка инфраструктуры

### 1.1 Доступность кластера

```bash
curl -s "$OS/_cluster/health?pretty"
```

Ожидание: `"status": "green"` или `"yellow"` (одна нода — yellow нормально).
**FAIL** если `"status": "red"` или нет ответа.

### 1.2 Наличие index templates

```bash
curl -s "$OS/_cat/templates?v&name=fluent-*"
```

Ожидание: строки `fluent-audit` (priority 200) и `fluent-osquery` (priority 200).
**FAIL** если шаблонов нет — данные попали под dynamic mapping, типы полей могут быть неверными.

### 1.3 Список индексов и объём данных

```bash
curl -s "$OS/_cat/indices?v&index=fluent-*&s=index"
```

Записать: какие индексы есть, сколько документов, статус. Если индексов нет — остановиться и сообщить пользователю.

---

## Шаг 2. Аудит `fluent-audit-*`

### 2.1 Все пары event.dataset + event.category

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "by_dataset": {
        "terms": { "field": "event.dataset", "size": 10 },
        "aggs": {
          "by_category": { "terms": { "field": "event.category", "size": 15 } }
        }
      },
      "by_action":        { "terms": { "field": "event.action", "size": 30 } },
      "by_type":          { "terms": { "field": "event.type",   "size": 10 } },
      "missing_dataset":  { "missing": { "field": "event.dataset"  } },
      "missing_category": { "missing": { "field": "event.category" } }
    }
  }'
```

Записать все найденные пары `event.dataset / event.category` — это список секций для шага 2.2.
Для `fluent-audit-*` `event.dataset` всегда `"auditd"`, категории: `process`, `network`, `file`, `authentication`, `iam`, `host`, `session`, `configuration`.
**WARN** если `event.category` вне этого набора.
**FAIL** если `missing_dataset.doc_count > 0` или `missing_category.doc_count > 0`.

### 2.2 Проверка каждой пары dataset / category

Для **каждой** пары из результата 2.1 выполнить следующий блок.
Подставить конкретные значения вместо `DATASET` и `CATEGORY`:

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 5,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset":  "DATASET"  } },
          { "term": { "event.category": "CATEGORY" } }
        ]
      }
    },
    "sort": [{ "@timestamp": { "order": "desc" } }]
  }'
```

Для каждого из 3–5 полученных документов проверить поля согласно таблице ниже.

#### Матрица проверок для fluent-audit-*

**Базовые поля (обязательны для ВСЕХ событий):**

| Поле | Ожидаемое значение / условие | Аномалия |
|------|------------------------------|----------|
| `@timestamp` | ISO 8601, не старше 24 ч | пусто / старые данные |
| `ecs.version` | `"8.11"` | любое другое |
| `event.kind` | `"event"` | любое другое |
| `event.dataset` | `"auditd"` | любое другое |
| `event.module` | `"auditd"` | любое другое |
| `event.category` | строка из ECS-набора | пусто, null |
| `event.type` | строка из ECS-набора | пусто, null |
| `host.name` | непустой hostname | пусто, `"localhost"` |
| `host.os.type` | `"linux"` | любое другое |
| `tags` | массив содержит `"auditd"` | пусто / не массив |

**Поля категории `process`:**

| Поле | Ожидание | Аномалия |
|------|----------|----------|
| `process.pid` | целое число > 0 | пусто, строка, 0 |
| `process.executable` | путь начиная с `/` | пусто, `"(null)"` |
| `process.name` | непустая строка | пусто |
| `process.entity_id` | непустая строка ≈16 символов | пусто → проверить холодный старт |
| `event.action` | syscall name (execve, fork…) | пусто |
| `process.args` | массив строк (для execve) | пусто при `event.action=execve` |
| `process.command_line` | непустая строка | пусто при наличии `process.args` |
| `labels.entity_id_source` | поле **не должно** присутствовать в норме | `"event_timestamp_fallback"` → fallback сработал |

**Поля категории `network`:**

| Поле | Ожидание | Аномалия |
|------|----------|----------|
| `destination.ip` или `source.ip` | хотя бы одно непустое | оба пусты |
| `network.type` | `"ipv4"` или `"ipv6"` | пусто, другое |
| `event.action` | `connect`, `bind`, `accept` | пусто |
| `process.pid` | целое число | пусто |

**Поля категории `file`:**

| Поле | Ожидание | Аномалия |
|------|----------|----------|
| `file.path` | абсолютный путь | пусто, относительный |
| `file.name` | имя файла без `/` | пусто при наличии `file.path` |
| `event.action` | `openat`, `unlink`, `mkdir`… | пусто |

**Поля категории `authentication` / `session`:**

| Поле | Ожидание | Аномалия |
|------|----------|----------|
| `user.name` | непустая строка | пусто |
| `user.id` | строка, число 0–65535 | пусто, `"4294967295"`, `"-1"` — unset UID протёк |
| `event.outcome` | `success` или `failure` | пусто (желательно) |
| `auditd.session` | целое число > 0 | пусто (WARN) |

**Поля категории `iam`:**

| Поле | Ожидание | Аномалия |
|------|----------|----------|
| `user.id` | строка, число 0–65535 | пусто, `"4294967295"` |
| `event.action` | `setuid`, `setreuid`, `setresuid` | пусто |

### 2.3 Проверка критических пустот через aggregations

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset":  "auditd"  } },
          { "term": { "event.category": "process" } }
        ]
      }
    },
    "aggs": {
      "total":             { "value_count": { "field": "process.pid" } },
      "missing_pid":       { "missing": { "field": "process.pid" } },
      "missing_exe":       { "missing": { "field": "process.executable" } },
      "missing_entity_id": { "missing": { "field": "process.entity_id" } },
      "entity_id_fallback":{ "filter":  { "exists": { "field": "labels.entity_id_source" } } }
    }
  }'
```

Интерпретация:
- `missing_pid` > 0 → **FAIL** — основное поле теряется.
- `missing_exe` / total > 30% → **WARN** — много событий без исполняемого файла (нормально для короткоживущих процессов).
- `missing_entity_id` / total > 50% → **WARN** — возможен cold start или баг в proc_common.
- `entity_id_fallback` > 5% от total → **WARN** — процессы завершаются быстрее, чем enrich успевает прочитать `/proc/<pid>/stat`.

То же самое выполнить для пары `auditd / network` (проверить `destination.ip`, `source.ip`, `network.type`).

---

## Шаг 3. Аудит `fluent-osquery-*`

### 3.1 Все пары event.dataset + event.category

```bash
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "by_dataset": {
        "terms": { "field": "event.dataset", "size": 30 },
        "aggs": {
          "by_category": { "terms": { "field": "event.category", "size": 10 } }
        }
      },
      "by_query":           { "terms": { "field": "osquery.result.name",   "size": 40 } },
      "by_result_action":   { "terms": { "field": "osquery.result.action", "size":  5 } },
      "missing_dataset":    { "missing": { "field": "event.dataset"        } },
      "missing_category":   { "missing": { "field": "event.category"       } },
      "missing_query_name": { "missing": { "field": "osquery.result.name"  } }
    }
  }'
```

Записать все найденные пары `event.dataset / event.category` — это список секций для шага 3.2.
Ожидаемые `event.dataset` для osquery: `osquery`, `osquery.shell_history`, `osquery.last`, `osquery.process_envs`, `osquery.bpf_process_events`, `osquery.bpf_socket_events`, `osquery.docker_containers`, `osquery.deb_packages`, `osquery.python_packages`, `osquery.sudoers`, `osquery.kernel_keys` и др.
**FAIL** если `missing_dataset > 0`, `missing_category > 0` или `missing_query_name > 0`.

### 3.2 Проверка каждой пары dataset / category

Для **каждой** пары из результата 3.1 (приоритет: `osquery/process`, `osquery.shell_history/process`, `osquery.bpf_process_events/process`, `osquery.bpf_socket_events/network`, `osquery.docker_containers/host`, `osquery.last/authentication`, `osquery.deb_packages/package`):

```bash
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset":  "DATASET"  } },
          { "term": { "event.category": "CATEGORY" } }
        ]
      }
    },
    "sort": [{ "@timestamp": { "order": "desc" } }]
  }'
```

#### Матрица проверок для fluent-osquery-*

**Базовые поля (обязательны для ВСЕХ событий):**

| Поле | Ожидание | Аномалия |
|------|----------|----------|
| `@timestamp` | ISO 8601 | пусто |
| `ecs.version` | `"8.11"` | другое |
| `event.kind` | `"event"` | другое |
| `event.module` | `"osquery"` | другое |
| `event.category` | строка из ECS-набора | пусто |
| `event.type` | строка из ECS-набора | пусто |
| `event.action` | осмысленная строка | пусто |
| `event.dataset` | начинается с `"osquery"` | пусто |
| `host.name` | непустой hostname | пусто |
| `osquery.result.name` | имя запроса | пусто |
| `osquery.result.action` | `"added"` или `"removed"` | другое |
| `tags` | содержит `"osquery"` | пусто / не массив |
| `columns` | поле **не должно** присутствовать | присутствует → Lua очистка не сработала |
| `decorations` | поле **не должно** присутствовать | присутствует → то же |

**Специфичные поля по паре dataset / category:**

| `event.dataset` | `event.category` | Обязательные ECS-поля | Аномалия |
|-----------------|------------------|-----------------------|----------|
| `osquery` | `process` | `process.pid` (int), `process.name`, `process.executable` | пусто / строковый pid |
| `osquery` | `network` | `process.pid`, `destination.ip`, `destination.port` | пусто |
| `osquery` | `network` (listening) | `destination.port` (int), `network.transport` | пусто |
| `osquery` | `authentication` | `user.name` | пусто |
| `osquery` | `iam` | `user.name`, `user.id` | пусто |
| `osquery` | `iam` (ssh_keys) | `user.name`, `file.path` | пусто |
| `osquery` | `configuration` | `osquery.name` (kernel module) | пусто |
| `osquery.shell_history` | `process` | `process.command_line`, `user.name`, `file.path` | пусто |
| `osquery.last` | `authentication` | `user.name` | пусто |
| `osquery.docker_containers` | `host` | `container.id` (12 hex), `container.name`, `container.image.name` | пусто / неверный формат |
| `osquery.bpf_process_events` | `process` | `process.pid`, `process.executable`, `container.id` | пусто |
| `osquery.bpf_socket_events` | `network` | `process.pid`, `network.transport` | пусто |
| `osquery.deb_packages` | `package` | `package.name`, `package.version` | пусто |
| `osquery.python_packages` | `package` | `package.name` | пусто |
| `osquery.process_envs` | `process` | `process.pid`, `process.env.key` | пусто |
| `osquery.process_memory_map` | `process` | `process.pid`, `file.path` | пусто |

---

## Шаг 4. Глобальные проверки

### 4.1 Согласованность host.name между индексами

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{ "size": 0, "aggs": { "hosts": { "terms": { "field": "host.name", "size": 20 } } } }'

curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{ "size": 0, "aggs": { "hosts": { "terms": { "field": "host.name", "size": 20 } } } }'
```

Ожидание: одинаковые имена хостов в обоих индексах.
**WARN** если расхождение — `process.entity_id` не будет совпадать при cross-index корреляции.

### 4.2 Совпадение entity_id между auditd и osquery

Найти в audit любой `process.pid` из недавних `execve` событий:

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1,
    "query": { "term": { "event.action": "execve" } },
    "sort":  [{ "@timestamp": { "order": "desc" } }],
    "_source": ["process.pid", "process.entity_id", "host.name", "@timestamp"]
  }'
```

Взять `process.pid` из ответа. Найти тот же pid в osquery:

```bash
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "bool": {
        "must": [
          { "term": { "osquery.result.name": "processes" } },
          { "term": { "process.pid": PID_FROM_ABOVE } }
        ]
      }
    },
    "_source": ["process.pid", "process.entity_id", "host.name"]
  }'
```

Ожидание: `process.entity_id` совпадает в обоих индексах для одного `host.name + pid`.
**WARN** если не совпадает — обращать внимание при UEBA-корреляции.

### 4.3 Проверка типов полей (маппинги)

```bash
curl -s "$OS/fluent-audit-*/_mapping?pretty" | grep -A2 '"process.pid"'
curl -s "$OS/fluent-audit-*/_mapping?pretty" | grep -A2 '"destination.port"'
curl -s "$OS/fluent-osquery-*/_mapping?pretty" | grep -A2 '"process.pid"'
```

Ожидание: `"type": "integer"` или `"type": "long"` для pid/port полей.
**FAIL** если `"type": "keyword"` или `"type": "text"` — Logstash convert не отработал или шаблон не применялся до первого документа.

---

## Шаг 5. Итоговый отчёт

Сформировать и вывести в диалог отчёт в следующем формате:

```
=== UEBA DATA QUALITY REPORT ===
OpenSearch: http://...
Индексы: fluent-audit-YYYY.MM.dd (N docs), fluent-osquery-YYYY.MM.dd (N docs)

--- fluent-audit-* ---
Пары dataset/category: auditd/process (N), auditd/network (N), auditd/file (N), ...

[auditd / process]
  OK   @timestamp, ecs.version, event.kind, host.name, tags
  OK   process.pid — целые числа, нет нулей
  WARN process.entity_id — 35% missing (холодный старт fluent-bit)
  OK   process.executable — пути вида /usr/bin/...
  ...

[auditd / network]
  OK   destination.ip — IPv4 адреса
  FAIL network.type   — отсутствует в 80% событий
  ...

--- fluent-osquery-* ---
Пары dataset/category: osquery/process (N), osquery.shell_history/process (N), ...

[osquery / process]
  OK   process.pid, process.name, process.executable
  WARN process.entity_id — 20% missing
  ...

[osquery.shell_history / process]
  OK   process.command_line — команды пользователей
  WARN user.name — 10% missing
  ...

[osquery.bpf_process_events / process]
  OK   process.pid, process.executable
  WARN container.id — 60% missing (нет docker_containers diff ещё в кэше)
  ...

--- ИТОГ ---
FAIL  N критичных проблем (данные неверны/теряются)
WARN  N предупреждений (данные есть, но могут потерять качество)
OK    N пар dataset/category без замечаний
```

Для каждого **FAIL** — добавить гипотезу причины (из знания о стеке: auditd_enrich.lua, merge.lua, Logstash convert, index template).

---

## Критерии завершения

- Все индексы с данными проверены.
- Каждая уникальная пара `event.dataset + event.category` из обоих индексов имеет свою запись в отчёте.
- Для каждого FAIL/WARN есть гипотеза причины.
- Отчёт выведен в диалог.
