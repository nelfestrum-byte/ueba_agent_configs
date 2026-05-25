# QA-01b. Аудит полей OpenSearch — тройной ключ группировки

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор по проекту и стеку агентов.
- [README_FOR_AI.md](../README_FOR_AI.md) — источник истины по ECS-схеме.
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — все поля, которые должен проставить enrich.
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) — то же для osquery.

Инструмент для HTTP-запросов — **Bash + curl** (OpenSearch без TLS, без auth).

## Цель

Последовательно обойти индексы `fluent-audit-*` и `fluent-osquery-*`. Для каждого уникального тройного ключа **`event.dataset` + `event.category` + `event.action`** взять 3–5 реальных документов и проверить каждое поле на адекватность. Зафиксировать все аномалии.

Тройка `(event.dataset, event.category, event.action)` — единица наблюдения. Именно она охватывает все варианты типов событий внутри одного источника и категории: например, `auditd / process / execve` и `auditd / process / fork` могут иметь разный набор заполненных полей и разные ожидания.

Результат итерации — письменный отчёт прямо в диалоге: по одной секции на каждую тройку с оценкой **OK / WARN / FAIL** для каждого поля.

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

### 2.1 Все тройки event.dataset + event.category + event.action

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "by_dataset": {
        "terms": { "field": "event.dataset", "size": 10 },
        "aggs": {
          "by_category": {
            "terms": { "field": "event.category", "size": 15 },
            "aggs": {
              "by_action": { "terms": { "field": "event.action", "size": 40 } }
            }
          }
        }
      },
      "by_type":          { "terms": { "field": "event.type",   "size": 10 } },
      "missing_dataset":  { "missing": { "field": "event.dataset"  } },
      "missing_category": { "missing": { "field": "event.category" } },
      "missing_action":   { "missing": { "field": "event.action"   } }
    }
  }'
```

Записать все найденные тройки `(event.dataset, event.category, event.action)` — это список секций для шага 2.2.

Ожидаемые тройки для `fluent-audit-*`:

| event.dataset | event.category | event.action (примеры) |
|---------------|----------------|------------------------|
| `auditd` | `process` | `execve`, `fork`, `clone`, `exit`, `exit_group`, `ptrace`, `prctl`, `memfd_create` |
| `auditd` | `network` | `connect`, `bind`, `accept`, `sendto`, `recvfrom`, `socket` |
| `auditd` | `network` (AF_UNIX) | `connect_unix`, `bind_unix` |
| `auditd` | `network` (AF_NETLINK) | `connect_netlink` |
| `auditd` | `file` | `openat`, `open`, `unlink`, `unlinkat`, `mkdir`, `mkdirat`, `rename`, `renameat2`, `chmod`, `chown`, `truncate` |
| `auditd` | `authentication` | `user_auth`, `user_login`, `user_logout`, `user_end`, `user_start`, `user_acct` |
| `auditd` | `iam` | `setuid`, `setreuid`, `setresuid`, `setgid`, `setregid`, `setresgid` |
| `auditd` | `host` | `system_boot`, `system_shutdown`, `system_runlevel` |
| `auditd` | `session` | `user_start`, `user_end` |
| `auditd` | `configuration` | `sysctl`, `audit_rule_change` |

**WARN** если `event.action` вне ожидаемого набора для данной категории.
**FAIL** если `missing_dataset.doc_count > 0`, `missing_category.doc_count > 0` или `missing_action.doc_count > 0`.

Перед переходом к 2.2 — дополнительно проверить распределение тройок: если какая-то action встречается < 3 раз, отметить как редкую (статистика может быть ненадёжной).

### 2.2 Проверка каждой тройки dataset / category / action

Для **каждой** тройки из результата 2.1 выполнить следующий блок.
Подставить конкретные значения вместо `DATASET`, `CATEGORY`, `ACTION`:

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 5,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset":  "DATASET"  } },
          { "term": { "event.category": "CATEGORY" } },
          { "term": { "event.action":   "ACTION"   } }
        ]
      }
    },
    "sort": [{ "@timestamp": { "order": "desc" } }]
  }'
```

Для каждого из 3–5 полученных документов проверить поля согласно таблицам ниже.

#### Матрица базовых полей (обязательны для ВСЕХ тройек)

| Поле | Ожидаемое значение / условие | Аномалия |
|------|------------------------------|----------|
| `@timestamp` | ISO 8601, не старше 24 ч | пусто / старые данные |
| `ecs.version` | `"8.11"` | любое другое |
| `event.kind` | `"event"` | любое другое |
| `event.dataset` | `"auditd"` | любое другое |
| `event.module` | `"auditd"` | любое другое |
| `event.category` | строка из ECS-набора | пусто, null |
| `event.type` | строка из ECS-набора | пусто, null |
| `event.action` | непустая строка | пусто, null |
| `host.name` | непустой hostname | пусто, `"localhost"` |
| `host.os.type` | `"linux"` | любое другое |
| `tags` | массив содержит `"auditd"` | пусто / не массив |

#### Матрица специфичных полей по action (категория `process`)

| event.action | Обязательные поля | Опциональные / контекстные | Аномалия |
|--------------|-------------------|----------------------------|----------|
| `execve` | `process.pid` (int>0), `process.executable` (путь `/`), `process.name`, `process.entity_id` | `process.args` (массив), `process.command_line`, `process.parent.pid`, `process.parent.entity_id` | `process.args` пусто; `process.command_line` пусто при наличии `args`; `labels.entity_id_source="event_timestamp_fallback"` |
| `fork`, `clone` | `process.pid`, `process.parent.pid` | `process.entity_id`, `process.parent.entity_id` | `process.parent.pid` пусто |
| `exit`, `exit_group` | `process.pid` | `process.exit_code` (int), `process.entity_id` | `process.exit_code` пусто (WARN) |
| `ptrace` | `process.pid`, `process.name` | `process.parent.pid` | пусто |
| `prctl` | `process.pid` | `process.name` | пусто |
| `memfd_create` | `process.pid`, `process.name` | — | пусто |
| `ebpf_use` | `process.pid`, `process.executable` | — | `exe=/usr/bin/osqueryd` → feedback loop (см. CLAUDE.md) |

#### Матрица специфичных полей по action (категория `network`)

| event.action | Обязательные поля | Аномалия |
|--------------|-------------------|----------|
| `connect` (AF_INET/6) | `destination.ip`, `destination.port` (int), `network.type` (`ipv4`/`ipv6`), `network.transport`, `process.pid` | IP пусто; `network.type` пусто |
| `bind` (AF_INET/6) | `destination.port` (int), `network.type`, `network.transport`, `process.pid` | `destination.port` пусто |
| `accept` (AF_INET/6) | `source.ip`, `source.port` (int), `network.type`, `process.pid` | `source.ip` пусто |
| `sendto`, `recvfrom` | `destination.ip` или `source.ip`, `process.pid` | оба IP пусты |
| `socket` | `network.type`, `network.transport`, `process.pid` | пусто |
| `connect_unix`, `bind_unix` | `process.pid`, `network.type=unix`, `event.category` содержит `["network","file"]` | `network.type` не `unix`; категория не массив |
| `connect_netlink` | `process.pid`, `network.type=netlink`, `event.category=process` | `event.category` не `process` для netlink |

#### Матрица специфичных полей по action (категория `file`)

| event.action | Обязательные поля | Аномалия |
|--------------|-------------------|----------|
| `openat`, `open` | `file.path` (абс.), `file.name`, `process.pid` | `file.path` пусто или относительный |
| `unlink`, `unlinkat` | `file.path`, `process.pid` | пусто |
| `mkdir`, `mkdirat` | `file.path`, `process.pid` | пусто |
| `rename`, `renameat2` | `file.path`, `process.pid` | пусто |
| `chmod`, `fchmodat` | `file.path`, `process.pid` | пусто |
| `chown`, `fchownat` | `file.path`, `process.pid` | пусто |
| `truncate`, `ftruncate` | `file.path`, `process.pid` | пусто |

#### Матрица специфичных полей по action (категория `authentication` / `session`)

| event.action | Обязательные поля | Аномалия |
|--------------|-------------------|----------|
| `user_auth`, `user_login` | `user.name`, `event.outcome` (`success`/`failure`), `auditd.session` | `user.name` пусто; `event.outcome` пусто; `user.id = "4294967295"` — unset UID |
| `user_logout`, `user_end` | `user.name`, `auditd.session` | пусто |
| `user_start`, `user_acct` | `user.name` | пусто |
| `user_cmd` | `user.name`, `user.target.name` (sudo target), `process.command_line` | `user.target.name` пусто при sudo |

#### Матрица специфичных полей по action (категория `iam`)

| event.action | Обязательные поля | Аномалия |
|--------------|-------------------|----------|
| `setuid`, `setreuid`, `setresuid` | `user.id`, `user.target.id`, `process.pid` | пусто; `user.id = "4294967295"` |
| `setgid`, `setregid`, `setresgid` | `user.id`, `process.pid` | пусто |

### 2.3 Проверка критических пустот через aggregations (по каждому action)

Для каждого `event.action` в категории `process` выполнить:

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset":  "auditd"  } },
          { "term": { "event.category": "process" } },
          { "term": { "event.action":   "ACTION"  } }
        ]
      }
    },
    "aggs": {
      "total":             { "value_count": { "field": "process.pid" } },
      "missing_pid":       { "missing": { "field": "process.pid" } },
      "missing_exe":       { "missing": { "field": "process.executable" } },
      "missing_entity_id": { "missing": { "field": "process.entity_id" } },
      "entity_id_fallback":{ "filter":  { "exists": { "field": "labels.entity_id_source" } } },
      "missing_args":      { "missing": { "field": "process.args" } }
    }
  }'
```

Интерпретация:
- `missing_pid` > 0 → **FAIL** — основное поле теряется.
- `missing_exe` / total > 30% → **WARN** — много событий без исполняемого файла.
- `missing_entity_id` / total > 50% → **WARN** — возможен cold start или баг в proc_common.
- `entity_id_fallback` > 5% от total → **WARN** — fallback на `@timestamp`.
- Для `execve`: `missing_args` / total > 5% → **WARN** — args должны быть всегда при execve.

Аналогично для `auditd / network / connect` — проверить `destination.ip`, `destination.port`, `network.type`.

---

## Шаг 3. Аудит `fluent-osquery-*`

### 3.1 Все тройки event.dataset + event.category + event.action

```bash
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "by_dataset": {
        "terms": { "field": "event.dataset", "size": 30 },
        "aggs": {
          "by_category": {
            "terms": { "field": "event.category", "size": 10 },
            "aggs": {
              "by_action": { "terms": { "field": "event.action", "size": 30 } }
            }
          }
        }
      },
      "by_result_action":   { "terms": { "field": "osquery.result.action", "size":  5 } },
      "missing_dataset":    { "missing": { "field": "event.dataset"        } },
      "missing_category":   { "missing": { "field": "event.category"       } },
      "missing_action":     { "missing": { "field": "event.action"         } },
      "missing_query_name": { "missing": { "field": "osquery.result.name"  } }
    }
  }'
```

Записать все найденные тройки — это список секций для шага 3.2.

Ожидаемые тройки для `fluent-osquery-*`:

| event.dataset | event.category | event.action (примеры) |
|---------------|----------------|------------------------|
| `osquery` | `process` | `process_added`, `process_removed` |
| `osquery` | `network` | `network_connection_added`, `network_connection_removed`, `listening_port_added`, `listening_port_removed` |
| `osquery` | `authentication` | `user_logged_in`, `user_logged_out` |
| `osquery` | `iam` | `user_account_added`, `user_account_removed`, `group_added`, `group_removed`, `ssh_authorized_key_added`, `ssh_authorized_key_removed` |
| `osquery` | `configuration` | `kernel_module_loaded`, `kernel_module_unloaded`, `sudoers_added`, `sudoers_removed`, `cron_added`, `cron_removed` |
| `osquery` | `package` | `package_installed`, `package_removed` |
| `osquery.shell_history` | `process` | `command_executed` |
| `osquery.last` | `authentication` | `user_logged_in`, `user_logged_out` |
| `osquery.docker_containers` | `host` | `container_observed_added`, `container_observed_removed`, `container_exited` |
| `osquery.bpf_process_events` | `process` | `process_started`, `process_exited` |
| `osquery.bpf_socket_events` | `network` | `socket_connect`, `socket_bind`, `socket_accept`, `socket_connect_nonip`, `socket_bind_nonip` |
| `osquery.deb_packages` | `package` | `package_installed`, `package_removed` |
| `osquery.python_packages` | `package` | `package_installed`, `package_removed` |
| `osquery.kernel_keys` | `configuration` | `kernel_key_added`, `kernel_key_removed` |
| `osquery.process_envs` | `process` | `env_var_added`, `env_var_removed` |

**FAIL** если `missing_dataset > 0`, `missing_category > 0`, `missing_action > 0` или `missing_query_name > 0`.

Перед 3.2 — проверить: если `event.action` содержит `_added`/`_removed` — `osquery.result.action` должен совпадать (`added`/`removed`) в 100% случаев.

### 3.2 Проверка каждой тройки dataset / category / action

Для **каждой** тройки из результата 3.1:

```bash
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset":  "DATASET"  } },
          { "term": { "event.category": "CATEGORY" } },
          { "term": { "event.action":   "ACTION"   } }
        ]
      }
    },
    "sort": [{ "@timestamp": { "order": "desc" } }]
  }'
```

#### Матрица базовых полей (обязательны для ВСЕХ тройек osquery)

| Поле | Ожидание | Аномалия |
|------|----------|----------|
| `@timestamp` | ISO 8601 | пусто |
| `ecs.version` | `"8.11"` | другое |
| `event.kind` | `"event"` | другое |
| `event.module` | `"osquery"` | другое |
| `event.category` | строка из ECS-набора | пусто |
| `event.type` | строка из ECS-набора | пусто |
| `event.action` | непустая строка | пусто |
| `event.dataset` | начинается с `"osquery"` | пусто |
| `host.name` | непустой hostname | пусто |
| `osquery.result.name` | имя запроса | пусто |
| `osquery.result.action` | `"added"` или `"removed"` | другое |
| `tags` | содержит `"osquery"` | пусто / не массив |
| `columns` | поле **не должно** присутствовать | присутствует → Lua очистка не сработала |
| `decorations` | поле **не должно** присутствовать | присутствует → то же |

#### Матрица специфичных полей по тройке (osquery)

**Категория `process`:**

| event.dataset | event.action | Обязательные поля | Аномалия |
|---------------|--------------|-------------------|----------|
| `osquery` | `process_added`, `process_removed` | `process.pid` (int), `process.name`, `process.executable` | строковый pid; `process.executable` пусто |
| `osquery` | `process_added` | `process.entity_id` | пусто → WARN (cold start) |
| `osquery.shell_history` | `command_executed` | `process.command_line`, `user.name`, `file.path` | `process.command_line` пусто |
| `osquery.bpf_process_events` | `process_started` | `process.pid` (int), `process.executable`, `process.entity_id` | пусто; `labels.cmdline_source` должен быть `"osquery_bpf"` |
| `osquery.bpf_process_events` | `process_started` (container) | `container.id` (12 hex), `container.name` | пусто → WARN (cgroup_ns_cache промах) |
| `osquery.bpf_process_events` | `process_started` | `labels.cmdline_truncated` | если `= "argv0_only"` → WARN, не ошибка |
| `osquery.bpf_process_events` | `process_exited` | `process.pid`, `process.exit_code` (int) | exit_code как uint64 (>2^63) → FAIL, normalize_int64 не сработал |
| `osquery.process_envs` | `env_var_added`, `env_var_removed` | `process.pid`, `osquery.env_key` | пусто |

**Категория `network`:**

| event.dataset | event.action | Обязательные поля | Аномалия |
|---------------|--------------|-------------------|----------|
| `osquery` | `network_connection_added`, `network_connection_removed` | `process.pid`, `destination.ip`, `destination.port` (int) | строковый port; IP пусто |
| `osquery` | `listening_port_added`, `listening_port_removed` | `destination.port` (int), `network.transport` | строковый port |
| `osquery.bpf_socket_events` | `socket_connect`, `socket_bind`, `socket_accept` | `process.pid`, `network.transport`, `destination.ip` или `source.ip` | IP пусто |
| `osquery.bpf_socket_events` | `socket_connect_nonip`, `socket_bind_nonip` | `process.pid`, `event.category=process` | `event.category=network` → FAIL (должна быть реклассификация) |
| `osquery.bpf_socket_events` | `socket_connect_nonip` (AF_UNIX) | `network.type=unix` | пусто |
| `osquery.bpf_socket_events` | `socket_connect_nonip` (AF_NETLINK) | `network.type=netlink` | пусто |

**Категория `authentication`:**

| event.dataset | event.action | Обязательные поля | Аномалия |
|---------------|--------------|-------------------|----------|
| `osquery` | `user_logged_in`, `user_logged_out` | `user.name` | пусто |
| `osquery.last` | `user_logged_in`, `user_logged_out` | `user.name` | пусто |

**Категория `iam`:**

| event.dataset | event.action | Обязательные поля | Аномалия |
|---------------|--------------|-------------------|----------|
| `osquery` | `user_account_added`, `user_account_removed` | `user.name`, `user.id` | пусто |
| `osquery` | `group_added`, `group_removed` | `group.name`, `group.id` | пусто |
| `osquery` | `ssh_authorized_key_added`, `ssh_authorized_key_removed` | `user.name`, `file.path` | пусто |
| `osquery` | `sudoers_added`, `sudoers_removed` | `user.name` или `group.name` | оба пусты |

**Категория `host`:**

| event.dataset | event.action | Обязательные поля | Аномалия |
|---------------|--------------|-------------------|----------|
| `osquery.docker_containers` | `container_observed_added` | `container.id` (12 hex), `container.name`, `container.image.name` | формат container.id не 12 hex |
| `osquery.docker_containers` | `container_observed_removed` | `container.id`, `container.name` | пусто |
| `osquery.docker_containers` | `container_exited` | `container.id`, `osquery.state` (`exited`/`dead`) | `event.action=container_observed_removed` когда state=exited → WARN |

**Категория `configuration`:**

| event.dataset | event.action | Обязательные поля | Аномалия |
|---------------|--------------|-------------------|----------|
| `osquery` | `kernel_module_loaded`, `kernel_module_unloaded` | `osquery.name` (название модуля) | пусто |
| `osquery` | `cron_added`, `cron_removed` | `user.name`, `process.command_line` | пусто |
| `osquery.kernel_keys` | `kernel_key_added`, `kernel_key_removed` | `user.name` | `user.id` = UID число → `user.name` должен быть резолвнут через `uid_to_name` |

**Категория `package`:**

| event.dataset | event.action | Обязательные поля | Аномалия |
|---------------|--------------|-------------------|----------|
| `osquery.deb_packages` | `package_installed`, `package_removed` | `package.name`, `package.version` | пусто |
| `osquery.python_packages` | `package_installed`, `package_removed` | `package.name` | пусто |

---

## Шаг 4. Глобальные проверки

### 4.1 Полнота матрицы тройек — проверка ожидаемых action

После построения полного списка тройек из шагов 2.1 и 3.1 — проверить:

```bash
# Проверить, есть ли хотя бы по 1 документу для ключевых action
for action in execve fork connect bind accept openat unlink; do
  count=$(curl -s -X GET "$OS/fluent-audit-*/_count" \
    -H "Content-Type: application/json" \
    -d "{\"query\":{\"term\":{\"event.action\":\"$action\"}}}" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
  echo "auditd action=$action : $count docs"
done
```

Если `execve` — 0 документов → **FAIL** (auditd execve rule не работает или fluent-bit не читает лог).
Если `connect` — 0 документов → **WARN** (возможно нет сетевой активности в период теста).

### 4.2 Согласованность host.name между индексами

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

### 4.3 Совпадение entity_id между auditd/execve и osquery/process_added

```bash
# Шаг A: найти execve-событие с известным pid
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1,
    "query": { "term": { "event.action": "execve" } },
    "sort":  [{ "@timestamp": { "order": "desc" } }],
    "_source": ["process.pid", "process.entity_id", "host.name", "@timestamp"]
  }'
```

```bash
# Шаг B: найти тот же pid в osquery processes (подставить PID_FROM_ABOVE)
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset":  "osquery"          } },
          { "term": { "event.action":   "process_added"    } },
          { "term": { "process.pid":    PID_FROM_ABOVE     } }
        ]
      }
    },
    "_source": ["process.pid", "process.entity_id", "host.name"]
  }'
```

Ожидание: `process.entity_id` совпадает в обоих результатах для одного `host.name + pid`.
**WARN** если не совпадает — обращать внимание при UEBA-корреляции.

### 4.4 Проверка bpf_process_events → auditd execve correlation

```bash
# Найти bpf process_started и попробовать найти соответствующий auditd execve
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.dataset": "osquery.bpf_process_events" } },
          { "term": { "event.action":  "process_started" } }
        ],
        "must_not": [
          { "exists": { "field": "labels.cmdline_truncated" } }
        ]
      }
    },
    "sort": [{ "@timestamp": { "order": "desc" } }],
    "_source": ["process.pid", "process.entity_id", "process.command_line", "host.name", "@timestamp", "labels"]
  }'
```

Взять `process.pid` + `host.name` + `@timestamp`. Проверить наличие соответствующего `execve` в auditd в пределах ±2 секунд:

```bash
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "bool": {
        "must": [
          { "term": { "event.action": "execve" } },
          { "term": { "process.pid":  PID_FROM_ABOVE } },
          { "range": { "@timestamp": { "gte": "TS_MINUS_2S", "lte": "TS_PLUS_2S" } } }
        ]
      }
    },
    "_source": ["process.pid", "process.entity_id", "process.command_line", "host.name"]
  }'
```

Если `labels.cmdline_truncated = "argv0_only"` у bpf-события — сравнить `process.command_line` из auditd execve. **WARN** если entity_id не совпадают.

### 4.5 Проверка типов полей (маппинги)

```bash
curl -s "$OS/fluent-audit-*/_mapping?pretty" | grep -A2 '"process.pid"'
curl -s "$OS/fluent-audit-*/_mapping?pretty" | grep -A2 '"destination.port"'
curl -s "$OS/fluent-osquery-*/_mapping?pretty" | grep -A2 '"process.pid"'
curl -s "$OS/fluent-osquery-*/_mapping?pretty" | grep -A2 '"osquery.exit_code"'
```

Ожидание: `"type": "integer"` или `"type": "long"` для pid/port/exit_code полей.
**FAIL** если `"type": "keyword"` или `"type": "text"` — Logstash convert не отработал или шаблон не применялся до первого документа.

Дополнительно проверить `osquery.exit_code` на значения > 2^63 (признак бага normalize_int64):

```bash
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "range": { "process.exit_code": { "gte": 9223372036854775807 } }
    },
    "_source": ["event.dataset", "event.action", "process.exit_code", "osquery.exit_code"]
  }'
```

Если есть результаты → **FAIL** (normalize_int64 в osquery_enrich.lua не декодировал uint64 overflow).

---

## Шаг 5. Итоговый отчёт

Сформировать и вывести в диалог отчёт в следующем формате:

```
=== UEBA DATA QUALITY REPORT (triple key) ===
OpenSearch: http://...
Индексы: fluent-audit-YYYY.MM.dd (N docs), fluent-osquery-YYYY.MM.dd (N docs)

--- fluent-audit-* ---
Тройки dataset/category/action:
  auditd/process/execve (N)
  auditd/process/fork (N)
  auditd/network/connect (N)
  auditd/network/bind (N)
  auditd/file/openat (N)
  auditd/authentication/user_auth (N)
  ...

[auditd / process / execve]
  OK   @timestamp, ecs.version, event.kind, host.name, tags
  OK   process.pid — целые числа, нет нулей
  OK   process.executable — пути /usr/bin/...
  OK   process.args — массивы строк
  WARN process.entity_id — 35% missing (холодный старт fluent-bit)
  WARN labels.entity_id_source="event_timestamp_fallback" — 3% событий

[auditd / process / fork]
  OK   process.pid, process.parent.pid
  WARN process.entity_id — 60% missing (fork до execve, cold start)

[auditd / network / connect]
  OK   destination.ip — IPv4 адреса
  FAIL network.type   — отсутствует в 80% событий
  OK   network.transport

[auditd / network / connect_unix]
  OK   network.type=unix
  OK   event.category — массив ["network","file"]

[auditd / authentication / user_auth]
  OK   user.name — заполнено через fallback auid_name
  OK   event.outcome — success/failure
  WARN auditd.session — 15% missing

--- fluent-osquery-* ---
Тройки dataset/category/action:
  osquery/process/process_added (N)
  osquery.shell_history/process/command_executed (N)
  osquery.bpf_process_events/process/process_started (N)
  osquery.bpf_socket_events/network/socket_connect (N)
  osquery.bpf_socket_events/process/socket_connect_nonip (N)
  osquery.docker_containers/host/container_observed_added (N)
  ...

[osquery / process / process_added]
  OK   process.pid, process.name, process.executable
  WARN process.entity_id — 20% missing

[osquery.shell_history / process / command_executed]
  OK   process.command_line — команды пользователей
  WARN user.name — 10% missing

[osquery.bpf_process_events / process / process_started]
  OK   process.pid, process.executable
  OK   labels.cmdline_source = "osquery_bpf"
  WARN container.id — 60% missing (нет docker_containers diff ещё в кэше)
  WARN labels.cmdline_truncated="argv0_only" — 25% событий (osquery BPF argv truncation, known)

[osquery.bpf_socket_events / process / socket_connect_nonip]
  OK   event.category=process (реклассификация AF_UNIX/AF_NETLINK)
  OK   network.type=unix / netlink / packet

[osquery.docker_containers / host / container_observed_added]
  OK   container.id — 12-char hex
  OK   container.name, container.image.name

--- ИТОГ ---
FAIL  N критичных проблем (данные неверны/теряются)
WARN  N предупреждений (данные есть, но могут потерять качество)
OK    N тройек dataset/category/action без замечаний
Покрыто тройек: N из ~ожидаемых M
```

Для каждого **FAIL** — добавить гипотезу причины (из знания о стеке: `auditd_enrich.lua`, `auditd_merge.lua`, `osquery_enrich.lua`, Logstash convert, index template).

---

## Критерии завершения

- Все индексы с данными проверены.
- Каждая уникальная тройка `(event.dataset, event.category, event.action)` из обоих индексов имеет свою запись в отчёте.
- Базовые поля проверены для каждой тройки.
- Специфичные для action поля проверены согласно матрицам из шагов 2.2 и 3.2.
- Для каждого FAIL/WARN есть гипотеза причины.
- Отчёт содержит итоговую строку с количеством тройек и покрытием.
- Отчёт выведен в диалог.
