# QA-FIX-05. osquery_enrich.lua — process.entity_id отсутствует в bpf_socket_events

## Контекст

Файл: `agents/configs/fluent-bit/scripts/osquery_enrich.lua`

По результатам QA-01 (второй прогон):

| Поле | bpf_socket_events (682 событий) | Причина |
|------|--------------------------------|---------|
| `process.entity_id` | **100% missing** (0/682) | Блок bpf_sockets не вычисляет entity_id |
| `network.transport` | **97% missing** (662/682) | `cols["protocol"] = "0"` для большинства сокетов |

**Приоритет F1: process.entity_id — критично для UEBA.**
Без entity_id нельзя связать сетевое событие (bpf_socket) с процессом в
auditd или osquery/processes. Это делает bpf_socket_events изолированными,
без атрибуции к субъекту действия.

**Уточнение F2: network.transport — ограничение BPF данных.**
`bpf_socket_events.protocol` = "0" когда приложение вызвало
`socket(AF_INET, SOCK_STREAM, 0)` — ядро выбирает протокол автоматически.
osquery BPF-проба захватывает именно этот "0". Полностью устранить нельзя,
но можно добавить best-effort вывод: AF_INET + `remote_port > 0` +
`local_port > 0` → вероятно TCP; AF_INET + только `local_port > 0` → неопределено.

## Что нужно сделать

### 1. Добавить process.entity_id в блок bpf_sockets

В `osquery_enrich.lua`, блок `elseif query_name == "bpf_sockets"` (≈строки 597–645).

Найти строку установки `record["process.pid"]`:
```lua
if cols["pid"] then record["process.pid"] = tonumber(cols["pid"]) end
```

После неё добавить вычисление entity_id:
```lua
-- process.entity_id для bpf_socket_events:
-- используем epoch-based start_time (та же формула что у auditd/osquery processes)
-- → cross-index join по entity_id с auditd корректен для долгоживущих процессов.
-- Для короткоживущих /proc/<pid>/stat может быть уже недоступен; в этом
-- случае entity_id не устанавливается (не ломаем событие частичными данными).
local bpf_sock_pid = tonumber(cols["pid"])
if bpf_sock_pid and bpf_sock_pid > 0 then
    local start_ts = common.resolve_start(bpf_sock_pid)
    if start_ts then
        local seed = (record["host.name"] or "")
                  .. ":" .. tostring(bpf_sock_pid)
                  .. ":" .. tostring(start_ts)
        record["process.entity_id"] = common.short_id(seed)
    end
end
```

Это обеспечивает:
- `process.entity_id` совпадает с auditd/osquery processes для тех же процессов
- Для короткоживущих процессов поле просто отсутствует (не fallback)
- `pid_cid_cache` уже заполнен из bpf_processes → resolve_start кэш тоже

### 2. Best-effort network.transport для AF_INET сокетов

В том же блоке bpf_sockets, после существующего кода установки network.transport:

```lua
-- Текущий код (строки ≈614–619):
local proto = cols["protocol"]
if proto and proto ~= "0" then
    local proto_name = PROTO[proto]
    if proto_name then record["network.transport"] = proto_name end
    record["network.iana_number"] = proto
end
```

Заменить на:

```lua
local proto = cols["protocol"]
if proto and proto ~= "0" then
    local proto_name = PROTO[proto]
    if proto_name then record["network.transport"] = proto_name end
    record["network.iana_number"] = proto
else
    -- protocol=0: приложение использовало SOCK_STREAM/SOCK_DGRAM с protocol=0
    -- (ядро выбирает автоматически). Best-effort: если есть remote_address и
    -- remote_port — скорее всего TCP (большинство соединений на типичных портах).
    -- Устанавливаем только при наличии обоих IP-адресных маркеров:
    -- AF_INET + remote_port > 0 → предполагаем TCP (преобладает для connect).
    local fam = cols["family"]
    local rport = tonumber(cols["remote_port"])
    if (fam == "2" or fam == "10") and rport and rport > 0 then
        record["network.transport"] = "tcp"
        record["labels.transport_inferred"] = "true"
    end
end
```

Поле `labels.transport_inferred = "true"` сигнализирует, что transport выведен
эвристически, а не из данных. Позволяет фильтровать/исключать в запросах при
необходимости точных данных.

**Важно:** не применять это эвристику к socket_bind (bind к порту — не обязательно TCP),
поэтому проверка только через наличие `remote_port > 0` (значимо для connect/accept).

## Важные ограничения

- `common.resolve_start(pid)` обращается к `/proc/<pid>/stat`. Для
  короткоживущих процессов (runc init, etc.) файл может быть недоступен.
  В этом случае entity_id просто не устанавливается — это норма.
- entity_id для bpf_sockets использует **epoch-based start_time** (не ntime),
  поэтому **совместим** с auditd и osquery/processes entity_id.
  Это отличается от bpf_processes (там ntime → несовместим). Такое разночтение
  внутри bpf-* семейства нужно зафиксировать в README_FOR_AI.md.
- `labels.transport_inferred` — нестандартное поле. Если не нужно — убрать
  эту строку, но оставить установку `record["network.transport"] = "tcp"`.

## Деплой

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass
```

## Критерии приёмки

```bash
OS="http://192.168.37.161:9200"

# 1. process.entity_id появился в bpf_socket_events
curl -s -X GET "$OS/fluent-osquery-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {"term": {"event.dataset": "osquery.bpf_socket_events"}},
    "aggs": {
      "total":              {"value_count": {"field": "process.pid"}},
      "has_entity_id":      {"filter": {"exists": {"field": "process.entity_id"}}},
      "missing_entity_id":  {"missing": {"field": "process.entity_id"}}
    }
  }' | grep -E '"doc_count":|"value":'
# Ожидание: has_entity_id.doc_count > 0 (не 0 как было)
# missing_entity_id / total < 80% (часть коротких процессов промажет — норма)

# 2. entity_id в bpf_sockets совпадает с auditd для того же процесса
# (взять pid из свежего socket_connect)
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {"bool": {"must": [
      {"term": {"event.dataset": "osquery.bpf_socket_events"}},
      {"term": {"event.action": "socket_connect"}},
      {"exists": {"field": "process.entity_id"}}
    ]}},
    "_source": ["process.pid", "process.entity_id", "host.name", "destination.ip"]
  }'
# Получить process.entity_id из результата, затем найти в auditd:
# curl -s "$OS/fluent-audit-*/_search" -d '{"size":5,"query":{"term":{"process.entity_id":"<EID>"}}}'
# Ожидание: найдены совпадающие auditd события для долгоживущих процессов

# 3. network.transport появился для socket_connect к IP
curl -s -X GET "$OS/fluent-osquery-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {"bool": {"must": [
      {"term": {"event.dataset": "osquery.bpf_socket_events"}},
      {"term": {"event.action": "socket_connect"}},
      {"exists": {"field": "destination.ip"}}
    ]}},
    "aggs": {
      "total":              {"value_count": {"field": "process.pid"}},
      "has_transport":      {"filter": {"exists": {"field": "network.transport"}}},
      "missing_transport":  {"missing": {"field": "network.transport"}}
    }
  }' | grep -E '"doc_count":|"value":'
# Ожидание: has_transport / total > 70% для socket_connect с destination.ip
```

## Обновление документации

После деплоя обновить `README_FOR_AI.md`:

1. **Раздел 4.5 (bpf_sockets):** добавить в таблицу ECS-полей:
   ```
   | `process.entity_id` | epoch-based (FNV-1a host:pid:start_time). Совместим с auditd/processes. Отсутствует для короткоживущих процессов. |
   | `labels.transport_inferred` | "true" если network.transport выведен эвристически (protocol=0 + remote_port>0). |
   ```

2. **Раздел 5 (Сквозные идентификаторы):**
   Добавить строку: `osquery.bpf_socket_events` теперь содержит `process.entity_id`
   с тем же seed, что auditd и osquery/processes → join корректен для живых процессов.
   Исключение bpf_processes (ntime) сохраняется.
