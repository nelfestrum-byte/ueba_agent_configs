# QA-FIX-03. osquery_enrich.lua — container.id для BPF событий

## Контекст

Файл: `agents/configs/fluent-bit/scripts/osquery_enrich.lua`

По результатам QA-аудита (QA-01) поле `container.id` отсутствует в событиях
`osquery.bpf_process_events` и `osquery.bpf_socket_events`, хотя код вызывает
`get_docker_cid(cols["pid"])`.

**Диагностика проблемы:**

Функция `get_docker_cid` читает `/proc/<pid>/cgroup`. Для BPF-событий это
гонка с жизненным циклом процесса:
- BPF-событие генерируется при `execve` — процесс жив
- Но к моменту обработки Lua-скриптом (через osquery → fluent-bit pipeline)
  короткоживущие процессы (`runc init`, `runc:[2:INIT]`) уже завершились
- `/proc/<pid>/cgroup` недоступен → `get_docker_cid` возвращает `nil`

Дополнительно: значение `osquery.cid` в bpf_process_events — это inode
cgroup-namespace, **не** Docker container ID. Его нельзя использовать напрямую.

**Решение:** каскадный fallback:
1. Попробовать `/proc/<pid>/cgroup` (текущий процесс)
2. Если не вышло — попробовать `/proc/<parent_pid>/cgroup` (родитель живёт дольше)
3. Если не вышло — поискать в `container_cache` по ближайшему совпадению
   через parent chain (parent PID встречался в docker_containers diff)

## Что нужно сделать

### 1. Расширить get_docker_cid: добавить fallback на parent PID

Текущая сигнатура функции (строки 18–28):
```lua
local function get_docker_cid(pid)
    if not pid or pid == "" then return nil end
    local f = io.open("/proc/" .. tostring(pid) .. "/cgroup", "r")
    ...
end
```

Добавить новую функцию-обёртку `resolve_container_id` после `get_docker_cid`:

```lua
-- Пытается определить Docker container ID для процесса pid.
-- Порядок: /proc/<pid>/cgroup → /proc/<ppid>/cgroup → container_cache lookup по ppid.
-- parent_pid — опционально, string или nil.
local function resolve_container_id(pid, parent_pid)
    -- 1. Прямое чтение cgroup текущего процесса
    local cid = get_docker_cid(pid)
    if cid then return cid end

    -- 2. Родительский процесс живёт дольше — читаем его cgroup
    if parent_pid and parent_pid ~= "" and parent_pid ~= "0" then
        cid = get_docker_cid(parent_pid)
        if cid then return cid end
    end

    -- 3. Если родитель есть в container_cache — значит родитель сам контейнерный
    --    процесс, чей cid мы уже знаем из docker_containers diff.
    --    Это работает для дочерних процессов контейнера (exec внутри контейнера).
    if parent_pid then
        local ppid_num = tostring(parent_pid)
        -- Ищем совпадение: проверяем, есть ли в кэше запись,
        -- у которой мы ранее запомнили ppid → cid маппинг
        -- (расширение кэша описано в пункте 2 ниже)
    end

    return nil
end
```

### 2. Расширить container_cache: добавить ppid → cid маппинг

Текущий кэш (строка 12): `local container_cache = {}` — хранит `cid → {name, image}`.

Добавить второй кэш рядом:
```lua
-- Маппинг pid → container_id для процессов, чей cgroup уже был успешно прочитан.
-- Используется как fallback для дочерних процессов.
local pid_cid_cache = {}
local PID_CID_CACHE_MAX = 5000
```

В функции `resolve_container_id`, после успешного получения `cid`, кэшировать
маппинг `pid → cid`:
```lua
local function resolve_container_id(pid, parent_pid)
    local cid = get_docker_cid(pid)
    if cid then
        -- сохраняем маппинг для дочерних процессов
        if pid and pid ~= "" then
            if #pid_cid_cache >= PID_CID_CACHE_MAX then pid_cid_cache = {} end
            pid_cid_cache[tostring(pid)] = cid
        end
        return cid
    end

    if parent_pid and parent_pid ~= "" and parent_pid ~= "0" then
        cid = get_docker_cid(parent_pid)
        if cid then
            if #pid_cid_cache >= PID_CID_CACHE_MAX then pid_cid_cache = {} end
            pid_cid_cache[tostring(parent_pid)] = cid
            return cid
        end
        -- Fallback: проверить pid_cid_cache — родитель мог уже быть разрезолвен
        cid = pid_cid_cache[tostring(parent_pid)]
        if cid then return cid end
    end

    return nil
end
```

### 3. Заменить вызовы get_docker_cid на resolve_container_id в bpf_processes и bpf_sockets

**В блоке bpf_processes (≈строки 541–551):**

```lua
-- Было:
local cid = get_docker_cid(cols["pid"])

-- Стало:
local cid = resolve_container_id(cols["pid"], cols["parent"])
```

**В блоке bpf_sockets (≈строки 594–604):**

```lua
-- Было:
local cid = get_docker_cid(cols["pid"])

-- Стало:
local cid = resolve_container_id(cols["pid"], cols["parent"])
```

### 4. Кэшировать pid → cid при успешном bpf_processes событии

В блоке bpf_processes, после установки `record["container.id"] = cid`,
добавить кэширование pid для последующих bpf_socket_events того же процесса:

```lua
if cid then
    record["container.id"] = cid
    -- кэшируем для дочерних сокетных событий
    pid_cid_cache[tostring(cols["pid"])] = cid
    local meta = container_cache[cid]
    ...
end
```

## Критерии приёмки

```bash
OS="http://192.168.37.161:9200"

# 1. container.id появился в bpf_process_events
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {"term": {"event.dataset": "osquery.bpf_process_events"}},
    "aggs": {
      "total":            {"value_count": {"field": "process.pid"}},
      "has_container_id": {"filter": {"exists": {"field": "container.id"}}},
      "missing_cid":      {"missing": {"field": "container.id"}}
    }
  }'
# Ожидание: has_container_id.doc_count > 0
# missing_cid / total < 50% (часть коротких процессов всё равно промажет — это норма)

# 2. container.id в bpf_socket_events
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {"term": {"event.dataset": "osquery.bpf_socket_events"}},
    "aggs": {
      "has_container_id": {"filter": {"exists": {"field": "container.id"}}}
    }
  }'
# Ожидание: has_container_id.doc_count > 0

# 3. Проверить что container.id = 12-hex символов (не inode)
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {
      "bool": {
        "must": [
          {"term": {"event.dataset": "osquery.bpf_process_events"}},
          {"exists": {"field": "container.id"}}
        ]
      }
    },
    "_source": ["container.id", "container.name", "process.executable"]
  }'
# Ожидание: container.id вида "32c3a7d60dd4" (12 hex), не число вроде "71929"
```

## Важные ограничения

- Не удалять `osquery.cid` из события — он может быть полезен для диагностики.
- `pid_cid_cache` — bulk eviction (полный сброс) при превышении MAX,
  так же как основной кэш в `proc_common.lua`. Не усложнять LRU.
- Функцию `get_docker_cid` не менять — она используется как есть в `resolve_container_id`.
- Если `/proc/<pid>/cgroup` не содержит docker-паттерна (например, у процессов хоста),
  `get_docker_cid` вернёт `nil` — это корректное поведение.
- После деплоя первые события после рестарта fluent-bit не получат container.id
  для уже запущенных процессов — это known limitation (cold start).
