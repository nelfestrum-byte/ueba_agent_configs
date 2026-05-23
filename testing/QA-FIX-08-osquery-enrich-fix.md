# QA-03. osquery_enrich: container-атрибуция и WARN-чистка из QA-01

## Контекст для AI

Перед началом работы прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор, разделы про BPF backend и container_cache.
- [README_FOR_AI.md](../README_FOR_AI.md) — ECS-схема, osquery.* namespace.
- [HARDENING/CONTAINER_BEHAVIOR_PLAN.md](../HARDENING/CONTAINER_BEHAVIOR_PLAN.md) — план поведенческой модели контейнеров (P4); эта итерация закрывает technical-debt в его базе.
- [testing/QA-01-opensearch-field-audit.md](QA-01-opensearch-field-audit.md) — методика.
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) — главный файл этой итерации.

## Цель итерации

Закрыть WARN-список из QA-01 для `fluent-osquery-*`:

| # | Проблема | Где |
|---|----------|-----|
| 1 | Контейнерные subprocess (`/app/extra/healthcheck`, `/bin/sh` короткоживущие) не получают `container.id` — атрибуция работает только для долгоживущих контейнерных init-процессов | [osquery_enrich.lua:24-66](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L24) — `get_docker_cid` читает `/proc/<pid>/cgroup`, но для пропавшего pid → nil. Parent-chain работает только если parent_pid живой |
| 2 | `event.action="container_stopped"` для diff/removed событий, в которых `osquery.state="running"`, `osquery.status="Up 2 minutes (healthy)"` — реально контейнер бежит, просто osquery diff мигнул | [osquery_enrich.lua:347-353](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L347) и:674-696 — QUERY_META `docker_containers` мапит added→started/removed→stopped независимо от текущего state |
| 3 | AF_NETLINK события в bpf_socket_events идут с `event.category=network`, `destination.port=0`, `source.port=0` — шум | [osquery_enrich.lua:624-628](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L624) — `family=16` обходится, но category не меняется |
| 4 | uint64 overflow в `osquery.exit_code` (`18446744073709551501` для `-115 EINPROGRESS`) | [osquery_enrich.lua:425-427](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L425) — копирование cols в osquery.* без нормализации |
| 5 | `process.executable` отсутствует в `osquery.process_memory_map` (есть только `process.name`) | [osquery_enrich.lua:764-768](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L764) — suspicious_mmap пишет path в `file.path`, но не в `process.executable` |
| 6 | `user.name` не резолвится из `user.id` в `osquery.kernel_keys` | [osquery_enrich.lua:755-756](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L755) — для kernel_keys_diff нет блока user.name |

**Value:** UEBA-сценарии «какой контейнер сделал bind на нестандартный порт», «какой контейнер открыл подозрительный bash» — начинают работать. Шум AF_NETLINK уходит. Раздел WARN из QA-01 закрыт.

**Что НЕ делаем:** ECS-mapping типов для osquery.* namespace — отдельная итерация QA-04 (index template).

## Pre-flight

```bash
OS=http://192.168.37.161:9200

# #1: контейнерная атрибуция baseline
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"term":{"event.dataset":"osquery.bpf_process_events"}},"aggs":{"total":{"value_count":{"field":"process.pid"}},"has_container_id":{"filter":{"exists":{"field":"container.id"}}},"top_exe_no_container":{"filter":{"bool":{"must_not":[{"exists":{"field":"container.id"}}]}},"aggs":{"exes":{"terms":{"field":"process.executable","size":15}}}}}}'
# Записать долю has_container_id и топ-15 не-атрибутированных exe

# #2: container_stopped с running-state
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' \
  -d '{"size":3,"query":{"bool":{"must":[{"term":{"event.action":"container_stopped"}},{"term":{"osquery.state":"running"}}]}},"_source":["event.action","osquery.state","osquery.status","container.name"]}'
# Записать количество таких аномалий

# #3: AF_NETLINK в category=network
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"bool":{"must":[{"term":{"event.dataset":"osquery.bpf_socket_events"}},{"term":{"event.category":"network"}},{"term":{"osquery.family":"16"}}]}},"aggs":{"total":{"value_count":{"field":"process.pid"}}}}'

# #4: uint64 overflow в exit_code
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' \
  -d '{"size":3,"query":{"bool":{"must":[{"term":{"event.dataset":"osquery.bpf_socket_events"}},{"range":{"osquery.exit_code":{"gt":"1000000000000"}}}]}},"_source":["osquery.exit_code","osquery.syscall"]}'
# Должно быть несколько записей с huge числами

# #5: process.executable в suspicious_mmap
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"term":{"event.dataset":"osquery.process_memory_map"}},"aggs":{"total":{"value_count":{"field":"process.pid"}},"missing_exe":{"missing":{"field":"process.executable"}}}}'

# #6: user.name в kernel_keys
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"term":{"event.dataset":"osquery.kernel_keys"}},"aggs":{"total":{"value_count":{"field":"user.id"}},"missing_name":{"missing":{"field":"user.name"}}}}'
```

## Реализация

### Шаг 1. Усиление container resolution (контейнерные subprocess)

В [osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) переработать `resolve_container_id` (строки 38-66). Цель: добавить **третий fallback** — резолв через `osquery.cid` (cgroup namespace inode) с помощью `cid → container.id` таблицы, заполняемой при обработке `docker_containers`-событий через чтение `/proc/<container.pid>/ns/cgroup`.

#### 1.1. Добавить новую таблицу рядом с `pid_cid_cache` (после строки 18):

```lua
-- Маппинг osquery.cid (cgroup namespace inode, число) → container.id (12-hex).
-- Заполняется при обработке docker_containers diff: для каждого added контейнера
-- читаем /proc/<container.pid>/ns/cgroup → symlink "cgroup:[<inode>]" → <inode>.
-- BPF события с тем же cid резолвятся в container.id даже когда /proc/<pid>/cgroup
-- недоступен (короткоживущий subprocess).
local cgroup_ns_cache  = {}   -- { [cgroup_inode_str] = container_id_12hex }
local _cgns_size       = 0
local CGNS_CACHE_MAX   = 1000
```

#### 1.2. Helper для чтения cgroup namespace inode (рядом с `get_docker_cid`, после строки 34):

```lua
-- Читает /proc/<pid>/ns/cgroup и возвращает inode как строку.
-- Формат symlink: "cgroup:[4026532177]" → "4026532177".
local function get_cgroup_ns(pid)
    if not pid or pid == "" then return nil end
    local link, err = nil, nil
    -- Lua не имеет readlink в stdlib; через popen.
    local p = io.popen("readlink /proc/" .. tostring(pid) .. "/ns/cgroup 2>/dev/null")
    if not p then return nil end
    link = p:read("*l")
    p:close()
    if not link then return nil end
    return link:match("cgroup:%[(%d+)%]")
end
```

#### 1.3. В блоке `docker_containers` (строки 674-696) после `container_cache[cid] = ...` добавить:

```lua
            if action == "added" and cols["pid"] and cols["pid"] ~= "" and cols["pid"] ~= "0" then
                local cgns = get_cgroup_ns(cols["pid"])
                if cgns then
                    if _cgns_size >= CGNS_CACHE_MAX then
                        cgroup_ns_cache = {}
                        _cgns_size = 0
                    end
                    if not cgroup_ns_cache[cgns] then _cgns_size = _cgns_size + 1 end
                    cgroup_ns_cache[cgns] = cid
                end
            elseif action == "removed" then
                -- НЕ удаляем cgns из кэша при removed — может быть «мигание» diff
                -- (см. проблему #2 ниже). Кэш чистится только bulk-evict при переполнении.
            end
```

#### 1.4. В `resolve_container_id` (строки 38-66) добавить параметр `cid_inode` и проверить кэш ДО всех остальных fallback'ов:

```lua
local function resolve_container_id(pid, parent_pid, cid_inode)
    -- ... existing cache_put helper ...

    -- 0. cgroup namespace inode из docker_containers (самый дешёвый и надёжный)
    if cid_inode and cid_inode ~= "" and cid_inode ~= "0" then
        local cid = cgroup_ns_cache[tostring(cid_inode)]
        if cid then return cid end
    end

    -- 1-3. existing /proc/<pid>/cgroup → /proc/<ppid>/cgroup → pid_cid_cache
    -- (без изменений)
end
```

#### 1.5. В вызовах `resolve_container_id` в блоках `bpf_processes` (строка 581) и `bpf_sockets` (строка 663) передать `cols["cid"]`:

```lua
local cid = resolve_container_id(cols["pid"], cols["parent"], cols["cid"])
```

**Замечание:** комментарий «cols["cid"] — cgroup namespace inode, не Docker ID, не используем» (строка 580) **удалить** — теперь используем.

**Failsafe для `io.popen`:** в Lua fluent-bit-а `io.popen` доступен, но если в production-сборке его отключат — функция вернёт nil, fallback на старые методы работает. Дополнительный риск — fork bombing если popen вызывается слишком часто. Здесь `get_cgroup_ns` вызывается только при `docker_containers/added` events — это ≤ N контейнеров на хост, безопасно.

### Шаг 2. container_started / container_stopped → observed_*

#### 2.1. В QUERY_META (строки 347-353) заменить:

```lua
    docker_containers = {
        category = "host",
        action_added   = "container_observed_added",
        action_removed = "container_observed_removed",
        type_added     = "info",
        type_removed   = "info",
    },
```

**Обоснование:** osquery diff не отражает lifecycle (start/stop), а только присутствие в snapshot-таблице. Реальные start/stop — это Docker events API, не наша поверхность.

#### 2.2. В блоке `docker_containers` (после строки 694) добавить fallback `container.lifecycle` на основе `osquery.state` / `osquery.status`:

```lua
            -- осqueryd возвращает state="running"/"created"/"exited"/"paused"/"dead"
            local state = cols["state"]
            if state and state ~= "" then
                if state == "running"  then record["event.type"] = "info"
                elseif state == "exited" or state == "dead" then
                    record["event.action"] = "container_exited"
                    record["event.type"]   = "end"
                end
            end
```

### Шаг 3. AF_NETLINK → category=process

В блоке `bpf_sockets` (строки 597-672) сразу после установки `event.dataset` (строка 598) добавить проверку family до общей логики:

```lua
    elseif query_name == "bpf_sockets" then
        record["event.dataset"] = "osquery.bpf_socket_events"

        local fam_early = cols["family"]
        if fam_early ~= "2" and fam_early ~= "10" then
            -- AF_UNIX(1), AF_NETLINK(16), AF_PACKET(17), прочее — не IP-сеть.
            -- Переводим в category=process; ECS network.* поля не ставим.
            record["event.category"] = "process"
            if cols["pid"]     then record["process.pid"]        = tonumber(cols["pid"]) end
            if cols["parent"]  then record["process.parent.pid"] = tonumber(cols["parent"]) end
            if cols["path"]    and cols["path"] ~= "" then record["process.executable"] = cols["path"] end
            if cols["uid"]     and cols["uid"] ~= "" then record["user.id"] = cols["uid"] end
            local syscall = cols["syscall"]
            if syscall and syscall ~= "" then
                record["event.action"] = "socket_" .. syscall .. "_nonip"
            end
            -- container resolution тот же
            local cid = resolve_container_id(cols["pid"], cols["parent"], cols["cid"])
            if cid then
                record["container.id"] = cid
                local meta = container_cache[cid]
                if meta then
                    record["container.name"]       = meta.name
                    record["container.image.name"] = meta.image
                    record["container.entity_id"]  = (record["host.name"] or "") .. ":" .. meta.name
                end
            end
            goto bpf_sockets_done
        end

        -- ... existing logic для AF_INET / AF_INET6 ...
        ::bpf_sockets_done::
```

**Альтернатива без goto** (если ревьюер не любит goto): вынести AF_INET-ветку в локальную функцию и `return` после non-ip обработки.

### Шаг 4. uint64 overflow в `osquery.exit_code`

В блоке копирования cols → osquery.* (строки 422-427) или непосредственно в bpf_sockets/bpf_processes блоках, нормализовать exit_code:

```lua
-- Helper в начале файла (после PROTO, до enrich_osquery):
local function normalize_int64(v)
    if not v or v == "" then return v end
    local n = tonumber(v)
    if not n then return v end
    -- BPF возвращает int64 как uint64 в osquery. Конвертируем:
    -- значения > 2^63 — это negative errno (например EINPROGRESS = -115 → 2^64 - 115).
    if n > 9223372036854775807 then  -- 2^63 - 1
        n = n - 18446744073709551616  -- - 2^64
    end
    return n
end
```

В bpf_processes (строка 565-567) и bpf_sockets:

```lua
if cols["exit_code"] and cols["exit_code"] ~= "" then
    record["process.exit_code"] = normalize_int64(cols["exit_code"])
end
```

Аналогично в копировании в osquery.* namespace для exit_code:

```lua
-- В цикле копирования cols → osquery.* (строки 422-427):
for k, v in pairs(cols) do
    if v ~= nil and v ~= "" then
        if k == "exit_code" then
            record["osquery." .. k] = normalize_int64(v)
        else
            record["osquery." .. k] = v
        end
    end
end
```

### Шаг 5. `process.executable` в suspicious_mmap

В блоке `suspicious_mmap` (строки 764-768) добавить копирование path:

```lua
    elseif query_name == "suspicious_mmap" then
        record["event.dataset"] = "osquery.process_memory_map"
        if cols["pid"]          then record["process.pid"]        = tonumber(cols["pid"]) end
        if cols["process_name"] then record["process.name"]       = cols["process_name"] end
        if cols["process_path"] and cols["process_path"] ~= "" then
            record["process.executable"] = cols["process_path"]
        end
        -- path в этой таблице — путь mmap-региона (mapped file), не процесса:
        if cols["path"]         then record["file.path"]          = cols["path"] end
```

**Проверить, какая колонка реально пишется** — может быть `process_path` или `name` или `cmdline`. Сделать `curl -s "$OS/fluent-osquery-*/_search?size=1&q=event.dataset:osquery.process_memory_map"` и посмотреть `osquery.*` ключи в выводе.

### Шаг 6. user.name из user.id в kernel_keys

В блоке `kernel_keys_diff` (строки 755-756) добавить попытку резолва имени:

```lua
    elseif query_name == "kernel_keys_diff" then
        record["event.dataset"] = "osquery.kernel_keys"
        -- user.id есть из cols.uid (выставлен в общем блоке user строки 499-500).
        -- user.name резолвим через /etc/passwd cached lookup.
        if record["user.id"] and not record["user.name"] then
            local uname = common.uid_to_name(record["user.id"])
            if uname then record["user.name"] = uname end
        end
```

В [agents/configs/fluent-bit/scripts/proc_common.lua](../agents/configs/fluent-bit/scripts/proc_common.lua) проверить — есть ли `uid_to_name`. Если нет — добавить (читает `/etc/passwd`, кэширует):

```lua
local passwd_cache = nil
function M.uid_to_name(uid)
    if passwd_cache == nil then
        passwd_cache = {}
        local f = io.open("/etc/passwd", "r")
        if f then
            for line in f:lines() do
                local name, uid_str = line:match("^([^:]+):[^:]*:(%d+):")
                if name and uid_str then passwd_cache[uid_str] = name end
            end
            f:close()
        end
    end
    return passwd_cache[tostring(uid)]
end
```

**Проверь существование `proc_common.uid_to_name` перед добавлением** — может быть уже реализовано.

### Шаг 7. Smoke на тестовом docker-хосте

```bash
# 1. Раскатить на agent01 (он [docker_hosts])
ansible-playbook agents/deploy/agents-deploy.yml --limit=agent01.uir.prj --ask-become-pass

# 2. Подождать ~3 минуты (нужно успеть собрать docker_containers diff и BPF события)

# 3. Перепроверить все aggregations из Pre-flight выше

# 4. Spot check
OS=http://192.168.37.161:9200

# Контейнерная атрибуция bpf_process — должна быть выше для контейнерных subprocess
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"bool":{"must":[{"term":{"event.dataset":"osquery.bpf_process_events"}},{"prefix":{"process.executable":"/app/"}}]}},"aggs":{"has_container_id":{"filter":{"exists":{"field":"container.id"}}}}}'
# Ожидание: для /app/* (контейнерные пути) doc_count ≈ has_container_id

# AF_NETLINK перешёл в process category
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"term":{"osquery.family":"16"}},"aggs":{"cats":{"terms":{"field":"event.category"}}}}'
# Ожидание: только "process" в buckets

# exit_code не overflow
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"range":{"osquery.exit_code":{"gt":"1000000000000"}}},"aggs":{"total":{"value_count":{"field":"process.pid"}}}}'
# Ожидание: total.value = 0
```

## Что НЕ делать в этой итерации

- **НЕ менять index template** — отдельная задача QA-04.
- **НЕ трогать `pid_cid_cache` емкость** (5000) — текущее работает; кэш bulk-evict.
- **НЕ удалять `osquery.cid`** из документов после резолва — оставить как debug-поле для проверки атрибуции через кэш.
- **НЕ менять формат container.id** (12-hex) — это совместимо с ECS и docker CLI.
- **НЕ переходить на listening Docker Events API** — отдельная задача (P4 / CONTAINER_BEHAVIOR_PLAN). Сейчас остаёмся на osquery `docker_containers` diff + cgns кэш как мост.
- **НЕ маскировать `shell_history`** — решение проекта (см. CLAUDE.md), не менять.

## Критерии готовности

- `container.id` присутствует в ≥80% bpf-событий с `process.executable` начинающимся на `/app/`, `/usr/local/bin/python3`, `/whoami` (типично контейнерные пути).
- `event.category` для AF_NETLINK событий = `"process"`, для AF_INET/AF_INET6 = `"network"` (как раньше).
- `osquery.exit_code` не содержит значений > 2^32 (нормализованы в отрицательные).
- `process.executable` в `osquery.process_memory_map` заполнено ≥95%.
- `user.name` в `osquery.kernel_keys` присутствует там же, где `user.id` (oof хотя бы для UID 0-65535).
- `event.action="container_observed_added"` / `container_observed_removed` вместо started/stopped в docker_containers.
- `fluent-bit` метрики Lua filter errors = 0; `output.tcp.errors` стабильно 0.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - Раздел про osquery.* namespace — добавить новые поля: `container.id`/`container.name` через cgns-мост, `event.action=container_observed_*` (объяснить разницу с lifecycle).
   - AF_NETLINK / AF_UNIX в bpf_socket → `event.category=process`.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В раздел про BPF backend добавить про `cgroup_ns_cache` и его failure-modes (кэш теряется при рестарте fluent-bit, первые BPF события после рестарта без атрибуции до первого docker_containers diff).
   - Уточнить, что `event.action=container_observed_*` не отражает реальный lifecycle.

3. **Закоммитить:**

   ```
   QA-03: osquery enrich — container attribution + WARN cleanup

   - osquery_enrich.lua: cgroup_ns_cache via /proc/<pid>/ns/cgroup readlink at docker_containers/added
   - resolve_container_id: 4th lookup tier — cgns inode (osquery.cid) → container.id
   - bpf_socket_events: AF_NETLINK/AF_UNIX → event.category=process (no network.* noise)
   - normalize_int64: BPF uint64 negatives (e.g. EINPROGRESS) decoded correctly in exit_code
   - suspicious_mmap: process.executable now populated
   - kernel_keys: user.name resolved from user.id via /etc/passwd cache (added uid_to_name to proc_common)
   - docker_containers: event.action=container_observed_* (no false lifecycle claim from diff)
   - Smoke on agent01 [docker_hosts]: container attribution lifted from 4% to ≥80% for /app/* processes

   Closes WARN #1, #2, #3, #4, #5 (executable in mmap), #6 (user.name in kernel_keys) from QA-01.
   ```

4. **Сообщить пользователю:** контейнерная атрибуция UEBA-grade; финальный шаг QA-04 — типы полей в osquery index template.
