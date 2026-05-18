# P0-01. process.entity_id и process.parent.entity_id в Lua-enrich

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — главный навигатор по проекту, структура каталогов, оптимизации токенов.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник по ECS-схеме данных, который мы здесь расширяем. Эта задача добавит два новых ECS-поля в auditd и osquery источники — README_FOR_AI обязан остаться источником истины по схеме.
- [HARDENING_PLAN.md, раздел P0-01](HARDENING_PLAN.md) — полное обоснование и acceptance criteria.

## Цель итерации

Добавить в Lua-enrich два ECS-поля: `process.entity_id` и `process.parent.entity_id` + сопутствующее `process.start` (epoch seconds). Это **независимый** value-add — после задачи UEBA-скоринг сможет строить корректное process tree и переживать PID reuse.

**Что приносит value сразу, даже если остальные задачи плана не сделаны:**

- Все будущие документы в `fluent-audit-*` и `fluent-osquery-*` получают стабильный ID процесса.
- Существующие дашборды/запросы продолжают работать (поля только добавляются, ничего не ломается).
- Корреляция между auditd и osquery источниками становится возможной через `entity_id`, а не через хрупкий `pid+host`.

### Ключевой инвариант (читать обязательно)

`process.entity_id` обязан быть **стабилен на всё время жизни процесса**, независимо от того, в каком событии этот процесс появился. То есть: execve, последующий connect, последующий close — все три события одного pid должны нести **одинаковый** entity_id.

Из этого следует, что seed для хэша **нельзя** строить на `@timestamp` события — иначе два события одного процесса дадут два разных entity_id и весь смысл поля пропадает.

Seed должен включать **process start time** — а это поле, которое в auditd-логе **отсутствует**. Источник истины — `/proc/<pid>/stat` field 22 (`starttime` в clock ticks с момента boot). Для osquery таблицы `processes` это поле есть нативно (`start_time`, epoch seconds) и совпадает с тем же источником. Если оба enrich-скрипта строят seed по одинаковой формуле на этом значении — entity_id одного процесса в auditd-документе **совпадёт** с entity_id того же процесса в osquery-документе. Это и есть основная UEBA-ценность.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Источник `process.start_time` для auditd-enrich:**
   - `/proc/<pid>/stat` field 22 + boot_time + `_SC_CLK_TCK` (рекомендуется — единый источник истины с osquery, кросс-источниковый join работает)
   - First-seen `@timestamp` события execve, кэшированный на pid (приближение — entity_id auditd ↔ osquery **не совпадёт**, документировать как known limitation)
2. **Хэш-функция:**
   - FNV-1a 64-bit через LuaJIT `bit`-модуль как **пара FNV-32** (рекомендуется — детерминированно, без потери точности в double, без зависимостей)
   - SHA-256 первые 16 hex (требует `sha2` либо внешний вызов — отвергнуть, если в LuaJIT нет нативной поддержки)
3. **Размер кэша pid→start_time:** 10 000 (по умолчанию) или другой?
4. **Применять ли изменения на dev-стенде немедленно после правки** или оставить для пользовательской раскатки через `ansible-playbook`?

Дальше — никаких вопросов, всё описано ниже.

## Pre-flight проверки

1. Подтвердить версию Lua, которую использует fluent-bit на целевых хостах:

   ```bash
   fluent-bit --version 2>&1 | head -3
   ```

   Ожидаем LuaJIT 2.1 (совместим с Lua 5.1). LuaJIT приносит `bit` модуль (`bit.bxor`, `bit.band`, `bit.lshift`) — на нём строим хэш честно, без потери точности через `double`. Если на dev-стенде PUC-Rio Lua 5.1 без BitOp — отметить и обсудить (откатиться на `require "bit32"` для Lua 5.2+ либо отказаться от FNV-64 в пользу FNV-32 single).

2. Прочитать текущие [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) и [osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) целиком — понять стиль и где вставлять.

3. Убедиться, что `process.pid` и `process.parent.pid` уже устанавливаются в обоих enrich (это так на момент написания плана — но перепроверь). В auditd_enrich.lua интересны строки 64-75 (`get_hostname` через `io.popen` — тот же приём используем для boot_time и CLK_TCK ниже).

4. Проверить доступность `/proc` и `getconf` на целевых хостах:

   ```bash
   cat /proc/stat | awk '/^btime/{print $2}'   # boot epoch, например 1735603200
   getconf CLK_TCK                              # обычно 100 на Linux
   awk '{print $22}' /proc/1/stat               # field 22 systemd, ticks с boot
   ```

   Если `btime` или `CLK_TCK` недоступны — fallback на @timestamp с понижением acceptance criterion (entity_id остаётся стабильным в пределах одного процесса fluent-bit, но **не** сходится с osquery).

5. Подтвердить, что fluent-bit-процесс работает под пользователем, у которого есть read-доступ к `/proc/<pid>/stat` для произвольных pid. На Linux это публично читаемо, но при `hidepid=2` в `mount /proc` — только владелец процесса. Проверить:

   ```bash
   mount | grep '/proc '          # есть ли hidepid в опциях?
   sudo -u fluent-bit cat /proc/1/stat   # читается ли?
   ```

## Реализация

### Шаг 1. Хэш-функция (FNV-1a 64-bit как пара FNV-32 на LuaJIT `bit`)

Добавить в начало `auditd_enrich.lua` (после таблиц SYSCALLS/EVENT_CATEGORY):

```lua
-- ── FNV-1a 64-bit хэш как две FNV-32 ветви на разных offset basis ──
-- Lua 5.1 / LuaJIT 2.1: 64-bit number = double (53-bit мантисса), поэтому прямой
-- FNV-1a 64-bit теряет точность уже на 7-м байте. Используем `bit` модуль LuaJIT
-- (32-bit unsigned операции) и считаем ДВА независимых FNV-32 с разными seed.
-- Конкатенация — 64 бита уникальности, чего хватает с большим запасом для
-- "(host, pid, start_time)" входа.
local bit = require("bit")  -- LuaJIT: built-in; PUC Lua 5.1: BitOp; Lua 5.2+: bit32
local FNV32_PRIME  = 16777619
local FNV32_OFFSET = 2166136261
local FNV32_OFFSET_ALT = 2654435769  -- Knuth multiplicative — несвязанный seed

local function fnv32(s, seed)
    local h = seed
    for i = 1, #s do
        h = bit.bxor(h, s:byte(i))
        -- эмулируем 32-bit unsigned multiply: умножение в double + усечение
        h = bit.band(h * FNV32_PRIME, 0xFFFFFFFF)
    end
    return h
end

local function short_id(s)
    local hi = fnv32(s, FNV32_OFFSET)
    local lo = fnv32(s, FNV32_OFFSET_ALT)
    return string.format("%08x%08x", hi, lo)
end
```

**Свойства:**

- Детерминированно: одинаковый seed → одинаковый 16-hex.
- Хэш-коллизии — пренебрежимо малы для (host, pid, start_time)-входа.
- Не требует ничего, кроме `bit` модуля (есть в LuaJIT, который использует fluent-bit ≥ 1.9).

Тот же блок копируется в `osquery_enrich.lua` (вынос в shared helper — отдельная задача, см. Out-of-scope).

### Шаг 2. Чтение `process.start_time` из `/proc` + кэш pid → start_time

Кэш нужен для **двух** целей: (а) self entity_id — чтобы все последующие события того же pid использовали тот же start_time без повторного похода в `/proc`; (б) parent entity_id — чтобы родитель резолвился без поиска `/proc/<ppid>/stat`.

```lua
-- ── Кэш pid → process.start (epoch seconds) ──
-- При cache miss читаем /proc/<pid>/stat field 22 и конвертируем в epoch.
-- При execve-событии (новый процесс) — ПЕРЕЗАПИСЫВАЕМ запись для этого pid
-- (иначе после PID reuse старый entity_id "переживёт" умерший процесс).
local PROC_CACHE_MAX = 10000  -- ≈ под 1 МБ RSS, реальный overhead копеечный
local _proc_cache = {}
local _proc_cache_size = 0

-- Boot time и CLK_TCK — кэшируем один раз, не меняются за время жизни fluent-bit.
local _btime = nil
local _clk_tck = nil

local function get_btime()
    if _btime then return _btime end
    local f = io.open("/proc/stat", "r")
    if not f then return nil end
    for line in f:lines() do
        local b = line:match("^btime%s+(%d+)")
        if b then _btime = tonumber(b); break end
    end
    f:close()
    return _btime
end

local function get_clk_tck()
    if _clk_tck then return _clk_tck end
    local f = io.popen("getconf CLK_TCK 2>/dev/null")
    if f then
        local v = f:read("*l")
        f:close()
        _clk_tck = tonumber(v)
    end
    -- Linux x86_64/arm64 — стандарт 100; используем как безопасный default.
    _clk_tck = _clk_tck or 100
    return _clk_tck
end

-- Чтение field 22 из /proc/<pid>/stat. Учесть, что comm в скобках может
-- содержать пробелы и сами скобки, поэтому ищем последнюю ')' и парсим хвост.
local function read_proc_start(pid)
    local f = io.open("/proc/" .. pid .. "/stat", "r")
    if not f then return nil end
    local line = f:read("*l")
    f:close()
    if not line then return nil end
    local tail_idx = line:find("%) ")
    if not tail_idx then return nil end
    local tail = line:sub(tail_idx + 2)
    -- В tail: state(1) ppid(2) ... starttime — это field 22 в полной строке,
    -- т.е. поле номер 20 в tail (после исключения pid и comm).
    local fields = {}
    for w in tail:gmatch("%S+") do fields[#fields+1] = w end
    local ticks = tonumber(fields[20])
    if not ticks then return nil end
    local btime = get_btime()
    if not btime then return nil end
    return btime + (ticks / get_clk_tck())
end

local function cache_evict_if_full()
    if _proc_cache_size > PROC_CACHE_MAX then
        _proc_cache = {}
        _proc_cache_size = 0
    end
end

local function cache_put(pid, start_ts, force)
    if force or not _proc_cache[pid] then
        if not _proc_cache[pid] then
            _proc_cache_size = _proc_cache_size + 1
        end
        _proc_cache[pid] = start_ts
        cache_evict_if_full()
    end
end

local function resolve_start(pid)
    local s = _proc_cache[pid]
    if s then return s end
    s = read_proc_start(pid)
    if s then cache_put(pid, s, false) end
    return s
end
```

**Инвариант кэша:** на событии `type=EXECVE` (новый процесс) вызываем `cache_put(pid, start_ts, true)` с `force=true`, чтобы перезаписать запись. Это критично для PID reuse: ядро освобождает pid → новый процесс получает тот же pid → execve → новый start_time → новый entity_id.

То же — в `osquery_enrich.lua`. В osquery таблице `processes` есть нативный `start_time` (epoch seconds, тот же `/proc/<pid>/stat` field 22 → btime + ticks/CLK_TCK). Поэтому `read_proc_start` в osquery не нужна — `cache_put(pid, cols["start_time"], false)` достаточно. Это и обеспечивает кросс-источниковую согласованность: оба enrich дают одинаковый seed для одного и того же процесса.

### Шаг 3. Установка entity_id в auditd_enrich.lua

Ключевое отличие от наивной реализации: **start_time берётся не из `@timestamp` события**, а из `/proc/<pid>/stat` через `resolve_start(pid)`. Это даёт одинаковый seed для всех событий одного процесса, и совпадение с osquery enrich для того же pid.

В блоке после установки `process.pid` (текущая строка ~125):

```lua
local is_execve = (record["type"] == "EXECVE") or (record["syscall"] == "execve")

if pid then
    record["process.pid"]          = pid
    record["process.name"]         = record["comm"]
    -- ... остальное как было ...

    -- ── process.start + process.entity_id ──
    local start_ts
    if is_execve then
        -- На execve процесс ТОЛЬКО что родился: его /proc уже создан, но мы
        -- также форсим запись в кэш на случай PID reuse (старая запись,
        -- оставшаяся от умершего процесса с тем же pid, должна быть стёрта).
        start_ts = read_proc_start(pid) or record["@timestamp"]
        cache_put(pid, start_ts, true)  -- force=true
    else
        start_ts = resolve_start(pid)
        -- Fallback: процесс уже мог умереть к моменту обработки события
        -- (короткоживущие процессы). В этом случае используем @timestamp,
        -- помечая событие тегом для отладки. entity_id такого события НЕ
        -- сойдётся с osquery — это known limitation для exit-событий.
        if not start_ts then
            start_ts = record["@timestamp"]
            record["labels.entity_id_source"] = "event_timestamp_fallback"
        end
    end

    record["process.start"] = start_ts
    local seed = (record["host.name"] or "")
              .. ":" .. tostring(pid)
              .. ":" .. tostring(start_ts)
    record["process.entity_id"] = short_id(seed)
end

if ppid then
    record["process.parent.pid"] = ppid

    -- ── process.parent.entity_id ──
    -- resolve_start читает /proc на cache miss — это работает только пока
    -- родитель жив. После смерти родителя кэш — единственный источник.
    local parent_start = resolve_start(ppid)
    if parent_start then
        record["process.parent.start"] = parent_start
        local pseed = (record["host.name"] or "")
                   .. ":" .. tostring(ppid)
                   .. ":" .. tostring(parent_start)
        record["process.parent.entity_id"] = short_id(pseed)
    end
    -- Если parent не резолвится (умер до прогрева кэша) — поле отсутствует.
    -- Это known limitation, описанное в HARDENING_PLAN P0-01.
end
```

**Важно про is_execve:** проверка по `record["type"]` или `record["syscall"]` зависит от того, какие поля доступны после `auditd_merge.lua`. Перед имплементацией прочитать [auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) и подтвердить корректное имя поля; если merge кладёт syscall в `record["audit_syscall"]` или подобное — использовать его.

### Шаг 4. То же в osquery_enrich.lua

В osquery таблице `processes` есть нативный `start_time` (epoch seconds) — тот же формат, что у `read_proc_start` в auditd, поэтому seed одного и того же процесса в обоих источниках совпадёт.

```lua
-- внутри ветки обработки таблицы processes:
if cols["pid"] then
    local pid    = cols["pid"]
    local pid_n  = tonumber(pid)
    local action = cols["action"]  -- "added" | "removed" (osquery diff)

    record["process.pid"] = pid_n

    -- start_time из osquery в epoch seconds (число или строка-число).
    local start_ts = tonumber(cols["start_time"])
    if start_ts then
        record["process.start"] = start_ts
        local seed = (record["host.name"] or "")
                  .. ":" .. pid
                  .. ":" .. tostring(start_ts)
        record["process.entity_id"] = short_id(seed)

        -- "added" в osquery — это аналог execve в auditd: новый процесс.
        -- force=true перезаписывает кэш на случай PID reuse.
        local force = (action == "added")
        cache_put(pid, start_ts, force)
    end
end

if cols["parent"] then
    local ppid = cols["parent"]
    record["process.parent.pid"] = tonumber(ppid)
    local parent_start = resolve_start(ppid)
    if parent_start then
        record["process.parent.start"] = parent_start
        local pseed = (record["host.name"] or "")
                   .. ":" .. ppid
                   .. ":" .. tostring(parent_start)
        record["process.parent.entity_id"] = short_id(pseed)
    end
end
```

**Заметка про совместимость с auditd-источником:** оба enrich держат **свои** кэши (это два разных Lua filter-instance в fluent-bit). Это нормально — синхронизация не нужна, потому что **формула seed детерминирована и одинакова в обоих** (host + pid + epoch-seconds). Один и тот же процесс на одной машине → один и тот же start_time из ядра → один и тот же seed → один и тот же entity_id.

### Шаг 5. Smoke на dev-стенде

```bash
cd dev_stand && docker compose up -d
# Послать тестовое auditd-событие через скрипт:
bash dev_stand/scripts/send-auditd.sh
# Проверить наличие поля в OpenSearch:
curl -s 'http://localhost:9200/fluent-audit-*/_search?size=1' | \
  jq '.hits.hits[0]._source | {entity_id: .["process.entity_id"], pid: .["process.pid"], start: .["process.start"]}'
```

Должен быть непустой 16-hex `entity_id` и числовой `process.start` (epoch seconds).

**Проверка инварианта стабильности (главное):** запустить долгоживущий процесс, дождаться второго auditd-события того же pid (например, execve + последующий connect/openat), сверить `entity_id` — обязан совпасть.

```bash
# На хосте с реальным auditd:
sleep 1000 &
PID=$!
# Триггер второго syscall того же процесса:
ls /proc/$PID/fd > /dev/null  # реальный access на /proc может не пройти auditd-фильтр —
                              # лучше использовать настоящий рабочий процесс под аудитом.
# Через ~10 сек проверить в OpenSearch:
curl -s "http://localhost:9200/fluent-audit-*/_search?q=process.pid:$PID&size=10" | \
  jq -r '.hits.hits[]._source["process.entity_id"]' | sort -u | wc -l
# Должно быть 1 (один уникальный entity_id на все события одного процесса).
```

**Проверка кросс-источника (auditd ↔ osquery):**

```bash
# Найти процесс, видный обоим источникам, и сравнить entity_id:
PID=<живой pid>
curl -s "http://localhost:9200/fluent-audit-*/_search?q=process.pid:$PID&size=1" | \
  jq -r '.hits.hits[0]._source["process.entity_id"]'
curl -s "http://localhost:9200/fluent-osquery-*/_search?q=process.pid:$PID&size=1" | \
  jq -r '.hits.hits[0]._source["process.entity_id"]'
# Должны совпасть.
```

## Что НЕ делать в этой итерации

- **НЕ выносить `short_id`, `read_proc_start`, кэш в shared helper.** Дублирование в двух файлах — приемлемо. Helper-модуль — отдельная задача рефакторинга, не сейчас.
- **НЕ менять `process.pid` / `process.parent.pid`** — это существующие гарантированные поля, формат не трогаем.
- **НЕ добавлять persistence кэша между рестартами fluent-bit** — это known limitation, описано в плане. Решение позже отдельной задачей.
- **НЕ писать unit-тесты** — это P3-01, отложено. Здесь только smoke на dev-стенде.
- **НЕ применять index template для нового поля** — это P1-02, отдельная задача.
- **НЕ пытаться резолвить start_time умерших процессов через bpftrace/eBPF/audit history** — out-of-scope. Для exit-событий короткоживущих процессов entity_id допустимо строить с fallback на `@timestamp`, помечая флагом.

## Грабли (специфичные для этой имплементации)

- **`/proc/<pid>/stat` parsing.** comm в скобках может содержать пробелы и сами `(`/`)`. Ищем **последнюю** `) ` и парсим хвост — реализация в `read_proc_start` выше учитывает это, не делать наивный split по пробелам.
- **`CLK_TCK` отличается от 100** очень редко (некоторые embedded), но `getconf CLK_TCK` отдаёт правильное значение. Default 100 — безопасный fallback.
- **`btime` — секундная точность.** `/proc/stat btime` — целое число секунд. ticks/CLK_TCK даёт миллисекундную точность для start_time, но boot_time всё равно округлен до секунды. Поэтому два процесса, стартовавшие в одну и ту же секунду на одном хосте, могут получить одинаковый entity_id если PID совпадёт — but в Linux ядро не переиспользует PID мгновенно, поэтому коллизия в пределах одной секунды на одном PID практически невозможна. Документировать.
- **PID = "unset"/0/нечисловое.** auditd может писать `pid=unset` для kernel-thread событий. `tonumber(pid)` вернёт nil → пропустить установку entity_id.
- **`is_execve` детект.** Зависит от того, в каком виде merge оставил тип события. Перед имплементацией убедиться через `out_file`-дамп fluent-bit, по какому ключу определять "это execve".
- **Lua-фильтр в fluent-bit — singleton state per filter instance.** Если в `fluent-bit.conf` один и тот же скрипт подключён в двух `[FILTER]` секциях — это два независимых state, два кэша. У нас auditd и osquery enrich — разные скрипты, разные state, и это нормально (Шаг 4 объясняет, почему синхронизация не нужна).

## Проверка готовности

Из [HARDENING_PLAN.md P0-01 → Критерий готовности](HARDENING_PLAN.md):

- В индексе `fluent-audit-*` для каждого события с `process.pid` присутствует непустой `process.entity_id` (16 hex).
- В индексе `fluent-audit-*` присутствует `process.start` (epoch seconds) для всех событий, где `process.pid` определён и процесс ещё жив; для exit-событий допустимо отсутствие `process.start` с пометкой `labels.entity_id_source=event_timestamp_fallback`.
- Для процессов с `process.parent.pid` присутствует `process.parent.entity_id` в **≥ 95 %** случаев после прогрева кэша.
- **Стабильность:** все события одного процесса в `fluent-audit-*` имеют **одинаковый** `process.entity_id` (проверка через `terms`-aggregation: `unique entity_id per pid == 1`).
- **Кросс-источник:** для процессов, видимых и auditd, и osquery — `process.entity_id` **совпадает** между `fluent-audit-*` и `fluent-osquery-*`.
- **PID reuse:** после убийства процесса и переиспользования PID — `process.entity_id` РАЗНЫЙ (новый execve форсит перезапись кэша).

Проверочные сценарии на dev-стенде:

```bash
# 1. Стабильность: один процесс — один entity_id во всех его событиях.
sleep 1000 &
PID=$!
# (триггер нескольких auditd-событий под аудитом на $PID)
curl -s "http://localhost:9200/fluent-audit-*/_search?q=process.pid:$PID&size=100" | \
  jq -r '.hits.hits[]._source["process.entity_id"]' | sort -u
# Ожидание: ровно ОДНА строка.

# 2. Кросс-источник: auditd entity_id == osquery entity_id для того же pid.
A=$(curl -s "http://localhost:9200/fluent-audit-*/_search?q=process.pid:$PID&size=1" | \
    jq -r '.hits.hits[0]._source["process.entity_id"]')
B=$(curl -s "http://localhost:9200/fluent-osquery-*/_search?q=process.pid:$PID&size=1" | \
    jq -r '.hits.hits[0]._source["process.entity_id"]')
test "$A" = "$B" && echo OK || echo MISMATCH "auditd=$A osquery=$B"

# 3. PID reuse: убить процесс, занять PID, entity_id должен отличаться.
kill $PID
# Запустить много короткоживущих, пока PID не переиспользуется:
for i in $(seq 1 5000); do sleep 1000 & NEW=$!; [ "$NEW" = "$PID" ] && break; kill $NEW; done
# Проверить, что entity_id для одного и того же pid в двух разных временных
# окнах — разный (различные значения start_time → разный seed).
```

## Финал

Обязательные действия после прохождения acceptance:

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В таблице "Гарантированные ECS-поля" (раздел 3.3 для auditd) добавить три строки: `process.entity_id`, `process.parent.entity_id`, `process.start` — с описанием семантики, источника (`/proc/<pid>/stat` field 22 + btime) и условиями заполнения.
   - В разделе "4.4 Гарантированные ECS-поля osquery" — добавить те же три поля + `process.parent.start`; явно указать, что значения **совпадают** с теми, что выдаёт auditd-enrich для того же процесса.
   - В разделе "6. Сквозные идентификаторы для UEBA" обновить строку про процесс: рекомендовать `process.entity_id` как primary key вместо `process.pid + host.name`; явно указать, что join auditd ↔ osquery по `process.entity_id` теперь корректен.
   - Добавить заметку про fallback-флаг `labels.entity_id_source=event_timestamp_fallback` — что он значит и когда появляется.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В разделе "Ключевые файлы по темам" обновить описание Lua enrich-скриптов — упомянуть pid→start_time кэш и чтение `/proc/<pid>/stat`.
   - В "Известные особенности и грабли" добавить:
     - "pid→start_time кэш теряется при рестарте fluent-bit — после старта возможен короткий период, когда entity_id событий долгоживущих процессов считаются с fallback'ом, а `process.parent.entity_id` отсутствует, пока родитель не появится в кэше через `/proc`-readout".
     - "auditd exit-события короткоживущих процессов могут иметь `labels.entity_id_source=event_timestamp_fallback` — entity_id такого события **не сходится** с осquery, потому что процесс уже исчез из `/proc` к моменту enrich".

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** найти раздел P0-01, поменять "**Статус:** не начато" на "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить** одним коммитом с сообщением вида:

   ```
   P0-01: add process.entity_id, process.parent.entity_id, process.start to Lua enrich

   - FNV-1a 64-bit (pair of FNV-32) via LuaJIT bit module
   - start_time sourced from /proc/<pid>/stat field 22 + btime — same as
     osquery's processes.start_time, so entity_id is consistent across sources
   - pid→start_time cache, force-rewritten on execve to handle PID reuse
   - Fallback to event @timestamp for exit-events of short-lived processes,
     marked with labels.entity_id_source for diagnostics
   - README_FOR_AI: documented three new ECS fields + cross-source join note
   - CLAUDE.md: noted cache cold-start and exit-event limitations
   ```

5. **Сообщить пользователю** одной фразой: что сделано, какие поля доступны, и что дальше предлагается P0-02 или P0-03 (на его выбор).
