# P0-01. process.entity_id и process.parent.entity_id в Lua-enrich

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — главный навигатор по проекту, структура каталогов, оптимизации токенов.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник по ECS-схеме данных, который мы здесь расширяем. Эта задача добавит два новых ECS-поля в auditd и osquery источники — README_FOR_AI обязан остаться источником истины по схеме.
- [HARDENING_PLAN.md, раздел P0-01](HARDENING_PLAN.md) — полное обоснование и acceptance criteria.

## Цель итерации

Добавить в Lua-enrich два ECS-поля: `process.entity_id` и `process.parent.entity_id`. Это **независимый** value-add — после задачи UEBA-скоринг сможет строить корректное process tree и переживать PID reuse.

**Что приносит value сразу, даже если остальные задачи плана не сделаны:**

- Все будущие документы в `fluent-audit-*` и `fluent-osquery-*` получают стабильный ID процесса.
- Существующие дашборды/запросы продолжают работать (поля только добавляются, ничего не ломается).
- Корреляция между auditd и osquery источниками становится возможной через `entity_id`, а не через хрупкий `pid+host`.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Какую хэш-функцию использовать для entity_id?**
   - FNV-1a 64-bit (рекомендуется — без зависимостей, быстро, для уникальности на хосте достаточно)
   - SHA-256 первые 16 hex (требует подключения `sha2` библиотеки Lua или внешнего вызова)
2. **Размер LRU-кэша pid→start_time:** 10 000 (по умолчанию) или другой?
3. **Применять ли изменения на dev-стенде немедленно после правки** или оставить для пользовательской раскатки через `ansible-playbook`?

Дальше — никаких вопросов, всё описано ниже.

## Pre-flight проверки

1. Подтвердить версию Lua, которую использует fluent-bit на целевых хостах:

   ```bash
   fluent-bit --version 2>&1 | head -3
   ```

   Ожидаем LuaJIT 2.1 (совместим с Lua 5.1). Если на dev-стенде другая версия — отметить и проверить совместимость xor-операций.

2. Прочитать текущие [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) и [osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) целиком — понять стиль и где вставлять.

3. Убедиться, что `process.pid` и `process.parent.pid` уже устанавливаются в обоих enrich (это так на момент написания плана — но перепроверь).

## Реализация

### Шаг 1. Хэш-функция (без внешних зависимостей)

Добавить в начало `auditd_enrich.lua` (после таблиц SYSCALLS/EVENT_CATEGORY):

```lua
-- ── FNV-1a 64-bit хэш (для process.entity_id) ──
-- Lua 5.1 / LuaJIT 2.1 не имеют bitwise-операторов как builtin —
-- используем числовую арифметику. Для seed-строки до ~512 байт это быстро.
local FNV_PRIME    = 1099511628211
local FNV_OFFSET   = 14695981039346656037
local function short_id(s)
    -- LuaJIT поддерживает 64-bit integers через native number type на x86_64,
    -- но overflow возможен — оборачиваем через bit.bxor если bit библиотека доступна.
    local h = FNV_OFFSET
    if bit and bit.bxor then
        for i = 1, #s do
            h = bit.bxor(h, s:byte(i))
            h = h * FNV_PRIME
        end
    else
        -- fallback на чисто-арифметический xor через двоичные операции
        for i = 1, #s do
            local b = s:byte(i)
            -- Простая аппроксимация xor через сложение и mod
            h = ((h + b) * FNV_PRIME) % (2^53)
        end
    end
    return string.format("%016x", h % (2^53))
end
```

**ВАЖНО:** проверь поведение `bit` библиотеки в LuaJIT, который использует fluent-bit (`bit.bxor` должен быть доступен). Если нет — fallback в else-ветке работает для нашей задачи (уникальность на хосте), хотя математически это не классический FNV.

Тот же блок копируется в `osquery_enrich.lua` или выносится в shared helper (см. Out-of-scope ниже — пока копируем).

### Шаг 2. LRU-кэш pid→start_time (для parent entity_id)

В `auditd_enrich.lua` добавить локальный кэш и две функции:

```lua
-- ── LRU кэш pid → start_time для resolve process.parent.entity_id ──
local PARENT_CACHE_MAX = 10000   -- ≈50 MB RSS — приемлемо
local _parent_cache = {}
local _parent_cache_size = 0

local function cache_put(pid, start_ts)
    if not _parent_cache[pid] then
        _parent_cache_size = _parent_cache_size + 1
    end
    _parent_cache[pid] = start_ts
    -- Грубая eviction: при переполнении сбросить всё
    -- (не классический LRU, но fluent-bit процесс перезапускается редко, для нас ок)
    if _parent_cache_size > PARENT_CACHE_MAX then
        _parent_cache = {}
        _parent_cache_size = 0
    end
end

local function cache_get(pid)
    return _parent_cache[pid]
end
```

То же — в `osquery_enrich.lua` (отдельный кэш, потому что enrich-функции в разных filter-instance).

### Шаг 3. Установка entity_id в auditd_enrich.lua

В блоке после установки `process.pid` (текущая строка ~125):

```lua
if pid then
    record["process.pid"]          = pid
    record["process.name"]         = record["comm"]
    -- ... остальное как было ...

    -- ── process.entity_id ──
    local start_ts = record["@timestamp"] or tostring(timestamp)
    local seed = (record["host.name"] or "")
              .. ":" .. tostring(pid)
              .. ":" .. start_ts
    record["process.entity_id"] = short_id(seed)

    -- Обновить кэш для будущих parent-resolutions
    cache_put(pid, start_ts)
end

if ppid then
    record["process.parent.pid"] = ppid

    -- ── process.parent.entity_id (через LRU кэш) ──
    local parent_start = cache_get(ppid)
    if parent_start then
        local pseed = (record["host.name"] or "")
                   .. ":" .. tostring(ppid)
                   .. ":" .. parent_start
        record["process.parent.entity_id"] = short_id(pseed)
    end
    -- Если parent ещё не виден в кэше (cold start) — поле отсутствует.
    -- Это known limitation, описанное в HARDENING_PLAN P0-01.
end
```

### Шаг 4. То же в osquery_enrich.lua

В osquery есть нативное поле `start_time` в таблице `processes` — НЕ нужна аппроксимация. Используем его напрямую:

```lua
-- внутри ветки обработки processes:
if cols["pid"] then
    local pid = cols["pid"]
    local start_time = cols["start_time"] or "0"
    record["process.pid"] = tonumber(pid)
    -- ...

    local seed = (record["host.name"] or "")
              .. ":" .. pid
              .. ":" .. start_time
    record["process.entity_id"] = short_id(seed)
    cache_put(pid, start_time)
end

if cols["parent"] then
    record["process.parent.pid"] = tonumber(cols["parent"])
    local parent_start = cache_get(cols["parent"])
    if parent_start then
        local pseed = (record["host.name"] or "")
                   .. ":" .. cols["parent"]
                   .. ":" .. parent_start
        record["process.parent.entity_id"] = short_id(pseed)
    end
end
```

### Шаг 5. Smoke на dev-стенде

```bash
cd dev_stand && docker compose up -d
# Послать тестовое auditd-событие через скрипт:
bash dev_stand/scripts/send-auditd.sh
# Проверить наличие поля в OpenSearch:
curl -s 'http://localhost:9200/fluent-audit-*/_search?size=1' | \
  jq '.hits.hits[0]._source | {entity_id: .["process.entity_id"], pid: .["process.pid"]}'
```

Должен быть непустой 16-hex `entity_id`.

## Что НЕ делать в этой итерации

- **НЕ выносить `short_id` и LRU-кэш в shared helper.** Дублирование в двух файлах — приемлемо. Helper-модуль — отдельная задача рефакторинга, не сейчас.
- **НЕ менять `process.pid` / `process.parent.pid`** — это существующие гарантированные поля, формат не трогаем.
- **НЕ добавлять persistence LRU-кэша между рестартами fluent-bit** — это known limitation, описано в плане. Решение позже отдельной задачей.
- **НЕ писать unit-тесты** — это P3-01, отложено. Здесь только smoke на dev-стенде.
- **НЕ применять index template для нового поля** — это P1-02, отдельная задача.

## Проверка готовности

Из [HARDENING_PLAN.md P0-01 → Критерий готовности](HARDENING_PLAN.md):

- В индексе `fluent-audit-*` для каждого события с `process.pid` присутствует непустой `process.entity_id` (16 hex).
- Для процессов с `process.parent.pid` присутствует `process.parent.entity_id` в **≥ 95 %** случаев после прогрева LRU.
- Два независимых события одного процесса (execve и его дочерний syscall) дают одинаковый `process.entity_id`.
- После убийства процесса и переиспользования PID — `process.entity_id` РАЗНЫЙ.

Проверочный сценарий на dev-стенде:

```bash
# 1. Запустить долгий процесс, получить PID
sleep 1000 & echo $!
# 2. Через 2-3 секунды убить его, тут же занять PID:
kill $(jobs -p); sleep 1000 & echo $!  # если PID совпал — повезло, иначе повторить
# 3. Проверить в OpenSearch, что entity_id у двух процессов разный
```

## Финал

Обязательные действия после прохождения acceptance:

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В таблице "Гарантированные ECS-поля" (раздел 3.3 для auditd) добавить строки `process.entity_id` и `process.parent.entity_id` с описанием семантики и условиями заполнения.
   - В разделе "4.4 Гарантированные ECS-поля osquery" — то же.
   - В разделе "6. Сквозные идентификаторы для UEBA" обновить строку про процесс: рекомендовать `process.entity_id` как primary key вместо `process.pid + host.name`.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В разделе "Ключевые файлы по темам" обновить описание Lua enrich-скриптов — упомянуть LRU кэш.
   - В "Известные особенности и грабли" добавить: "LRU кэш parent_start_time теряется при рестарте fluent-bit — известное ограничение P0-01, parent_entity_id может отсутствовать в первые секунды после старта".

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** найти раздел P0-01, поменять "**Статус:** не начато" на "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить** одним коммитом с сообщением вида:

   ```
   P0-01: add process.entity_id and process.parent.entity_id to Lua enrich

   - FNV-1a short_id() in auditd_enrich.lua and osquery_enrich.lua
   - LRU pid→start_time cache for parent entity_id resolution
   - README_FOR_AI: documented two new ECS fields
   - CLAUDE.md: noted LRU cold-start limitation
   ```

5. **Сообщить пользователю** одной фразой: что сделано, какие поля доступны, и что дальше предлагается P0-02 или P0-03 (на его выбор).
