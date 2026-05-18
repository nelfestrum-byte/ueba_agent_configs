# P0-02. `user.session.id` — сквозной идентификатор сессии

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — главный навигатор по проекту.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник по ECS-схеме. Разделы 3.3, 4.4 и 6 содержат текущие таблицы полей, которые нужно дополнить.
- [HARDENING_PLAN.md, раздел P0-02](HARDENING_PLAN.md) — полные детали, формула, грабли.
- [P0-01-process-entity-id.md](P0-01-process-entity-id.md) — **выполнена**. Функция `short_id()` и кэш `btime` уже реализованы в enrich-скриптах. Переиспользовать без дублирования.

## Цель итерации

Добавить поле `user.session.id` в оба Lua-enrich скрипта. Поле связывает все события одной пользовательской сессии (от логина до выхода) единым идентификатором, что позволяет строить граф сессии и считать сессионные базовые линии в UEBA.

**Value сразу, даже без остальных задач:**
- В OpenSearch запрос `user.session.id: <id>` выдаёт полный timeline сессии из auditd + osquery.
- UEBA-скоринг получает «сессия» как единицу анализа.
- Кросс-источниковый join auditd ↔ osquery по `user.session.id` корректен (одна формула, один seed).

## Pre-flight проверки

Перед началом выполни:

```bash
# Убедиться что P0-01 выполнена — short_id() должна быть в скриптах
grep -n "short_id" agents/configs/fluent-bit/scripts/auditd_enrich.lua
grep -n "short_id" agents/configs/fluent-bit/scripts/osquery_enrich.lua

# Убедиться что btime уже читается
grep -n "btime" agents/configs/fluent-bit/scripts/auditd_enrich.lua

# Убедиться что ses поле присутствует в тестовых событиях
# (это поле auditd пишет в каждую запись SYSCALL/USER_*)
grep -n '"ses"' agents/configs/fluent-bit/scripts/auditd_enrich.lua
```

Если `short_id()` отсутствует — сначала выполни P0-01.

## Реализация

### 1. `agents/configs/fluent-bit/scripts/auditd_enrich.lua`

Найти место, где уже вычисляется `process.entity_id`, и добавить рядом:

```lua
-- user.session.id
local ses = tonumber(record["ses"] or record["auditd.session"] or "0") or 0
if ses > 0 and ses ~= 4294967295 then
    record["user.session.id"] = short_id(hostname .. ":" .. tostring(btime) .. ":" .. tostring(ses))
end
```

Комментарий: `ses = 4294967295` (0xFFFFFFFF) означает `auid=unset` — kernel tasks без сессии.

### 2. `agents/configs/fluent-bit/scripts/osquery_enrich.lua`

Для всех событий с `pid > 0` добавить чтение `/proc/<pid>/sessionid`:

```lua
-- user.session.id (только для событий с pid)
local function get_sessionid(pid)
    if not pid or pid <= 0 then return nil end
    local f = io.open("/proc/" .. tostring(pid) .. "/sessionid", "r")
    if not f then return nil end
    local s = f:read("*n")
    f:close()
    if not s or s <= 0 or s == 4294967295 then return nil end
    return s
end
```

И в основном теле enrich-функции (рядом с `process.entity_id`):

```lua
local ses = get_sessionid(pid)
if ses then
    record["user.session.id"] = short_id(hostname .. ":" .. tostring(btime) .. ":" .. tostring(ses))
end
```

### 3. `README_FOR_AI.md`

Добавить `user.session.id` в три места:
- Раздел 3.3 (auditd гарантированные поля): после строки `auditd.session`
- Раздел 4.4 (osquery гарантированные поля): после `process.parent.start`
- Раздел 6 (сквозные идентификаторы): новая строка в таблице

## Что НЕ делать

- Не создавать отдельный кэш для `ses` — значение читается напрямую из события/proc.
- Не читать `/proc/stat` повторно — `btime` уже доступен из P0-01 инициализации.
- Не добавлять fallback для `ses = 0` или `ses = 4294967295` — просто пропускать поле.
- Не менять ECS-поля `auditd.session` — оставить сырой integer как есть, `user.session.id` — отдельное поле.

## Проверка готовности

```bash
# На агентском хосте: залогиниться по SSH и найти свою сессию
ssh user@host

# Проверить что auditd события содержат user.session.id
curl -s 'http://localhost:9200/fluent-audit-*/_search' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"exists":{"field":"user.session.id"}},"size":3,"_source":["user.session.id","auditd.session","user.name","event.action"]}' \
  | python3 -m json.tool

# Два события одного ses должны давать одинаковый user.session.id
# Новый SSH-логин — другой user.session.id

# Кросс-источниковый запрос — события из обоих индексов
SESSION_ID="<взять из предыдущего запроса>"
curl -s "http://localhost:9200/fluent-audit-*,fluent-osquery-*/_search" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"term\":{\"user.session.id\":\"$SESSION_ID\"}},\"_source\":[\"event.dataset\",\"user.session.id\",\"user.name\",\"event.action\"]}" \
  | python3 -m json.tool
```

## Финал

После успешной проверки:

1. Обновить `README_FOR_AI.md` — добавить `user.session.id` в разделы 3.3, 4.4 и 6 (если ещё не сделано в ходе реализации).
2. Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md): `**Статус:** выполнено YYYY-MM-DD`.
3. Закоммитить все изменения одним коммитом с сообщением вида:
   `add user.session.id to auditd_enrich and osquery_enrich (P0-02)`
