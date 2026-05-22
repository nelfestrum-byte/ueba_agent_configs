# QA-FIX-04. proc_common.lua — нестандартная длина entity_id и session_id

## Контекст

Файл: `agents/configs/fluent-bit/scripts/proc_common.lua`

По результатам QA-01 (второй прогон) в индексах `fluent-audit-*` и `fluent-osquery-*`
обнаружено, что ~50 % значений `process.entity_id` и `process.parent.entity_id`
имеют длину 24 или 32 hex-символа вместо ожидаемых 16.

Примеры из данных:
```
"process.entity_id": "ffffffffb52e54f4ffffffffef92e014"  ← 32 символа (НЕВЕРНО)
"process.entity_id": "773daf7dffffffffb6603f88"          ← 24 символа (НЕВЕРНО)
"process.entity_id": "023a27bc1bcfa600"                  ← 16 символов (норма)
"user.session.id":   "13d8d4ba6cbf916e"                  ← 16 символов (норма)
```

**Причина:**

В `proc_common.lua`, функция `short_id()` (строки 22–26):

```lua
function M.short_id(s)
    local hi = fnv32(s, FNV32_OFFSET)
    local lo = fnv32(s, FNV32_OFFSET_ALT)
    return string.format("%08x%08x", hi, lo)
end
```

Внутренняя функция `fnv32()` возвращает результат `bit.band(h * FNV32_PRIME, 0xFFFFFFFF)`.
В зависимости от реализации `bit`-библиотеки (LuaJIT или Lua 5.3 compat),
`bit.band()` возвращает знаковое 32-битное целое (int32), которое может быть
отрицательным. В Lua 5.3+, `string.format("%08x", negative_int64)` форматирует
полное 64-битное представление, давая 16 символов вместо 8:
- `string.format("%08x", -1)` → `"ffffffffffffffff"` (16 chars, не 8)

Результат: когда `hi` или `lo` отрицательные → каждый даёт 16 hex-символов
вместо 8, итого 24 или 32 символа.

**Важно:** cross-index join `auditd ↔ osquery/processes` **по-прежнему работает**,
так как оба скрипта используют один и тот же `proc_common.lua` и производят
одинаково «неправильный» hash для одного и того же процесса. Но hash не
соответствует спецификации (16 символов), и `user.session.id` подвержен той
же проблеме при совпадении знака.

## Что нужно сделать

### Единственное изменение: proc_common.lua строки 22–26

Заменить:
```lua
function M.short_id(s)
    local hi = fnv32(s, FNV32_OFFSET)
    local lo = fnv32(s, FNV32_OFFSET_ALT)
    return string.format("%08x%08x", hi, lo)
end
```

На:
```lua
function M.short_id(s)
    local hi = fnv32(s, FNV32_OFFSET)
    local lo = fnv32(s, FNV32_OFFSET_ALT)
    -- Маскируем в беззнаковый диапазон [0, 2^32-1]:
    -- bit.band() возвращает signed int32, format("%08x", negative) даёт
    -- 16 символов в Lua 5.3+. Модуль 2^32 гарантирует ровно 8 hex-символов.
    return string.format("%08x%08x", hi % 0x100000000, lo % 0x100000000)
end
```

Больше ничего в файле не менять.

## Важные ограничения

1. **Смена формата = смена значений.** После деплоя entity_id для одних и тех
   же процессов изменятся: "ffffffffb52e54f4..." → "b52e54f4...". Документы,
   записанные до фикса, и документы после — будут иметь разные entity_id для
   одного процесса. Это ожидаемо и неизбежно. Влияние ограничено одним
   текущим индексом (он ротируется по дням). Долгосрочные корреляции
   затронуты только в пределах текущего дня деплоя.

2. **Оба Lua-стейта обновляются автоматически.** `auditd_enrich.lua` и
   `osquery_enrich.lua` оба импортируют `proc_common.lua` — при рестарте
   fluent-bit оба начнут генерировать 16-символьные entity_id одновременно.

3. **Рестарт fluent-bit обязателен** для применения изменения в Lua-файле.
   Делается через деплой-плейбук (см. ниже).

4. Не менять `FNV32_PRIME`, `FNV32_OFFSET`, `FNV32_OFFSET_ALT` — алгоритм
   верен, проблема только в финальном форматировании.

## Деплой

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass
```

Плейбук копирует обновлённые Lua-файлы и перезапускает fluent-bit.

## Критерии приёмки

```bash
OS="http://192.168.37.161:9200"

# 1. Все новые entity_id = ровно 16 символов
# Ждём ~1 минуту после деплоя для накопления новых событий, затем:
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 10,
    "query": { "term": { "event.action": "execve" } },
    "sort": [{ "@timestamp": { "order": "desc" } }],
    "_source": ["process.entity_id", "process.parent.entity_id", "user.session.id", "@timestamp"]
  }'
# Ожидание: process.entity_id = 16 hex-символов (нет "ffffffff" префиксов)
# Ожидание: process.parent.entity_id = 16 hex-символов
# Ожидание: user.session.id = 16 hex-символов

# 2. Отдельно проверить osquery:
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 5,
    "query": { "term": { "osquery.result.name": "processes" } },
    "sort": [{ "@timestamp": { "order": "desc" } }],
    "_source": ["process.entity_id", "process.parent.entity_id"]
  }'
# Ожидание: оба поля = 16 hex-символов

# 3. Проверить, что join auditd↔osquery по entity_id работает:
# (взять entity_id любого execve из auditd и найти его в osquery/processes)
EID=$(curl -s "$OS/fluent-audit-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":1,"query":{"term":{"event.action":"execve"}},"sort":[{"@timestamp":{"order":"desc"}}],"_source":["process.entity_id"]}' \
  | grep -o '"process\.entity_id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "Looking for entity_id: $EID"
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d "{\"size\":3,\"query\":{\"term\":{\"process.entity_id\":\"$EID\"}}}"
# Ожидание: найден хотя бы один документ в osquery (для долгоживущих процессов)
```

## Обновление документации

После успешного деплоя обновить `README_FOR_AI.md`, раздел 3.3
и раздел 5 (Сквозные идентификаторы):
- Убрать оговорку о нестабильной длине entity_id
- Подтвердить: `process.entity_id` = ровно 16 hex-символов
