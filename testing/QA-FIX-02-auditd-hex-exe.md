# QA-FIX-02. auditd_enrich.lua — декодирование hex-encoded exe

## Контекст

Файл: `agents/configs/fluent-bit/scripts/auditd_enrich.lua`

По результатам QA-аудита в категориях `process` и `iam` поле
`process.executable` для контейнерных процессов `runc:[2:INIT]` содержит
hex-строку вместо пути:

```
"process.executable": "2F6D656D66643A72756E635F636C6F6E65643A2F70726F632F73656C662F657865202864656C6574656429"
```

Декодированный hex: `/memfd:runc_cloned:/proc/self/exe (deleted)`

**Причина:** auditd записывает поле `exe` в hex когда путь содержит
непечатаемые символы, пробелы или помечен как `(deleted)`. Enrich-скрипт
присваивает `record["process.executable"] = record["exe"]` без декодирования
(строка 160).

## Что нужно сделать

Добавить в `auditd_enrich.lua` функцию `decode_hex_str` и вызвать её при
установке `process.executable`.

### 1. Добавить функцию декодирования (разместить рядом с `decode_saddr`)

```lua
-- Декодирует hex-строку auditd в обычный текст.
-- auditd hex-кодирует exe когда путь содержит пробелы, (deleted) или non-ASCII.
-- Возвращает исходную строку если она не является валидным hex.
local function decode_hex_str(s)
    if not s or #s == 0 or #s % 2 ~= 0 then return s end
    -- hex-строки auditd: только [0-9A-Fa-f], длина чётная, обычно > 8 символов
    if not s:match("^[0-9A-Fa-f]+$") then return s end
    local result = s:gsub("%x%x", function(h)
        return string.char(tonumber(h, 16))
    end)
    -- Принимаем результат только если он начинается с '/' (абсолютный путь)
    -- или с известных префиксов memfd/proc. Иначе возвращаем оригинал.
    if result:sub(1,1) == "/" or result:sub(1,7) == "memfd::" then
        return result
    end
    return s
end
```

### 2. Применить декодирование при установке process.executable

Найти строку (≈160):
```lua
record["process.executable"]   = record["exe"]
```

Заменить на:
```lua
record["process.executable"]   = decode_hex_str(record["exe"])
```

Так же обработать поле `exe` в секции нормализации USER_*/CRED_* событий
(из QA-FIX-01), если она добавлена:
```lua
if u_exe and u_exe ~= "" then
    record["process.executable"] = decode_hex_str(u_exe)
end
```

## Критерии приёмки

```bash
# В новых событиях process.executable не должен быть hex-строкой
curl -s 'http://192.168.37.161:9200/fluent-audit-*/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 5,
    "query": {
      "bool": {
        "must": [{"term": {"event.category": "process"}}],
        "must_not": [{"prefix": {"process.executable": "/"}}]
      }
    },
    "_source": ["process.executable", "process.name", "@timestamp"]
  }'
# Ожидание: hits.total.value = 0 (нет непутевых значений)
# Или: оставшиеся значения — только "(null)" / реальные не-path случаи,
#       но НЕ hex-строки длиной > 8 символов вида [0-9a-f]+
```

## Важные ограничения

- Декодирование применять **только** к полю `exe` / `process.executable`.
  НЕ применять к другим полям (proctitle, comm и т.д.) — они hex не кодируются.
- Проверка `result:sub(1,1) == "/"` обязательна: если hex не является путём,
  лучше вернуть исходный hex чем испорченную строку.
- `#s % 2 ~= 0` guard нужен: нечётная длина → не hex.
