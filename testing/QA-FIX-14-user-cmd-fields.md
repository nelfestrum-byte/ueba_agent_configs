# QA-FIX-14. USER_CMD: user.name/target.name/process.command_line отсутствуют + host event.action=null

## Контекст для AI

Прочитай перед стартом:

- [CLAUDE.md](../CLAUDE.md) — раздел «`USER_*` / `CRED_*` / `SERVICE_*`: очистка raw-полей» и «`user.name` fallback».
- [agents/configs/fluent-bit/scripts/auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) — строки 127–140 (ветка `^USER_`).
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — строки 396–460 (блок PAM/USER событий).

Инструмент проверки — **Bash + curl** (`http://192.168.37.161:9200`).

---

## Проблема A (FAIL F-03): USER_CMD теряет все ключевые поля

QA-01b итерация 5: **166 событий user_cmd** имеют `user.name=0%, user.target.name=0%, process.command_line=0%`.

### Причина 1: uid_name/auid_name не извлекаются для USER_CMD

В `auditd_merge.lua` SYSCALL-ветка (строки 86–87) единственная, где `uid_name`/`auid_name` берутся из uppercase-алиасов `UID=`/`AUID=`:

```lua
if atype == "SYSCALL" then
    ...
    if kv["UID"]  and kv["UID"]  ~= "unset" then entry["uid_name"]  = kv["UID"]  end
    if kv["AUID"] and kv["AUID"] ~= "unset" then entry["auid_name"] = kv["AUID"] end
```

USER_CMD идёт через ветку `^USER_` и сохраняет UID= как `user_UID`, AUID= как `user_AUID`. Эти поля `enrich.lua` не читает в fallback цепочке — она ищет `uid_name`/`auid_name` которые для чистых USER_CMD событий пусты.

### Причина 2: process.command_line не извлекается из cmd= поля

Сырой аудит USER_CMD:
```
type=USER_CMD msg=audit(ts:N): pid=X uid=Y auid=Z ses=N msg='cwd="/path" cmd=73756470 terminal=pts/0 res=success'
```

`cmd=` содержит hex-encoded командную строку (`73756470` = `sudo`). Merge сохраняет весь inner-msg как `user_msg`, но enrich не парсит `cmd=` из него.

### Причина 3: нет acct= в USER_CMD → user.target.name всегда пусто

USER_CMD не содержит `acct=` поля (оно есть в USER_START, USER_LOGIN, но не в USER_CMD). Текущий код пытается `u_target = record["user_acct"]` — всегда nil для USER_CMD.

---

## Правка A: auditd_enrich.lua — блок USER_CMD (строки ~401–431)

В блоке PAM/USER событий добавить **отдельную ветку для USER_CMD** сразу после строки `record["event.action"] = etype:lower()`:

```lua
    -- ── Специфика USER_CMD (sudo audit) ──────────────────────────────────────
    if primary_type == "USER_CMD" then
        -- user.name: USER_CMD содержит UID=/AUID= только внутри user_* префикса.
        -- uid_name/auid_name пусты (SYSCALL нет). Читаем user_UID/user_AUID.
        local cmd_uid_name  = record["user_UID"]
        local cmd_auid_name = record["user_AUID"]
        if cmd_uid_name  and cmd_uid_name  ~= "" and cmd_uid_name  ~= "unset" then
            record["user.name"] = cmd_uid_name
        elseif cmd_auid_name and cmd_auid_name ~= "" and cmd_auid_name ~= "unset" then
            record["user.name"] = cmd_auid_name
        elseif record["user_uid"] then
            record["user.id"] = record["user_uid"]   -- хотя бы id, если имя нет
        end

        -- process.command_line: извлекаем cmd=<hex> из user_msg (inner msg)
        local inner_msg = record["user_msg"]
        if inner_msg then
            -- inner_msg вида: 'cwd="/path" cmd=73756470 terminal=pts/0 res=success'
            local cmd_hex = inner_msg:match("cmd=(%x+)")
            if cmd_hex then
                -- Декодируем hex (если все символы hex и длина чётная)
                if #cmd_hex % 2 == 0 and cmd_hex:match("^%x+$") then
                    local decoded = cmd_hex:gsub("%x%x", function(h)
                        return string.char(tonumber(h, 16))
                    end):gsub("%z", " "):gsub("%s+$", "")
                    record["process.command_line"] = decoded
                else
                    record["process.command_line"] = cmd_hex
                end
            end
            -- cwd из inner msg
            local cwd_val = inner_msg:match('cwd="([^"]*)"')
            if cwd_val and cwd_val ~= "" then
                record["process.working_directory"] = cwd_val
            end
        end

        -- user.target.name: USER_CMD не несёт acct=; берём из user_AUID как
        -- initiating user если отличается от uid, иначе не ставим.
        -- (реальный target виден из USER_START сессии — cross-event семантика)
    end
```

**Вставить этот блок сразу после строки `record["event.action"] = etype:lower()`** (около строки 408), до общего блока `u_uid/u_target/u_exe/u_pid`.

---

## Проблема B (FAIL F-01): 9 host/info документов без event.action

9 документов с `event.category=host`, `event.type=info` не имеют `event.action`. Это события типов auditd DAEMON_START / DAEMON_STOP которые проходят через else-ветку merge и не имеют обработчика в enrich.

### Причина

В `auditd_enrich.lua` таблица EVENT_CATEGORY содержит:
```lua
SERVICE_START = {"host"},
SERVICE_STOP  = {"host"},
```

Но DAEMON_START / DAEMON_END типы отсутствуют в таблице → primary_type = "UNKNOWN" → `cats = EVENT_CATEGORY["UNKNOWN"] or {"host"}` — category=host выставляется, но action не ставится.

### Правка B: auditd_enrich.lua — таблица EVENT_CATEGORY (~строка 45) и обработчик

**Шаг 1.** Добавить в таблицу EVENT_CATEGORY:
```lua
DAEMON_START  = {"host"},
DAEMON_END    = {"host"},
DAEMON_ABORT  = {"host"},
```

**Шаг 2.** В блоке определения primary_type (~строки 167–183) добавить:
```lua
    elseif etypes["DAEMON_START"] then primary_type = "DAEMON_START"
    elseif etypes["DAEMON_END"]   then primary_type = "DAEMON_END"
    elseif etypes["DAEMON_ABORT"] then primary_type = "DAEMON_ABORT"
```

**Шаг 3.** В конце блока SERVICE_START/STOP (~строки 433–461) добавить обработчик:
```lua
    -- ── DAEMON_START / DAEMON_END / DAEMON_ABORT (auditd lifecycle) ──
    if primary_type == "DAEMON_START" or primary_type == "DAEMON_END"
    or primary_type == "DAEMON_ABORT" then
        local action_map = {
            DAEMON_START = "daemon_started",
            DAEMON_END   = "daemon_stopped",
            DAEMON_ABORT = "daemon_aborted",
        }
        record["event.action"] = action_map[primary_type]
        record["event.type"]   = (primary_type == "DAEMON_START") and "start" or "end"
        -- Поля daemon_start_*/daemon_end_* удаляются в финальном блоке через else-ветку
        -- Для очистки добавить префиксы в финальный loop (см. ниже).
    end
```

**Шаг 4.** В финальном cleanup-loop (~строки 577–583) добавить условия:
```lua
        or k:sub(1, 13) == "daemon_start_"
        or k:sub(1, 11) == "daemon_end_"
        or k:sub(1, 13) == "daemon_abort_"
```

---

## Проверка после деплоя

```bash
OS=http://192.168.37.161:9200

# A1. user_cmd — user.name должно быть > 0%
curl -s -X GET "$OS/fluent-audit-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":0,"query":{"term":{"event.action":"user_cmd"}},
      "aggs":{"has_name":{"filter":{"exists":{"field":"user.name"}}},
              "has_cmdline":{"filter":{"exists":{"field":"process.command_line"}}},
              "total":{"value_count":{"field":"process.pid"}}}}'
# Ожидание: has_name.doc_count > 0, has_cmdline.doc_count > 0

# A2. Пример user_cmd — проверить command_line
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"size":3,"query":{"term":{"event.action":"user_cmd"}},
      "sort":[{"@timestamp":{"order":"desc"}}],
      "_source":["user.name","user.id","process.command_line","event.outcome","auditd.session"]}'

# B1. Нет документов без event.action
curl -s -X GET "$OS/fluent-audit-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"bool":{"must_not":[{"exists":{"field":"event.action"}}]}}}'
# Ожидание: {"count":0,...}
```

---

## Деплой

```bash
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```
