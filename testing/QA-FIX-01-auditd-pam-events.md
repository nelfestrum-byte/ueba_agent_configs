# QA-FIX-01. auditd_enrich.lua — нормализация PAM/USER событий

## Контекст

Файл: `agents/configs/fluent-bit/scripts/auditd_enrich.lua`

По результатам QA-аудита (QA-01) в индексе `fluent-audit-*` выявлены четыре
критических проблемы с событиями типа USER_START / USER_END / USER_ACCT /
CRED_DISP / CRED_REFR (PAM-сессии, sudo):

| # | Симптом | Причина в коде |
|---|---------|---------------|
| F-1 | Категория `host` вместо `authentication`; `authentication` = 0 docs | Типы USER_START/USER_END/CRED_* не попадают в if-цепочку primary_type (строки 141–147), падают в `else {"host"}` |
| F-2 | `event.action` и `user.id` отсутствуют в 97 % host-событий | Нет ветки, которая ставит эти поля для USER_*/CRED_* |
| F-3 | `event.outcome = "failure"` для успешных PAM-событий | `user_res = "success'\x1D"` — trailing GS-символ (0x1D) не обрезается, сравнение со `"success"` (строка 383) не срабатывает |
| F-4 | CRED_DISP / CRED_REFR хранят сырые поля (`cred_disp_uid`, …) | Нет ветки нормализации для этих типов |

## Что нужно сделать

### 1. Добавить USER_START, USER_END, USER_LOGOUT, CRED_DISP, CRED_REFR в таблицу EVENT_CATEGORY

Текущий блок (строки 44–57):
```lua
local EVENT_CATEGORY = {
    SYSCALL       = {"process"},
    ...
    USER_START    = {"session"},
    USER_END      = {"session"},
    ...
}
```

Заменить маппинги так, чтобы PAM-сессионные события давали `authentication`:

```lua
USER_LOGIN    = {"authentication"},
USER_AUTH     = {"authentication"},
USER_LOGOUT   = {"authentication"},
USER_START    = {"authentication"},    -- PAM session_open
USER_END      = {"authentication"},    -- PAM session_close
USER_ACCT     = {"authentication"},    -- PAM accounting
CRED_DISP     = {"authentication"},    -- PAM setcred (dispose)
CRED_REFR     = {"authentication"},    -- PAM setcred (refresh)
CRED_ACQ      = {"authentication"},    -- PAM setcred (acquire)
```

### 2. Добавить недостающие типы в if-цепочку primary_type (строки 141–147)

После существующих `elseif`-ветвей добавить:
```lua
elseif etypes["USER_START"]  then primary_type = "USER_START"
elseif etypes["USER_END"]    then primary_type = "USER_END"
elseif etypes["USER_ACCT"]   then primary_type = "USER_ACCT"
elseif etypes["USER_LOGOUT"] then primary_type = "USER_LOGOUT"
elseif etypes["CRED_DISP"]   then primary_type = "CRED_DISP"
elseif etypes["CRED_REFR"]   then primary_type = "CRED_REFR"
elseif etypes["CRED_ACQ"]    then primary_type = "CRED_ACQ"
```

### 3. Добавить нормализацию для USER_*/CRED_* событий

После блока «Syscall» (после строки 325) добавить блок, который работает когда
`primary_type` — один из USER_*/CRED_* типов (т.е. нет syscall):

```lua
-- ── PAM / USER события (USER_START, USER_END, CRED_DISP, CRED_REFR, …) ──
if primary_type == "USER_START" or primary_type == "USER_END"
   or primary_type == "USER_ACCT" or primary_type == "USER_LOGOUT"
   or primary_type == "CRED_DISP" or primary_type == "CRED_REFR"
   or primary_type == "CRED_ACQ" then

    -- event.action из user_event_type или primary_type
    local etype = record["user_event_type"] or primary_type
    record["event.action"] = etype:lower()

    -- event.type
    if primary_type == "USER_START" or primary_type == "USER_ACCT" or primary_type == "CRED_ACQ" then
        record["event.type"] = "start"
    elseif primary_type == "USER_END" or primary_type == "USER_LOGOUT" then
        record["event.type"] = "end"
    else
        record["event.type"] = "info"
    end

    -- user fields: USER_* события хранят поля с префиксом user_*
    -- CRED_* события хранят поля с префиксом cred_disp_*/cred_refr_*
    local u_uid  = record["user_uid"]  or record["cred_disp_uid"]  or record["cred_refr_uid"]
    local u_name = record["user_acct"] or record["cred_disp_acct"] or record["cred_refr_acct"]
    local u_exe  = record["user_exe"]  or record["cred_disp_exe"]  or record["cred_refr_exe"]
    local u_pid  = tonumber(record["user_pid"] or record["cred_disp_pid"] or record["cred_refr_pid"])

    if u_uid  and u_uid  ~= "" then record["user.id"]   = u_uid  end
    if u_name and u_name ~= "" then record["user.name"] = u_name end
    if u_exe  and u_exe  ~= "" then record["process.executable"] = u_exe end
    if u_pid  then record["process.pid"] = u_pid end

    -- Очищаем сырые prefixed-поля чтобы не засорять индекс
    for _, prefix in ipairs({"user_", "cred_disp_", "cred_refr_", "cred_acq_"}) do
        for k in pairs(record) do
            if k:sub(1, #prefix) == prefix then
                record[k] = nil
            end
        end
    end
end
```

### 4. Исправить strip trailing control chars из user_res (строка 381–385)

Текущий код:
```lua
local success = record["syscall_success"] or record["user_res"]
if success then
    record["event.outcome"] = (success == "yes" or success == "success")
        and "success" or "failure"
end
```

Заменить на:
```lua
local success = record["syscall_success"] or record["user_res"]
if success then
    -- strip trailing control chars (auditd добавляет GS 0x1D в конец PAM полей)
    success = success:match("^([%a]+)") or success
    record["event.outcome"] = (success == "yes" or success == "success")
        and "success" or "failure"
end
```

## Критерии приёмки

После деплоя (`cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass`)
в OpenSearch `http://192.168.37.161:9200` должно выполняться:

```bash
# 1. Категория authentication появилась
curl -s 'http://192.168.37.161:9200/fluent-audit-*/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"cats":{"terms":{"field":"event.category","size":20}}}}'
# Ожидание: "authentication" > 0

# 2. event.outcome для USER_START = success (не failure)
curl -s 'http://192.168.37.161:9200/fluent-audit-*/_search?pretty' \
  -H 'Content-Type: application/json' \
  -d '{"size":3,"query":{"term":{"event.category":"authentication"}},"_source":["event.action","event.outcome","user.id","user.name"]}'
# Ожидание: event.outcome = "success" для успешных PAM-сессий

# 3. Нет сырых полей cred_disp_* / user_uid в индексе
curl -s 'http://192.168.37.161:9200/fluent-audit-*/_field_caps?fields=user_uid,cred_disp_uid&pretty'
# Ожидание: поля отсутствуют
```

## Важные ограничения

- Не менять логику для SYSCALL/EXECVE/LOGIN ветвей — они работают корректно.
- Не затрагивать структуру `_event_types` — она заполняется в `auditd_merge.lua`.
- Очистка сырых полей через цикл должна работать при итерации по копии ключей
  (в Lua безопасно удалять из таблицы при итерации `pairs` только с осторожностью;
  лучше сначала собрать список ключей для удаления, потом удалить).
