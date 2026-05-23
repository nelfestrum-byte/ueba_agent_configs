# QA-02. auditd_enrich/merge: ECS-нормализация по результатам QA-01

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор, известные грабли (auditd 4.x EOE, pid→start_time кэш).
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник по ECS-схеме; раздел про event.action / event.category.
- [testing/QA-01-opensearch-field-audit.md](QA-01-opensearch-field-audit.md) — методика аудита, по которой получены данные ниже.
- [agents/configs/fluent-bit/scripts/auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) — где собираются `_execve_args`, `user_*`-поля.
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — где формируется ECS.

## Цель итерации

Закрыть **FAIL и часть WARN из QA-01 отчёта**, относящиеся к `fluent-audit-*`:

| # | Проблема | Где найдено |
|---|----------|-------------|
| 1 | `process.args` идёт в **обратном порядке** (`["10","sleep"]` для `sleep 10`) — нарушает ECS, ломает совместимость с Elastic | [auditd_merge.lua:110-116](../agents/configs/fluent-bit/scripts/auditd_merge.lua#L110) — `pairs(kv)` итерирует ключи `a0/a1/...` в порядке хешмапа, не индекса |
| 2 | `event.action` отсутствует в **37%** событий `event.category=process` (697/1871) | [auditd_enrich.lua:268-359](../agents/configs/fluent-bit/scripts/auditd_enrich.lua#L268) — если `syscall` не в таблице SYSCALLS (или nil), `event.action` не ставится, а category уже `"process"` из EVENT_CATEGORY default для SYSCALL |
| 3 | `event.outcome` отсутствует в **100%** authentication-событий | [auditd_enrich.lua:392-401 vs 458-464](../agents/configs/fluent-bit/scripts/auditd_enrich.lua#L392) — `user_*` ключи **удаляются раньше**, чем считывается `user_res` для outcome. То же для `auditd.session` (читается user_ses на стр.469, удалён на стр.392) |
| 4 | SERVICE_START / SERVICE_STOP идут с не-ECS префиксом (`service_start_msg`, `service_stop_uid`, ...), `event.action` пуст, `host`-категория без атрибутики | [auditd_merge.lua:132-135](../agents/configs/fluent-bit/scripts/auditd_merge.lua#L132) — fallback кладёт всё как `<type:lower>_<k>`; в enrich нет обработчика SERVICE_* |
| 5 | `process.pid` теряется в 2.7% (50/1871) событий с `event.category=process` | USER_CMD-события: enrich блок строки 362-365 покрывает USER_START/END/ACCT/CRED_*/USER_LOGOUT, но **не USER_CMD**, чья category уже `process` (EVENT_CATEGORY:56) → `user_pid → process.pid` не маппится |
| 6 | AF_UNIX/AF_NETLINK события идут с `event.category=network`, но без IP/network.type — шум в индексе (90% network-документов) | [auditd_enrich.lua:437-450](../agents/configs/fluent-bit/scripts/auditd_enrich.lua#L437) — для unix family только `socket_saddr=nil`, категория не меняется |

Решение по AF_UNIX из обсуждения с пользователем: переклассифицировать в `event.category=["network","file"]` (двойная ECS-категория). AF_NETLINK → `event.category="process"`.

Решение по SERVICE_*/USER_*: маппить `auditd type` → `event.action` (например `service_started`, `user_acct`), нормализовать вложенные поля в ECS (`service.name`, `event.outcome`).

**Value сразу:** `fluent-audit-*` становится ECS-консистентным — корреляция в OpenSearch / Kibana / UEBA-корреляторе перестаёт промахиваться по `event.action` / `process.args` / `event.outcome`. Это **критично для главного приоритета проекта — совместимости с оригинальным Elastic**.

## Pre-flight

1. Скриптинг локально (без раскатки на флот):

   ```bash
   # Lua 5.1+
   lua -e 'kv = {a0="grep", a1="-q", a2="pattern"}; for k,v in pairs(kv) do print(k,v) end'
   ```

   Воспроизвести недетерминированный/обратный порядок `pairs(kv)` — подтвердить корневую причину #1.

2. Снимок текущих метрик до фикса (для сравнения):

   ```bash
   OS=http://192.168.37.161:9200

   # #1: посмотреть текущий порядок args
   curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' \
     -d '{"size":3,"query":{"term":{"event.action":"execve"}},"_source":["process.args","process.command_line"],"sort":[{"@timestamp":"desc"}]}'

   # #2: missing event.action в process category
   curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' \
     -d '{"size":0,"query":{"term":{"event.category":"process"}},"aggs":{"total":{"value_count":{"field":"event.dataset"}},"missing_action":{"missing":{"field":"event.action"}}}}'

   # #3: missing event.outcome / auditd.session в auth
   curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' \
     -d '{"size":0,"query":{"term":{"event.category":"authentication"}},"aggs":{"total":{"value_count":{"field":"event.dataset"}},"missing_outcome":{"missing":{"field":"event.outcome"}},"missing_session":{"missing":{"field":"auditd.session"}}}}'

   # #4: SERVICE_* без event.action
   curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' \
     -d '{"size":0,"query":{"term":{"event.category":"host"}},"aggs":{"missing_action":{"missing":{"field":"event.action"}},"has_service_msg":{"filter":{"exists":{"field":"service_start_msg"}}}}}'
   ```

   Записать числа — потом понадобятся для post-flight.

## Реализация

### Шаг 1. Фикс реверса `process.args` в `auditd_merge.lua`

В [auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) в блоке EXECVE (строки 110-116) заменить on:

```lua
elseif atype == "EXECVE" then
    entry["execve_argc"] = kv["argc"]
    -- Собираем a0, a1, ..., a<argc-1> в порядке индекса.
    -- pairs(kv) НЕ детерминирован — нельзя полагаться на порядок хеш-таблицы.
    local argc = tonumber(kv["argc"]) or 0
    local args = entry["_execve_args"]
    for i = 0, argc - 1 do
        local v = kv["a" .. i]
        if v then
            args[#args + 1] = decode_hex(v)
        end
    end
```

**Не использовать** `pairs(kv) + sort` — `argc` единственный источник истины для длины массива.

### Шаг 2. Порядок очистки в `auditd_enrich.lua` (USER_* блок)

В [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) блок USER/CRED (строки 362-402): **переместить очистку `user_*` ключей в конец функции** (после `event.outcome` и `auditd.session`). Простейший подход — удалить блок 392-401 и заменить добавление имён в финальную «Очистку служебных полей» (строки 479-485):

```lua
    -- ── Очистка служебных полей ──
    record["_paths"]           = nil
    record["_execve_args"]     = nil
    record["_event_types"]     = nil
    record["syscall_success"]  = nil
    record["syscall_exit"]     = nil

    -- user_*/cred_*: удаляем В САМОМ КОНЦЕ — после event.outcome (user_res)
    -- и auditd.session (user_ses) ниже. Если очистить раньше, эти поля будут пусты.
    local user_keys = {}
    for k in pairs(record) do
        for _, prefix in ipairs({"user_", "cred_disp_", "cred_refr_", "cred_acq_"}) do
            if k:sub(1, #prefix) == prefix then
                user_keys[#user_keys + 1] = k
                break
            end
        end
    end
    for _, k in ipairs(user_keys) do record[k] = nil end
```

Также:
- Расширить блок строки 362-365 — **добавить `USER_CMD` и `USER_LOGIN`** в условие (чтобы они тоже получили `process.pid = user_pid`):

  ```lua
  if primary_type == "USER_START"  or primary_type == "USER_END"
  or primary_type == "USER_ACCT"   or primary_type == "USER_LOGOUT"
  or primary_type == "USER_LOGIN"  or primary_type == "USER_CMD"
  or primary_type == "CRED_DISP"   or primary_type == "CRED_REFR"
  or primary_type == "CRED_ACQ" then
  ```

- Внутри блока action ставится из `user_event_type` (строка 367-368) — оставить. Но добавить нормализацию пробелов/префиксов: `record["event.action"] = etype:lower():gsub("^user_", "")` если хочется коротких имён (`auth`, `start`, `end`, `acct`, `cmd`, `login`, `logout`). **Не обязательно** — главное, чтобы поле было непустым; для UEBA-корреляции достаточно `user_auth`, `user_acct` и т.д.

### Шаг 3. event.action для SYSCALL вне таблицы SYSCALLS

В [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) после блока 268-349 добавить fallback (после `end` строки 349, до закрывающего `end` блока syscall):

```lua
    -- если syscall не в SYSCALLS, но record["syscall"] есть — оставить номер
    -- как event.action чтобы поле не было пустым (фикс для UEBA-корреляции).
    if record["syscall"] and not record["event.action"] then
        record["event.action"] = "syscall_" .. record["syscall"]
        record["auditd.data.syscall"] = record["auditd.data.syscall"]
            or ("syscall_" .. record["syscall"])
    end
```

Это закрывает 37% missing — но **корректнее**: посмотреть в логах `journalctl -u fluent-bit | grep "syscall.*not in SYSCALLS"` (если решишь логировать) или прямо в `fluent-audit-*` через aggregation, **какие именно номера** теряются:

```bash
curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"bool":{"must":[{"term":{"event.category":"process"}}],"must_not":[{"exists":{"field":"event.action"}}]}},"aggs":{"by_syscall":{"terms":{"field":"syscall","size":20}}}}'
```

И добавить топ-N номеров в таблицу SYSCALLS (строки 9-41). Скорее всего это будут setresgid (119), setregid (114), setfsuid (122), setfsgid (123) — приватизированные варианты, audit правила их ловят, но enrich не знает.

### Шаг 4. SERVICE_START / SERVICE_STOP нормализация

В [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua):

#### 4.1. Расширить EVENT_CATEGORY (строки 44-61):

```lua
local EVENT_CATEGORY = {
    -- ... существующее ...
    SERVICE_START = {"host"},
    SERVICE_STOP  = {"host"},
}
```

#### 4.2. Добавить SERVICE_* в primary_type детектор (строки 156-173):

```lua
    elseif etypes["SERVICE_START"] then primary_type = "SERVICE_START"
    elseif etypes["SERVICE_STOP"]  then primary_type = "SERVICE_STOP"
```

#### 4.3. Добавить обработчик SERVICE_* (после блока USER, до блока File):

```lua
    -- ── SERVICE_START / SERVICE_STOP (systemd unit lifecycle) ──
    if primary_type == "SERVICE_START" or primary_type == "SERVICE_STOP" then
        record["event.action"] = (primary_type == "SERVICE_START")
            and "service_started" or "service_stopped"
        record["event.type"]   = (primary_type == "SERVICE_START") and "start" or "end"

        local prefix = primary_type:lower() .. "_"  -- "service_start_" / "service_stop_"

        -- msg='unit=foo comm=systemd ...' либо msg='unit=foo' (auditd quote-quirks)
        local raw_msg = record[prefix .. "msg"]
        if raw_msg then
            -- strip leading/trailing quote/control chars
            local unit = raw_msg:match("unit=([%w@%-_.:]+)")
            if unit then record["service.name"] = unit end
        end

        local res = record[prefix .. "res"]
        if res then
            res = res:match("^([%a]+)") or res
            record["event.outcome"] = (res == "success") and "success" or "failure"
        end

        if record[prefix .. "pid"] then record["process.pid"] = tonumber(record[prefix .. "pid"]) end
        if record[prefix .. "exe"] then record["process.executable"] = record[prefix .. "exe"] end
        if record[prefix .. "uid"] then record["user.id"] = record[prefix .. "uid"] end
        if record[prefix .. "UID"] and record[prefix .. "UID"] ~= "unset" then
            record["user.name"] = record[prefix .. "UID"]
        end

        -- очистка raw-полей в финальном блоке (см. ниже)
    end
```

#### 4.4. В финальной очистке (строки 479-485) добавить:

```lua
    -- service_start_*/service_stop_* → удаляем после нормализации
    local svc_keys = {}
    for k in pairs(record) do
        if k:sub(1, 14) == "service_start_" or k:sub(1, 13) == "service_stop_" then
            svc_keys[#svc_keys + 1] = k
        end
    end
    for _, k in ipairs(svc_keys) do record[k] = nil end
```

### Шаг 5. AF_UNIX / AF_NETLINK переклассификация

В [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) блок socket (строки 433-450) заменить на:

```lua
    -- ── Сетевой адрес из SOCKADDR ──
    local saddr_hex = record["socket_saddr"]
    if saddr_hex then
        local net_type, ip, port = decode_saddr(saddr_hex)
        if net_type == "ipv4" or net_type == "ipv6" then
            local action = record["event.action"]
            if action == "accept" or action == "accept4" then
                record["source.ip"]   = ip
                record["source.port"] = port
            else
                record["destination.ip"]   = ip
                record["destination.port"] = port
            end
            record["network.type"] = net_type
        elseif net_type == "unix" then
            -- AF_UNIX: IPC через файл-сокет → file-семантика дороже network-семантики
            -- для UEBA. ECS позволяет массив значений в event.category.
            record["event.category"] = {"network", "file"}
            record["network.type"]   = "unix"
            -- file.path установится ниже из PATH-записи, если auditd её прислал
        else
            -- AF_NETLINK / AF_PACKET / прочее — не сетевые в UEBA-смысле,
            -- переводим в process-категорию (это управление ядром/маршрутизацией).
            record["event.category"] = "process"
            record["network.type"]   = (saddr_hex:sub(1,2) == "10" and "netlink") or nil
        end
        record["socket_saddr"]  = nil
        record["socket_family"] = nil
    end
```

Hex-маркер `10` для NETLINK — это little-endian AF_NETLINK=16=0x10. Если в decode_saddr захочется расширить — добавить:

```lua
    elseif family == 16 then return "netlink", nil, nil
    elseif family == 17 then return "packet",  nil, nil
```

(семейство 16 = AF_NETLINK, 17 = AF_PACKET).

### Шаг 6. Сборка и smoke-тест

```bash
# 1. Lua syntax check
lua -e 'dofile("agents/configs/fluent-bit/scripts/auditd_merge.lua")' || true
lua -e 'dofile("agents/configs/fluent-bit/scripts/auditd_enrich.lua")' || true
# (вернёт ошибку из-за require("proc_common") — это нормально, проверяет только парсинг)

# 2. Раскатать на ОДИН тестовый хост
ansible-playbook agents/deploy/agents-deploy.yml --limit=agent03.uir.prj --ask-become-pass

# 3. Подождать ~2 минуты, повторить QA-01 чек
OS=http://192.168.37.161:9200

# args order — должен быть прямой
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' \
  -d '{"size":3,"query":{"term":{"event.action":"execve"}},"_source":["process.args","process.command_line"],"sort":[{"@timestamp":"desc"}]}'
# Ожидание: process.args[0] = базовое имя процесса, не последний arg

# missing event.action
curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"term":{"event.category":"process"}},"aggs":{"missing_action":{"missing":{"field":"event.action"}}}}'
# Ожидание: missing_action.doc_count → ~0 (или близко к нулю; зависит от того, добавлены ли все недостающие syscall в SYSCALLS)

# missing event.outcome / auditd.session
curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"term":{"event.category":"authentication"}},"aggs":{"missing_outcome":{"missing":{"field":"event.outcome"}},"missing_session":{"missing":{"field":"auditd.session"}}}}'
# Ожидание: оба → ~0

# SERVICE_*
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' \
  -d '{"size":3,"query":{"term":{"event.action":"service_started"}},"_source":["event.action","service.name","event.outcome","host.name"]}'
# Ожидание: service.name заполнен, event.outcome=success/failure

# AF_UNIX category
curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"term":{"network.type":"unix"}},"aggs":{"cats":{"terms":{"field":"event.category"}}}}'
# Ожидание: buckets содержат "network" И "file"
```

### Шаг 7. Раскатка по флоту

После 30 минут стабильной работы на agent03 — раскатить на остальные:

```bash
ansible-playbook agents/deploy/agents-deploy.yml --ask-become-pass
```

## Что НЕ делать в этой итерации

- **НЕ трогать pid→start_time cold-start fallback** (`labels.entity_id_source=event_timestamp_fallback`) — это known limitation из CLAUDE.md, требует переработки кэша или подсасывания из osquery, отдельная задача.
- **НЕ исключать AF_UNIX из audit.rules** — теряется видимость Docker IPC. Решение принято: переклассификация в enrich.
- **НЕ менять структуру `_event_types` / `_paths`** в merge — это служебные поля, читаются enrich'ем, ломать обратную совместимость.
- **НЕ добавлять MITRE ATT&CK теги** (`threat.*`) — закомментированы намеренно (см. README_FOR_AI.md). Не разкомментировать.
- **НЕ переименовывать `event.action=connect` в `socket_connect`** — auditd-выходы должны оставаться по имени syscall, осquery BPF — отдельная convention.

## Критерии готовности

- `process.args` для execve событий — массив с первым элементом = базовое имя процесса (`["grep","-q","pattern"]` для `grep -q pattern`).
- `event.action` отсутствует не более чем в 1% событий `event.category=process` (было 37%).
- `event.outcome` присутствует в ≥95% событий authentication (было 0%).
- `auditd.session` присутствует в ≥95% событий authentication (было 0%).
- SERVICE_START / SERVICE_STOP события имеют `event.action ∈ {service_started, service_stopped}`, `service.name` заполнен.
- AF_UNIX события имеют `event.category=["network","file"]`, `network.type="unix"`. `network.type` присутствует в ≥80% событий `event.category=network` (было 10%).
- `fluent-bit` метрики: `input.tail.0.errors`, `filter.lua.*.errors` остаются 0.
- Старые поля `service_start_*` / `service_stop_*` / `user_res` / `user_ses` НЕ присутствуют в новых документах.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - Раздел про auditd ECS-схему: явно описать, что `process.args[0]` = базовое имя, не последний arg.
   - Добавить SERVICE_START / SERVICE_STOP в перечень поддерживаемых `event.action`.
   - AF_UNIX → `event.category=["network","file"]` — задокументировать как ECS-расширение проекта.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В «Известные особенности и грабли» добавить пункт «USER_*: очистка после event.outcome/session, не до» как анти-граблю.
   - В таблицу «Ключевые файлы по темам» — упоминание SERVICE_* обработчика.

3. **Закоммитить:**

   ```
   QA-02: ECS normalization fixes from QA-01 audit

   - merge.lua: collect _execve_args by index (a0..a<argc-1>) — fixes reversed process.args
   - enrich.lua: move user_*/cred_* cleanup AFTER event.outcome/auditd.session reads
   - enrich.lua: USER_CMD and USER_LOGIN now in PAM block — process.pid no longer lost
   - enrich.lua: SYSCALL fallback action when number unknown — no more 37% missing event.action
   - enrich.lua: SERVICE_START/SERVICE_STOP normalization (service.name, event.outcome, event.action)
   - enrich.lua: AF_UNIX → event.category=["network","file"], network.type="unix";
                 AF_NETLINK → event.category="process", network.type="netlink"
   - Smoke on agent03: all post-flight checks green; no fluent-bit Lua errors

   Closes FAIL #1-5 from testing/QA-01 report.
   ```

4. **Сообщить пользователю**: «raw audit-стрим теперь ECS-консистентен; следующий шаг — QA-03 (osquery_enrich)».
