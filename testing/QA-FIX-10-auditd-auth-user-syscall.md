# QA-FIX-10. auditd_enrich: user.name fallback для USER_*/CRED_* + маппинг syscall_119/126/44/46

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор, раздел «USER_* / SERVICE_*: очистка raw-полей в самом конце enrich (QA-02)» — обязательное чтение перед правкой блока USER/CRED.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник ECS, разделы про `event.action` и `user.*`.
- [testing/QA-01-opensearch-field-audit.md](QA-01-opensearch-field-audit.md) — методика, по которой найдены проблемы.
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — главный файл правки.
- [agents/configs/fluent-bit/scripts/auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) — где формируются `user_*_acct` / `cred_*_acct` префиксы.

## Цель итерации

Закрыть **FAIL и WARN из QA-01 v4-итерации**, относящиеся к `fluent-audit-*`:

| # | Проблема | Симптом в QA-01 v4 |
|---|----------|--------------------|
| 1 | `user.name` отсутствует в **100%** events `event.category=authentication` (513/513) | `missing_user.doc_count=513`; затрагивает `cred_disp`, `cred_refr`, `cred_acq`, `user_acct`, `user_start`, `user_end` |
| 2 | `event.outcome` отсутствует у `cred_disp`/`cred_refr`/`cred_acq` (207/207) | хотя `user_acct`/`user_start`/`user_end` его имеют — значит `cred_*_res` не маппится |
| 3 | `auditd.session` отсутствует у `cred_*` (213/513) | `cred_*_ses` не маппится; `user_acct`/`user_start`/`user_end` маппят |
| 4 | `event.action` остаётся числовым: `syscall_119`, `syscall_126`, `syscall_44`, `syscall_46` (суммарно **1101 events**, ~26% от audit/process) | auditd 4.x не интерпретирует имя для setresgid (119), setregid (126), sendto (44), sendmsg (46); enrich не имеет fallback таблицы для них |

**Гипотеза причин** (нужно подтвердить чтением кода перед правкой):

- (#1) В [auditd_enrich.lua:248-265](../agents/configs/fluent-bit/scripts/auditd_enrich.lua#L248) `user.name` присваивается ТОЛЬКО из `record["uid_name"]`. В сообщениях `USER_CRED_DISP`, `USER_CRED_REFR`, `USER_CRED_ACQ`, `USER_ACCT`, `USER_START`, `USER_END` ядро auditd не пишет поле `uid=`/`uid_name=` — только `acct=` (целевой пользователь) и `auid=` (запросивший). После merge.lua они оказываются в `record["user_acct"]`, `record["cred_disp_acct"]`, `record["cred_refr_acct"]`, `record["cred_acq_acct"]` (с префиксом источника). `auid_name` тоже доступен. Нужна fallback-цепочка.
- (#2, #3) Только `USER_ACCT`/`USER_START`/`USER_END` мержатся с префиксом `user_*` → `user_res`/`user_ses` (читаются в финальном блоке outcome). `CRED_*` мержатся с префиксом `cred_disp_*`/`cred_refr_*`/`cred_acq_*` → `cred_*_res`, `cred_*_ses` — но финальный блок outcome/session их **не читает**. Нужно добавить fallback в чтение.
- (#4) Простая правка: добавить в таблицу маппинга syscall числовое → имя для 119/126/44/46.

**Value:** authentication-события (sudo, su, login, pam) становятся полноценными для UEBA-скоринга: видим **кто** (`user.name`), **результат** (`event.outcome`), **сессию** (`auditd.session`). 1101 process-событий получают читабельное `event.action` вместо `syscall_NNN`. Совместимость с Elastic auditbeat пайплайнами восстанавливается.

## Pre-flight

```bash
OS=http://192.168.37.161:9200

# Снимок до правки — записать числа для post-flight сравнения

# #1, #2, #3: missing fields в auth-категории, разрез по action
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "term": { "event.dataset":  "auditd"  } },
    { "term": { "event.category": "authentication" } }
  ]}},
  "aggs": {
    "by_action": { "terms": { "field": "event.action", "size": 20 },
      "aggs": {
        "has_user_name": { "filter": { "exists": { "field": "user.name" } } },
        "has_outcome":   { "filter": { "exists": { "field": "event.outcome" } } },
        "has_session":   { "filter": { "exists": { "field": "auditd.session" } } }
      }
    },
    "missing_user":     { "missing": { "field": "user.name" } },
    "missing_outcome":  { "missing": { "field": "event.outcome" } },
    "missing_session":  { "missing": { "field": "auditd.session" } }
  }
}'
# Ожидание ДО фикса: missing_user.doc_count = total. После фикса: 0.

# #4: распределение syscall_NNN в process
curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "wildcard": { "event.action": "syscall_*" } },
  "aggs": { "by_action": { "terms": { "field": "event.action", "size": 20 } } }
}'
# Ожидание ДО: syscall_119, syscall_126, syscall_44, syscall_46.
# После: только редкие syscall_NNN, которых нет в нашей таблице.

# Один сэмпл cred_disp — посмотреть какие raw-поля доступны
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 1,
  "query": { "term": { "event.action": "cred_disp" } },
  "_source": ["*"]
}' | python3 -m json.tool
# Записать какие cred_disp_* поля присутствуют (acct, auid, res, ses, hostname).
```

## Реализация

### Шаг 0. Подтвердить корневые причины чтением кода

Прочитать целиком (не grep'ами, а full read — файл ~600 строк):

- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — блок «Пользователь» (~стр.248-275), блок USER_* (~стр.377-440), финальный cleanup (см. CLAUDE.md «USER_* / SERVICE_*»), таблица SYSCALLS.
- [agents/configs/fluent-bit/scripts/auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) — раздел про USER/CRED префиксы (~стр.122-160). Подтвердить, что `cred_disp_*`, `cred_refr_*`, `cred_acq_*` действительно формируются.

Если фактическое поведение отличается от гипотез выше — **скорректировать план и сообщить пользователю до правки**.

### Шаг 1. user.name fallback (закрывает #1)

В [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua), блок «Пользователь» (примерно строки 248-275), добавить fallback **до финального cleanup**:

```lua
-- ── Пользователь ──
local uid = record["uid"]
if uid then
    record["user.id"] = uid
    if record["uid_name"] then record["user.name"] = record["uid_name"] end
end

local auid = record["auid"]
if auid and auid ~= "4294967295" and auid ~= "-1" then
    record["user.effective.id"] = auid
    if record["auid_name"] then record["user.effective.name"] = record["auid_name"] end
end

-- Основной источник user.name — uid_name (соответствует user.id).
if record["uid_name"] and record["uid_name"] ~= "" then
    record["user.name"] = record["uid_name"]
end

-- Fallback для USER_*/CRED_* событий: ядро не пишет uid= в эти сообщения,
-- только acct= (целевой) и auid= (запросивший). Берём в порядке предпочтения:
-- запросивший пользователь (auid_name) → имя целевой учётки (acct).
-- Это закрывает 100% missing user.name в category=authentication.
if not record["user.name"] or record["user.name"] == "" then
    record["user.name"] = record["auid_name"]
                       or record["user_acct"]
                       or record["cred_disp_acct"]
                       or record["cred_refr_acct"]
                       or record["cred_acq_acct"]
end

-- user.target.name = целевая учётная запись PAM/sudo.
-- Если user.name взяли из acct (fallback), user.target.name не дублируем.
if record["user_acct"] and record["user_acct"] ~= "" then
    record["user.target.name"] = record["user_acct"]
end
```

**Важно:** fallback должен идти **ПЕРЕД** финальным cleanup raw-полей (см. CLAUDE.md, грабли QA-02). Если поставить после — `user_acct`/`cred_*_acct` будут уже nil.

### Шаг 2. event.outcome / auditd.session fallback для CRED_* (закрывает #2, #3)

Найти финальные блоки «Результат события» (читает `user_res`/`service_*_res`) и «Сессия auditd» (читает `user_ses`). Расширить чтение fallback на `cred_*_res` / `cred_*_ses`:

```lua
-- ── Результат события (event.outcome) ──
local res = record["user_res"]
          or record["cred_disp_res"]
          or record["cred_refr_res"]
          or record["cred_acq_res"]
          or record["service_start_res"]
          or record["service_stop_res"]
if res == "success" or res == "failed" then
    record["event.outcome"] = (res == "success") and "success" or "failure"
end

-- ── Сессия auditd (auditd.session) ──
local ses = record["user_ses"]
         or record["cred_disp_ses"]
         or record["cred_refr_ses"]
         or record["cred_acq_ses"]
if ses and ses ~= "" and ses ~= "unset" and ses ~= "4294967295" then
    record["auditd.session"] = tonumber(ses) or ses
end
```

**Финальный cleanup всех raw-полей** (выполняется в конце `enrich_ecs` по требованию CLAUDE.md) расширить — добавить очистку cred_*-полей:

```lua
-- Очистка raw-полей USER_*/CRED_*/SERVICE_* в самом конце функции.
-- Идёт ПОСЛЕ блоков event.outcome / auditd.session / user.name fallback.
record["user_acct"]        = nil
record["user_res"]         = nil
record["user_ses"]         = nil
record["user_hostname"]    = nil
record["cred_disp_acct"]   = nil
record["cred_disp_res"]    = nil
record["cred_disp_ses"]    = nil
record["cred_disp_hostname"] = nil
record["cred_refr_acct"]   = nil
record["cred_refr_res"]    = nil
record["cred_refr_ses"]    = nil
record["cred_refr_hostname"] = nil
record["cred_acq_acct"]    = nil
record["cred_acq_res"]     = nil
record["cred_acq_ses"]     = nil
record["cred_acq_hostname"] = nil
record["service_start_msg"] = nil
record["service_start_res"] = nil
record["service_stop_msg"]  = nil
record["service_stop_res"]  = nil
record["auid_name"]        = nil
record["uid_name"]         = nil
```

**Проверить полный список префиксов в [auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) — если есть другие (`user_login_*`, `user_logout_*` и т.д.), добавить их в fallback и в cleanup.**

### Шаг 3. Маппинг syscall_119/126/44/46 (закрывает #4)

Найти таблицу маппинга syscall number → name в [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) (поищи `SYSCALLS = {` или похожее). Добавить недостающие записи:

```lua
local SYSCALLS = {
    -- ... existing ...
    ["44"]  = "sendto",      -- network/process
    ["46"]  = "sendmsg",     -- network
    ["119"] = "setresgid",   -- iam
    ["126"] = "setregid",    -- iam
    -- ... existing ...
}
```

Если таблицы нет (enrich использует прямой `auditd.data.syscall` string), то добавить map-функцию:

```lua
local NUMERIC_SYSCALL_NAMES = {
    ["44"]  = "sendto",
    ["46"]  = "sendmsg",
    ["119"] = "setresgid",
    ["126"] = "setregid",
}

-- Применять там, где event.action = "syscall_<number>" сейчас формируется:
local sc = record["auditd.data.syscall"]
if sc and sc:match("^syscall_(%d+)$") then
    local num = sc:match("^syscall_(%d+)$")
    if NUMERIC_SYSCALL_NAMES[num] then
        record["event.action"] = NUMERIC_SYSCALL_NAMES[num]
        record["auditd.data.syscall"] = NUMERIC_SYSCALL_NAMES[num]
    end
end
```

**Категория для новых имён:**
- `sendto` (44), `sendmsg` (46) — это **network** syscalls. Если уже есть SOCKADDR в merged event → категория переключится на `network` через существующий код. Если нет — оставить `process` (общий случай).
- `setresgid` (119), `setregid` (126) — это **iam** (изменение GID). Должны идти в `event.category=iam`. Проверить, что в enrich есть таблица `EVENT_CATEGORY` или similar — добавить эти syscalls в группу iam (рядом с `setuid`, `setresuid`, `setgid`).

### Шаг 4. Раскатка через ansible

```bash
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass --tags fluent-bit
# или, если тегов нет:
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

После раскатки проверить, что fluent-bit перезапустился без ошибок Lua:

```bash
ansible all -m shell -a "systemctl is-active fluent-bit; journalctl -u fluent-bit -n 30 --no-pager | grep -iE 'error|fatal|lua'" -i agents/deploy/inventory.ini
```

## Post-flight (smoke-тест)

Подождать 2-3 минуты для генерации новых событий, затем:

```bash
OS=http://192.168.37.161:9200

# #1 + #2 + #3: повторить pre-flight aggregation
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "term": { "event.dataset":  "auditd"  } },
    { "term": { "event.category": "authentication" } },
    { "range": { "@timestamp": { "gte": "now-5m" } } }
  ]}},
  "aggs": {
    "by_action": { "terms": { "field": "event.action", "size": 20 },
      "aggs": {
        "has_user_name": { "filter": { "exists": { "field": "user.name" } } },
        "has_outcome":   { "filter": { "exists": { "field": "event.outcome" } } },
        "has_session":   { "filter": { "exists": { "field": "auditd.session" } } }
      }
    }
  }
}'
# Ожидание: has_user_name.doc_count ≈ total для каждого action.
# Ожидание: has_outcome.doc_count ≈ total для cred_disp/cred_refr/cred_acq.
# Ожидание: has_session.doc_count ≈ total для cred_*.

# #4: syscall_NNN остался?
curl -s "$OS/fluent-audit-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "wildcard": { "event.action": "syscall_*" } },
    { "range":    { "@timestamp": { "gte": "now-5m" } } }
  ]}},
  "aggs": { "by_action": { "terms": { "field": "event.action", "size": 20 } } }
}'
# Ожидание: syscall_119, syscall_126, syscall_44, syscall_46 — пусто.
# Ожидание: появились event.action=setresgid, setregid, sendto, sendmsg.

# Проверка, что setresgid/setregid идут в iam, а не process
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "terms": { "event.action": ["setresgid","setregid"] } },
    { "range": { "@timestamp": { "gte": "now-5m" } } }
  ]}},
  "aggs": { "by_category": { "terms": { "field": "event.category" } } }
}'
# Ожидание: by_category buckets: iam — большинство.
```

## Что НЕ делать в этой итерации

- **НЕ трогать `auditd_merge.lua`** — это правка только в enrich (источники полей уже формируются корректно).
- **НЕ менять index template** — все правки совместимы с текущим маппингом (user.name/event.outcome — keyword, auditd.session — long, уже типизированы корректно).
- **НЕ добавлять новые syscall'ы кроме 119/126/44/46** в этот патч — если в post-flight всплывут другие `syscall_NNN`, открыть отдельный QA-FIX.
- **НЕ переписывать таблицу EVENT_CATEGORY с нуля** — только добавить недостающие записи для 119/126.
- **НЕ перетягивать fallback на bash_history/last_logins** — это osquery, отдельная задача QA-FIX-11/12.

## Критерии готовности

- `user.name` присутствует в **100%** событий `event.category=authentication` за окно после раскатки.
- `event.outcome` присутствует в `cred_disp`/`cred_refr`/`cred_acq` событиях (там, где raw `cred_*_res` есть).
- `auditd.session` присутствует в `cred_*` событиях.
- `event.action=setresgid` / `setregid` / `sendto` / `sendmsg` появились в новых документах; `syscall_119`/`126`/`44`/`46` исчезли.
- `setresgid`/`setregid` имеют `event.category=iam`.
- fluent-bit healthy на всех хостах, нет Lua errors в journalctl.
- Старые документы (с ошибкой) не трогаем — они уходят с ротацией индекса.

## Финал

1. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В раздел «USER_* / SERVICE_*: очистка raw-полей в самом конце enrich (QA-02)» добавить заметку, что список raw-полей теперь включает `cred_*_*` (расширили в QA-FIX-10).
   - В раздел «Известные особенности и грабли» добавить блок про fallback `user.name = uid_name | auid_name | user_acct | cred_*_acct` для CRED_*-сообщений.

2. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В разделе про authentication-события упомянуть fallback-цепочку для `user.name`.

3. **Закоммитить:**

   ```
   QA-FIX-10: auditd auth/iam fixes + syscall mapping for 119/126/44/46

   - auditd_enrich.lua:
     - user.name fallback: uid_name -> auid_name -> user_acct -> cred_*_acct
       Closes 100% missing user.name in authentication events.
     - event.outcome / auditd.session fallback to cred_disp_*/cred_refr_*/cred_acq_*.
       Closes missing outcome+session for CRED_DISP/CRED_REFR/CRED_ACQ.
     - Syscall map: 44=sendto, 46=sendmsg, 119=setresgid, 126=setregid.
       setresgid/setregid routed to event.category=iam.
     - Final cleanup expanded to cred_*_* raw fields.

   Closes FAIL #1/#2/#3 and WARN #syscall_NNN from QA-01 v4 audit.
   ```

4. **Сообщить пользователю:** все FAIL по authentication закрыты, ~26% process-событий получают читабельный `event.action`. Старые накопленные документы остаются как есть (audit-индекс ротируется по дате).
