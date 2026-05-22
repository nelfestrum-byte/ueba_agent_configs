# QA-FIX-06. auditd_enrich.lua — user.name/user.target.name для PAM событий

## Контекст

Файл: `agents/configs/fluent-bit/scripts/auditd_enrich.lua`

По результатам QA-01 (второй прогон) в категории `authentication` обнаружена
несогласованность `user.id` и `user.name`:

```json
{
  "event.action": "cred_disp",
  "user.id": "1000",       ← UID вызывающего процесса (installer)
  "user.name": "root"      ← НЕВЕРНО: это target account (sudo target), не имя uid=1000
}
```

Для UEBA-корреляции это критично: граф пользователь→действие строится
по `user.id + user.name`. Несоответствие означает, что uid=1000 будет
ошибочно ассоциирован с именем "root", делая атрибуцию действий неверной.

**Причина в коде:**

Два места в `auditd_enrich.lua` ошибочно используют `user_acct` как `user.name`:

**Место 1 — глобальный блок (≈строки 253–258):**
```lua
if record["user_acct"] then
    record["user.name"] = record["user_acct"]   -- НЕВЕРНО: user_acct = target
end

record["uid_name"]  = nil    -- ← uid_name (имя вызывающего) здесь очищается!
record["auid_name"] = nil
```

`uid_name` — это строковое имя, соответствующее `uid` (поле `uid_name` из auditd).
Оно очищается на строке 257–258 **после** того, как `user_acct` уже был
ошибочно записан в `user.name`. В итоге:
- `user.name = "root"` (из user_acct — target)
- `uid_name = nil` (имя процессного пользователя потеряно)

**Место 2 — PAM-блок (≈строки 371–375):**
```lua
local u_name = record["user_acct"] or record["cred_disp_acct"] or record["cred_refr_acct"]
if u_name and u_name ~= "" then record["user.name"] = u_name end
```

Та же ошибка: `user_acct` (target) → `user.name`.

**Правильная ECS-семантика для PAM/sudo событий:**

| ECS поле | Значение | Источник в auditd |
|----------|----------|-------------------|
| `user.id` | UID вызывающего (1000) | uid / user_uid |
| `user.name` | Имя вызывающего ("installer") | uid_name |
| `user.target.name` | Целевая учётная запись ("root") | acct / user_acct / cred_*_acct |
| `user.effective.id` | auid (login UID) | auid |
| `user.effective.name` | Имя login-пользователя | auid_name |

## Что нужно сделать

### Исправление 1: глобальный блок (≈строки 247–258)

**Найти блок** (выглядит приблизительно так):
```lua
local auid = record["auid"]
if auid and auid ~= "4294967295" and auid ~= "-1" then
    record["user.effective.id"] = auid
    if record["auid_name"] then record["user.effective.name"] = record["auid_name"] end
end

if record["user_acct"] then
    record["user.name"] = record["user_acct"]
end

record["uid_name"]  = nil
record["auid_name"] = nil
```

**Заменить на:**
```lua
local auid = record["auid"]
if auid and auid ~= "4294967295" and auid ~= "-1" then
    record["user.effective.id"] = auid
    if record["auid_name"] then record["user.effective.name"] = record["auid_name"] end
end

-- user.name = имя вызывающего процесса (uid_name, соответствует user.id/uid).
-- Устанавливаем ДО очистки uid_name.
if record["uid_name"] and record["uid_name"] ~= "" then
    record["user.name"] = record["uid_name"]
end

-- user.target.name = целевая учётная запись PAM/sudo (acct-поле auditd).
-- Отличается от user.name при sudo (installer → root).
if record["user_acct"] and record["user_acct"] ~= "" then
    record["user.target.name"] = record["user_acct"]
end

record["uid_name"]  = nil
record["auid_name"] = nil
```

### Исправление 2: PAM-блок (≈строки 371–380)

**Найти блок** (внутри `if primary_type == "USER_START" or ...`):
```lua
local u_uid  = record["user_uid"]  or record["cred_disp_uid"]  or record["cred_refr_uid"]
local u_name = record["user_acct"] or record["cred_disp_acct"] or record["cred_refr_acct"]
local u_exe  = record["user_exe"]  or record["cred_disp_exe"]  or record["cred_refr_exe"]
local u_pid  = tonumber(record["user_pid"] or record["cred_disp_pid"] or record["cred_refr_pid"])

if u_uid  and u_uid  ~= "" then record["user.id"]   = u_uid  end
if u_name and u_name ~= "" then record["user.name"] = u_name end
if u_exe  and u_exe  ~= "" then record["process.executable"] = u_exe end
if u_pid  then record["process.pid"] = u_pid end
```

**Заменить на:**
```lua
local u_uid    = record["user_uid"]   or record["cred_disp_uid"]   or record["cred_refr_uid"]
local u_target = record["user_acct"]  or record["cred_disp_acct"]  or record["cred_refr_acct"]
local u_exe    = record["user_exe"]   or record["cred_disp_exe"]   or record["cred_refr_exe"]
local u_pid    = tonumber(record["user_pid"] or record["cred_disp_pid"] or record["cred_refr_pid"])

if u_uid    and u_uid    ~= "" then record["user.id"]          = u_uid    end
-- user.name уже установлен из uid_name в глобальном блоке выше.
-- user_acct (target account) → user.target.name.
if u_target and u_target ~= "" then record["user.target.name"] = u_target end
if u_exe    and u_exe    ~= "" then record["process.executable"] = u_exe  end
if u_pid    then record["process.pid"] = u_pid end
```

## Что НЕ менять

- Логику для SYSCALL/EXECVE/LOGIN ветвей — они работают корректно.
- Блок очистки сырых префиксных полей (`user_`, `cred_disp_`, ...) — оставить как есть.
- Поля `user.effective.id` / `user.effective.name` — они правильные.

## Поведение после фикса

Для sudo (`installer` → `root`):
```json
{
  "event.action": "cred_disp",
  "user.id": "1000",
  "user.name": "installer",        ← теперь соответствует user.id
  "user.target.name": "root",      ← целевая учётная запись
  "user.effective.id": "1000",     ← auid (login UID)
  "user.effective.name": "installer"
}
```

Для прямого логина (`user_start` installer → installer):
```json
{
  "event.action": "user_start",
  "user.id": "1000",
  "user.name": "installer",
  "user.target.name": "installer"  ← совпадает с user.name (OK, это норма)
}
```

## Дополнительно: user.target.name в index template

Поле `user.target.name` не включено в текущий `opensearch/templates/fluent-audit.json`.
OpenSearch получит его через dynamic mapping как `keyword` — это приемлемо,
но нет гарантии корректного маппинга.

Если нужна явная типизация: добавить в `opensearch/templates/fluent-audit.json`
в секцию `mappings.properties.user.properties`:
```json
"target": {
  "properties": {
    "name": { "type": "keyword" }
  }
}
```

Это опционально для данной итерации — сделать, если dynamic mapping
покажет `text` вместо `keyword` в логах.

## Деплой

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass
```

## Критерии приёмки

```bash
OS="http://192.168.37.161:9200"

# 1. Для cred_disp: user.id и user.name теперь согласованы
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "query": {"bool": {"must": [
      {"term": {"event.category": "authentication"}},
      {"term": {"event.action": "cred_disp"}},
      {"term": {"user.id": "1000"}}
    ]}},
    "_source": ["event.action", "user.id", "user.name", "user.target.name", "user.effective.id"]
  }'
# Ожидание:
#   user.id = "1000"
#   user.name = "installer"    (не "root"!)
#   user.target.name = "root"  (новое поле)

# 2. user.target.name присутствует в authentication событиях
curl -s -X GET "$OS/fluent-audit-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {"term": {"event.category": "authentication"}},
    "aggs": {
      "has_target_name": {"filter": {"exists": {"field": "user.target.name"}}}
    }
  }' | grep -o '"doc_count":[0-9]*'
# Ожидание: has_target_name.doc_count > 0

# 3. Нет расхождения user.id / user.name (нет uid=1000, name=root)
curl -s -X GET "$OS/fluent-audit-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {"bool": {"must": [
      {"term": {"user.id": "1000"}},
      {"term": {"user.name": "root"}}
    ]}},
    "aggs": {"total": {"value_count": {"field": "user.id"}}}
  }' | grep -o '"value":[0-9]*'
# Ожидание: value = 0 (нет событий с uid=1000 + name=root)
```

## Обновление документации

После деплоя обновить `README_FOR_AI.md`, раздел 3.3 (Гарантированные ECS-поля):
добавить строку для `user.target.name`:

```
| `user.target.name` | keyword | при PAM/sudo | Целевая учётная запись
  (acct-поле auditd). "root" при sudo, имя пользователя при прямом логине. |
```
