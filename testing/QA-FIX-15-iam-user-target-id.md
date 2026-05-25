# QA-FIX-15. setuid/setgid: user.target.id отсутствует (целевой UID не извлекается)

## Контекст для AI

Прочитай перед стартом:

- [CLAUDE.md](../CLAUDE.md) — раздел «Стек агентов», ECS IAM события.
- [agents/configs/fluent-bit/scripts/auditd_merge.lua](../agents/configs/fluent-bit/scripts/auditd_merge.lua) — строки 79–90 (SYSCALL ветка, список полей).
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — строки 289–395 (блок Syscall).

Инструмент проверки — **Bash + curl** (`http://192.168.37.161:9200`).

---

## Проблема (FAIL F-04)

QA-01b итерация 5: **7495 IAM событий** (setuid, setgid, setreuid, setregid, setresuid, setresgid) имеют `user.target.id=0%` и `user.target.name=0%`. Поле `user.id` присутствует (100%), но содержит uid процесса, а не целевой UID после setuid.

Для UEBA-скоринга privilege escalation (`setresuid(1000, 0, 0)`) требует знать **кем стал процесс** (target UID = 0), а не только кем был. Без `user.target.id` все setuid события выглядят одинаково.

---

## Механика: откуда берётся целевой UID

Syscall `setuid(uid)` → аргумент в auditd SYSCALL-записи: `a0=<new_uid_hex>`.
Syscall `setresuid(ruid, euid, suid)` → аргументы: `a0=ruid_hex`, `a1=euid_hex`, `a2=suid_hex`.

Текущий `auditd_merge.lua` SYSCALL-ветка (строки 79–90) **не извлекает a0/a1/a2**:

```lua
if atype == "SYSCALL" then
    for _, f in ipairs({"arch","syscall","success","exit","ppid","pid",
                         "uid","gid","euid","egid","auid","ses",
                         "comm","exe","key","tty"}) do
        if kv[f] then entry[f] = kv[f] end
    end
    -- a0, a1, a2, a3 здесь не читаются → теряются навсегда
```

---

## Правка 1: auditd_merge.lua — SYSCALL ветка

В блоке `if atype == "SYSCALL"` (после строки `entry["syscall_exit"] = kv["exit"]`) добавить сохранение syscall-аргументов:

```lua
        -- Аргументы syscall (hex LE) — нужны для семантики IAM событий.
        -- a0=первый арг (напр. target_uid для setuid), a1/a2 для setresuid.
        for _, f in ipairs({"a0", "a1", "a2", "a3"}) do
            if kv[f] then entry["sc_" .. f] = kv[f] end
        end
```

Префикс `sc_` (syscall arg) выбран чтобы не конфликтовать с другими полями и легко читался в enrich.

---

## Правка 2: auditd_enrich.lua — IAM блок

В блоке Syscall (~строки 323–328), после строк:

```lua
        elseif sc_name == "setuid"    or sc_name == "setreuid"  or
               sc_name == "setresuid" or sc_name == "setgid"    or
               sc_name == "setregid"  or sc_name == "setresgid" then
            record["event.type"]     = "change"
            record["event.category"] = "iam"
```

Добавить извлечение target ID:

```lua
            -- user.target.id: новый UID после setuid-семейства.
            -- sc_a0 — hex-строка (напр. "3e8" = 1000, "0" = root, "ffffffff" = -1/unchanged).
            -- 0xffffffff = 4294967295 = "unset" (ядро не меняет этот компонент).
            local function sc_hex_to_uid(hex)
                if not hex then return nil end
                local n = tonumber("0x" .. hex)
                if n and n ~= 4294967295 then return tostring(n) end
                return nil
            end

            local target_uid
            if sc_name == "setuid" or sc_name == "setgid" then
                -- setuid(uid): один аргумент — целевой UID/GID
                target_uid = sc_hex_to_uid(record["sc_a0"])
            elseif sc_name == "setreuid" or sc_name == "setregid" then
                -- setreuid(ruid, euid): используем euid (a1) как target
                target_uid = sc_hex_to_uid(record["sc_a1"])
                            or sc_hex_to_uid(record["sc_a0"])
            elseif sc_name == "setresuid" or sc_name == "setresgid" then
                -- setresuid(ruid, euid, suid): euid (a1) наиболее значим для UEBA
                target_uid = sc_hex_to_uid(record["sc_a1"])
                            or sc_hex_to_uid(record["sc_a0"])
            end
            if target_uid then
                record["user.target.id"] = target_uid
            end
```

**Важно:** поместить этот блок ВНУТРИ условия `if sc_name == "setuid" or...`, до закрывающего `end` ветки IAM. Вспомогательную функцию `sc_hex_to_uid` определить один раз — в начале функции `enrich_ecs` или как локальную вверху файла.

### Очистка sc_a* полей в финальном блоке

В финальном cleanup-loop (~строки 575–586) добавить:
```lua
        or k:sub(1, 3) == "sc_"
```

---

## Маппинг user.target.id в OpenSearch

Проверить что `user.target.id` попадает в маппинг как `keyword`. Если нет — добавить в `opensearch/templates/fluent-audit.json` в секцию `user.properties`:

```json
"target": {
  "properties": {
    "name": { "type": "keyword" },
    "id":   { "type": "keyword" }
  }
}
```

Применить шаблон (если индекс уже существует — удалить и дать fluent-bit пересоздать, или сделать rollover):
```bash
curl -s -X PUT "http://192.168.37.161:9200/_index_template/fluent-audit" \
  -H "Content-Type: application/json" \
  -d @opensearch/templates/fluent-audit.json
```

---

## Проверка после деплоя

```bash
OS=http://192.168.37.161:9200

# 1. user.target.id появился
curl -s -X GET "$OS/fluent-audit-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":0,"query":{"term":{"event.category":"iam"}},
      "aggs":{"has_target_id":{"filter":{"exists":{"field":"user.target.id"}}},
              "target_ids":{"terms":{"field":"user.target.id","size":5}},
              "total":{"value_count":{"field":"process.pid"}}}}'
# Ожидание: has_target_id.doc_count > 0; target_ids показывает "0","1000" и т.п.

# 2. Проверить корректность: sudo выполняет setresuid(1000,0,0) → target_id="0"
curl -s -X GET "$OS/fluent-audit-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"size":3,"query":{"bool":{"must":[{"term":{"event.action":"setresuid"}},
      {"term":{"user.target.id":"0"}}]}},
      "_source":["user.id","user.target.id","process.executable","@timestamp"]}'
# Ожидание: process.executable=/usr/bin/sudo, user.id=1000, user.target.id=0
```

---

## Деплой

```bash
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

Применить обновлённый index template до следующего daily rollover (или создать новый индекс вручную).
