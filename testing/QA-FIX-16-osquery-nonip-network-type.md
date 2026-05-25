# QA-FIX-16. osquery bpf_socket_events: network.type отсутствует для non-IP сокетов

## Контекст для AI

Прочитай перед стартом:

- [CLAUDE.md](../CLAUDE.md) — раздел «AF_UNIX/AF_NETLINK/AF_PACKET в bpf_sockets (QA-03)».
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) — строки ~690–775 (блок bpf_sockets).

Инструмент проверки — **Bash + curl** (`http://192.168.37.161:9200`).

---

## Проблема (FAIL F-05)

QA-01b итерация 5: **1107 событий** `bpf_socket_events` с action `socket_*_nonip` (AF_UNIX=1, AF_NETLINK=16, AF_PACKET=17) имеют `network.type=0%`. Поле отсутствует у всех non-IP событий.

Для UEBA: `network.type=unix` нужен чтобы различать unix IPC от netlink управления ядром. Без него все `socket_connect_nonip` неразличимы.

---

## Причина

В `osquery_enrich.lua` блок bpf_sockets, строки ~762–770:

```lua
        else
            -- AF_UNIX=1, AF_NETLINK=16, AF_PACKET=17, прочие non-IP family.
            -- Reklass из QUERY_META "network" → "process"
            record["event.category"] = "process"
            if syscall and syscall ~= "" then
                record["event.action"] = "socket_" .. syscall .. "_nonip"
            end
            -- network.type НЕ ставится ← вот проблема
        end
```

QA-03 добавил реклассификацию category и суффикс `_nonip` в action, но забыл добавить `network.type`.

---

## Правка: osquery_enrich.lua — else-ветка non-IP сокетов

Найти блок (после строки `record["event.category"] = "process"`):

```lua
        else
            -- AF_UNIX=1, AF_NETLINK=16, AF_PACKET=17, прочие non-IP family.
            -- Reklass из QUERY_META "network" → "process": это не сетевой
            -- трафик, а IPC / управление ядром. ECS network.* поля не ставим
            -- (нет IP/port, заполнение нулями = шум в OpenSearch).
            record["event.category"] = "process"
            if syscall and syscall ~= "" then
                record["event.action"] = "socket_" .. syscall .. "_nonip"
            end
        end
```

Заменить на:

```lua
        else
            -- AF_UNIX=1, AF_NETLINK=16, AF_PACKET=17, прочие non-IP family.
            -- Reklass из QUERY_META "network" → "process": это не сетевой
            -- трафик, а IPC / управление ядром. ECS network.* поля не ставим
            -- (нет IP/port, заполнение нулями = шум в OpenSearch).
            record["event.category"] = "process"
            if syscall and syscall ~= "" then
                record["event.action"] = "socket_" .. syscall .. "_nonip"
            end
            -- network.type по family: позволяет различать unix IPC vs netlink vs raw L2.
            if     fam == "1"  then record["network.type"] = "unix"
            elseif fam == "16" then record["network.type"] = "netlink"
            elseif fam == "17" then record["network.type"] = "packet"
            end
        end
```

**Единственное добавление:** три строки `if/elseif/end` после `record["event.action"]`.

Переменная `fam` уже объявлена в начале блока bpf_sockets (`local fam = cols["family"]`), правка безопасна.

---

## Соответствие с auditd_enrich.lua

После правки семантика совпадёт с `auditd_enrich.lua` блоком SOCKADDR (строки ~506–519):

| Family | auditd event.category | auditd network.type | osquery (после правки) |
|--------|----------------------|---------------------|------------------------|
| AF_UNIX (1) | ["network","file"] | unix | process + unix ✓ |
| AF_NETLINK (16) | process | netlink | process + netlink ✓ |
| AF_PACKET (17) | process | packet | process + packet ✓ |

Разница в event.category (auditd ставит массив ["network","file"] для AF_UNIX, osquery — строку "process") — это known проектное различие, описано в CLAUDE.md. Не унифицировать без отдельного решения.

---

## Проверка после деплоя

```bash
OS=http://192.168.37.161:9200

# 1. network.type должен появиться для всех nonip событий
curl -s -X GET "$OS/fluent-osquery-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":0,
      "query":{"bool":{"must":[{"term":{"event.dataset":"osquery.bpf_socket_events"}},
                               {"wildcard":{"event.action":"*_nonip"}}]}},
      "aggs":{
        "has_network_type":{"filter":{"exists":{"field":"network.type"}}},
        "network_types":{"terms":{"field":"network.type","size":5}},
        "total":{"value_count":{"field":"process.pid"}}}}'
# Ожидание: has_network_type.doc_count == total.value
# network_types buckets: unix, netlink (и/или packet если есть AF_PACKET)

# 2. AF_UNIX пример: socket_connect_nonip должен иметь network.type=unix
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"size":3,"query":{"bool":{"must":[{"term":{"event.action":"socket_connect_nonip"}},
      {"term":{"network.type":"unix"}}]}},
      "_source":["event.category","event.action","network.type","process.executable","container.id"]}'

# 3. AF_NETLINK пример: socket_bind_nonip + network.type=netlink
curl -s -X GET "$OS/fluent-osquery-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"size":3,"query":{"bool":{"must":[{"term":{"event.action":"socket_bind_nonip"}},
      {"term":{"network.type":"netlink"}}]}},
      "_source":["event.category","event.action","network.type","process.executable"]}'
```

---

## Деплой

```bash
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

Правка минимальна (3 строки кода), риск регрессии нулевой — добавление, не изменение существующей логики.
