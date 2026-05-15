-- auditd_merge.lua
-- Объединяет разрозненные события auditd с одинаковым serial number
-- в одну обогащённую запись.
--
-- Стратегия:
--   - Буферизуем строки в глобальной таблице по serial
--   - Флашим запись когда: (1) встречаем EOE, (2) serial меняется и
--     предыдущий старше TIMEOUT секунд, (3) размер буфера > MAX_BUF
--
-- ВНИМАНИЕ: fluent-bit вызывает Lua однопоточно, глобальное состояние безопасно.

local buf     = {}   -- { [serial] = merged_record }
local last_ts = {}   -- { [serial] = os.clock() }
local TIMEOUT = 3.0  -- секунды ожидания после последнего события
local MAX_BUF = 512  -- максимум накопленных незакрытых serial'ов

-- Список типов событий, которые формируют "набор" SYSCALL
local SYSCALL_SET = {
    SYSCALL=true, CWD=true, PATH=true, PROCTITLE=true,
    EXECVE=true, SOCKETCALL=true, SOCKADDR=true,
}

-- Разбираем строку "key=value key2=val2" или "key="quoted val""
local function parse_kv(s)
    local out = {}
    -- Сначала обрабатываем quoted значения
    local rest = s:gsub('(%w+)="([^"]*)"', function(k, v)
        out[k] = v
        return ""
    end)
    -- Затем unquoted
    for k, v in rest:gmatch('([%w_%-]+)=(%S+)') do
        out[k] = v
    end
    return out
end

-- Декодируем hex-закодированные строки auditd (proctitle, a0..a3)
local function decode_hex(s)
    if not s then return s end
    if s:match('^%x+$') and #s % 2 == 0 and #s > 2 then
        local decoded = s:gsub('%x%x', function(h)
            return string.char(tonumber(h, 16))
        end)
        -- Заменяем нулевые байты на пробел (аргументы execve)
        return decoded:gsub('%z', ' '):gsub('%s+$', '')
    end
    return s
end

local function flush_record(serial)
    local rec = buf[serial]
    buf[serial]    = nil
    last_ts[serial] = nil
    return rec
end

local function buf_size()
    local n = 0
    for _ in pairs(buf) do n = n + 1 end
    return n
end

function merge_auditd(tag, timestamp, record)
    local serial = tostring(record["serial"] or "")
    local atype  = record["audit_type"] or "UNKNOWN"
    local msg    = record["msg"] or ""
    local now    = os.clock()

    -- Событие без serial — отдаём как есть
    if serial == "" then
        return 1, timestamp, record
    end

    -- ── Инициализация буфера для нового serial ──
    if not buf[serial] then
        -- Если буфер переполнен — флашим самый старый
        if buf_size() >= MAX_BUF then
            local oldest_s, oldest_t = nil, math.huge
            for s, t in pairs(last_ts) do
                if t < oldest_t then oldest_s, oldest_t = s, t end
            end
            if oldest_s then flush_record(oldest_s) end
        end

        buf[serial] = {
            serial       = serial,
            timestamp    = timestamp,
            _paths       = {},
            _execve_args = {},
        }
    end

    local entry = buf[serial]
    last_ts[serial] = now

    -- ── Парсим и мержим поля в зависимости от типа ──
    local kv = parse_kv(msg)

    if atype == "SYSCALL" then
        for _, f in ipairs({"arch","syscall","success","exit","ppid","pid",
                             "uid","gid","euid","egid","auid","ses",
                             "comm","exe","key","tty"}) do
            if kv[f] then entry[f] = kv[f] end
        end
        entry["syscall_success"] = kv["success"]
        entry["syscall_exit"]    = kv["exit"]

    elseif atype == "CWD" then
        entry["cwd"] = kv["cwd"]

    elseif atype == "PATH" then
        -- PATH может быть несколько (item=0, item=1...)
        local item = kv["item"] or tostring(#entry["_paths"])
        entry["_paths"][#entry["_paths"]+1] = {
            item    = item,
            name    = kv["name"],
            inode   = kv["inode"],
            dev     = kv["dev"],
            mode    = kv["mode"],
            ouid    = kv["ouid"],
            ogid    = kv["ogid"],
            objtype = kv["objtype"],
        }

    elseif atype == "PROCTITLE" then
        entry["proctitle"] = decode_hex(kv["proctitle"])

    elseif atype == "EXECVE" then
        -- Аргументы execve: argc, a0, a1, a2...
        entry["execve_argc"] = kv["argc"]
        for k, v in pairs(kv) do
            if k:match('^a%d+$') then
                entry["_execve_args"][#entry["_execve_args"]+1] = decode_hex(v)
            end
        end

    elseif atype == "SOCKADDR" then
        entry["socket_family"] = kv["saddr"] and kv["saddr"]:sub(1,4) or nil
        entry["socket_saddr"]  = kv["saddr"]

    elseif atype:match("^USER_") or atype == "LOGIN" then
        -- USER_LOGIN, USER_AUTH, USER_CMD и пр.
        entry["user_event_type"] = atype
        for k, v in pairs(kv) do
            entry["user_" .. k] = v
        end

    elseif atype == "NETFILTER_CFG" then
        entry["netfilter_table"]  = kv["table"]
        entry["netfilter_family"] = kv["family"]

    else
        -- Всё остальное — сохраняем с префиксом типа
        for k, v in pairs(kv) do
            entry[atype:lower() .. "_" .. k] = v
        end
    end

    -- Добавляем тип события в список
    local types = entry["_event_types"] or {}
    types[atype] = true
    entry["_event_types"] = types

    -- ── Проверяем готовность к флашу ──

    -- EOE = явный конец набора
    if atype == "EOE" then
        return 2, entry.timestamp, flush_record(serial)
    end

    -- Флашим старые серийники с таймаутом (не текущий)
    -- Ограничение fluent-bit Lua: невозможно вернуть несколько записей за раз.
    -- Старые записи флашатся при следующем входящем событии.
    for s, t in pairs(last_ts) do
        if s ~= serial and (now - t) > TIMEOUT then
            flush_record(s)
        end
    end

    -- Текущее событие добавлено в буфер — удаляем из потока
    return -1, timestamp, record
end
