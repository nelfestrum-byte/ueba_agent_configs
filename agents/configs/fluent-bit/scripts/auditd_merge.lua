-- auditd_merge.lua
-- Объединяет разрозненные события auditd с одинаковым serial number
-- в одну обогащённую запись.
--
-- Стратегия:
--   1. Каждую входящую запись сразу мержим в буфер по serial.
--   2. После мержа проверяем буфер на протухшие serial'ы (wall clock > TIMEOUT).
--      Если есть — флашим один и возвращаем его в поток.
--   3. Если протухших нет — дропаем текущую запись (-1); она уже в буфере.
--   4. EOE-запись (auditd < 4.0) флашит serial немедленно.
--
-- ВНИМАНИЕ: fluent-bit вызывает Lua однопоточно, глобальное состояние безопасно.
-- os.time() используется для wall clock timeout (os.clock() — CPU time, не подходит).

local buf     = {}   -- { [serial] = merged_record }
local last_ts = {}   -- { [serial] = os.time() }
local TIMEOUT = 5    -- секунд ожидания после последнего события в наборе
local MAX_BUF = 512  -- максимум незакрытых serial'ов в буфере

local function parse_kv(s)
    local out = {}
    local rest = s:gsub('(%w+)="([^"]*)"', function(k, v)
        out[k] = v
        return ""
    end)
    for k, v in rest:gmatch('([%w_%-]+)=(%S+)') do
        out[k] = v
    end
    return out
end

local function decode_hex(s)
    if not s then return s end
    if s:match('^%x+$') and #s % 2 == 0 and #s > 2 then
        local decoded = s:gsub('%x%x', function(h)
            return string.char(tonumber(h, 16))
        end)
        return decoded:gsub('%z', ' '):gsub('%s+$', '')
    end
    return s
end

local function flush_record(serial)
    local rec = buf[serial]
    buf[serial]     = nil
    last_ts[serial] = nil
    return rec
end

local function buf_size()
    local n = 0
    for _ in pairs(buf) do n = n + 1 end
    return n
end

-- Мержит одну запись auditd в буфер по serial; возвращает запись буфера.
local function merge_into_buf(serial, atype, msg, timestamp)
    if not buf[serial] then
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
    last_ts[serial] = os.time()

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
        entry["user_event_type"] = atype
        for k, v in pairs(kv) do
            entry["user_" .. k] = v
        end

    elseif atype == "NETFILTER_CFG" then
        entry["netfilter_table"]  = kv["table"]
        entry["netfilter_family"] = kv["family"]

    else
        for k, v in pairs(kv) do
            entry[atype:lower() .. "_" .. k] = v
        end
    end

    local types = entry["_event_types"] or {}
    types[atype] = true
    entry["_event_types"] = types

    return entry
end

function merge_auditd(tag, timestamp, record)
    local serial = tostring(record["serial"] or "")
    local atype  = record["audit_type"] or "UNKNOWN"
    local msg    = record["msg"] or ""
    local now    = os.time()

    -- Событие без serial — отдаём как есть
    if serial == "" then
        return 1, timestamp, record
    end

    -- Мержим текущую запись в буфер (всегда, до любых проверок)
    local entry = merge_into_buf(serial, atype, msg, timestamp)

    -- EOE = явный конец набора (auditd < 4.0); флашим немедленно
    if atype == "EOE" then
        return 1, entry.timestamp, flush_record(serial)
    end

    -- Ищем любой протухший serial и флашим его
    -- last_ts[serial] только что обновлён → текущий serial не протухнет здесь
    for s, t in pairs(last_ts) do
        if (now - t) >= TIMEOUT then
            return 1, buf[s].timestamp, flush_record(s)
        end
    end

    -- Текущая запись в буфере — убираем из потока
    return -1, timestamp, record
end
