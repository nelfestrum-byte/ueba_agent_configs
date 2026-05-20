-- auditd_enrich.lua
-- Enriches merged auditd records with ECS 8.x fields.

local _dir = (debug.getinfo(1, "S").source or ""):match("^@(.+/)") or ""
package.path = _dir .. "?.lua;" .. package.path
local common = require("proc_common")

-- ── Таблица syscall number -> имя (Linux x86_64) ──
local SYSCALLS = {
    ["0"]="read",        ["1"]="write",       ["2"]="open",
    ["3"]="close",       ["4"]="stat",        ["5"]="fstat",
    ["6"]="lstat",       ["9"]="mmap",        ["11"]="munmap",
    ["21"]="access",     ["32"]="dup",        ["33"]="dup2",
    ["41"]="socket",     ["42"]="connect",    ["43"]="accept",
    ["49"]="bind",       ["50"]="listen",     ["54"]="setsockopt",
    ["56"]="clone",      ["57"]="fork",       ["58"]="vfork",
    ["59"]="execve",     ["60"]="exit",       ["61"]="wait4",
    ["62"]="kill",       ["83"]="mkdir",      ["84"]="rmdir",
    ["85"]="creat",      ["86"]="link",       ["87"]="unlink",
    ["88"]="symlink",    ["90"]="chmod",      ["92"]="chown",
    ["94"]="lchown",     ["105"]="setuid",    ["106"]="setgid",
    ["113"]="setreuid",  ["117"]="setresuid", ["132"]="utime",
    ["257"]="openat",    ["258"]="mkdirat",   ["263"]="unlinkat",
    ["265"]="linkat",    ["266"]="symlinkat", ["288"]="accept4",
    ["316"]="renameat2", ["322"]="execveat",
}

-- ── ECS event.category по типу auditd-события ──
local EVENT_CATEGORY = {
    SYSCALL       = {"process"},
    EXECVE        = {"process"},
    USER_LOGIN    = {"authentication","session"},
    USER_AUTH     = {"authentication"},
    USER_LOGOUT   = {"session"},
    USER_START    = {"session"},
    USER_END      = {"session"},
    USER_CMD      = {"process"},
    LOGIN         = {"authentication"},
    NETFILTER_CFG = {"network","configuration"},
    PATH          = {"file"},
    CWD           = {"file"},
}

-- ── MITRE ATT&CK теги по syscall ──
-- Отключено: threat.* предназначен для алертов, не для raw-событий.
--[[
local MITRE_TAGS = {
    execve    = {"T1059",     "Execution: Command and Scripting Interpreter"},
    execveat  = {"T1059",     "Execution: Command and Scripting Interpreter"},
    fork      = {"T1059.004", "Execution: Unix Shell"},
    clone     = {"T1059.004", "Execution: Unix Shell"},
    setuid    = {"T1548.001", "Privilege Escalation: Setuid"},
    setreuid  = {"T1548.001", "Privilege Escalation: Setuid"},
    setresuid = {"T1548.001", "Privilege Escalation: Setuid"},
    connect   = {"T1071",     "Command and Control: Application Layer Protocol"},
    bind      = {"T1071",     "Command and Control: Application Layer Protocol"},
    socket    = {"T1071",     "Command and Control: Application Layer Protocol"},
    openat    = {"T1083",     "Discovery: File and Directory Discovery"},
    unlink    = {"T1070.004", "Defense Evasion: Indicator Removal on Host"},
    unlinkat  = {"T1070.004", "Defense Evasion: Indicator Removal on Host"},
}
--]]

-- ── Декодирование saddr (hex sockaddr из SOCKADDR-записи auditd) ──
-- saddr — hex-дамп struct sockaddr. Первые 2 байта = family (LE на x86_64).
-- Возвращает: net_type ("ipv4"|"ipv6"|"unix"|nil), ip, port
local function decode_saddr(saddr)
    if not saddr or #saddr < 4 then return nil, nil, nil end
    local family = tonumber(saddr:sub(1, 2), 16)
    if family == 2 and #saddr >= 16 then           -- AF_INET
        local port = tonumber(saddr:sub(5, 8), 16)
        local a = tonumber(saddr:sub(9,  10), 16)
        local b = tonumber(saddr:sub(11, 12), 16)
        local c = tonumber(saddr:sub(13, 14), 16)
        local d = tonumber(saddr:sub(15, 16), 16)
        if a and b and c and d and port then
            return "ipv4", string.format("%d.%d.%d.%d", a, b, c, d), port
        end
    elseif family == 10 and #saddr >= 48 then      -- AF_INET6
        local port = tonumber(saddr:sub(5, 8), 16)
        local parts = {}
        for i = 0, 7 do
            parts[i+1] = saddr:sub(17 + i*4, 20 + i*4)
        end
        if port then
            return "ipv6", table.concat(parts, ":"), port
        end
    elseif family == 1 then                        -- AF_UNIX
        return "unix", nil, nil
    end
    return nil, nil, nil
end

-- ── Конвертация Unix mode в строку (rwxr-xr-x) ──
local function mode_to_str(mode_oct)
    if not mode_oct then return nil end
    local m = tonumber(mode_oct, 8) or 0
    local bits = "rwxrwxrwx"
    local result = ""
    for i = 1, 9 do
        local b = math.floor(m / (2^(9-i))) % 2
        result = result .. (b == 1 and bits:sub(i,i) or "-")
    end
    return result
end

function enrich_ecs(tag, timestamp, record)

    -- ── Базовые ECS поля ──
    record["ecs.version"]   = "8.11"
    record["event.dataset"] = "auditd"
    record["event.module"]  = "auditd"
    record["event.kind"]    = "event"
    record["@timestamp"]    = record["@timestamp"] or
        os.date("!%Y-%m-%dT%H:%M:%S.000Z", timestamp)

    -- ── Хост ──
    record["host.name"]      = common.get_hostname()
    record["host.os.type"]   = "linux"
    record["host.os.family"] = "linux"

    -- ── Определяем тип события (из _event_types) ──
    local primary_type = "UNKNOWN"
    local etypes = record["_event_types"] or {}
    if     etypes["SYSCALL"]       then primary_type = "SYSCALL"
    elseif etypes["EXECVE"]        then primary_type = "EXECVE"
    elseif etypes["USER_LOGIN"]    then primary_type = "USER_LOGIN"
    elseif etypes["USER_AUTH"]     then primary_type = "USER_AUTH"
    elseif etypes["USER_CMD"]      then primary_type = "USER_CMD"
    elseif etypes["LOGIN"]         then primary_type = "LOGIN"
    elseif etypes["NETFILTER_CFG"] then primary_type = "NETFILTER_CFG"
    end

    local cats = EVENT_CATEGORY[primary_type] or {"host"}
    record["event.category"] = cats[1]
    record["event.type"]     = "info"

    -- ── Процесс ──
    local is_execve = etypes["EXECVE"] == true
    local pid = tonumber(record["pid"])
    if pid then
        record["process.pid"]          = pid
        record["process.name"]         = record["comm"]
        if record["comm"] then common.cache_put_name(pid, record["comm"]) end
        record["process.executable"]   = record["exe"]
        record["process.title"]        = record["proctitle"]
        record["process.command_line"] = record["proctitle"]

        -- process.start + process.entity_id
        local start_ts
        if is_execve then
            start_ts = common.read_proc_start(pid) or record["@timestamp"]
            common.cache_put(pid, start_ts, true)
        else
            start_ts = common.resolve_start(pid)
            if not start_ts then
                start_ts = record["@timestamp"]
                record["labels.entity_id_source"] = "event_timestamp_fallback"
            end
        end
        record["process.start"] = start_ts
        local seed = (record["host.name"] or "")
                  .. ":" .. tostring(pid)
                  .. ":" .. tostring(start_ts)
        record["process.entity_id"] = common.short_id(seed)
    end

    local ppid = tonumber(record["ppid"])
    if ppid then
        record["process.parent.pid"]  = ppid
        local parent_name = common.resolve_name(ppid)
        if parent_name then record["process.parent.name"] = parent_name end
        local parent_cmdline = common.resolve_cmdline(ppid)
        if parent_cmdline then record["process.parent.command_line"] = parent_cmdline end
        local parent_start = common.resolve_start(ppid)
        if parent_start then
            record["process.parent.start"]     = parent_start
            local pseed = (record["host.name"] or "")
                       .. ":" .. tostring(ppid)
                       .. ":" .. tostring(parent_start)
            record["process.parent.entity_id"] = common.short_id(pseed)
        end
    end

    -- Аргументы execve
    if record["_execve_args"] and #record["_execve_args"] > 0 then
        record["process.args"]       = record["_execve_args"]
        record["process.args_count"] = #record["_execve_args"]
        if not record["process.command_line"] then
            record["process.command_line"] = table.concat(record["_execve_args"], " ")
        end
    end

    -- Cache command line after all sources are resolved (proctitle + execve args)
    if pid and record["process.command_line"] then
        common.cache_put_cmdline(pid, record["process.command_line"])
    end

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

    if record["user_acct"] then
        record["user.name"] = record["user_acct"]
    end

    record["uid_name"]  = nil
    record["auid_name"] = nil

    -- ── Syscall ──
    local sc_num  = record["syscall"]
    local sc_name = sc_num and SYSCALLS[sc_num]
    if sc_name then
        record["auditd.data.syscall"] = sc_name
        record["event.action"]        = sc_name

        if sc_name == "execve" or sc_name == "execveat" then
            record["event.type"]     = "start"
            record["event.category"] = "process"
        elseif sc_name == "fork" or sc_name == "clone" then
            record["event.type"]     = "start"
            record["event.category"] = "process"
        elseif sc_name == "exit" then
            record["event.type"]     = "end"
            record["event.category"] = "process"
        elseif sc_name == "connect" or sc_name == "bind" or
               sc_name == "accept"  or sc_name == "accept4" then
            record["event.type"]     = "start"
            record["event.category"] = "network"
        elseif sc_name == "open" or sc_name == "openat" or sc_name == "creat" then
            record["event.type"]     = "access"
            record["event.category"] = "file"
        elseif sc_name == "unlink" or sc_name == "unlinkat" then
            record["event.type"]     = "deletion"
            record["event.category"] = "file"
        elseif sc_name == "mkdir" or sc_name == "mkdirat" then
            record["event.type"]     = "creation"
            record["event.category"] = "file"
        elseif sc_name == "setuid" or sc_name == "setreuid" or
               sc_name == "setresuid" then
            record["event.type"]     = "change"
            record["event.category"] = "iam"
        end

        --[[
        local mitre = MITRE_TAGS[sc_name]
        if mitre then
            record["threat.technique.id"]   = mitre[1]
            record["threat.technique.name"] = mitre[2]
            record["threat.framework"]      = "MITRE ATT&CK"
        end
        --]]
    end

    -- ── Файл (из PATH и CWD) ──
    local paths = record["_paths"]
    if paths and #paths > 0 then
        local primary = paths[1]
        local name = primary.name
        if name then
            if name:sub(1,1) ~= "/" and record["cwd"] then
                name = record["cwd"] .. "/" .. name
            end
            record["file.path"]   = name
            record["file.inode"]  = primary.inode
            record["file.device"] = primary.dev
            record["file.mode"]   = mode_to_str(primary.mode)
            record["file.uid"]    = primary.ouid
            record["file.gid"]    = primary.ogid
            local fname = name:match("([^/]+)$")
            if fname then record["file.name"] = fname end
            local ext = fname and fname:match("%.([^%.]+)$")
            if ext then record["file.extension"] = ext end
        end
        local path_list = {}
        for _, p in ipairs(paths) do
            if p.name then path_list[#path_list+1] = p.name end
        end
        if #path_list > 1 then
            record["auditd.paths"] = path_list
        end
    end

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
        end
        record["socket_saddr"]  = nil
        record["socket_family"] = nil
    end

    -- ── Рабочая директория ──
    if record["cwd"] then
        record["process.working_directory"] = record["cwd"]
    end

    -- ── Результат события ──
    local success = record["syscall_success"] or record["user_res"]
    if success then
        record["event.outcome"] = (success == "yes" or success == "success")
            and "success" or "failure"
    end

    -- ── Сессия auditd ──
    -- USER_* события мержатся с префиксом user_* (merge.lua:122-126),
    -- поэтому ses из USER_LOGIN/USER_AUTH/USER_LOGOUT лежит в user_ses.
    local ses = tonumber(record["ses"] or record["user_ses"])
    if ses and ses > 0 and ses ~= 4294967295 then
        record["auditd.session"] = ses
        local sid = common.make_session_id(record["host.name"] or "", ses)
        if sid then record["user.session.id"] = sid end
    end

    -- ── Теги ──
    record["tags"] = {"auditd", "security", "linux"}

    -- ── Очистка служебных полей ──
    record["_paths"]           = nil
    record["_execve_args"]     = nil
    record["_event_types"]     = nil
    record["syscall_success"]  = nil
    record["syscall_exit"]     = nil

    return 2, timestamp, record
end
