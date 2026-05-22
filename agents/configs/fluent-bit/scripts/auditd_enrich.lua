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
    -- P0-04: modern bypass vectors
    ["101"]="ptrace",          ["310"]="process_vm_readv",
    ["311"]="process_vm_writev",["319"]="memfd_create",
    ["321"]="bpf",             ["425"]="io_uring_setup",
    -- P1-01 Tier A: anti-forensics, persistence, container escape, exploit primitives
    ["133"]="mknod",        ["155"]="pivot_root",   ["163"]="acct",
    ["165"]="mount",        ["166"]="umount2",      ["167"]="swapon",
    ["168"]="swapoff",      ["169"]="reboot",       ["235"]="utimes",
    ["246"]="kexec_load",   ["259"]="mknodat",      ["261"]="futimesat",
    ["272"]="unshare",      ["280"]="utimensat",    ["282"]="userfaultfd",
    ["308"]="setns",        ["320"]="kexec_file_load",
    ["428"]="open_tree",    ["429"]="move_mount",   ["430"]="fsopen",
    ["431"]="fsconfig",     ["432"]="fsmount",
    -- P1-01 Tier B: network/DNS, special files
    ["170"]="sethostname",  ["171"]="setdomainname",
}

-- ── ECS event.category по типу auditd-события ──
local EVENT_CATEGORY = {
    SYSCALL       = {"process"},
    EXECVE        = {"process"},
    USER_LOGIN    = {"authentication"},
    USER_AUTH     = {"authentication"},
    USER_LOGOUT   = {"authentication"},
    USER_START    = {"authentication"},    -- PAM session_open
    USER_END      = {"authentication"},    -- PAM session_close
    USER_ACCT     = {"authentication"},    -- PAM accounting
    CRED_DISP     = {"authentication"},    -- PAM setcred (dispose)
    CRED_REFR     = {"authentication"},    -- PAM setcred (refresh)
    CRED_ACQ      = {"authentication"},    -- PAM setcred (acquire)
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

-- Декодирует hex-строку auditd в обычный текст.
-- auditd hex-кодирует exe когда путь содержит пробелы, (deleted) или non-ASCII.
-- Возвращает исходную строку если она не является валидным hex.
local function decode_hex_str(s)
    if not s or #s == 0 or #s % 2 ~= 0 then return s end
    if not s:match("^[0-9A-Fa-f]+$") then return s end
    local result = s:gsub("%x%x", function(h)
        return string.char(tonumber(h, 16))
    end)
    if result:sub(1,1) == "/" or result:sub(1,7) == "memfd::" then
        return result
    end
    return s
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
    elseif etypes["USER_START"]    then primary_type = "USER_START"
    elseif etypes["USER_END"]      then primary_type = "USER_END"
    elseif etypes["USER_ACCT"]     then primary_type = "USER_ACCT"
    elseif etypes["USER_LOGOUT"]   then primary_type = "USER_LOGOUT"
    elseif etypes["CRED_DISP"]     then primary_type = "CRED_DISP"
    elseif etypes["CRED_REFR"]     then primary_type = "CRED_REFR"
    elseif etypes["CRED_ACQ"]      then primary_type = "CRED_ACQ"
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
        record["process.executable"]   = decode_hex_str(record["exe"])
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
        local seed = (record["host.name"] or "")
                  .. ":" .. tostring(pid)
                  .. ":" .. tostring(start_ts)
        record["process.entity_id"] = common.short_id(seed)
        record["process.start"]     = common.to_iso(start_ts)
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
            local pseed = (record["host.name"] or "")
                       .. ":" .. tostring(ppid)
                       .. ":" .. tostring(parent_start)
            record["process.parent.entity_id"] = common.short_id(pseed)
            record["process.parent.start"]     = common.to_iso(parent_start)
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
        -- P0-04: modern bypass vectors
        elseif sc_name == "ptrace"
            or sc_name == "process_vm_readv"
            or sc_name == "process_vm_writev" then
            record["event.type"]     = "change"
            record["event.category"] = "process"
        elseif sc_name == "memfd_create" then
            record["event.type"]     = "creation"
            record["event.category"] = "process"
        elseif sc_name == "bpf" then
            record["event.type"]     = "info"
            record["event.category"] = "process"
        elseif sc_name == "io_uring_setup" then
            record["event.type"]     = "info"
            record["event.category"] = "process"
        -- P1-01 Tier A
        elseif sc_name == "mount"      or sc_name == "umount2"
            or sc_name == "move_mount" or sc_name == "open_tree"
            or sc_name == "fsopen"     or sc_name == "fsconfig"
            or sc_name == "fsmount" then
            record["event.type"]     = "change"
            record["event.category"] = "host"
        elseif sc_name == "unshare" or sc_name == "setns"
            or sc_name == "pivot_root" then
            record["event.type"]     = "change"
            record["event.category"] = "process"
        elseif sc_name == "reboot"   or sc_name == "kexec_load"
            or sc_name == "kexec_file_load" then
            record["event.type"]     = "change"
            record["event.category"] = "host"
        elseif sc_name == "acct"   or sc_name == "swapon"
            or sc_name == "swapoff" then
            record["event.type"]     = "change"
            record["event.category"] = "host"
        elseif sc_name == "utimensat" or sc_name == "utimes"
            or sc_name == "futimesat" then
            record["event.type"]     = "change"
            record["event.category"] = "file"
        elseif sc_name == "userfaultfd" then
            record["event.type"]     = "info"
            record["event.category"] = "process"
        -- P1-01 Tier B
        elseif sc_name == "mknod" or sc_name == "mknodat" then
            record["event.type"]     = "creation"
            record["event.category"] = "file"
        elseif sc_name == "sethostname" or sc_name == "setdomainname" then
            record["event.type"]     = "change"
            record["event.category"] = "host"
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

    -- ── PAM / USER события (USER_START, USER_END, CRED_DISP, CRED_REFR, …) ──
    if primary_type == "USER_START"  or primary_type == "USER_END"
    or primary_type == "USER_ACCT"   or primary_type == "USER_LOGOUT"
    or primary_type == "CRED_DISP"   or primary_type == "CRED_REFR"
    or primary_type == "CRED_ACQ" then

        local etype = record["user_event_type"] or primary_type
        record["event.action"] = etype:lower()

        if primary_type == "USER_START" or primary_type == "USER_ACCT"
        or primary_type == "CRED_ACQ" then
            record["event.type"] = "start"
        elseif primary_type == "USER_END" or primary_type == "USER_LOGOUT" then
            record["event.type"] = "end"
        else
            record["event.type"] = "info"
        end

        local u_uid  = record["user_uid"]  or record["cred_disp_uid"]  or record["cred_refr_uid"]
        local u_name = record["user_acct"] or record["cred_disp_acct"] or record["cred_refr_acct"]
        local u_exe  = record["user_exe"]  or record["cred_disp_exe"]  or record["cred_refr_exe"]
        local u_pid  = tonumber(record["user_pid"] or record["cred_disp_pid"] or record["cred_refr_pid"])

        if u_uid  and u_uid  ~= "" then record["user.id"]            = u_uid  end
        if u_name and u_name ~= "" then record["user.name"]          = u_name end
        if u_exe  and u_exe  ~= "" then record["process.executable"] = decode_hex_str(u_exe)  end
        if u_pid                   then record["process.pid"]         = u_pid  end

        -- collect keys to delete first, then delete (safe iteration)
        local keys_to_del = {}
        for k in pairs(record) do
            for _, prefix in ipairs({"user_", "cred_disp_", "cred_refr_", "cred_acq_"}) do
                if k:sub(1, #prefix) == prefix then
                    keys_to_del[#keys_to_del+1] = k
                    break
                end
            end
        end
        for _, k in ipairs(keys_to_del) do record[k] = nil end
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
        -- strip trailing control chars (auditd appends GS 0x1D to PAM fields)
        success = success:match("^([%a]+)") or success
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
