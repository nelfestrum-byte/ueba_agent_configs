-- auditd_enrich.lua
-- Обогащает объединённую запись auditd полями ECS (Elastic Common Schema 8.x)
-- и добавляет MITRE ATT&CK теги для распространённых TTP.

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

-- ── Кэш hostname ──
local _hostname = nil
local function get_hostname()
    if not _hostname then
        local f = io.popen("hostname -f 2>/dev/null")
        if f then
            _hostname = f:read("*l") or "unknown"
            f:close()
        else
            _hostname = os.getenv("HOSTNAME") or "unknown"
        end
    end
    return _hostname
end

-- ── Конвертация Unix mode в строку (rwxr-xr-x) ──
local function mode_to_str(mode_oct)
    if not mode_oct then return nil end
    local m = tonumber(mode_oct, 8) or 0
    local bits = "rwxrwxrwx"
    local result = ""
    for i = 1, 9 do
        local bit = math.floor(m / (2^(9-i))) % 2
        result = result .. (bit == 1 and bits:sub(i,i) or "-")
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
    record["host.name"]      = get_hostname()
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
    local pid = tonumber(record["pid"])
    if pid then
        record["process.pid"]          = pid
        record["process.name"]         = record["comm"]
        record["process.executable"]   = record["exe"]
        record["process.title"]        = record["proctitle"]
        record["process.command_line"] = record["proctitle"]
    end

    local ppid = tonumber(record["ppid"])
    if ppid then
        record["process.parent.pid"] = ppid
    end

    -- Аргументы execve
    if record["_execve_args"] and #record["_execve_args"] > 0 then
        record["process.args"]       = record["_execve_args"]
        record["process.args_count"] = #record["_execve_args"]
        if not record["process.command_line"] then
            record["process.command_line"] = table.concat(record["_execve_args"], " ")
        end
    end

    -- ── Пользователь ──
    local uid = record["uid"]
    if uid then record["user.id"] = uid end

    -- auid = audit user id (реальный пользователь до su/sudo)
    local auid = record["auid"]
    if auid and auid ~= "4294967295" and auid ~= "-1" then
        record["user.effective.id"] = auid
    end
    if record["user_acct"] then
        record["user.name"] = record["user_acct"]
    end

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

        -- MITRE ATT&CK
        local mitre = MITRE_TAGS[sc_name]
        if mitre then
            record["threat.technique.id"]   = mitre[1]
            record["threat.technique.name"] = mitre[2]
            record["threat.framework"]      = "MITRE ATT&CK"
        end
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
    local ses = tonumber(record["ses"])
    if ses and ses > 0 and ses ~= 4294967295 then
        record["auditd.session"] = ses
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
