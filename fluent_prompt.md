# Claude Code Prompt: Auditd → Fluent-bit → Logstash → SIEM Pipeline

## Контекст проекта

Ты дорабатываешь существующий проект мониторинга безопасности на Linux-хостах.
Стек: **auditd → fluent-bit → Logstash → SIEM (Elasticsearch/OpenSearch/Splunk)**.


Задача: настроить сбор логов auditd с объединением разрозненных событий в обогащённые
записи формата ECS (Elastic Common Schema) для отправки через Logstash.

---

## Структура файлов для создания

Создай следующие файлы в директории проекта `./fluent-bit/`:

```
fluent-bit/
├── fluent-bit.conf          # главный конфиг
├── parsers.conf             # парсеры
├── scripts/
    ├── auditd_merge.lua     # объединение событий по serial number
    └── auditd_enrich.lua    # обогащение в ECS
```

---

## Файл 1: `fluent-bit/fluent-bit.conf`

```ini
[SERVICE]
    Flush         5
    Daemon        Off
    Log_Level     info
    Log_File      /var/log/fluent-bit/fluent-bit.log
    Parsers_File  /etc/fluent-bit/parsers.conf
    HTTP_Server   On
    HTTP_Listen   127.0.0.1
    HTTP_Port     2020
    storage.path  /var/lib/fluent-bit/
    storage.sync  normal
    storage.checksum off
    storage.backlog.mem_limit 50M

# ────────────────────────────────────────────
# INPUT: читаем audit.log построчно
# ────────────────────────────────────────────
[INPUT]
    Name              tail
    Tag               auditd.raw
    Path              /var/log/audit/audit.log
    Parser            auditd_line
    DB                /var/lib/fluent-bit/auditd.db
    DB.locking        true
    Skip_Long_Lines   On
    Refresh_Interval  5
    Mem_Buf_Limit     32MB
    storage.type      filesystem

# ────────────────────────────────────────────
# FILTER 1: отбрасываем EOE-строки до Lua (они нужны только как сигнал)
# и строки-пустышки
# ────────────────────────────────────────────
[FILTER]
    Name    grep
    Match   auditd.raw
    Exclude audit_type ^(EOE)$

# ────────────────────────────────────────────
# FILTER 2: Lua — объединяем разрозненные записи по serial number
# ────────────────────────────────────────────
[FILTER]
    Name    lua
    Match   auditd.raw
    script  /etc/fluent-bit/scripts/auditd_merge.lua
    call    merge_auditd

# ────────────────────────────────────────────
# FILTER 3: Lua — обогащение в ECS-поля
# ────────────────────────────────────────────
[FILTER]
    Name    lua
    Match   auditd.raw
    script  /etc/fluent-bit/scripts/auditd_enrich.lua
    call    enrich_ecs

# ────────────────────────────────────────────
# FILTER 4: добавляем статические метаданные хоста
# ────────────────────────────────────────────
[FILTER]
    Name    record_modifier
    Match   auditd.*
    Record  agent.name    fluent-bit
    Record  agent.version 3.x
    Record  agent.type    filebeat-compat
    Record  data_stream.type   logs
    Record  data_stream.dataset auditd
    Record  data_stream.namespace security

# ────────────────────────────────────────────
# FILTER 5: убираем служебные поля которые не нужны в SIEM
# ────────────────────────────────────────────
[FILTER]
    Name    record_modifier
    Match   auditd.*
    Remove_key audit_type
    Remove_key serial
    Remove_key msg

# ────────────────────────────────────────────
# OUTPUT: отправка в Logstash по TCP (Lumberjack/Forward)
# ────────────────────────────────────────────
[OUTPUT]
    Name          forward
    Match         auditd.*
    Host          ${LOGSTASH_HOST}
    Port          ${LOGSTASH_PORT}
    Self_Hostname ${HOSTNAME}
    TLS           On
    TLS.Verify    On
    TLS.CA_File   /etc/fluent-bit/certs/ca.crt
    TLS.CRT_File  /etc/fluent-bit/certs/client.crt
    TLS.KEY_File  /etc/fluent-bit/certs/client.key
    Retry_Limit   10
    storage.total_limit_size 1G

# Fallback output для отладки (закомментировать в проде)
#[OUTPUT]
#    Name   stdout
#    Match  auditd.*
#    Format json_lines
```

---

## Файл 2: `fluent-bit/parsers.conf`

```ini
# ────────────────────────────────────────────
# Парсер для строк auditd
# Формат: type=SYSCALL msg=audit(1613845287.701:6542): arch=c000003e ...
# ────────────────────────────────────────────
[PARSER]
    Name        auditd_line
    Format      regex
    Regex       ^type=(?<audit_type>[A-Z0-9_]+) msg=audit\((?<audit_epoch>[0-9]+)\.(?<audit_ms>[0-9]+):(?<serial>[0-9]+)\):\s*(?<msg>.*)$
    Time_Key    audit_epoch
    Time_Format %s
    Time_Keep   On
    Types       serial:integer audit_ms:integer

# ────────────────────────────────────────────
# Парсер для USER_* событий (msg содержит op= acct= exe= ... res=)
# ────────────────────────────────────────────
[PARSER]
    Name        auditd_user_msg
    Format      regex
    Regex       op=(?<op>[^ ]+) (?:grantors=(?<grantors>[^ ]+) )?acct="(?<acct>[^"]*)" exe="(?<exe>[^"]*)" hostname=(?<hostname>[^ ]+) addr=(?<addr>[^ ]+) terminal=(?<terminal>[^ ]+) res=(?<res>[^ ]+)

# ────────────────────────────────────────────
# Парсер для SYSCALL msg-поля (key=value пары)
# ────────────────────────────────────────────
[PARSER]
    Name        auditd_kv
    Format      logfmt
```

---

## Файл 3: `fluent-bit/scripts/auditd_merge.lua`

```lua
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
    buf[serial]   = nil
    last_ts[serial] = nil
    return rec
end

local function buf_size()
    local n = 0
    for _ in pairs(buf) do n = n + 1 end
    return n
end

function merge_auditd(tag, timestamp, record)
    local serial    = tostring(record["serial"] or "")
    local atype     = record["audit_type"] or "UNKNOWN"
    local msg       = record["msg"] or ""
    local now       = os.clock()

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
            serial    = serial,
            timestamp = timestamp,
            _paths    = {},
            _execve_args = {},
        }
    end

    local entry = buf[serial]
    last_ts[serial] = now

    -- ── Парсим и мержим поля в зависимости от типа ──
    local kv = parse_kv(msg)

    if atype == "SYSCALL" then
        -- Базовые поля — берём из SYSCALL
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
    for s, t in pairs(last_ts) do
        if s ~= serial and (now - t) > TIMEOUT then
            -- К сожалению fluent-bit Lua не умеет возвращать несколько записей
            -- из одного вызова. Старые записи будут флашнуты при следующем
            -- событии. Для продакшена используйте flush_interval в конфиге
            -- или перейдите на Fluentd с fluent-plugin-concat.
            flush_record(s)
        end
    end

    -- Текущее событие добавлено в буфер — удаляем из потока
    return -1, timestamp, record
end
```

---

## Файл 4: `fluent-bit/scripts/auditd_enrich.lua`

```lua
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
    execve    = {"T1059","Execution: Command and Scripting Interpreter"},
    execveat  = {"T1059","Execution: Command and Scripting Interpreter"},
    fork      = {"T1059.004","Execution: Unix Shell"},
    clone     = {"T1059.004","Execution: Unix Shell"},
    setuid    = {"T1548.001","Privilege Escalation: Setuid"},
    setreuid  = {"T1548.001","Privilege Escalation: Setuid"},
    setresuid = {"T1548.001","Privilege Escalation: Setuid"},
    connect   = {"T1071","Command and Control: Application Layer Protocol"},
    bind      = {"T1071","Command and Control: Application Layer Protocol"},
    socket    = {"T1071","Command and Control: Application Layer Protocol"},
    openat    = {"T1083","Discovery: File and Directory Discovery"},
    unlink    = {"T1070.004","Defense Evasion: Indicator Removal on Host"},
    unlinkat  = {"T1070.004","Defense Evasion: Indicator Removal on Host"},
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
    record["ecs.version"]      = "8.11"
    record["event.dataset"]    = "auditd"
    record["event.module"]     = "auditd"
    record["event.kind"]       = "event"
    record["@timestamp"]       = record["@timestamp"] or
        os.date("!%Y-%m-%dT%H:%M:%S.000Z", timestamp)

    -- ── Хост ──
    record["host.name"]        = get_hostname()
    record["host.os.type"]     = "linux"
    record["host.os.family"]   = "linux"

    -- ── Определяем тип события (из _event_types) ──
    local primary_type = "UNKNOWN"
    local etypes = record["_event_types"] or {}
    if etypes["SYSCALL"]    then primary_type = "SYSCALL"
    elseif etypes["EXECVE"] then primary_type = "EXECVE"
    elseif etypes["USER_LOGIN"]   then primary_type = "USER_LOGIN"
    elseif etypes["USER_AUTH"]    then primary_type = "USER_AUTH"
    elseif etypes["USER_CMD"]     then primary_type = "USER_CMD"
    elseif etypes["LOGIN"]        then primary_type = "LOGIN"
    elseif etypes["NETFILTER_CFG"] then primary_type = "NETFILTER_CFG"
    end

    local cats = EVENT_CATEGORY[primary_type] or {"host"}
    record["event.category"] = cats[1]
    record["event.type"]     = "info"

    -- ── Процесс ──
    local pid = tonumber(record["pid"])
    if pid then
        record["process.pid"]        = pid
        record["process.name"]       = record["comm"]
        record["process.executable"] = record["exe"]
        record["process.title"]      = record["proctitle"]
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
    if uid then
        record["user.id"] = uid
    end
    -- auid = audit user id (реальный пользователь до su/sudo)
    local auid = record["auid"]
    if auid and auid ~= "4294967295" and auid ~= "-1" then
        record["user.effective.id"] = auid
    end
    -- Из USER_* событий
    if record["user_acct"] then
        record["user.name"] = record["user_acct"]
    end

    -- ── Syscall ──
    local sc_num = record["syscall"]
    local sc_name = sc_num and SYSCALLS[sc_num]
    if sc_name then
        record["auditd.data.syscall"]  = sc_name
        record["event.action"]         = sc_name

        -- Специализация по syscall
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
        elseif sc_name == "open" or sc_name == "openat" or
               sc_name == "creat" then
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
            record["file.path"]      = name
            record["file.inode"]     = primary.inode
            record["file.device"]    = primary.dev
            record["file.mode"]      = mode_to_str(primary.mode)
            record["file.uid"]       = primary.ouid
            record["file.gid"]       = primary.ogid
            -- Имя файла без пути
            local fname = name:match("([^/]+)$")
            if fname then record["file.name"] = fname end
            -- Расширение
            local ext = fname and fname:match("%.([^%.]+)$")
            if ext then record["file.extension"] = ext end
        end
        -- Все пути сохраняем в массив
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
    record["_paths"]        = nil
    record["_execve_args"]  = nil
    record["_event_types"]  = nil
    record["syscall_success"] = nil
    record["syscall_exit"]  = nil

    return 2, timestamp, record
end
```

---

## Файл 5: `fluent-bit/logstash/auditd-pipeline.conf`

```ruby
# ─────────────────────────────────────────────────────────────
# Logstash pipeline: приём от fluent-bit → нормализация → SIEM
# Сохранить в: /etc/logstash/conf.d/auditd-pipeline.conf
# ─────────────────────────────────────────────────────────────

input {
  # Fluent-bit forward protocol (beats-compatible)
  beats {
    port            => 5044
    ssl_enabled     => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key         => "/etc/logstash/certs/logstash.key"
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
    ssl_client_authentication => "required"
    tags            => ["auditd_raw"]
  }
}

filter {

  # ── Обрабатываем только auditd-теги ──
  if "auditd_raw" in [tags] {

    # ── Нормализация типов данных ──
    mutate {
      convert => {
        "process.pid"         => "integer"
        "process.parent.pid"  => "integer"
        "process.args_count"  => "integer"
        "user.id"             => "string"
        "user.effective.id"   => "string"
        "auditd.session"      => "integer"
        "file.uid"            => "string"
        "file.gid"            => "string"
      }
      # Переименование если fluent-bit прислал с точками в ключах
      rename => {
        "[ecs][version]"       => "ecs.version"
        "[event][category]"    => "event.category"
        "[event][dataset]"     => "event.dataset"
        "[event][kind]"        => "event.kind"
        "[event][module]"      => "event.module"
        "[event][type]"        => "event.type"
        "[event][outcome]"     => "event.outcome"
        "[event][action]"      => "event.action"
        "[host][name]"         => "host.name"
        "[host][os][type]"     => "host.os.type"
        "[process][pid]"       => "process.pid"
        "[process][name]"      => "process.name"
        "[process][executable]" => "process.executable"
        "[process][command_line]" => "process.command_line"
        "[user][id]"           => "user.id"
        "[user][name]"         => "user.name"
        "[file][path]"         => "file.path"
        "[file][name]"         => "file.name"
      }
      remove_field => ["tags", "beat", "prospector", "input", "@version"]
    }

    # ── Гео-обогащение для network событий ──
    if [event][category] == "network" and [destination][ip] {
      geoip {
        source => "[destination][ip]"
        target => "[destination][geo]"
      }
    }

    # ── Lookup имён пользователей по UID (опционально, если есть база) ──
    # translate {
    #   field       => "[user][id]"
    #   destination => "[user][name]"
    #   dictionary_path => "/etc/logstash/dictionaries/uid_to_name.yml"
    #   fallback    => "unknown"
    # }

    # ── Добавляем severity для SIEM ──
    if [event][outcome] == "failure" {
      mutate { add_field => { "event.severity" => 3 } }
    } else if [threat][technique][id] {
      mutate { add_field => { "event.severity" => 2 } }
    } else {
      mutate { add_field => { "event.severity" => 1 } }
    }

    # ── data_stream routing ──
    if ![data_stream][type]      { mutate { add_field => { "[data_stream][type]"      => "logs" } } }
    if ![data_stream][dataset]   { mutate { add_field => { "[data_stream][dataset]"   => "auditd" } } }
    if ![data_stream][namespace] { mutate { add_field => { "[data_stream][namespace]" => "security" } } }
  }
}

output {
  if "auditd_raw" in [tags] or [event][dataset] == "auditd" {

    # ── Elasticsearch / OpenSearch ──
    elasticsearch {
      hosts         => ["${ES_HOST}:9200"]
      user          => "${ES_USER}"
      password      => "${ES_PASS}"
      ssl_enabled   => true
      ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
      # Data stream routing
      data_stream         => true
      data_stream_type    => "%{[data_stream][type]}"
      data_stream_dataset => "%{[data_stream][dataset]}"
      data_stream_namespace => "%{[data_stream][namespace]}"
      # Fallback index
      index         => "logs-auditd-security-%{+YYYY.MM.dd}"
    }

    # ── Опционально: дубль в Splunk ──
    # http {
    #   url              => "https://splunk:8088/services/collector"
    #   http_method      => "post"
    #   headers          => ["Authorization", "Splunk ${SPLUNK_HEC_TOKEN}"]
    #   format           => "json"
    #   mapping          => {
    #     "event"        => "%{message}"
    #     "sourcetype"   => "linux:audit"
    #     "index"        => "security"
    #   }
    # }
  }
}
```

---

## Инструкции по донастройке auditd

### 1. Установить правила аудита для SIEM

Создать файл `/etc/audit/rules.d/99-siem.rules`:

```bash
# /etc/audit/rules.d/99-siem.rules
# Правила auditd для сбора событий безопасности → SIEM

# ── Очистка буфера и параметры ──
-D
-b 8192
-f 1
--backlog_wait_time 60000

# ── Игнорируем высокочастотные системные вызовы ──
-a never,exit -F arch=b64 -S epoll_wait -S epoll_pwait
-a never,exit -F arch=b64 -S getpid -S gettid -S clock_gettime
-a never,exit -F arch=b64 -S recvmsg -F uid=root

# ── Privilege escalation ──
-a always,exit -F arch=b64 -S setuid  -S setreuid -S setresuid -k priv_escalation
-a always,exit -F arch=b64 -S setgid  -S setregid -S setresgid -k priv_escalation
-a always,exit -F arch=b64 -S capset -k priv_escalation

# ── Выполнение команд (Execution) ──
-a always,exit -F arch=b64 -S execve  -k execution
-a always,exit -F arch=b32 -S execve  -k execution
-a always,exit -F arch=b64 -S execveat -k execution

# ── Сетевые соединения (Network) ──
-a always,exit -F arch=b64 -S connect  -k network_connect
-a always,exit -F arch=b64 -S bind     -k network_bind
-a always,exit -F arch=b64 -S accept   -k network_accept
-a always,exit -F arch=b64 -S accept4  -k network_accept
-a always,exit -F arch=b64 -S socket   -F a0=2  -k network_socket_ipv4
-a always,exit -F arch=b64 -S socket   -F a0=10 -k network_socket_ipv6

# ── Изменения файловой системы (критичные пути) ──
-w /etc/passwd          -p wa -k identity_change
-w /etc/shadow          -p wa -k identity_change
-w /etc/group           -p wa -k identity_change
-w /etc/gshadow         -p wa -k identity_change
-w /etc/sudoers         -p wa -k sudo_change
-w /etc/sudoers.d/      -p wa -k sudo_change
-w /etc/ssh/sshd_config -p wa -k sshd_config_change
-w /etc/pam.d/          -p wa -k pam_change
-w /etc/cron.d/         -p wa -k cron_change
-w /etc/crontab         -p wa -k cron_change
-w /var/spool/cron/     -p wa -k cron_change
-w /etc/ld.so.conf      -p wa -k ldconfig_change
-w /etc/ld.so.conf.d/   -p wa -k ldconfig_change

# ── Изменения в бинарниках и системных директориях ──
-a always,exit -F arch=b64 -S rename -S renameat -S renameat2 \
   -F dir=/usr/bin  -k binary_modification
-a always,exit -F arch=b64 -S rename -S renameat -S renameat2 \
   -F dir=/usr/sbin -k binary_modification
-a always,exit -F arch=b64 -S rename -S renameat -S renameat2 \
   -F dir=/bin      -k binary_modification

# ── Загрузка/выгрузка модулей ядра ──
-a always,exit -F arch=b64 -S init_module  -k kernel_module
-a always,exit -F arch=b64 -S finit_module -k kernel_module
-a always,exit -F arch=b64 -S delete_module -k kernel_module

# ── Монтирование ──
-a always,exit -F arch=b64 -S mount   -k mount
-a always,exit -F arch=b64 -S umount2 -k mount

# ── Вход/выход пользователей ──
-w /var/log/faillog  -p wa -k login_failure
-w /var/log/lastlog  -p wa -k login_tracking
-w /var/run/utmp     -p wa -k session_tracking
-w /var/log/wtmp     -p wa -k session_tracking
-w /var/log/btmp     -p wa -k session_tracking

# ── Аудит самого auditd ──
-w /etc/audit/        -p wa -k audit_config_change
-w /etc/audisp/       -p wa -k audit_config_change

# ── Подозрительные действия ──
# Запись в /tmp с последующим exec
-a always,exit -F arch=b64 -S openat -F dir=/tmp -F success=1 -k tmp_write
-a always,exit -F arch=b64 -S execve -F dir=/tmp  -k tmp_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k tmp_exec

# ── Заморозить правила (опционально, рекомендуется в проде) ──
# -e 2
```

### 2. Настройки `/etc/audit/auditd.conf`

Изменить следующие параметры:

```ini
# Размер лог-файла (MB) до ротации
max_log_file = 100
max_log_file_action = ROTATE
num_logs = 5

# Что делать при нехватке диска
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SYSLOG

# Flush на диск каждые N секунд (0 = каждую запись, медленнее)
freq = 50
flush = INCREMENTAL_ASYNC

# EOE-записи — КРИТИЧЕСКИ ВАЖНО для fluent-bit
# Гарантирует явный маркер конца набора событий
end_of_event_timeout = 2

# Формат записи
log_format = ENRICHED
```

### 3. Применить правила и перезапустить

```bash
# Применить правила
sudo augenrules --load

# Проверить статус
sudo auditctl -s
sudo auditctl -l

# Перезапустить службы
sudo systemctl restart auditd
sudo systemctl enable auditd

# Дать fluent-bit доступ к логу
sudo usermod -aG adm fluent-bit
# или через ACL:
sudo setfacl -m u:fluent-bit:r /var/log/audit/audit.log
sudo setfacl -m d:u:fluent-bit:r /var/log/audit/

# Запустить fluent-bit
sudo systemctl restart fluent-bit
sudo systemctl enable fluent-bit
```

### 4. Переменные окружения для fluent-bit

Создать `/etc/fluent-bit/fluent-bit.env` (и добавить в systemd unit):

```bash
LOGSTASH_HOST=logstash.internal
LOGSTASH_PORT=5044
HOSTNAME=<имя_хоста>
```

В `/etc/systemd/system/fluent-bit.service.d/override.conf`:

```ini
[Service]
EnvironmentFile=/etc/fluent-bit/fluent-bit.env
```

### 5. Проверка пайплайна

```bash
# Проверить парсинг — запустить fluent-bit с выводом в stdout
sudo fluent-bit -c /etc/fluent-bit/fluent-bit.conf \
  -o stdout -f 1 --match auditd.*

# Сгенерировать тестовое событие
sudo ausyscall execve  # проверить, что execve есть в таблице
sudo touch /tmp/testfile && cat /tmp/testfile  # PATH + SYSCALL

# Посмотреть сырые события auditd
sudo ausearch -ts recent -i | head -50

# Проверить Logstash pipeline
curl -s http://localhost:9600/_node/stats/pipelines | jq .pipelines.auditd
```

---

## Дополнительные инструкции для Claude Code

1. Убедись, что все Lua-скрипты имеют unix line endings (`\n`, не `\r\n`).
2. Замени `${LOGSTASH_HOST}`, `${ES_HOST}` и другие переменные в конфигах
   на реальные значения из `.env` файла проекта или передай через systemd.
3. Для TLS-сертификатов — проверь наличие файлов в `/etc/fluent-bit/certs/`.
   Если их нет — сгенерируй самоподписанные для теста:
   ```bash
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout /etc/fluent-bit/certs/client.key \
     -out /etc/fluent-bit/certs/client.crt \
     -subj "/CN=fluent-bit-client"
   ```
4. Logstash должен быть настроен на beats-input на порту 5044
   с тем же CA-сертификатом.
5. Lua-ограничение fluent-bit: функция не может вернуть несколько записей
   за один вызов. Если нужен полноценный таймаут-флаш, добавь в pipeline
   промежуточный Fluentd как агрегатор или используй fluent-plugin-concat.
6. После применения правил auditd — проверь что не растёт очередь:
   ```bash
   watch -n 1 'sudo auditctl -s | grep backlog'
   ```
   Если backlog растёт — увеличь `-b` в rules или уменьши детализацию правил.