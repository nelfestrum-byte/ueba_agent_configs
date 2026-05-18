-- osquery_enrich.lua
-- Нормализует события osqueryd.results.log в ECS 8.x + osquery.* namespace.
--
-- Входящий record после JSON-парсера:
--   record.name            — имя запроса (processes, listening_ports, ...)
--   record.action          — "added" | "removed"
--   record.hostIdentifier  — hostname из osquery
--   record.unixTime        — unix timestamp (уже используется как time_key)
--   record.columns         — таблица с колонками результата (вложенный объект)
--   record.decorations     — таблица {hostname, osquery_version}

-- ── Маппинг имени запроса → ECS category / type / action ──────────────────
local QUERY_META = {
    processes = {
        category = "process",
        action_added   = "process_started",
        action_removed = "process_stopped",
        type_added     = "start",
        type_removed   = "end",
    },
    listening_ports = {
        category = "network",
        action_added   = "port_listening",
        action_removed = "port_closed",
        type_added     = "start",
        type_removed   = "end",
    },
    process_connections = {
        category = "network",
        action_added   = "network_connection",
        action_removed = "network_connection_closed",
        type_added     = "start",
        type_removed   = "end",
    },
    logged_in_users = {
        category = "authentication",
        action_added   = "user_login",
        action_removed = "user_logout",
        type_added     = "start",
        type_removed   = "end",
    },
    users = {
        category = "iam",
        action_added   = "user_created",
        action_removed = "user_deleted",
        type_added     = "creation",
        type_removed   = "deletion",
    },
    ssh_authorized_keys = {
        category = "iam",
        action_added   = "ssh_key_added",
        action_removed = "ssh_key_removed",
        type_added     = "change",
        type_removed   = "change",
    },
    sudoers = {
        category = "iam",
        action_added   = "sudoers_modified",
        action_removed = "sudoers_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    user_groups = {
        category = "iam",
        action_added   = "user_group_modified",
        action_removed = "user_group_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    groups = {
        category = "iam",
        action_added   = "group_modified",
        action_removed = "group_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    kernel_modules = {
        category = "configuration",
        action_added   = "kernel_module_loaded",
        action_removed = "kernel_module_unloaded",
        type_added     = "start",
        type_removed   = "end",
    },
    services = {
        category = "configuration",
        action_added   = "service_modified",
        action_removed = "service_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    crontabs = {
        category = "configuration",
        action_added   = "cron_modified",
        action_removed = "cron_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    startup_items = {
        category = "configuration",
        action_added   = "startup_item_modified",
        action_removed = "startup_item_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    suid_bins = {
        category = "configuration",
        action_added   = "suid_binary_added",
        action_removed = "suid_binary_removed",
        type_added     = "change",
        type_removed   = "change",
    },
    etc_hosts = {
        category = "configuration",
        action_added   = "hosts_file_modified",
        action_removed = "hosts_file_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    mounts = {
        category = "configuration",
        action_added   = "mount_added",
        action_removed = "mount_removed",
        type_added     = "change",
        type_removed   = "change",
    },
    iptables = {
        category = "network",
        action_added   = "firewall_rule_added",
        action_removed = "firewall_rule_removed",
        type_added     = "change",
        type_removed   = "change",
    },
    routes = {
        category = "network",
        action_added   = "route_added",
        action_removed = "route_removed",
        type_added     = "change",
        type_removed   = "change",
    },
    arp_cache = {
        category = "network",
        action_added   = "arp_entry_added",
        action_removed = "arp_entry_removed",
        type_added     = "change",
        type_removed   = "change",
    },
    dns_resolvers = {
        category = "network",
        action_added   = "dns_resolver_modified",
        action_removed = "dns_resolver_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    usb_devices = {
        category = "host",
        action_added   = "usb_connected",
        action_removed = "usb_removed",
        type_added     = "start",
        type_removed   = "end",
    },
    pci_devices = {
        category = "host",
        action_added   = "pci_device_added",
        action_removed = "pci_device_removed",
        type_added     = "info",
        type_removed   = "info",
    },
    process_open_files = {
        category = "file",
        action_added   = "file_opened",
        action_removed = "file_closed",
        type_added     = "access",
        type_removed   = "access",
    },
    certificates = {
        category = "configuration",
        action_added   = "certificate_added",
        action_removed = "certificate_removed",
        type_added     = "change",
        type_removed   = "change",
    },
}

-- ── Кэш hostname ──────────────────────────────────────────────────────────
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

-- ── Протокол: номер IANA → имя ────────────────────────────────────────────
local PROTO = { ["6"] = "tcp", ["17"] = "udp", ["1"] = "icmp",
                ["58"] = "ipv6-icmp", ["132"] = "sctp" }

-- ── FNV-1a 64-bit хэш как две FNV-32 ветви на разных offset basis ──
-- Идентичен auditd_enrich.lua — одинаковая формула обеспечивает совпадение
-- process.entity_id для одного процесса в fluent-audit-* и fluent-osquery-*.
local bit = require("bit")
local FNV32_PRIME      = 16777619
local FNV32_OFFSET     = 2166136261
local FNV32_OFFSET_ALT = 2654435769

local function fnv32(s, seed)
    local h = seed
    for i = 1, #s do
        h = bit.bxor(h, s:byte(i))
        h = bit.band(h * FNV32_PRIME, 0xFFFFFFFF)
    end
    return h
end

local function short_id(s)
    local hi = fnv32(s, FNV32_OFFSET)
    local lo = fnv32(s, FNV32_OFFSET_ALT)
    return string.format("%08x%08x", hi, lo)
end

-- ── Кэш pid → process.start (epoch seconds) ──
local PROC_CACHE_MAX   = 10000
local _proc_cache      = {}
local _proc_cache_size = 0
local _btime           = nil
local _clk_tck         = nil

local function get_btime()
    if _btime then return _btime end
    local f = io.open("/proc/stat", "r")
    if not f then return nil end
    for line in f:lines() do
        local b = line:match("^btime%s+(%d+)")
        if b then _btime = tonumber(b); break end
    end
    f:close()
    return _btime
end

local function get_clk_tck()
    if _clk_tck then return _clk_tck end
    local f = io.popen("getconf CLK_TCK 2>/dev/null")
    if f then
        local v = f:read("*l")
        f:close()
        _clk_tck = tonumber(v)
    end
    _clk_tck = _clk_tck or 100
    return _clk_tck
end

local function read_proc_start(pid)
    local f = io.open("/proc/" .. pid .. "/stat", "r")
    if not f then return nil end
    local line = f:read("*l")
    f:close()
    if not line then return nil end
    local tail_idx = line:find("%) ")
    if not tail_idx then return nil end
    local tail = line:sub(tail_idx + 2)
    local fields = {}
    for w in tail:gmatch("%S+") do fields[#fields+1] = w end
    local ticks = tonumber(fields[20])
    if not ticks then return nil end
    local btime = get_btime()
    if not btime then return nil end
    return btime + math.floor(ticks / get_clk_tck())
end

local function cache_evict_if_full()
    if _proc_cache_size > PROC_CACHE_MAX then
        _proc_cache      = {}
        _proc_cache_size = 0
    end
end

local function cache_put(pid, start_ts, force)
    if force or not _proc_cache[pid] then
        if not _proc_cache[pid] then
            _proc_cache_size = _proc_cache_size + 1
        end
        _proc_cache[pid] = start_ts
        cache_evict_if_full()
    end
end

local function resolve_start(pid)
    local s = _proc_cache[pid]
    if s then return s end
    s = read_proc_start(pid)
    if s then cache_put(pid, s, false) end
    return s
end

-- ── Главная функция ───────────────────────────────────────────────────────
function enrich_osquery(tag, timestamp, record)

    local query_name = record["name"]
    local action     = record["action"] or "added"
    local cols       = record["columns"]
    local deco       = record["decorations"]

    -- Без columns — пропускаем (нераспознанный формат)
    if type(cols) ~= "table" then
        return -1, timestamp, record
    end

    -- ── ECS базовые поля ──────────────────────────────────────────────────
    record["ecs.version"]   = "8.11"
    record["event.kind"]    = "event"
    record["event.dataset"] = "osquery"
    record["event.module"]  = "osquery"
    record["@timestamp"]    = record["@timestamp"] or
        os.date("!%Y-%m-%dT%H:%M:%S.000Z", timestamp)

    -- ── Host ──────────────────────────────────────────────────────────────
    local host_id = record["hostIdentifier"]
        or (deco and deco["hostname"])
        or get_hostname()
    record["host.name"]      = host_id
    record["host.os.type"]   = "linux"
    record["host.os.family"] = "linux"

    -- ── osquery.result.* — метаданные запроса ─────────────────────────────
    record["osquery.result.name"]            = query_name
    record["osquery.result.action"]          = action
    record["osquery.result.host_identifier"] = host_id
    record["osquery.result.unix_time"]       = record["unixTime"]
    if deco and deco["osquery_version"] then
        record["osquery.result.version"] = deco["osquery_version"]
    end

    -- ── ECS event.category / type / action ───────────────────────────────
    local meta = query_name and QUERY_META[query_name]
    if meta then
        record["event.category"] = meta.category
        if action == "removed" then
            record["event.action"] = meta.action_removed
            record["event.type"]   = meta.type_removed
        else
            record["event.action"] = meta.action_added
            record["event.type"]   = meta.type_added
        end
    else
        record["event.category"] = "host"
        record["event.action"]   = (query_name or "unknown") .. "_" .. action
        record["event.type"]     = "info"
    end

    -- ── Колонки → osquery.<column> (flat, совместимо с Elastic mapping) ───
    for k, v in pairs(cols) do
        if v ~= nil and v ~= "" then
            record["osquery." .. k] = v
        end
    end

    -- ── ECS процессные поля ───────────────────────────────────────────────
    if query_name == "processes" or query_name == "process_connections"
       or query_name == "process_open_files" or query_name == "listening_ports" then

        local pid = tonumber(cols["pid"])
        if pid then
            record["process.pid"] = pid

            if pid > 0 then
                local start_ts
                if query_name == "processes" then
                    -- processes.start_time: epoch seconds (integer), тот же источник что
                    -- и /proc/<pid>/stat field 22 + btime в auditd — seed совпадёт.
                    start_ts = tonumber(cols["start_time"])
                    if start_ts then
                        record["process.start"] = start_ts
                        -- "added" = новый процесс; force=true для PID reuse.
                        cache_put(pid, start_ts, action == "added")
                    end
                else
                    start_ts = resolve_start(pid)
                    if start_ts then
                        record["process.start"] = start_ts
                    end
                end

                if start_ts then
                    local seed = (record["host.name"] or "")
                              .. ":" .. tostring(pid)
                              .. ":" .. tostring(start_ts)
                    record["process.entity_id"] = short_id(seed)
                end
            end
        end

        local ppid = tonumber(cols["parent"])
        if ppid then
            record["process.parent.pid"] = ppid
            if ppid > 0 then
                local parent_start = resolve_start(ppid)
                if parent_start then
                    record["process.parent.start"]     = parent_start
                    local pseed = (record["host.name"] or "")
                               .. ":" .. tostring(ppid)
                               .. ":" .. tostring(parent_start)
                    record["process.parent.entity_id"] = short_id(pseed)
                end
            end
        end

        if cols["name"] then
            record["process.name"] = cols["name"]
        end
        if cols["path"] and cols["path"] ~= "" then
            record["process.executable"] = cols["path"]
        end
        if cols["process_path"] and cols["process_path"] ~= "" then
            record["process.executable"] = cols["process_path"]
        end
        if cols["cmdline"] and cols["cmdline"] ~= "" then
            record["process.command_line"] = cols["cmdline"]
        end
        if cols["process_name"] then
            record["process.name"] = cols["process_name"]
        end
    end

    -- ── ECS user ──────────────────────────────────────────────────────────
    local username = cols["username"] or cols["user"]
    if username and username ~= "" then
        record["user.name"] = username
    end
    local uid = cols["uid"]
    if uid and uid ~= "" then
        record["user.id"] = uid
    end

    -- ── ECS network (process_connections, listening_ports) ────────────────
    if query_name == "process_connections" then
        if cols["remote_address"] and cols["remote_address"] ~= "" then
            record["destination.ip"]   = cols["remote_address"]
        end
        if cols["remote_port"] then
            record["destination.port"] = tonumber(cols["remote_port"])
        end
        if cols["local_address"] and cols["local_address"] ~= "" then
            record["source.ip"]   = cols["local_address"]
        end
        if cols["local_port"] then
            record["source.port"] = tonumber(cols["local_port"])
        end
        local proto = cols["protocol"]
        if proto then
            record["network.transport"] = PROTO[proto] or proto
            record["network.iana_number"] = proto
        end
    end

    if query_name == "listening_ports" then
        if cols["port"] then
            record["destination.port"] = tonumber(cols["port"])
        end
        local proto = cols["protocol"]
        if proto then
            record["network.transport"] = PROTO[proto] or proto
            record["network.iana_number"] = proto
        end
        if cols["address"] and cols["address"] ~= "" then
            record["destination.ip"] = cols["address"]
        end
    end

    -- ── ECS file ──────────────────────────────────────────────────────────
    if query_name == "process_open_files" then
        local fpath = cols["file_path"]
        if fpath and fpath ~= "" then
            record["file.path"] = fpath
            local fname = fpath:match("([^/]+)$")
            if fname then record["file.name"] = fname end
        end
    end
    if query_name == "ssh_authorized_keys" then
        if cols["key_file"] and cols["key_file"] ~= "" then
            record["file.path"] = cols["key_file"]
        end
    end

    -- ── Теги ──────────────────────────────────────────────────────────────
    record["tags"] = {"osquery", "security", "linux"}

    -- ── Очистка служебных полей osquery JSON ─────────────────────────────
    record["name"]           = nil
    record["action"]         = nil
    record["hostIdentifier"] = nil
    record["calendarTime"]   = nil
    record["unixTime"]       = nil
    record["epoch"]          = nil
    record["counter"]        = nil
    record["numerics"]       = nil
    record["columns"]        = nil
    record["decorations"]    = nil

    return 2, timestamp, record
end
