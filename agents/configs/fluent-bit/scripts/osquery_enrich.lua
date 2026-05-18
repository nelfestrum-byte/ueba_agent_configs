-- osquery_enrich.lua
-- Normalises osqueryd.results.log events to ECS 8.x + osquery.* namespace.

local _dir = (debug.getinfo(1, "S").source or ""):match("^@(.+/)") or ""
package.path = _dir .. "?.lua;" .. package.path
local common = require("proc_common")

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

-- ── Протокол: номер IANA → имя ────────────────────────────────────────────
local PROTO = { ["6"] = "tcp", ["17"] = "udp", ["1"] = "icmp",
                ["58"] = "ipv6-icmp", ["132"] = "sctp" }

-- ── Главная функция ───────────────────────────────────────────────────────
function enrich_osquery(tag, timestamp, record)

    local query_name = record["name"]
    local action     = record["action"] or "added"
    local cols       = record["columns"]
    local deco       = record["decorations"]

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
    -- host.name берём из hostname -f (FQDN) — как в auditd_enrich,
    -- иначе entity_id seed расходится и cross-index корреляция ломается.
    local host_id = record["hostIdentifier"]
        or (deco and deco["hostname"])
        or common.get_hostname()
    record["host.name"]      = common.get_hostname()
    record["host.os.type"]   = "linux"
    record["host.os.family"] = "linux"

    -- ── osquery.result.* ─────────────────────────────────────────────────
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

    -- ── Колонки → osquery.<column> ────────────────────────────────────────
    for k, v in pairs(cols) do
        if v ~= nil and v ~= "" then
            record["osquery." .. k] = v
        end
    end

    -- ── ECS процессные поля ───────────────────────────────────────────────
    if query_name == "processes" or query_name == "process_connections"
       or query_name == "process_open_files" or query_name == "listening_ports" then

        local pid = tonumber(cols["pid"])
        if pid and pid > 0 then
            record["process.pid"] = pid

            local start_ts
            if query_name == "processes" then
                -- processes.start_time: epoch seconds, same source as /proc/<pid>/stat
                -- field 22 + btime in auditd → entity_id seed matches.
                start_ts = tonumber(cols["start_time"])
                if start_ts then
                    record["process.start"] = start_ts
                    common.cache_put(pid, start_ts, action == "added")
                end
            else
                start_ts = common.resolve_start(pid)
                if start_ts then
                    record["process.start"] = start_ts
                end
            end

            if start_ts then
                local seed = (record["host.name"] or "")
                          .. ":" .. tostring(pid)
                          .. ":" .. tostring(start_ts)
                record["process.entity_id"] = common.short_id(seed)
            end

            local ses = common.get_sessionid(pid)
            if ses then
                local sid = common.make_session_id(record["host.name"] or "", ses)
                if sid then record["user.session.id"] = sid end
            end
        end

        local ppid = tonumber(cols["parent"])
        if ppid and ppid > 0 then
            record["process.parent.pid"] = ppid
            local parent_start = common.resolve_start(ppid)
            if parent_start then
                record["process.parent.start"]     = parent_start
                local pseed = (record["host.name"] or "")
                           .. ":" .. tostring(ppid)
                           .. ":" .. tostring(parent_start)
                record["process.parent.entity_id"] = common.short_id(pseed)
            end
        end

        if cols["name"]         then record["process.name"] = cols["name"] end
        if cols["process_name"] then record["process.name"] = cols["process_name"] end
        if cols["path"]         and cols["path"] ~= ""         then record["process.executable"] = cols["path"] end
        if cols["process_path"] and cols["process_path"] ~= "" then record["process.executable"] = cols["process_path"] end
        if cols["cmdline"]      and cols["cmdline"] ~= ""      then record["process.command_line"] = cols["cmdline"] end
    end

    -- user.session.id для logged_in_users (cols.pid = PID shell сессии)
    if query_name == "logged_in_users" then
        local pid = tonumber(cols["pid"])
        if pid and pid > 0 then
            local ses = common.get_sessionid(pid)
            if ses then
                local sid = common.make_session_id(record["host.name"] or "", ses)
                if sid then record["user.session.id"] = sid end
            end
        end
    end

    -- ── ECS user ──────────────────────────────────────────────────────────
    local username = cols["username"] or cols["user"]
    if username and username ~= "" then record["user.name"] = username end
    local uid = cols["uid"]
    if uid and uid ~= "" then record["user.id"] = uid end

    -- ── ECS network ───────────────────────────────────────────────────────
    if query_name == "process_connections" then
        if cols["remote_address"] and cols["remote_address"] ~= "" then
            record["destination.ip"] = cols["remote_address"]
        end
        if cols["remote_port"] then
            record["destination.port"] = tonumber(cols["remote_port"])
        end
        if cols["local_address"] and cols["local_address"] ~= "" then
            record["source.ip"] = cols["local_address"]
        end
        if cols["local_port"] then
            record["source.port"] = tonumber(cols["local_port"])
        end
        local proto = cols["protocol"]
        if proto then
            record["network.transport"]   = PROTO[proto] or proto
            record["network.iana_number"] = proto
        end
    end

    if query_name == "listening_ports" then
        if cols["port"]    then record["destination.port"] = tonumber(cols["port"]) end
        if cols["address"] and cols["address"] ~= "" then
            record["destination.ip"] = cols["address"]
        end
        local proto = cols["protocol"]
        if proto then
            record["network.transport"]   = PROTO[proto] or proto
            record["network.iana_number"] = proto
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
