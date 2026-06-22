-- osquery_enrich.lua
-- Normalises osqueryd.results.log events to ECS 8.x + osquery.* namespace.

local _dir = (debug.getinfo(1, "S").source or ""):match("^@(.+/)") or ""
package.path = _dir .. "?.lua;" .. package.path
local common = require("proc_common")

-- in-memory кэш container_id[12] → {name, image} для резолвинга container.name
-- в bpf_process_events / bpf_socket_events.
-- Заполняется при обработке событий от таблицы docker_containers.
-- Кэш теряется при рестарте fluent-bit.
local container_cache = {}

-- Маппинг pid → container_id для процессов, чей cgroup уже был успешно прочитан.
-- Используется как fallback для дочерних процессов (parent chain).
local pid_cid_cache      = {}
local _pid_cid_size      = 0
local PID_CID_CACHE_MAX  = 5000

-- Маппинг osquery.cid (cgroup namespace inode, число) → container.id (12-hex).
-- Заполняется при обработке docker_containers diff: для каждого added контейнера
-- читаем /proc/<container.pid>/ns/cgroup → symlink "cgroup:[<inode>]" → <inode>.
-- BPF события с тем же cid резолвятся в container.id даже когда /proc/<pid>/cgroup
-- недоступен (короткоживущий subprocess).
local cgroup_ns_cache  = {}   -- { [cgroup_inode_str] = container_id_12hex }
local _cgns_size       = 0
local CGNS_CACHE_MAX   = 1000

-- Читает /proc/<pid>/cgroup и возвращает первые 12 символов Docker container ID.
-- cgroup v2: "0::/system.slice/docker-<hex>.scope"
-- cgroup v1: ".../docker/<hex>"
-- Возвращает nil если процесс не в Docker-контейнере или файл недоступен.
local function get_docker_cid(pid)
    if not pid or pid == "" then return nil end
    local f = io.open("/proc/" .. tostring(pid) .. "/cgroup", "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    local cid = content:match("docker%-(%x+)%.scope")
    if not cid then cid = content:match("/docker/(%x+)") end
    if cid and #cid >= 12 then return string.sub(cid, 1, 12) end
    return nil
end

-- Читает /proc/<pid>/ns/cgroup и возвращает inode как строку.
-- Формат symlink: "cgroup:[4026532177]" → "4026532177".
-- Используется при docker_containers/added для пополнения cgroup_ns_cache.
local function get_cgroup_ns(pid)
    if not pid or pid == "" then return nil end
    local p = io.popen("readlink /proc/" .. tostring(pid) .. "/ns/cgroup 2>/dev/null")
    if not p then return nil end
    local link = p:read("*l")
    p:close()
    if not link then return nil end
    return link:match("cgroup:%[(%d+)%]")
end

-- Пытается определить Docker container ID для процесса pid.
-- Порядок:
--   0. cgroup_ns_cache[osquery.cid] — самый дешёвый, работает для коротко-
--      живущих subprocess после первого docker_containers diff.
--   1. /proc/<pid>/cgroup           — авторитетно, пока процесс жив.
--   2. /proc/<ppid>/cgroup          — для exit-событий, если родитель жив.
--   3. pid_cid_cache[ppid]          — фолбэк parent chain.
local function resolve_container_id(pid, parent_pid, cid_inode)
    local function cache_put(p, cid)
        if not p or p == "" then return end
        if _pid_cid_size >= PID_CID_CACHE_MAX then
            pid_cid_cache = {}
            _pid_cid_size = 0
        end
        if not pid_cid_cache[p] then _pid_cid_size = _pid_cid_size + 1 end
        pid_cid_cache[p] = cid
    end

    -- 0. cgroup namespace inode из docker_containers
    if cid_inode and cid_inode ~= "" and cid_inode ~= "0" then
        local cid = cgroup_ns_cache[tostring(cid_inode)]
        if cid then
            if pid and pid ~= "" then cache_put(tostring(pid), cid) end
            return cid
        end
    end

    local cid = get_docker_cid(pid)
    if cid then
        cache_put(tostring(pid), cid)
        return cid
    end

    if parent_pid and parent_pid ~= "" and parent_pid ~= "0" then
        cid = get_docker_cid(parent_pid)
        if cid then
            cache_put(tostring(parent_pid), cid)
            return cid
        end
        cid = pid_cid_cache[tostring(parent_pid)]
        if cid then return cid end
    end

    return nil
end

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

    -- P2-02: new scheduled queries
    shell_history = {
        category     = "process",
        action_added   = "shell_command",
        action_removed = "shell_command",
        type_added     = "info",
        type_removed   = "info",
    },
    last_logins = {
        category     = "authentication",
        action_added   = "user_login",
        action_removed = "user_logout",
        type_added     = "start",
        type_removed   = "end",
    },
    preload_envs = {
        category     = "process",
        action_added   = "preload_env_set",
        action_removed = "preload_env_set",
        type_added     = "info",
        type_removed   = "info",
    },
    python_packages_diff = {
        category     = "package",
        action_added   = "package_installed",
        action_removed = "package_removed",
        type_added     = "installation",
        type_removed   = "deletion",
    },
    npm_packages_diff = {
        category     = "package",
        action_added   = "package_installed",
        action_removed = "package_removed",
        type_added     = "installation",
        type_removed   = "deletion",
    },
    pip_packages_diff = {
        category     = "package",
        action_added   = "package_installed",
        action_removed = "package_removed",
        type_added     = "installation",
        type_removed   = "deletion",
    },
    deb_packages_diff = {
        category     = "package",
        action_added   = "package_installed",
        action_removed = "package_removed",
        type_added     = "installation",
        type_removed   = "deletion",
    },
    kernel_keys_diff = {
        category     = "iam",
        action_added   = "kernel_key_added",
        action_removed = "kernel_key_removed",
        type_added     = "creation",
        type_removed   = "deletion",
    },
    sudoers_diff = {
        category     = "iam",
        action_added   = "sudoers_modified",
        action_removed = "sudoers_modified",
        type_added     = "change",
        type_removed   = "change",
    },
    acpi_tables_diff = {
        category     = "host",
        action_added   = "acpi_table_added",
        action_removed = "acpi_table_removed",
        type_added     = "change",
        type_removed   = "change",
    },
    suspicious_mmap = {
        category     = "process",
        action_added   = "non_standard_mmap",
        action_removed = "non_standard_mmap",
        type_added     = "info",
        type_removed   = "info",
    },
    chrome_extensions_diff = {
        category     = "configuration",
        action_added   = "extension_installed",
        action_removed = "extension_removed",
        type_added     = "installation",
        type_removed   = "deletion",
    },
    firefox_addons_diff = {
        category     = "configuration",
        action_added   = "addon_installed",
        action_removed = "addon_removed",
        type_added     = "installation",
        type_removed   = "deletion",
    },

    -- BPF event-driven tables (P2-01, docker-хосты, ядро ≥5.10)
    bpf_processes = {
        category = "process",
        action_added   = "process_started",
        action_removed = "process_stopped",
        type_added     = "start",
        type_removed   = "end",
    },
    bpf_sockets = {
        category = "network",
        action_added   = "socket_event",
        action_removed = "socket_event",
        type_added     = "start",
        type_removed   = "end",
    },
    docker_containers = {
        -- osquery diff не отражает реальный lifecycle (start/stop) —
        -- only появление/исчезновение строки в snapshot-таблице. Поэтому
        -- observed_*, не started/stopped. Реальный lifecycle — Docker Events API
        -- (см. HARDENING/CONTAINER_BEHAVIOR_PLAN.md, P4).
        category = "host",
        action_added   = "container_observed_added",
        action_removed = "container_observed_removed",
        type_added     = "info",
        type_removed   = "info",
    },
}

-- ── Протокол: номер IANA → имя ────────────────────────────────────────────
local PROTO = { ["6"] = "tcp", ["17"] = "udp", ["1"] = "icmp",
                ["58"] = "ipv6-icmp", ["132"] = "sctp" }

-- BPF taps log syscall return codes as uint64; negative errno (e.g. -115
-- EINPROGRESS) приходит как 2^64 - 115 = 18446744073709551501.
-- Декодируем обратно в signed int64.
local INT64_MAX = 9223372036854775807
local UINT64_MOD = 18446744073709551616
local function normalize_int64(v)
    if v == nil or v == "" then return v end
    local n = tonumber(v)
    if not n then return v end
    if n > INT64_MAX then n = n - UINT64_MOD end
    return n
end

-- ── Главная функция ───────────────────────────────────────────────────────
function enrich_osquery(tag, timestamp, record)

    local query_name = record["name"]
    local action     = record["action"] or "added"
    local cols       = record["columns"]
    local deco       = record["decorations"]

    if type(cols) ~= "table" then
        return -1, timestamp, record
    end

    if query_name == "process_connections"
       and (cols["process_path"] == "/opt/fluent-bit/bin/fluent-bit"
            or cols["process_name"] == "fluent-bit") then
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
    -- exit_code: BPF возвращает signed int64 как uint64 — декодируем, иначе
    -- значения вида 18446744073709551501 (=-115 EINPROGRESS) ломают range queries
    -- и mapping (uint64 не помещается в long).
    for k, v in pairs(cols) do
        if v ~= nil and v ~= "" then
            if k == "exit_code" then
                record["osquery." .. k] = normalize_int64(v)
            else
                record["osquery." .. k] = v
            end
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
                    common.cache_put(pid, start_ts, action == "added")
                end
            else
                start_ts = common.resolve_start(pid)
            end

            if start_ts then
                local seed = (record["host.name"] or "")
                          .. ":" .. tostring(pid)
                          .. ":" .. tostring(start_ts)
                record["process.entity_id"] = common.short_id(seed)
                record["process.start"]     = common.to_iso(start_ts)
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
                local pseed = (record["host.name"] or "")
                           .. ":" .. tostring(ppid)
                           .. ":" .. tostring(parent_start)
                record["process.parent.entity_id"] = common.short_id(pseed)
                record["process.parent.start"]     = common.to_iso(parent_start)
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
        if cols["remote_address"] and cols["remote_address"] ~= "" and cols["remote_address"] ~= "0" then
            record["destination.ip"] = cols["remote_address"]
        end
        if cols["remote_port"] then
            record["destination.port"] = tonumber(cols["remote_port"])
        end
        if cols["local_address"] and cols["local_address"] ~= "" and cols["local_address"] ~= "0" then
            record["source.ip"] = cols["local_address"]
        end
        if cols["local_port"] then
            record["source.port"] = tonumber(cols["local_port"])
        end
        local proto = cols["protocol"]
        if proto and proto ~= "0" then
            local proto_name = PROTO[proto]
            if proto_name then record["network.transport"] = proto_name end
            record["network.iana_number"] = proto
        end
    end

    if query_name == "listening_ports" then
        if cols["port"]    then record["destination.port"] = tonumber(cols["port"]) end
        if cols["address"] and cols["address"] ~= "" and cols["address"] ~= "0" then
            record["destination.ip"] = cols["address"]
        end
        local proto = cols["protocol"]
        if proto and proto ~= "0" then
            local proto_name = PROTO[proto]
            if proto_name then record["network.transport"] = proto_name end
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

    -- ── BPF process events (P2-01, docker-хосты) ─────────────────────────
    if query_name == "bpf_processes" then
        record["event.dataset"] = "osquery.bpf_process_events"
        if cols["pid"]       then record["process.pid"]          = tonumber(cols["pid"]) end
        if cols["parent"]    then record["process.parent.pid"]   = tonumber(cols["parent"]) end
        if cols["path"]      and cols["path"] ~= "" then
            record["process.executable"] = cols["path"]
        end

        -- process.command_line из osquery BPF tap.
        -- osquery BPF probe (sched_process_exec) подвержен race condition
        -- (github.com/osquery/osquery/issues/7497): при коротких процессах
        -- argv копируется только частично, остаётся argv[0].
        -- Детектируем truncation и помечаем флагом для downstream UEBA:
        -- если cmdline без пробелов И равен basename(path) — это с большой
        -- вероятностью обрезанный argv (UEBA-коррелятор должен учитывать
        -- этот флаг как сигнал НЕОПРЕДЕЛЁННОСТИ, а не повышать score за
        -- "cat" без аргументов).
        if cols["cmdline"]   and cols["cmdline"] ~= "" then
            record["process.command_line"] = cols["cmdline"]

            local exe = cols["path"] or ""
            local base = exe:match("([^/]+)$") or exe
            if base ~= "" and cols["cmdline"] == base
               and not cols["cmdline"]:find(" ", 1, true) then
                record["labels.cmdline_truncated"] = "argv0_only"
            end
        end

        -- Источник cmdline для downstream корреляции с auditd execve.
        record["labels.cmdline_source"] = "osquery_bpf"

        if cols["uid"]       and cols["uid"] ~= "" then record["user.id"]        = cols["uid"] end
        if cols["gid"]       and cols["gid"] ~= "" then record["user.group.id"]  = cols["gid"] end
        if cols["exit_code"] and cols["exit_code"] ~= "" then
            record["process.exit_code"] = normalize_int64(cols["exit_code"])
        end

        -- process.entity_id — выровнено с auditd_enrich, osquery/processes и
        -- bpf_socket_events: seed = host:pid:epoch_start_time через
        -- /proc/<pid>/stat. Кросс-индекс JOIN audit↔bpf_process_events по
        -- host.name + process.entity_id корректен для живых процессов.
        -- Для короткоживущих процессов /proc/<pid>/stat уже недоступен —
        -- entity_id НЕ ставим (лучше пусто, чем mismatch). Маркируем
        -- labels.entity_id_source="bpf_proc_short_lived" чтобы UEBA-коррелятор
        -- знал использовать host.name+pid+@timestamp±2s как fallback.
        -- osquery.ntime остаётся в индексе как сырое поле для отладки.
        local bpf_pid = tonumber(cols["pid"])
        if bpf_pid and bpf_pid > 0 then
            local start_ts = common.resolve_start(bpf_pid)
            if start_ts then
                local seed = (record["host.name"] or "")
                          .. ":" .. tostring(bpf_pid)
                          .. ":" .. tostring(start_ts)
                record["process.entity_id"] = common.short_id(seed)
            else
                record["labels.entity_id_source"] = "bpf_proc_short_lived"
            end
        end

        -- container resolution:
        -- cgroup_ns_cache[osquery.cid] → /proc/<pid>/cgroup → /proc/<ppid>/cgroup → pid_cid_cache
        local cid = resolve_container_id(cols["pid"], cols["parent"], cols["cid"])
        if cid then
            record["container.id"] = cid
            -- кэшируем pid для последующих bpf_socket_events того же процесса
            if cols["pid"] and cols["pid"] ~= "" then
                pid_cid_cache[tostring(cols["pid"])] = cid
            end
            local meta = container_cache[cid]
            if meta then
                record["container.name"]       = meta.name
                record["container.image.name"] = meta.image
                record["container.entity_id"]  = (record["host.name"] or "") .. ":" .. meta.name
            end
        end

    -- ── BPF socket events (P2-01, docker-хосты) ──────────────────────────
    elseif query_name == "bpf_sockets" then
        record["event.dataset"] = "osquery.bpf_socket_events"

        local fam   = cols["family"]
        local is_ip = (fam == "2" or fam == "10")

        if cols["pid"]    then record["process.pid"]        = tonumber(cols["pid"]) end
        if cols["parent"] then record["process.parent.pid"] = tonumber(cols["parent"]) end
        if cols["path"]   and cols["path"] ~= "" then
            record["process.executable"] = cols["path"]
        end

        -- process.entity_id: epoch-based start_time через /proc/<pid>/stat,
        -- та же формула что в auditd_enrich и osquery/processes →
        -- cross-index join по entity_id корректен для живых процессов.
        -- Отличается от bpf_processes (ntime). Для короткоживущих процессов
        -- /proc/<pid>/stat может быть уже недоступен — entity_id не ставим.
        local bpf_sock_pid = tonumber(cols["pid"])
        if bpf_sock_pid and bpf_sock_pid > 0 then
            local start_ts = common.resolve_start(bpf_sock_pid)
            if start_ts then
                local seed = (record["host.name"] or "")
                          .. ":" .. tostring(bpf_sock_pid)
                          .. ":" .. tostring(start_ts)
                record["process.entity_id"] = common.short_id(seed)
            end
        end

        local syscall = cols["syscall"] or cols["action"]

        if is_ip then
            -- syscall (bind/connect/accept) переопределяет QUERY_META default
            if syscall and syscall ~= "" then
                record["event.action"] = "socket_" .. syscall
            end

            -- family → network.type (AF_INET=2 / AF_INET6=10)
            if fam == "2"  then record["network.type"] = "ipv4"
            elseif fam == "10" then record["network.type"] = "ipv6"
            end

            -- protocol: IANA number → имя; сырое число в network.transport не пишем.
            local proto = cols["protocol"]
            if proto and proto ~= "0" then
                local proto_name = PROTO[proto]
                if proto_name then record["network.transport"] = proto_name end
                record["network.iana_number"] = proto
            else
                -- protocol=0: приложение использовало SOCK_STREAM/SOCK_DGRAM
                -- с protocol=0 (ядро выбирает автоматически). Best-effort:
                -- AF_INET/AF_INET6 + remote_port>0 → предполагаем TCP (connect/accept).
                -- Не применяем к bind (socket_bind может быть UDP).
                local rport = tonumber(cols["remote_port"])
                if rport and rport > 0 then
                    record["network.transport"] = "tcp"
                    record["labels.transport_inferred"] = "true"
                end
            end

            -- "0" из BPF — unbound/any адрес, не валидный IP для OpenSearch.
            if cols["local_address"]  and cols["local_address"] ~= "" and cols["local_address"] ~= "0" then
                record["source.ip"]   = cols["local_address"]
            end
            if cols["local_port"]     and cols["local_port"] ~= "" then
                record["source.port"] = tonumber(cols["local_port"])
            end
            if cols["remote_address"] and cols["remote_address"] ~= "" and cols["remote_address"] ~= "0" then
                record["destination.ip"]   = cols["remote_address"]
            end
            if cols["remote_port"]    and cols["remote_port"] ~= "" then
                record["destination.port"] = tonumber(cols["remote_port"])
            end
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

        -- container resolution (общий для is_ip и non-IP):
        -- cgroup_ns_cache[osquery.cid] → /proc/<pid>/cgroup → /proc/<ppid>/cgroup → pid_cid_cache
        local cid = resolve_container_id(cols["pid"], cols["parent"], cols["cid"])
        if cid then
            record["container.id"] = cid
            local meta = container_cache[cid]
            if meta then
                record["container.name"]       = meta.name
                record["container.image.name"] = meta.image
                record["container.entity_id"]  = (record["host.name"] or "") .. ":" .. meta.name
            end
        end

    -- ── Docker container inventory (P2-01) ────────────────────────────────
    elseif query_name == "docker_containers" then
        record["event.dataset"]    = "osquery.docker_containers"
        record["container.runtime"] = "docker"

        if cols["id"] and cols["name"] then
            local cid  = string.sub(cols["id"], 1, 12)
            local name = cols["name"]
            local img  = cols["image"] or ""

            -- обновляем container_cache: bpf_* события резолвят name/image отсюда
            if action == "added" then
                container_cache[cid] = { name = name, image = img }
            else
                container_cache[cid] = nil
                -- НЕ удаляем запись из cgroup_ns_cache при removed: osquery diff
                -- может «мигнуть» (контейнер бежит, но строка пропала на 1 интервал).
                -- Кэш чистится только bulk-evict при переполнении.
            end

            record["container.id"]         = cid
            record["container.name"]       = name
            record["container.image.name"] = img   -- ECS 8.x: container.image.name
            record["container.entity_id"]  = (record["host.name"] or "") .. ":" .. name

            -- Заполняем cgroup_ns_cache для последующего резолвинга BPF-событий
            -- по osquery.cid (cgroup namespace inode), включая короткоживущие
            -- subprocess где /proc/<pid>/cgroup уже недоступен.
            if action == "added" and cols["pid"] and cols["pid"] ~= "" and cols["pid"] ~= "0" then
                local cgns = get_cgroup_ns(cols["pid"])
                if cgns then
                    if _cgns_size >= CGNS_CACHE_MAX then
                        cgroup_ns_cache = {}
                        _cgns_size = 0
                    end
                    if not cgroup_ns_cache[cgns] then _cgns_size = _cgns_size + 1 end
                    cgroup_ns_cache[cgns] = cid
                end
            end

            -- Fallback по osquery.state: если контейнер exited/dead — это
            -- event.action=container_exited, не observed_removed.
            -- state="running"/"created"/"exited"/"paused"/"dead".
            local state = cols["state"]
            if state == "exited" or state == "dead" then
                record["event.action"] = "container_exited"
                record["event.type"]   = "end"
            end
        end
    end

    -- ── P2-02: field extraction for new scheduled queries ────────────────
    if query_name == "shell_history" then
        record["event.dataset"] = "osquery.shell_history"
        if cols["command"]      and cols["command"] ~= ""      then
            record["process.command_line"] = cols["command"]
        end
        if cols["history_file"] and cols["history_file"] ~= "" then
            record["file.path"] = cols["history_file"]
        end

    elseif query_name == "last_logins" then
        record["event.dataset"] = "osquery.last"
        -- type=8 (DEAD_PROCESS) → logout; type=7 (USER_PROCESS) → login (QUERY_META default)
        if cols["type"] == "8" then
            record["event.action"] = "user_logout"
            record["event.type"]   = "end"
        end
        if cols["source_host"] and cols["source_host"] ~= "" then
            record["source.ip"] = cols["source_host"]
        end
        if cols["tty"] and cols["tty"] ~= "" then
            record["user.terminal"] = cols["tty"]
        end

    elseif query_name == "preload_envs" then
        record["event.dataset"] = "osquery.process_envs"
        if cols["pid"]          then record["process.pid"]          = tonumber(cols["pid"]) end
        if cols["process_name"] then record["process.name"]         = cols["process_name"] end
        if cols["process_path"] then record["process.executable"]   = cols["process_path"] end
        if cols["cmdline"]      then record["process.command_line"] = cols["cmdline"] end
        if cols["key"]          then record["process.env.key"]      = cols["key"] end
        if cols["value"]        then record["process.env.value"]    = cols["value"] end

    elseif query_name == "python_packages_diff" then
        record["event.dataset"] = "osquery.python_packages"
        if cols["name"]    then record["package.name"]    = cols["name"] end
        if cols["version"] then record["package.version"] = cols["version"] end
        if cols["path"]    then record["package.path"]    = cols["path"] end

    elseif query_name == "npm_packages_diff" then
        record["event.dataset"] = "osquery.npm_packages"
        if cols["name"]    then record["package.name"]    = cols["name"] end
        if cols["version"] then record["package.version"] = cols["version"] end
        if cols["path"]    then record["package.path"]    = cols["path"] end

    elseif query_name == "pip_packages_diff" then
        record["event.dataset"] = "osquery.pip_packages"
        if cols["name"]    then record["package.name"]    = cols["name"] end
        if cols["version"] then record["package.version"] = cols["version"] end
        if cols["path"]    then record["package.path"]    = cols["path"] end

    elseif query_name == "deb_packages_diff" then
        record["event.dataset"] = "osquery.deb_packages"
        if cols["name"]    then record["package.name"]         = cols["name"] end
        if cols["version"] then record["package.version"]      = cols["version"] end
        if cols["arch"]    then record["package.architecture"] = cols["arch"] end

    elseif query_name == "kernel_keys_diff" then
        record["event.dataset"] = "osquery.kernel_keys"
        -- user.id выставлен общим блоком user (cols.uid); user.name отсутствует
        -- в kernel_keys-таблице osquery → резолвим через /etc/passwd cache.
        if record["user.id"] and not record["user.name"] then
            local uname = common.uid_to_name(record["user.id"])
            if uname then record["user.name"] = uname end
        end

    elseif query_name == "sudoers_diff" then
        record["event.dataset"] = "osquery.sudoers"

    elseif query_name == "acpi_tables_diff" then
        record["event.dataset"] = "osquery.acpi_tables"

    elseif query_name == "suspicious_mmap" then
        record["event.dataset"] = "osquery.process_memory_map"
        if cols["pid"]          then record["process.pid"]  = tonumber(cols["pid"]) end
        if cols["process_name"] then record["process.name"] = cols["process_name"] end
        if cols["process_path"] and cols["process_path"] ~= "" then
            record["process.executable"] = cols["process_path"]
        end
        -- pmm.path в этой таблице — путь mmap-региона (mapped file), не процесса.
        if cols["path"]         then record["file.path"]    = cols["path"] end

    elseif query_name == "chrome_extensions_diff" then
        record["event.dataset"] = "osquery.chrome_extensions"
        if cols["name"]       then record["package.name"]       = cols["name"] end
        if cols["version"]    then record["package.version"]    = cols["version"] end
        if cols["identifier"] then record["package.identifier"] = cols["identifier"] end
        if cols["uid"]        then record["user.id"]            = cols["uid"] end

    elseif query_name == "firefox_addons_diff" then
        record["event.dataset"] = "osquery.firefox_addons"
        if cols["name"]       then record["package.name"]       = cols["name"] end
        if cols["version"]    then record["package.version"]    = cols["version"] end
        if cols["identifier"] then record["package.identifier"] = cols["identifier"] end
        if cols["uid"]        then record["user.id"]            = cols["uid"] end
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
