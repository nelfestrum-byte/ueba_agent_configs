-- sshd_enrich.lua
-- Normalises /var/log/auth.log sshd lines to ECS 8.x (system.auth dataset).

local _dir = (debug.getinfo(1, "S").source or ""):match("^@(.+/)") or ""
package.path = _dir .. "?.lua;" .. package.path
local common = require("proc_common")

-- ── Pattern table ─────────────────────────────────────────────────────────────
-- Capture group indices reference the match result for that pattern.
local PATTERNS = {
    -- Failed password for invalid user <user> from <ip> port <port>
    {
        pat     = "^Failed password for invalid user (%S+) from (%S+) port (%d+)",
        action  = "ssh_login_failed",
        outcome = "failure",
        etype   = "start",
        user_g = 1, ip_g = 2, port_g = 3,
    },
    -- Failed password for <user> from <ip> port <port>
    {
        pat     = "^Failed password for (%S+) from (%S+) port (%d+)",
        action  = "ssh_login_failed",
        outcome = "failure",
        etype   = "start",
        user_g = 1, ip_g = 2, port_g = 3,
    },
    -- Accepted password for <user> from <ip> port <port>
    {
        pat     = "^Accepted password for (%S+) from (%S+) port (%d+)",
        action  = "ssh_login",
        outcome = "success",
        etype   = "start",
        user_g = 1, ip_g = 2, port_g = 3,
    },
    -- Accepted publickey for <user> from <ip> port <port>
    {
        pat     = "^Accepted publickey for (%S+) from (%S+) port (%d+)",
        action  = "ssh_login",
        outcome = "success",
        etype   = "start",
        user_g = 1, ip_g = 2, port_g = 3,
    },
    -- session opened for user <user>
    {
        pat     = "^session opened for user (%S+)",
        action  = "session_opened",
        outcome = "success",
        etype   = "start",
        user_g = 1,
    },
    -- session closed for user <user>
    {
        pat     = "^session closed for user (%S+)",
        action  = "session_closed",
        outcome = "success",
        etype   = "end",
        user_g = 1,
    },
    -- Invalid user <user> from <ip> port <port>
    {
        pat     = "^Invalid user (%S+) from (%S+) port (%d+)",
        action  = "invalid_user",
        outcome = "failure",
        etype   = "start",
        user_g = 1, ip_g = 2, port_g = 3,
    },
    -- Disconnected from authenticating user <user> <ip> port <port> [preauth]
    {
        pat     = "^Disconnected from authenticating user (%S+) (%S+) port (%d+)",
        action  = "ssh_disconnect_preauth",
        outcome = "failure",
        etype   = "end",
        user_g = 1, ip_g = 2, port_g = 3,
    },
    -- Connection closed by authenticating user <user> <ip> port <port>
    {
        pat     = "^Connection closed by authenticating user (%S+) (%S+) port (%d+)",
        action  = "ssh_connection_closed",
        etype   = "end",
        user_g = 1, ip_g = 2, port_g = 3,
    },
    -- Connection closed by <ip> port <port>
    {
        pat    = "^Connection closed by (%S+) port (%d+)",
        action = "ssh_connection_closed",
        etype  = "end",
        ip_g = 1, port_g = 2,
    },
    -- PAM N more authentication failure(s)
    {
        pat     = "^PAM %d+ more authentication failure",
        action  = "pam_auth_failure",
        outcome = "failure",
        etype   = "info",
    },
}

-- ── Main function ─────────────────────────────────────────────────────────────
function enrich_sshd(tag, timestamp, record)

    -- Accept both "sshd" (listener) and "sshd-session" (OpenSSH 9.x per-connection process)
    local prog = record["program"] or ""
    if prog ~= "sshd" and prog ~= "sshd-session" then
        return 0, timestamp, record
    end

    local msg = record["message"] or ""

    -- ── Static ECS fields ─────────────────────────────────────────────────
    record["ecs.version"]    = "8.11"
    record["event.dataset"]  = "system.auth"
    record["event.module"]   = "system"
    record["event.kind"]     = "event"
    record["event.category"] = "authentication"
    record["process.name"]   = "sshd"
    record["host.name"]      = common.get_hostname()
    record["host.os.type"]   = "linux"
    record["host.os.family"] = "linux"
    record["tags"]           = {"system-auth", "fluent-bit", "linux"}

    if record["pid"] then
        local pid = tonumber(record["pid"])
        if pid then record["process.pid"] = pid end
    end

    -- ── Pattern matching ─────────────────────────────────────────────────
    -- captures[1] ~= nil means the pattern matched (match() returns nil on failure)
    local matched = false
    for _, p in ipairs(PATTERNS) do
        local captures = { msg:match(p.pat) }
        if captures[1] ~= nil then
            matched = true
            record["event.action"] = p.action
            record["event.type"]   = p.etype
            if p.outcome then
                record["event.outcome"] = p.outcome
            end

            local user = p.user_g and captures[p.user_g]
            local ip   = p.ip_g   and captures[p.ip_g]
            local port = p.port_g and captures[p.port_g]

            if user and user ~= "" then
                record["user.name"]    = user
                record["related.user"] = {user}
            end
            if ip and ip ~= "" then
                record["source.ip"]   = ip
                record["related.ip"]  = {ip}
            end
            if port and port ~= "" then
                record["source.port"] = tonumber(port)
            end
            break
        end
    end

    -- Lines that matched no sshd pattern (su, CRON, sudo via PAM, etc.) —
    -- kept with event.action=other so downstream can filter/enrich them.
    if not matched then
        record["event.action"] = "other"
        record["event.type"]   = "info"
    end

    -- Remove parser artefacts not needed downstream
    record["program"]  = nil
    record["hostname"] = nil

    return 2, timestamp, record
end
