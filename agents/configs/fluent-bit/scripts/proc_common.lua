-- proc_common.lua
-- Shared utilities for fluent-bit Lua enrich scripts (auditd_enrich, osquery_enrich).
-- Each [FILTER] lua block loads this in its own Lua state → caches are NOT shared.

local M = {}

-- ── FNV-1a 64-bit hash: two independent FNV-32 branches ─────────────────────
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

function M.short_id(s)
    local hi = fnv32(s, FNV32_OFFSET)
    local lo = fnv32(s, FNV32_OFFSET_ALT)
    -- bit.band() returns signed int32; format("%08x", negative) gives 16 chars
    -- in Lua 5.3+. Mod 2^32 forces unsigned [0, 2^32-1] → exactly 8 hex chars.
    return string.format("%08x%08x", hi % 0x100000000, lo % 0x100000000)
end

-- ── Per-instance state (each Lua VM gets its own copy) ──────────────────────
local _btime    = nil
local _clk_tck  = nil
local _hostname = nil

local PROC_CACHE_MAX   = 10000
local _proc_cache      = {}
local _proc_cache_size = 0
local _name_cache      = {}
local _name_cache_size = 0
local _cmdline_cache      = {}
local _cmdline_cache_size = 0

-- ── /proc helpers ────────────────────────────────────────────────────────────

function M.get_btime()
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

function M.get_clk_tck()
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

-- Reads starttime from /proc/<pid>/stat field 22, returns epoch seconds.
-- Parses from the last ') ' to handle comm fields with spaces/parens.
function M.read_proc_start(pid)
    local f = io.open("/proc/" .. tostring(pid) .. "/stat", "r")
    if not f then return nil end
    local line = f:read("*l")
    f:close()
    if not line then return nil end
    local tail_idx = line:find("%) ")
    if not tail_idx then return nil end
    local tail = line:sub(tail_idx + 2)
    local fields = {}
    for w in tail:gmatch("%S+") do fields[#fields+1] = w end
    local ticks = tonumber(fields[20])  -- field 22 in full stat = field 20 after ') '
    if not ticks then return nil end
    local btime = M.get_btime()
    if not btime then return nil end
    return btime + math.floor(ticks / M.get_clk_tck())
end

local function cache_evict_if_full()
    if _proc_cache_size > PROC_CACHE_MAX then
        _proc_cache      = {}
        _proc_cache_size = 0
    end
end

function M.cache_put(pid, start_ts, force)
    if force or not _proc_cache[pid] then
        if not _proc_cache[pid] then
            _proc_cache_size = _proc_cache_size + 1
        end
        _proc_cache[pid] = start_ts
        cache_evict_if_full()
    end
end

function M.resolve_start(pid)
    local s = _proc_cache[pid]
    if s then return s end
    s = M.read_proc_start(pid)
    if s then M.cache_put(pid, s, false) end
    return s
end

function M.cache_put_name(pid, name)
    if not _name_cache[pid] then
        _name_cache_size = _name_cache_size + 1
    end
    _name_cache[pid] = name
    if _name_cache_size > PROC_CACHE_MAX then
        _name_cache      = {}
        _name_cache_size = 0
    end
end

-- Returns process name for pid: from cache first, then /proc/<pid>/comm.
function M.resolve_name(pid)
    local n = _name_cache[pid]
    if n then return n end
    local f = io.open("/proc/" .. tostring(pid) .. "/comm", "r")
    if not f then return nil end
    n = f:read("*l")
    f:close()
    if n then M.cache_put_name(pid, n) end
    return n
end

-- Converts epoch-seconds integer to ISO 8601 date string for ECS date fields.
-- Passes through strings unchanged (e.g. @timestamp fallback already ISO).
function M.to_iso(ts)
    if type(ts) == "number" then
        return os.date("!%Y-%m-%dT%H:%M:%S.000Z", ts)
    end
    return ts
end

function M.cache_put_cmdline(pid, cmdline)
    if not _cmdline_cache[pid] then
        _cmdline_cache_size = _cmdline_cache_size + 1
    end
    _cmdline_cache[pid] = cmdline
    if _cmdline_cache_size > PROC_CACHE_MAX then
        _cmdline_cache      = {}
        _cmdline_cache_size = 0
    end
end

-- Returns command line for pid: from cache first, then /proc/<pid>/cmdline.
-- /proc/<pid>/cmdline args are null-separated; returned as space-joined string.
function M.resolve_cmdline(pid)
    local c = _cmdline_cache[pid]
    if c then return c end
    local f = io.open("/proc/" .. tostring(pid) .. "/cmdline", "r")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    if not data or #data == 0 then return nil end
    c = data:gsub("%z", " "):gsub("%s+$", "")
    if #c > 0 then M.cache_put_cmdline(pid, c) end
    return c
end

function M.get_hostname()
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

-- Returns audit session number from /proc/<pid>/sessionid, or nil if not applicable.
-- Filters out 0 (kernel) and 4294967295 (0xFFFFFFFF = unset / no session).
function M.get_sessionid(pid)
    if not pid or pid <= 0 then return nil end
    local f = io.open("/proc/" .. tostring(pid) .. "/sessionid", "r")
    if not f then return nil end
    local s = f:read("*n")
    f:close()
    if not s or s <= 0 or s == 4294967295 then return nil end
    return s
end

-- Computes user.session.id from a pre-validated ses integer (> 0, != 4294967295).
-- Returns nil if btime unavailable.
function M.make_session_id(hostname, ses)
    local btime = M.get_btime()
    if not btime then return nil end
    return M.short_id(hostname .. ":" .. tostring(btime) .. ":" .. tostring(ses))
end

return M
