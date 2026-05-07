-- flatten.lua — нормализация osquery результатов для fluent-bit

function flatten_snapshot(tag, timestamp, record)
    if record["action"] ~= "snapshot" then
        return -1, timestamp, record
    end
    local snap = record["snapshot"]
    if type(snap) ~= "table" or snap[1] == nil then
        return -1, timestamp, record
    end
    local row = snap[1]
    local out = {}
    out["metric_name"]  = row["metric_name"]  or "unknown"
    out["value"]        = tonumber(row["value"]) or 0
    out["entity_id"]    = row["entity_id"]    or os.getenv("HOSTNAME") or "unknown"
    out["entity_type"]  = row["entity_type"]  or "host"
    out["query_name"]   = record["name"]      or "unknown"
    out["action"]       = "snapshot"
    out["source"]       = "osquery"
    out["hostname"]     = record["hostname"]  or os.getenv("HOSTNAME") or "unknown"
    return 1, timestamp, out
end

function flatten_diff(tag, timestamp, record)
    if record["action"] == "snapshot" then
        return -1, timestamp, record
    end
    local action  = record["action"]
    if action ~= "added" and action ~= "removed" then
        return -1, timestamp, record
    end
    local cols = record["columns"]
    if type(cols) ~= "table" then
        return -1, timestamp, record
    end
    local out = {}
    for k, v in pairs(cols) do
        out[k] = v
    end
    out["action"]      = action
    out["query_name"]  = record["name"]     or "unknown"
    out["entity_id"]   = record["hostname"] or os.getenv("HOSTNAME") or "unknown"
    out["entity_type"] = "host"
    out["source"]      = "osquery"
    out["hostname"]    = record["hostname"] or os.getenv("HOSTNAME") or "unknown"
    return 1, timestamp, out
end
