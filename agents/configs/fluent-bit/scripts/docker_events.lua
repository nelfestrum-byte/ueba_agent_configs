function sanitize_attributes(tag, timestamp, record)
    local function sanitize_keys(hash)
        local new_hash = {}
        for key, value in pairs(hash) do
            local safe_key = string.gsub(tostring(key), "%.", "_")
            if type(value) == "table" then
                new_hash[safe_key] = sanitize_keys(value)
            else
                new_hash[safe_key] = value
            end
        end
        return new_hash
    end
    local actor = record["Actor"]
    if actor ~= nil and type(actor) == "table" and actor["Attributes"] ~= nil then
        record["Actor"]["Attributes"] = sanitize_keys(actor["Attributes"])
    end
    return 2, timestamp, record
end
