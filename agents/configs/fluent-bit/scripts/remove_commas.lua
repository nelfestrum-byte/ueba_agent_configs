function remove_commas(tag, timestamp, record)
    if record["message"] ~= nil then
        record["message"] = string.gsub(record["message"], ", ", " ")
    end
    return 2, timestamp, record
end
