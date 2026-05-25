function normalize(tag, timestamp, record)

    local msg = record["message"]

    if msg == nil then
        return 1, timestamp, record
    end
    if string.find(msg, "BIND dn=") and string.find(msg, "err=0") then
        record["event.category"] = "authentication"
        record["event.action"] = "ldap_bind"
        record["event.outcome"] = "success"
    end
    if string.find(msg, "err=49") then
        record["event.category"] = "authentication"
        record["event.action"] = "ldap_bind"
        record["event.outcome"] = "failure"
    end
    if string.find(msg, "userPassword") then
        record["event.category"] = "iam"
        record["event.action"] = "password_change"
    end
    if string.find(msg, "ISSUE") then
        record["event.category"] = "authentication"
        record["event.action"] = "kerberos_ticket"
        record["event.outcome"] = "success"
    end
    if string.find(msg, "PREAUTH_FAILED") then
        record["event.category"] = "authentication"
        record["event.action"] = "kerberos_auth"
        record["event.outcome"] = "failure"
    end
    if record["url.path"] ~= nil then

        if string.find(record["url.path"], "/ipa/session") then
            record["event.category"] = "authentication"
            record["event.action"] = "web_login"
        end
    end
    if tag == "freeipa.dogtag" then

        if string.find(msg, "issued certificate") then
            record["event.category"] = "iam"
            record["event.action"] = "certificate_issued"
            record["event.outcome"] = "success"
        end

        if string.find(msg, "revoked certificate") then
            record["event.category"] = "iam"
            record["event.action"] = "certificate_revoked"
            record["event.outcome"] = "success"
        end

        if string.find(msg, "authentication failure") then
            record["event.action"] = "pki_auth"
            record["event.outcome"] = "failure"
        end
    end
    if tag == "freeipa.dns" then

        if string.find(msg, "query:") then
            record["event.category"] = "network"
            record["event.action"] = "dns_query"
        end

        if string.find(msg, "updating zone") then
            record["event.category"] = "configuration"
            record["event.action"] = "dns_update"
        end

        if string.find(msg, "transfer of") then
            record["event.category"] = "network"
            record["event.action"] = "zone_transfer"
        end

        if string.find(msg, "denied") then
            record["event.outcome"] = "failure"
        end
    end
    if tag == "freeipa.sssd" then

        if string.find(msg, "Authenticated") then
            record["event.category"] = "authentication"
            record["event.outcome"] = "success"
        end

        if string.find(msg, "authentication failed") then
            record["event.category"] = "authentication"
            record["event.outcome"] = "failure"
        end

        if string.find(msg, "Backend is offline") then
            record["event.category"] = "availability"
            record["event.action"] = "ldap_offline"
        end
    end
    return 1, timestamp, record
end
