-- $crypt HTTP/1.1 Dissector Plugin (Lua)
-- Parses basic HTTP request and response headers.

plugin = {
    name = "HTTP",
    version = "0.1.0",
    author = "$crypt Collective",
    description = "HTTP/1.1 request/response dissector",
}

-- Check if data looks like HTTP
function can_dissect(data_len, src_port, dst_port)
    -- HTTP typically runs on port 80, 8080, 8443
    if dst_port == 80 or src_port == 80 then
        return "high"
    end
    if dst_port == 8080 or src_port == 8080 then
        return "high"
    end
    return "none"
end

-- Dissect HTTP data
function dissect(data, src_port, dst_port)
    local text = tostring(data)
    local fields = {}
    local summary = ""
    local header_end = text:find("\r\n\r\n")
    local header_len = header_end and (header_end + 3) or #text

    -- Check if it's a request or response
    local method, uri, version = text:match("^(%u+)%s+(%S+)%s+(HTTP/%d%.%d)")
    if method then
        -- HTTP Request
        summary = method .. " " .. uri .. " " .. version
        table.insert(fields, {
            name = "Method",
            value = method,
            offset = 0,
            len = #method,
        })
        table.insert(fields, {
            name = "URI",
            value = uri,
            offset = #method + 1,
            len = #uri,
        })
        table.insert(fields, {
            name = "Version",
            value = version,
            offset = #method + 1 + #uri + 1,
            len = #version,
        })
    else
        local resp_version, status_code, reason = text:match("^(HTTP/%d%.%d)%s+(%d+)%s+(.-)%\r")
        if resp_version then
            -- HTTP Response
            summary = resp_version .. " " .. status_code .. " " .. reason
            table.insert(fields, {
                name = "Version",
                value = resp_version,
                offset = 0,
                len = #resp_version,
            })
            table.insert(fields, {
                name = "Status Code",
                value = status_code,
                offset = #resp_version + 1,
                len = #status_code,
            })
            table.insert(fields, {
                name = "Reason",
                value = reason,
                offset = #resp_version + 1 + #status_code + 1,
                len = #reason,
            })
        else
            summary = "HTTP data"
        end
    end

    -- Parse headers
    for name, value in text:gmatch("([%w%-]+):%s*(.-)\r\n") do
        table.insert(fields, {
            name = name,
            value = value,
            offset = 0,
            len = 0,
        })
    end

    return {
        protocol = "HTTP",
        summary = summary,
        header_len = header_len,
        fields = fields,
        next_protocol = nil,
    }
end
