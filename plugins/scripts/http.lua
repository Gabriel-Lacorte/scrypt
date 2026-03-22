-- $crypt HTTP/1.x Dissector Plugin (Lua)
-- Parses HTTP request and response headers with content analysis.

plugin = {
    name = "HTTP",
    version = "0.2.0",
    author = "$crypt Collective",
    description = "HTTP/1.x request/response dissector with header analysis",
}

-- Common HTTP ports
local http_ports = {
    [80] = true, [8080] = true, [8443] = true,
    [8000] = true, [8888] = true, [3000] = true,
}

-- Check if data looks like HTTP
function can_dissect(data_len, src_port, dst_port)
    if http_ports[dst_port] or http_ports[src_port] then
        return "high"
    end
    return "none"
end

-- Well-known HTTP methods
local http_methods = {
    GET = true, POST = true, PUT = true, DELETE = true, PATCH = true,
    HEAD = true, OPTIONS = true, TRACE = true, CONNECT = true,
}

-- Categorize status code
local function status_category(code)
    local n = tonumber(code) or 0
    if n >= 100 and n < 200 then return "Informational"
    elseif n >= 200 and n < 300 then return "Success"
    elseif n >= 300 and n < 400 then return "Redirection"
    elseif n >= 400 and n < 500 then return "Client Error"
    elseif n >= 500 and n < 600 then return "Server Error"
    else return "Unknown" end
end

-- Detect content type category for summary
local function content_category(ct)
    if not ct then return nil end
    ct = ct:lower()
    if ct:find("text/html") then return "HTML"
    elseif ct:find("application/json") then return "JSON"
    elseif ct:find("application/xml") or ct:find("text/xml") then return "XML"
    elseif ct:find("text/plain") then return "Text"
    elseif ct:find("text/css") then return "CSS"
    elseif ct:find("javascript") then return "JavaScript"
    elseif ct:find("image/") then return "Image"
    elseif ct:find("application/octet") then return "Binary"
    elseif ct:find("multipart/form") then return "Form Data"
    else return nil end
end

-- Dissect HTTP data
function dissect(data, src_port, dst_port)
    local text = tostring(data)
    local fields = {}
    local summary = ""
    local header_end = text:find("\r\n\r\n")
    local header_len = header_end and (header_end + 3) or #text

    -- Headers lookup (lowercase keys for easy access)
    local headers = {}
    local header_count = 0

    -- Check if it's a request or response
    local method, uri, version = text:match("^(%u+)%s+(%S+)%s+(HTTP/%d%.%d)")
    if method and http_methods[method] then
        -- HTTP Request
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

        -- Parse headers
        for name, value in text:gmatch("([%w%-]+):%s*(.-)\r\n") do
            headers[name:lower()] = value
            header_count = header_count + 1
            table.insert(fields, { name = name, value = value, offset = 0, len = 0 })
        end

        -- Add host to summary if present
        local host = headers["host"] or ""
        summary = string.format("%s %s %s", method, uri, version)
        if host ~= "" then
            summary = string.format("%s %s%s %s", method, host, uri, version)
        end
    else
        local resp_version, status_code, reason = text:match("^(HTTP/%d%.%d)%s+(%d+)%s+(.-)%\r")
        if resp_version then
            -- HTTP Response
            local cat = status_category(status_code)
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
            table.insert(fields, {
                name = "Category",
                value = cat,
                offset = 0,
                len = 0,
            })

            -- Parse headers
            for name, value in text:gmatch("([%w%-]+):%s*(.-)\r\n") do
                headers[name:lower()] = value
                header_count = header_count + 1
                table.insert(fields, { name = name, value = value, offset = 0, len = 0 })
            end

            summary = string.format("%s %s %s", resp_version, status_code, reason)

            -- Annotate content type
            local ct = headers["content-type"]
            local ct_cat = content_category(ct)
            if ct_cat then
                summary = summary .. " [" .. ct_cat .. "]"
            end

            -- Content-Length
            local cl = headers["content-length"]
            if cl then
                table.insert(fields, { name = "Body Length", value = cl .. " bytes", offset = 0, len = 0 })
            end
        else
            -- Could be continuation data or partial
            summary = "HTTP data (continuation)"
            -- Still try to parse as headers
            for name, value in text:gmatch("([%w%-]+):%s*(.-)\r\n") do
                header_count = header_count + 1
                table.insert(fields, { name = name, value = value, offset = 0, len = 0 })
            end
        end
    end

    table.insert(fields, 1, {
        name = "Header Count",
        value = tostring(header_count),
        offset = 0,
        len = 0,
    })

    return {
        protocol = "HTTP",
        summary = summary,
        header_len = header_len,
        fields = fields,
        next_protocol = nil,
    }
end
