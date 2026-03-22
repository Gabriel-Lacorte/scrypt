-- $crypt DNS Dissector Plugin (Lua)
-- Parses basic DNS query and response messages.

plugin = {
    name = "DNS",
    version = "0.1.0",
    author = "$crypt Collective",
    description = "DNS query/response dissector",
}

-- Check if data could be DNS
function can_dissect(data_len, src_port, dst_port)
    if dst_port == 53 or src_port == 53 then
        return "high"
    end
    return "none"
end

-- Helper: read 16-bit big-endian from string
local function read_u16(data, offset)
    local b1 = data:byte(offset)
    local b2 = data:byte(offset + 1)
    if b1 and b2 then
        return b1 * 256 + b2
    end
    return 0
end

-- Helper: read DNS name from wire format
local function read_dns_name(data, offset)
    local parts = {}
    local pos = offset
    local jumps = 0
    while pos <= #data and jumps < 10 do
        local len = data:byte(pos)
        if not len or len == 0 then
            pos = pos + 1
            break
        end
        -- Compression pointer
        if len >= 192 then
            local ptr_byte = data:byte(pos + 1)
            if ptr_byte then
                local ptr = (len - 192) * 256 + ptr_byte
                pos = ptr + 1
                jumps = jumps + 1
            else
                break
            end
        else
            local label = data:sub(pos + 1, pos + len)
            table.insert(parts, label)
            pos = pos + len + 1
        end
    end
    return table.concat(parts, "."), pos
end

-- Dissect DNS data
function dissect(data, src_port, dst_port)
    local text = tostring(data)
    local fields = {}

    if #text < 12 then
        return {
            protocol = "DNS",
            summary = "DNS (truncated)",
            header_len = #text,
            fields = {},
        }
    end

    local tx_id = read_u16(text, 1)
    local flags = read_u16(text, 3)
    local qr = (flags >= 32768) and 1 or 0
    local qdcount = read_u16(text, 5)
    local ancount = read_u16(text, 7)

    table.insert(fields, { name = "Transaction ID", value = string.format("0x%04x", tx_id), offset = 0, len = 2 })
    table.insert(fields, { name = "QR", value = qr == 1 and "Response" or "Query", offset = 2, len = 2 })
    table.insert(fields, { name = "Questions", value = tostring(qdcount), offset = 4, len = 2 })
    table.insert(fields, { name = "Answers", value = tostring(ancount), offset = 6, len = 2 })

    -- Try to read first query name
    local qname = ""
    if qdcount > 0 and #text > 12 then
        qname = read_dns_name(text, 13)
        table.insert(fields, { name = "Query Name", value = qname, offset = 12, len = 0 })
    end

    local msg_type = qr == 1 and "Response" or "Query"
    local summary = string.format("DNS %s: %s (QD=%d, AN=%d)", msg_type, qname, qdcount, ancount)

    return {
        protocol = "DNS",
        summary = summary,
        header_len = #text,
        fields = fields,
    }
end
