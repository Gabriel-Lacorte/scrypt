-- $crypt DNS Dissector Plugin (Lua)
-- Parses DNS query and response messages with full record decoding.

plugin = {
    name = "DNS",
    version = "0.2.0",
    author = "$crypt Collective",
    description = "DNS query/response dissector with record parsing",
}

-- Check if data could be DNS
function can_dissect(data_len, src_port, dst_port)
    if dst_port == 53 or src_port == 53 then
        return "high"
    end
    if dst_port == 5353 or src_port == 5353 then
        return "medium" -- mDNS
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

-- Helper: read 32-bit big-endian from string
local function read_u32(data, offset)
    local b1 = data:byte(offset) or 0
    local b2 = data:byte(offset + 1) or 0
    local b3 = data:byte(offset + 2) or 0
    local b4 = data:byte(offset + 3) or 0
    return b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
end

-- Helper: read DNS name from wire format (handles compression pointers)
local function read_dns_name(data, offset)
    local parts = {}
    local pos = offset
    local jumps = 0
    local end_pos = nil
    while pos <= #data and jumps < 10 do
        local len = data:byte(pos)
        if not len or len == 0 then
            if not end_pos then end_pos = pos + 1 end
            break
        end
        -- Compression pointer
        if len >= 192 then
            local ptr_byte = data:byte(pos + 1)
            if ptr_byte then
                if not end_pos then end_pos = pos + 2 end
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
    return table.concat(parts, "."), end_pos or pos
end

-- DNS type name lookup
local function dns_type_name(qtype)
    local types = {
        [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA",
        [12] = "PTR", [15] = "MX", [16] = "TXT", [28] = "AAAA",
        [33] = "SRV", [43] = "DS", [46] = "RRSIG", [47] = "NSEC",
        [48] = "DNSKEY", [65] = "HTTPS", [257] = "CAA",
    }
    return types[qtype] or string.format("TYPE%d", qtype)
end

-- DNS class name lookup
local function dns_class_name(qclass)
    if qclass == 1 then return "IN"
    elseif qclass == 3 then return "CH"
    elseif qclass == 255 then return "ANY"
    else return string.format("CLASS%d", qclass) end
end

-- DNS opcode name
local function dns_opcode_name(opcode)
    local names = { [0] = "Query", [1] = "IQuery", [2] = "Status", [4] = "Notify", [5] = "Update" }
    return names[opcode] or string.format("Opcode%d", opcode)
end

-- DNS rcode (response code) name
local function dns_rcode_name(rcode)
    local names = {
        [0] = "NOERROR", [1] = "FORMERR", [2] = "SERVFAIL", [3] = "NXDOMAIN",
        [4] = "NOTIMP", [5] = "REFUSED", [6] = "YXDOMAIN", [7] = "YXRRSET",
    }
    return names[rcode] or string.format("RCODE%d", rcode)
end

-- Format IPv4 address from 4 bytes
local function format_ipv4(data, offset)
    local a = data:byte(offset) or 0
    local b = data:byte(offset + 1) or 0
    local c = data:byte(offset + 2) or 0
    local d = data:byte(offset + 3) or 0
    return string.format("%d.%d.%d.%d", a, b, c, d)
end

-- Format IPv6 address from 16 bytes
local function format_ipv6(data, offset)
    local parts = {}
    for i = 0, 7 do
        local val = read_u16(data, offset + i * 2)
        table.insert(parts, string.format("%x", val))
    end
    return table.concat(parts, ":")
end

-- Parse resource record data into human-readable string
local function parse_rdata(data, rr_offset, rdlength, rtype)
    if rtype == 1 and rdlength == 4 then -- A
        return format_ipv4(data, rr_offset)
    elseif rtype == 28 and rdlength == 16 then -- AAAA
        return format_ipv6(data, rr_offset)
    elseif rtype == 5 or rtype == 2 or rtype == 12 then -- CNAME, NS, PTR
        local name = read_dns_name(data, rr_offset)
        return name
    elseif rtype == 15 then -- MX
        local pref = read_u16(data, rr_offset)
        local name = read_dns_name(data, rr_offset + 2)
        return string.format("%d %s", pref, name)
    elseif rtype == 16 then -- TXT
        local txt_len = data:byte(rr_offset) or 0
        return data:sub(rr_offset + 1, rr_offset + txt_len)
    else
        return string.format("(%d bytes)", rdlength)
    end
end

-- Parse a sequence of resource records
local function parse_records(data, pos, count, section_name, fields)
    for i = 1, count do
        if pos > #data then break end
        local name, next_pos = read_dns_name(data, pos)
        pos = next_pos
        if pos + 10 > #data + 1 then break end

        local rtype = read_u16(data, pos)
        local rclass = read_u16(data, pos + 2)
        local ttl = read_u32(data, pos + 4)
        local rdlength = read_u16(data, pos + 8)
        pos = pos + 10

        local rdata = ""
        if rdlength > 0 and pos + rdlength - 1 <= #data then
            rdata = parse_rdata(data, pos, rdlength, rtype)
        end
        pos = pos + rdlength

        local display = string.format("%s %s %s TTL=%d %s",
            name, dns_type_name(rtype), dns_class_name(rclass), ttl, rdata)
        table.insert(fields, {
            name = string.format("%s[%d]", section_name, i),
            value = display,
            offset = 0, len = 0,
        })
    end
    return pos
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
    local opcode = math.floor(flags / 2048) % 16
    local aa = math.floor(flags / 1024) % 2
    local tc = math.floor(flags / 512) % 2
    local rd = math.floor(flags / 256) % 2
    local ra = math.floor(flags / 128) % 2
    local rcode = flags % 16

    local qdcount = read_u16(text, 5)
    local ancount = read_u16(text, 7)
    local nscount = read_u16(text, 9)
    local arcount = read_u16(text, 11)

    table.insert(fields, { name = "Transaction ID", value = string.format("0x%04x", tx_id), offset = 0, len = 2 })
    table.insert(fields, { name = "QR", value = qr == 1 and "Response" or "Query", offset = 2, len = 2 })
    table.insert(fields, { name = "Opcode", value = dns_opcode_name(opcode), offset = 2, len = 2 })
    if qr == 1 then
        table.insert(fields, { name = "Authoritative", value = aa == 1 and "Yes" or "No", offset = 2, len = 2 })
        table.insert(fields, { name = "Response Code", value = dns_rcode_name(rcode), offset = 2, len = 2 })
    end
    table.insert(fields, { name = "Truncated", value = tc == 1 and "Yes" or "No", offset = 2, len = 2 })
    table.insert(fields, { name = "Recursion Desired", value = rd == 1 and "Yes" or "No", offset = 2, len = 2 })
    table.insert(fields, { name = "Recursion Available", value = ra == 1 and "Yes" or "No", offset = 2, len = 2 })
    table.insert(fields, { name = "Questions", value = tostring(qdcount), offset = 4, len = 2 })
    table.insert(fields, { name = "Answers", value = tostring(ancount), offset = 6, len = 2 })
    table.insert(fields, { name = "Authority", value = tostring(nscount), offset = 8, len = 2 })
    table.insert(fields, { name = "Additional", value = tostring(arcount), offset = 10, len = 2 })

    -- Parse question section
    local pos = 13
    local qname = ""
    local qtype_str = ""
    for i = 1, qdcount do
        if pos > #text then break end
        local name, next_pos = read_dns_name(text, pos)
        pos = next_pos
        if pos + 4 > #text + 1 then break end
        local qtype = read_u16(text, pos)
        local qclass = read_u16(text, pos + 2)
        pos = pos + 4
        if i == 1 then
            qname = name
            qtype_str = dns_type_name(qtype)
        end
        table.insert(fields, {
            name = string.format("Query[%d]", i),
            value = string.format("%s %s %s", name, dns_type_name(qtype), dns_class_name(qclass)),
            offset = 12, len = 0,
        })
    end

    -- Parse answer, authority, additional sections
    pos = parse_records(text, pos, ancount, "Answer", fields)
    pos = parse_records(text, pos, nscount, "Authority", fields)
    parse_records(text, pos, arcount, "Additional", fields)

    local msg_type = qr == 1 and "Response" or "Query"
    local rcode_info = ""
    if qr == 1 then
        rcode_info = string.format(", %s", dns_rcode_name(rcode))
    end
    local summary = string.format("DNS %s %s %s (QD=%d AN=%d NS=%d AR=%d%s)",
        msg_type, qtype_str, qname, qdcount, ancount, nscount, arcount, rcode_info)

    return {
        protocol = "DNS",
        summary = summary,
        header_len = #text,
        fields = fields,
    }
end
