use crate::dissector::*;
use crate::model::*;
use nom::number::complete::be_u16;
use nom::IResult;
use sc_core::Protocol;

/// Native DNS dissector.
pub struct DnsDissector;

fn dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        65 => "HTTPS",
        255 => "ANY",
        _ => "Unknown",
    }
}

fn dns_class_name(class: u16) -> &'static str {
    match class {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        255 => "ANY",
        _ => "Unknown",
    }
}

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0 => "Query",
        1 => "IQuery",
        2 => "Status",
        4 => "Notify",
        5 => "Update",
        _ => "Unknown",
    }
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "No Error",
        1 => "Format Error",
        2 => "Server Failure",
        3 => "Name Error",
        4 => "Not Implemented",
        5 => "Refused",
        _ => "Other",
    }
}

struct DnsHeader {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

fn parse_dns_header(input: &[u8]) -> IResult<&[u8], DnsHeader> {
    let (input, id) = be_u16(input)?;
    let (input, flags) = be_u16(input)?;
    let (input, qd_count) = be_u16(input)?;
    let (input, an_count) = be_u16(input)?;
    let (input, ns_count) = be_u16(input)?;
    let (input, ar_count) = be_u16(input)?;
    Ok((
        input,
        DnsHeader {
            id,
            flags,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        },
    ))
}

/// Read a DNS domain name, handling compression pointers.
/// `full_packet` is the complete DNS payload for pointer resolution.
/// Returns the domain name and the number of bytes consumed from `data`.
fn read_dns_name(data: &[u8], full_packet: &[u8], max_depth: u8) -> Option<(String, usize)> {
    if max_depth == 0 {
        return None;
    }
    let mut labels = Vec::new();
    let mut pos = 0;
    let mut consumed = None; // first time we follow a pointer, save consumed

    loop {
        if pos >= data.len() {
            return None;
        }
        let b = data[pos];
        if b == 0 {
            pos += 1;
            break;
        }
        if b & 0xC0 == 0xC0 {
            // compression pointer
            if pos + 1 >= data.len() {
                return None;
            }
            let offset = ((b as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if consumed.is_none() {
                consumed = Some(pos + 2);
            }
            if offset >= full_packet.len() {
                return None;
            }
            let (rest_name, _) = read_dns_name(&full_packet[offset..], full_packet, max_depth - 1)?;
            if !rest_name.is_empty() {
                labels.push(rest_name);
            }
            return Some((labels.join("."), consumed.unwrap()));
        }
        let len = b as usize;
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&data[pos..pos + len]).into_owned();
        labels.push(label);
        pos += len;
    }

    let total = consumed.unwrap_or(pos);
    Some((labels.join("."), total))
}

fn skip_name(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    loop {
        if pos >= data.len() {
            return None;
        }
        let b = data[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + b as usize;
    }
}

fn format_rdata(rtype: u16, rdata: &[u8], full_packet: &[u8]) -> String {
    match rtype {
        1 if rdata.len() == 4 => {
            // A record
            format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        28 if rdata.len() == 16 => {
            // AAAA record
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        2 | 5 | 12 => {
            // NS, CNAME, PTR
            read_dns_name(rdata, full_packet, 10)
                .map(|(n, _)| n)
                .unwrap_or_else(|| format!("{} bytes", rdata.len()))
        }
        15 if rdata.len() >= 2 => {
            // MX
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let name = read_dns_name(&rdata[2..], full_packet, 10)
                .map(|(n, _)| n)
                .unwrap_or_default();
            format!("{pref} {name}")
        }
        16 => {
            // TXT — one or more length-prefixed strings
            let mut parts = Vec::new();
            let mut pos = 0;
            while pos < rdata.len() {
                let len = rdata[pos] as usize;
                pos += 1;
                if pos + len > rdata.len() {
                    break;
                }
                parts.push(String::from_utf8_lossy(&rdata[pos..pos + len]).into_owned());
                pos += len;
            }
            parts.join(" ")
        }
        _ => format!("{} bytes", rdata.len()),
    }
}

impl Dissector for DnsDissector {
    fn id(&self) -> DissectorId {
        DissectorId("dns".into())
    }

    fn name(&self) -> &str {
        "DNS"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Dns) && data.len() >= 12 {
            return Confidence::Exact;
        }
        // Heuristic: check common DNS ports
        let dns_port = matches!(context.src_port, Some(53) | Some(5353))
            || matches!(context.dst_port, Some(53) | Some(5353));
        if dns_port && data.len() >= 12 {
            return Confidence::High;
        }
        Confidence::None
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> sc_core::Result<DissectedLayer<'a>> {
        let full_packet = data;
        let (body, hdr) = parse_dns_header(data).map_err(|e| sc_core::ShadowError::Parse {
            message: format!("DNS parse error: {e}"),
        })?;

        let is_response = (hdr.flags >> 15) & 1 == 1;
        let opcode = ((hdr.flags >> 11) & 0xF) as u8;
        let rcode = (hdr.flags & 0xF) as u8;
        let aa = (hdr.flags >> 10) & 1;
        let tc = (hdr.flags >> 9) & 1;
        let rd = (hdr.flags >> 8) & 1;
        let ra = (hdr.flags >> 7) & 1;

        let mut fields = vec![
            Field {
                name: "Transaction ID".into(),
                display_value: format!("0x{:04x}", hdr.id),
                byte_range: 0..2,
                field_type: FieldType::UInt16,
            },
            Field {
                name: "Flags".into(),
                display_value: format!(
                    "0x{:04x} ({}, opcode={}, AA={aa}, TC={tc}, RD={rd}, RA={ra}, rcode={})",
                    hdr.flags,
                    if is_response { "Response" } else { "Query" },
                    opcode_name(opcode),
                    rcode_name(rcode),
                ),
                byte_range: 2..4,
                field_type: FieldType::Flags(vec![]),
            },
            Field {
                name: "Questions".into(),
                display_value: format!("{}", hdr.qd_count),
                byte_range: 4..6,
                field_type: FieldType::UInt16,
            },
            Field {
                name: "Answers".into(),
                display_value: format!("{}", hdr.an_count),
                byte_range: 6..8,
                field_type: FieldType::UInt16,
            },
            Field {
                name: "Authority".into(),
                display_value: format!("{}", hdr.ns_count),
                byte_range: 8..10,
                field_type: FieldType::UInt16,
            },
            Field {
                name: "Additional".into(),
                display_value: format!("{}", hdr.ar_count),
                byte_range: 10..12,
                field_type: FieldType::UInt16,
            },
        ];

        // Parse questions
        let mut pos = body;
        let mut first_qname = String::new();
        let mut first_qtype: u16 = 0;

        for _ in 0..hdr.qd_count {
            let offset = full_packet.len() - pos.len();
            if let Some((name, consumed)) = read_dns_name(pos, full_packet, 10) {
                if first_qname.is_empty() {
                    first_qname = name.clone();
                }
                pos = &pos[consumed..];
                if pos.len() >= 4 {
                    let qtype = u16::from_be_bytes([pos[0], pos[1]]);
                    let qclass = u16::from_be_bytes([pos[2], pos[3]]);
                    if first_qtype == 0 {
                        first_qtype = qtype;
                    }
                    fields.push(Field {
                        name: "Query".into(),
                        display_value: format!(
                            "{name} {} {}",
                            dns_type_name(qtype),
                            dns_class_name(qclass),
                        ),
                        byte_range: offset..offset + consumed + 4,
                        field_type: FieldType::String,
                    });
                    pos = &pos[4..];
                }
            } else {
                break;
            }
        }

        // Parse resource records (answers, authority, additional)
        let section_counts = [
            ("Answer", hdr.an_count),
            ("Authority", hdr.ns_count),
            ("Additional", hdr.ar_count),
        ];

        for (section_name, count) in &section_counts {
            for _ in 0..*count {
                let offset = full_packet.len() - pos.len();
                let name_len = match skip_name(pos) {
                    Some(n) => n,
                    None => break,
                };
                let name = read_dns_name(pos, full_packet, 10)
                    .map(|(n, _)| n)
                    .unwrap_or_default();
                pos = &pos[name_len..];
                if pos.len() < 10 {
                    break;
                }
                let rtype = u16::from_be_bytes([pos[0], pos[1]]);
                let _rclass = u16::from_be_bytes([pos[2], pos[3]]);
                let ttl = u32::from_be_bytes([pos[4], pos[5], pos[6], pos[7]]);
                let rdlength = u16::from_be_bytes([pos[8], pos[9]]) as usize;
                pos = &pos[10..];
                if pos.len() < rdlength {
                    break;
                }
                let rdata = &pos[..rdlength];
                let rdata_str = format_rdata(rtype, rdata, full_packet);
                let total_rr_len = name_len + 10 + rdlength;

                fields.push(Field {
                    name: section_name.to_string(),
                    display_value: format!(
                        "{name} {} TTL={ttl} {rdata_str}",
                        dns_type_name(rtype),
                    ),
                    byte_range: offset..offset + total_rr_len,
                    field_type: FieldType::String,
                });
                pos = &pos[rdlength..];
            }
        }

        let qr_str = if is_response { "Response" } else { "Query" };
        let summary = if !first_qname.is_empty() {
            format!(
                "DNS {} 0x{:04x} {} {} [{} answer(s)]",
                qr_str,
                hdr.id,
                dns_type_name(first_qtype),
                first_qname,
                hdr.an_count,
            )
        } else {
            format!("DNS {} 0x{:04x}", qr_str, hdr.id)
        };

        let consumed = full_packet.len() - pos.len();
        let node = ProtocolNode {
            protocol: "DNS".into(),
            byte_range: 0..consumed,
            fields,
            summary,
        };

        Ok(DissectedLayer {
            node,
            remaining: pos,
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dns_query() -> Vec<u8> {
        #[rustfmt::skip]
        let pkt = vec![
            // Header
            0xab, 0xcd, // Transaction ID
            0x01, 0x00, // Flags: standard query, RD=1
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,       // root
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        pkt
    }

    fn make_dns_response() -> Vec<u8> {
        #[rustfmt::skip]
        let pkt = vec![
            // Header
            0xab, 0xcd, // Transaction ID
            0x81, 0x80, // Flags: response, RD=1, RA=1
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answers: 1
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01,
            0x00, 0x01,
            // Answer: example.com A IN TTL=300 93.184.216.34
            0xc0, 0x0c, // Name pointer to offset 12
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x01, 0x2c, // TTL: 300
            0x00, 0x04, // RDLength: 4
            0x5d, 0xb8, 0xd8, 0x22, // 93.184.216.34
        ];
        pkt
    }

    #[test]
    fn test_dns_query() {
        let pkt = make_dns_query();
        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Dns);

        let conf = DnsDissector.can_dissect(&pkt, &ctx);
        assert_eq!(conf, Confidence::Exact);

        let layer = DnsDissector.dissect(&pkt, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "DNS");
        assert!(layer.node.summary.contains("Query"));
        assert!(layer.node.summary.contains("example.com"));
        assert!(layer.node.summary.contains("A"));
    }

    #[test]
    fn test_dns_response() {
        let pkt = make_dns_response();
        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Dns);

        let layer = DnsDissector.dissect(&pkt, &mut ctx).unwrap();
        assert!(layer.node.summary.contains("Response"));
        assert!(layer.node.summary.contains("example.com"));
        assert!(layer.node.summary.contains("1 answer"));

        // Check that the answer field contains the IP
        let answer_field = layer
            .node
            .fields
            .iter()
            .find(|f| f.name == "Answer")
            .expect("should have Answer field");
        assert!(answer_field.display_value.contains("93.184.216.34"));
    }

    #[test]
    fn test_dns_port_heuristic() {
        let pkt = make_dns_query();
        let mut ctx = DissectionContext::new(16);
        ctx.dst_port = Some(53);

        let conf = DnsDissector.can_dissect(&pkt, &ctx);
        assert_eq!(conf, Confidence::High);
    }
}
