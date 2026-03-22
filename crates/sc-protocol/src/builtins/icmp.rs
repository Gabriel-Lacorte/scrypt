use crate::dissector::*;
use crate::model::*;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use sc_core::Protocol;

/// ICMP (Internet Control Message Protocol) dissector.
pub struct IcmpDissector;

fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        4 => "Source Quench",
        5 => "Redirect",
        8 => "Echo Request",
        9 => "Router Advertisement",
        10 => "Router Solicitation",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp Request",
        14 => "Timestamp Reply",
        17 => "Address Mask Request",
        18 => "Address Mask Reply",
        _ => "Unknown",
    }
}

fn unreachable_code_name(code: u8) -> &'static str {
    match code {
        0 => "Network Unreachable",
        1 => "Host Unreachable",
        2 => "Protocol Unreachable",
        3 => "Port Unreachable",
        4 => "Fragmentation Needed",
        5 => "Source Route Failed",
        6 => "Destination Network Unknown",
        7 => "Destination Host Unknown",
        13 => "Communication Administratively Prohibited",
        _ => "Other",
    }
}

fn redirect_code_name(code: u8) -> &'static str {
    match code {
        0 => "Network",
        1 => "Host",
        2 => "TOS + Network",
        3 => "TOS + Host",
        _ => "Other",
    }
}

fn time_exceeded_code_name(code: u8) -> &'static str {
    match code {
        0 => "TTL Expired in Transit",
        1 => "Fragment Reassembly Time Exceeded",
        _ => "Other",
    }
}

struct IcmpHeader {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    rest: u32, // bytes 4-7; interpretation depends on type
}

fn parse_icmp(input: &[u8]) -> IResult<&[u8], IcmpHeader> {
    let (input, icmp_type) = be_u8(input)?;
    let (input, code) = be_u8(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, rest) = be_u32(input)?;
    Ok((
        input,
        IcmpHeader {
            icmp_type,
            code,
            checksum,
            rest,
        },
    ))
}

impl Dissector for IcmpDissector {
    fn id(&self) -> DissectorId {
        DissectorId("icmp".into())
    }

    fn name(&self) -> &str {
        "ICMP"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Icmp) && data.len() >= 8 {
            Confidence::Exact
        } else {
            Confidence::None
        }
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> sc_core::Result<DissectedLayer<'a>> {
        let (remaining, hdr) = parse_icmp(data).map_err(|e| sc_core::ShadowError::Parse {
            message: format!("ICMP parse error: {e}"),
        })?;

        let type_name = icmp_type_name(hdr.icmp_type);

        let mut fields = vec![
            Field {
                name: "Type".into(),
                display_value: format!("{} ({})", hdr.icmp_type, type_name),
                byte_range: 0..1,
                field_type: FieldType::Enum {
                    value: hdr.icmp_type as u32,
                    label: type_name.into(),
                },
            },
            Field {
                name: "Code".into(),
                display_value: format!("{}", hdr.code),
                byte_range: 1..2,
                field_type: FieldType::UInt8,
            },
            Field {
                name: "Checksum".into(),
                display_value: format!("0x{:04x}", hdr.checksum),
                byte_range: 2..4,
                field_type: FieldType::UInt16,
            },
        ];

        // Add type-specific fields
        let detail = match hdr.icmp_type {
            0 | 8 => {
                // Echo Request/Reply: rest = identifier(16) + sequence(16)
                let id = (hdr.rest >> 16) as u16;
                let seq = (hdr.rest & 0xFFFF) as u16;
                fields.push(Field {
                    name: "Identifier".into(),
                    display_value: format!("0x{id:04x}"),
                    byte_range: 4..6,
                    field_type: FieldType::UInt16,
                });
                fields.push(Field {
                    name: "Sequence".into(),
                    display_value: format!("{seq}"),
                    byte_range: 6..8,
                    field_type: FieldType::UInt16,
                });
                format!("id=0x{id:04x} seq={seq}")
            }
            3 => {
                let code_name = unreachable_code_name(hdr.code);
                fields[1].display_value = format!("{} ({})", hdr.code, code_name);
                code_name.to_string()
            }
            5 => {
                let code_name = redirect_code_name(hdr.code);
                fields[1].display_value = format!("{} ({})", hdr.code, code_name);
                let gw = std::net::Ipv4Addr::from(hdr.rest);
                fields.push(Field {
                    name: "Gateway".into(),
                    display_value: gw.to_string(),
                    byte_range: 4..8,
                    field_type: FieldType::Ipv4Address,
                });
                format!("Redirect to {gw} ({code_name})")
            }
            11 => {
                let code_name = time_exceeded_code_name(hdr.code);
                fields[1].display_value = format!("{} ({})", hdr.code, code_name);
                code_name.to_string()
            }
            _ => String::new(),
        };

        let summary = if detail.is_empty() {
            format!("ICMP {type_name}")
        } else {
            format!("ICMP {type_name}, {detail}")
        };

        let node = ProtocolNode {
            protocol: "ICMP".into(),
            byte_range: 0..8,
            fields,
            summary,
        };

        Ok(DissectedLayer {
            node,
            remaining,
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_echo_request() {
        let dissector = IcmpDissector;

        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x08,       // Type: Echo Request
            0x00,       // Code: 0
            0x4d, 0x56, // Checksum
            0x00, 0x01, // Identifier
            0x00, 0x0a, // Sequence: 10
            0xde, 0xad, 0xbe, 0xef, // payload
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Icmp);

        let conf = dissector.can_dissect(&packet, &ctx);
        assert_eq!(conf, Confidence::Exact);

        let layer = dissector.dissect(&packet, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "ICMP");
        assert!(layer.node.summary.contains("Echo Request"));
        assert!(layer.node.summary.contains("seq=10"));
        assert_eq!(layer.remaining.len(), 4);
    }

    #[test]
    fn test_icmp_echo_reply() {
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x05,
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Icmp);

        let layer = IcmpDissector.dissect(&packet, &mut ctx).unwrap();
        assert!(layer.node.summary.contains("Echo Reply"));
        assert!(layer.node.summary.contains("seq=5"));
    }

    #[test]
    fn test_icmp_dest_unreachable() {
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x03, 0x03, 0x00, 0x00, // Type 3, Code 3 (Port Unreachable)
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Icmp);

        let layer = IcmpDissector.dissect(&packet, &mut ctx).unwrap();
        assert!(layer.node.summary.contains("Destination Unreachable"));
        assert!(layer.node.summary.contains("Port Unreachable"));
    }
}
