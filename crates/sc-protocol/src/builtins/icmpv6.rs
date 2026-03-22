use crate::dissector::*;
use crate::model::*;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use sc_core::Protocol;

/// ICMPv6 dissector.
pub struct Icmpv6Dissector;

fn icmpv6_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        4 => "Parameter Problem",
        128 => "Echo Request",
        129 => "Echo Reply",
        130 => "Multicast Listener Query",
        131 => "Multicast Listener Report",
        132 => "Multicast Listener Done",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        137 => "Redirect",
        _ => "Unknown",
    }
}

fn unreachable_code_name(code: u8) -> &'static str {
    match code {
        0 => "No Route to Destination",
        1 => "Administratively Prohibited",
        3 => "Address Unreachable",
        4 => "Port Unreachable",
        _ => "Other",
    }
}

struct Icmpv6Header {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    body: u32,
}

fn parse_icmpv6(input: &[u8]) -> IResult<&[u8], Icmpv6Header> {
    let (input, icmp_type) = be_u8(input)?;
    let (input, code) = be_u8(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, body) = be_u32(input)?;
    Ok((
        input,
        Icmpv6Header {
            icmp_type,
            code,
            checksum,
            body,
        },
    ))
}

fn parse_ipv6_addr(data: &[u8]) -> Option<std::net::Ipv6Addr> {
    if data.len() < 16 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&data[..16]);
    Some(std::net::Ipv6Addr::from(octets))
}

impl Dissector for Icmpv6Dissector {
    fn id(&self) -> DissectorId {
        DissectorId("icmpv6".into())
    }

    fn name(&self) -> &str {
        "ICMPv6"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Icmpv6) && data.len() >= 8 {
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
        let (remaining, hdr) = parse_icmpv6(data).map_err(|e| sc_core::ShadowError::Parse {
            message: format!("ICMPv6 parse error: {e}"),
        })?;

        let type_name = icmpv6_type_name(hdr.icmp_type);

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

        let header_len;
        let detail = match hdr.icmp_type {
            128 | 129 => {
                // Echo Request/Reply
                let id = (hdr.body >> 16) as u16;
                let seq = (hdr.body & 0xFFFF) as u16;
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
                header_len = 8;
                format!("id=0x{id:04x} seq={seq}")
            }
            1 => {
                // Dest Unreachable
                let code_name = unreachable_code_name(hdr.code);
                fields[1].display_value = format!("{} ({})", hdr.code, code_name);
                header_len = 8;
                code_name.to_string()
            }
            2 => {
                // Packet Too Big
                let mtu = hdr.body;
                fields.push(Field {
                    name: "MTU".into(),
                    display_value: format!("{mtu}"),
                    byte_range: 4..8,
                    field_type: FieldType::UInt32,
                });
                header_len = 8;
                format!("MTU {mtu}")
            }
            135 => {
                // Neighbor Solicitation — target address at bytes 8..24
                header_len = 24;
                if let Some(addr) = parse_ipv6_addr(remaining) {
                    fields.push(Field {
                        name: "Target Address".into(),
                        display_value: addr.to_string(),
                        byte_range: 8..24,
                        field_type: FieldType::Ipv6Address,
                    });
                    format!("Who has {addr}?")
                } else {
                    String::new()
                }
            }
            136 => {
                // Neighbor Advertisement — flags in body, target at bytes 8..24
                let router = (hdr.body >> 31) & 1;
                let solicited = (hdr.body >> 30) & 1;
                let over = (hdr.body >> 29) & 1;
                let flags_str = format!("R={router} S={solicited} O={over}",);
                fields.push(Field {
                    name: "Flags".into(),
                    display_value: flags_str.clone(),
                    byte_range: 4..8,
                    field_type: FieldType::Flags(vec![]),
                });
                header_len = 24;
                if let Some(addr) = parse_ipv6_addr(remaining) {
                    fields.push(Field {
                        name: "Target Address".into(),
                        display_value: addr.to_string(),
                        byte_range: 8..24,
                        field_type: FieldType::Ipv6Address,
                    });
                    format!("{addr} is at [flags: {flags_str}]")
                } else {
                    String::new()
                }
            }
            133 | 134 => {
                // Router Solicitation / Router Advertisement
                header_len = 8;
                String::new()
            }
            _ => {
                header_len = 8;
                String::new()
            }
        };

        let consumed = header_len.min(data.len());
        let remaining = &data[consumed..];

        let summary = if detail.is_empty() {
            format!("ICMPv6 {type_name}")
        } else {
            format!("ICMPv6 {type_name}, {detail}")
        };

        let node = ProtocolNode {
            protocol: "ICMPv6".into(),
            byte_range: 0..consumed,
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
    fn test_icmpv6_echo_request() {
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x80,       // Type 128: Echo Request
            0x00,       // Code 0
            0xab, 0xcd, // Checksum
            0x00, 0x42, // Identifier
            0x00, 0x01, // Sequence: 1
            0xaa, 0xbb, // payload
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Icmpv6);

        let conf = Icmpv6Dissector.can_dissect(&packet, &ctx);
        assert_eq!(conf, Confidence::Exact);

        let layer = Icmpv6Dissector.dissect(&packet, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "ICMPv6");
        assert!(layer.node.summary.contains("Echo Request"));
        assert!(layer.node.summary.contains("seq=1"));
        assert_eq!(layer.remaining.len(), 2);
    }

    #[test]
    fn test_icmpv6_neighbor_solicitation() {
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x87,       // Type 135: Neighbor Solicitation
            0x00,       // Code 0
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Reserved
            // Target: fe80::1
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Icmpv6);

        let layer = Icmpv6Dissector.dissect(&packet, &mut ctx).unwrap();
        assert!(layer.node.summary.contains("Neighbor Solicitation"));
        assert!(layer.node.summary.contains("fe80::1"));
    }

    #[test]
    fn test_icmpv6_packet_too_big() {
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x02,       // Type 2: Packet Too Big
            0x00,       // Code 0
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x05, 0xdc, // MTU 1500
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Icmpv6);

        let layer = Icmpv6Dissector.dissect(&packet, &mut ctx).unwrap();
        assert!(layer.node.summary.contains("Packet Too Big"));
        assert!(layer.node.summary.contains("MTU 1500"));
    }
}
