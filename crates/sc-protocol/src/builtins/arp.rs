use crate::dissector::*;
use crate::model::*;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use sc_core::Protocol;
use std::net::Ipv4Addr;

/// ARP (Address Resolution Protocol) dissector.
pub struct ArpDissector;

struct ArpPacket {
    hw_type: u16,
    proto_type: u16,
    hw_len: u8,
    proto_len: u8,
    operation: u16,
    sender_hw: Vec<u8>,
    sender_proto: Vec<u8>,
    target_hw: Vec<u8>,
    target_proto: Vec<u8>,
    total_len: usize,
}

fn parse_arp(input: &[u8]) -> IResult<&[u8], ArpPacket> {
    let (input, hw_type) = be_u16(input)?;
    let (input, proto_type) = be_u16(input)?;
    let (input, hw_len_slice) = take(1usize)(input)?;
    let hw_len = hw_len_slice[0];
    let (input, proto_len_slice) = take(1usize)(input)?;
    let proto_len = proto_len_slice[0];
    let (input, operation) = be_u16(input)?;
    let (input, sender_hw) = take(hw_len as usize)(input)?;
    let (input, sender_proto) = take(proto_len as usize)(input)?;
    let (input, target_hw) = take(hw_len as usize)(input)?;
    let (input, target_proto) = take(proto_len as usize)(input)?;

    let total_len = 8 + (hw_len as usize + proto_len as usize) * 2;

    Ok((
        input,
        ArpPacket {
            hw_type,
            proto_type,
            hw_len,
            proto_len,
            operation,
            sender_hw: sender_hw.to_vec(),
            sender_proto: sender_proto.to_vec(),
            target_hw: target_hw.to_vec(),
            target_proto: target_proto.to_vec(),
            total_len,
        },
    ))
}

fn operation_name(op: u16) -> &'static str {
    match op {
        1 => "Request",
        2 => "Reply",
        3 => "RARP Request",
        4 => "RARP Reply",
        _ => "Unknown",
    }
}

fn format_hw_addr(bytes: &[u8]) -> String {
    if bytes.len() == 6 {
        format_mac(bytes)
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

fn format_proto_addr(bytes: &[u8], proto_type: u16) -> String {
    if proto_type == 0x0800 && bytes.len() == 4 {
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Dissector for ArpDissector {
    fn id(&self) -> DissectorId {
        DissectorId("arp".into())
    }

    fn name(&self) -> &str {
        "ARP"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Arp) && data.len() >= 8 {
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
        let (remaining, pkt) = parse_arp(data).map_err(|e| sc_core::ShadowError::Parse {
            message: format!("ARP parse error: {e}"),
        })?;

        let sender_hw_str = format_hw_addr(&pkt.sender_hw);
        let sender_proto_str = format_proto_addr(&pkt.sender_proto, pkt.proto_type);
        let target_hw_str = format_hw_addr(&pkt.target_hw);
        let target_proto_str = format_proto_addr(&pkt.target_proto, pkt.proto_type);

        let summary = match pkt.operation {
            1 => format!("Who has {target_proto_str}? Tell {sender_proto_str}"),
            2 => format!("{sender_proto_str} is at {sender_hw_str}"),
            _ => format!(
                "ARP {} {sender_proto_str} -> {target_proto_str}",
                operation_name(pkt.operation)
            ),
        };

        let node = ProtocolNode {
            protocol: "ARP".into(),
            byte_range: 0..pkt.total_len,
            fields: vec![
                Field {
                    name: "Hardware Type".into(),
                    display_value: format!(
                        "0x{:04x} ({})",
                        pkt.hw_type,
                        if pkt.hw_type == 1 {
                            "Ethernet"
                        } else {
                            "Other"
                        }
                    ),
                    byte_range: 0..2,
                    field_type: FieldType::UInt16,
                },
                Field {
                    name: "Protocol Type".into(),
                    display_value: format!(
                        "0x{:04x} ({})",
                        pkt.proto_type,
                        if pkt.proto_type == 0x0800 {
                            "IPv4"
                        } else {
                            "Other"
                        }
                    ),
                    byte_range: 2..4,
                    field_type: FieldType::UInt16,
                },
                Field {
                    name: "Operation".into(),
                    display_value: format!("{} ({})", pkt.operation, operation_name(pkt.operation)),
                    byte_range: 6..8,
                    field_type: FieldType::Enum {
                        value: pkt.operation as u32,
                        label: operation_name(pkt.operation).into(),
                    },
                },
                Field {
                    name: "Sender MAC".into(),
                    display_value: sender_hw_str,
                    byte_range: 8..8 + pkt.hw_len as usize,
                    field_type: FieldType::MacAddress,
                },
                Field {
                    name: "Sender IP".into(),
                    display_value: sender_proto_str,
                    byte_range: 8 + pkt.hw_len as usize
                        ..8 + pkt.hw_len as usize + pkt.proto_len as usize,
                    field_type: FieldType::Ipv4Address,
                },
                Field {
                    name: "Target MAC".into(),
                    display_value: target_hw_str,
                    byte_range: 8 + pkt.hw_len as usize + pkt.proto_len as usize
                        ..8 + pkt.hw_len as usize * 2 + pkt.proto_len as usize,
                    field_type: FieldType::MacAddress,
                },
                Field {
                    name: "Target IP".into(),
                    display_value: target_proto_str,
                    byte_range: 8 + pkt.hw_len as usize * 2 + pkt.proto_len as usize..pkt.total_len,
                    field_type: FieldType::Ipv4Address,
                },
            ],
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
    fn test_arp_request() {
        let dissector = ArpDissector;

        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x00, 0x01,             // HW type: Ethernet
            0x08, 0x00,             // Proto type: IPv4
            0x06,                   // HW len: 6
            0x04,                   // Proto len: 4
            0x00, 0x01,             // Operation: Request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC
            0xc0, 0xa8, 0x01, 0x01,             // Sender IP: 192.168.1.1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC (unknown)
            0xc0, 0xa8, 0x01, 0x02,             // Target IP: 192.168.1.2
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Arp);

        let conf = dissector.can_dissect(&packet, &ctx);
        assert_eq!(conf, Confidence::Exact);

        let layer = dissector.dissect(&packet, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "ARP");
        assert!(layer.node.summary.contains("192.168.1.2"));
        assert!(layer.node.summary.contains("192.168.1.1"));
        assert!(layer.node.summary.contains("Who has"));
    }

    #[test]
    fn test_arp_reply() {
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
            0x00, 0x02,             // Operation: Reply
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0xc0, 0xa8, 0x01, 0x02,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xc0, 0xa8, 0x01, 0x01,
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Arp);

        let layer = ArpDissector.dissect(&packet, &mut ctx).unwrap();
        assert!(layer.node.summary.contains("is at"));
        assert!(layer.node.summary.contains("aa:bb:cc:dd:ee:ff"));
    }
}
