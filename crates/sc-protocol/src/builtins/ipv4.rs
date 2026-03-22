use crate::dissector::*;
use crate::model::*;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;
use sc_core::Protocol;
use std::net::Ipv4Addr;

/// IPv4 packet dissector.
pub struct Ipv4Dissector;

#[allow(dead_code)]
struct Ipv4Header {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    header_len: usize,
}

fn parse_ipv4(input: &[u8]) -> IResult<&[u8], Ipv4Header> {
    let (input, ver_ihl) = be_u8(input)?;
    let version = ver_ihl >> 4;
    let ihl = ver_ihl & 0x0f;
    let header_len = (ihl as usize) * 4;

    let (input, dscp_ecn) = be_u8(input)?;
    let dscp = dscp_ecn >> 2;
    let ecn = dscp_ecn & 0x03;

    let (input, total_length) = be_u16(input)?;
    let (input, identification) = be_u16(input)?;
    let (input, flags_frag) = be_u16(input)?;
    let flags = (flags_frag >> 13) as u8;
    let fragment_offset = flags_frag & 0x1fff;

    let (input, ttl) = be_u8(input)?;
    let (input, protocol) = be_u8(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, src_bytes) = take(4usize)(input)?;
    let (input, dst_bytes) = take(4usize)(input)?;

    let src_addr = Ipv4Addr::new(src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3]);
    let dst_addr = Ipv4Addr::new(dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]);

    // Skip options (header_len - 20 bytes already consumed)
    let options_len = header_len.saturating_sub(20);
    let (input, _options) = take(options_len)(input)?;

    Ok((input, Ipv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        src_addr,
        dst_addr,
        header_len,
    }))
}

fn ip_protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "Unknown",
    }
}

impl Dissector for Ipv4Dissector {
    fn id(&self) -> DissectorId {
        DissectorId("ipv4".into())
    }

    fn name(&self) -> &str {
        "IPv4"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Ipv4) && data.len() >= 20 {
            Confidence::Exact
        } else if data.len() >= 20 && (data[0] >> 4) == 4 {
            Confidence::High
        } else {
            Confidence::None
        }
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> sc_core::Result<DissectedLayer<'a>> {
        let (remaining, hdr) =
            parse_ipv4(data).map_err(|e| sc_core::ShadowError::Parse {
                message: format!("IPv4 parse error: {e}"),
            })?;

        let next_protocol = match hdr.protocol {
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            1 => Some(Protocol::Icmp),
            58 => Some(Protocol::Icmpv6),
            _ => None,
        };

        // Calculate payload based on total_length - header_len
        let payload_len = (hdr.total_length as usize).saturating_sub(hdr.header_len);
        let actual_remaining = if remaining.len() > payload_len {
            &remaining[..payload_len]
        } else {
            remaining
        };

        let _base = 14; // Assuming after Ethernet — offset would be tracked properly in full impl
        let node = ProtocolNode {
            protocol: "IPv4".into(),
            byte_range: 0..hdr.header_len,
            fields: vec![
                Field {
                    name: "Version".into(),
                    display_value: format!("{}", hdr.version),
                    byte_range: 0..1,
                    field_type: FieldType::UInt8,
                },
                Field {
                    name: "Header Length".into(),
                    display_value: format!("{} bytes", hdr.header_len),
                    byte_range: 0..1,
                    field_type: FieldType::UInt8,
                },
                Field {
                    name: "Total Length".into(),
                    display_value: format!("{}", hdr.total_length),
                    byte_range: 2..4,
                    field_type: FieldType::UInt16,
                },
                Field {
                    name: "TTL".into(),
                    display_value: format!("{}", hdr.ttl),
                    byte_range: 8..9,
                    field_type: FieldType::UInt8,
                },
                Field {
                    name: "Protocol".into(),
                    display_value: format!("{} ({})", hdr.protocol, ip_protocol_name(hdr.protocol)),
                    byte_range: 9..10,
                    field_type: FieldType::Enum {
                        value: hdr.protocol as u32,
                        label: ip_protocol_name(hdr.protocol).into(),
                    },
                },
                Field {
                    name: "Source".into(),
                    display_value: format!("{}", hdr.src_addr),
                    byte_range: 12..16,
                    field_type: FieldType::Ipv4Address,
                },
                Field {
                    name: "Destination".into(),
                    display_value: format!("{}", hdr.dst_addr),
                    byte_range: 16..20,
                    field_type: FieldType::Ipv4Address,
                },
            ],
            summary: format!(
                "{} -> {}, TTL={}, Proto={}",
                hdr.src_addr, hdr.dst_addr, hdr.ttl, ip_protocol_name(hdr.protocol)
            ),
        };

        Ok(DissectedLayer {
            node,
            remaining: actual_remaining,
            next_protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_tcp() {
        let dissector = Ipv4Dissector;

        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x28,  // ver=4, IHL=5, total_len=40
            0x00, 0x01, 0x00, 0x00,  // id, flags/offset
            0x40, 0x06, 0x00, 0x00,  // TTL=64, proto=TCP
            0xc0, 0xa8, 0x01, 0x01,  // src: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02,  // dst: 192.168.1.2
            // TCP payload (20 bytes)
            0x00, 0x50, 0xc0, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Ipv4);

        let conf = dissector.can_dissect(&packet, &ctx);
        assert_eq!(conf, Confidence::Exact);

        let layer = dissector.dissect(&packet, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "IPv4");
        assert!(layer.node.summary.contains("192.168.1.1"));
        assert!(layer.node.summary.contains("192.168.1.2"));
        assert_eq!(layer.next_protocol, Some(Protocol::Tcp));
        assert_eq!(layer.remaining.len(), 20);
    }
}
