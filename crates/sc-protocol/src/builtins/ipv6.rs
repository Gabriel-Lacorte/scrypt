use crate::dissector::*;
use crate::model::*;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;
use sc_core::Protocol;
use std::net::Ipv6Addr;

/// IPv6 packet dissector.
pub struct Ipv6Dissector;

#[allow(dead_code)]
struct Ipv6Header {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
}

fn parse_ipv6(input: &[u8]) -> IResult<&[u8], Ipv6Header> {
    let (input, first_word_bytes) = take(4usize)(input)?;
    let first_word = u32::from_be_bytes([
        first_word_bytes[0],
        first_word_bytes[1],
        first_word_bytes[2],
        first_word_bytes[3],
    ]);
    let version = (first_word >> 28) as u8;
    let traffic_class = ((first_word >> 20) & 0xff) as u8;
    let flow_label = first_word & 0x000f_ffff;

    let (input, payload_length) = be_u16(input)?;
    let (input, next_header) = be_u8(input)?;
    let (input, hop_limit) = be_u8(input)?;
    let (input, src_bytes) = take(16usize)(input)?;
    let (input, dst_bytes) = take(16usize)(input)?;

    let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(src_bytes).unwrap());
    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(dst_bytes).unwrap());

    Ok((input, Ipv6Header {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        src_addr,
        dst_addr,
    }))
}

impl Dissector for Ipv6Dissector {
    fn id(&self) -> DissectorId {
        DissectorId("ipv6".into())
    }

    fn name(&self) -> &str {
        "IPv6"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Ipv6) && data.len() >= 40 {
            Confidence::Exact
        } else if data.len() >= 40 && (data[0] >> 4) == 6 {
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
            parse_ipv6(data).map_err(|e| sc_core::ShadowError::Parse {
                message: format!("IPv6 parse error: {e}"),
            })?;

        let next_protocol = match hdr.next_header {
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            58 => Some(Protocol::Icmpv6),
            _ => None,
        };

        let payload_len = hdr.payload_length as usize;
        let actual_remaining = if remaining.len() > payload_len {
            &remaining[..payload_len]
        } else {
            remaining
        };

        let node = ProtocolNode {
            protocol: "IPv6".into(),
            byte_range: 0..40,
            fields: vec![
                Field {
                    name: "Version".into(),
                    display_value: format!("{}", hdr.version),
                    byte_range: 0..1,
                    field_type: FieldType::UInt8,
                },
                Field {
                    name: "Traffic Class".into(),
                    display_value: format!("0x{:02x}", hdr.traffic_class),
                    byte_range: 0..2,
                    field_type: FieldType::UInt8,
                },
                Field {
                    name: "Payload Length".into(),
                    display_value: format!("{}", hdr.payload_length),
                    byte_range: 4..6,
                    field_type: FieldType::UInt16,
                },
                Field {
                    name: "Next Header".into(),
                    display_value: format!("{}", hdr.next_header),
                    byte_range: 6..7,
                    field_type: FieldType::UInt8,
                },
                Field {
                    name: "Hop Limit".into(),
                    display_value: format!("{}", hdr.hop_limit),
                    byte_range: 7..8,
                    field_type: FieldType::UInt8,
                },
                Field {
                    name: "Source".into(),
                    display_value: format!("{}", hdr.src_addr),
                    byte_range: 8..24,
                    field_type: FieldType::Ipv6Address,
                },
                Field {
                    name: "Destination".into(),
                    display_value: format!("{}", hdr.dst_addr),
                    byte_range: 24..40,
                    field_type: FieldType::Ipv6Address,
                },
            ],
            summary: format!(
                "{} -> {}, Hop Limit={}, Next={}",
                hdr.src_addr, hdr.dst_addr, hdr.hop_limit, hdr.next_header
            ),
        };

        Ok(DissectedLayer {
            node,
            remaining: actual_remaining,
            next_protocol,
        })
    }
}
