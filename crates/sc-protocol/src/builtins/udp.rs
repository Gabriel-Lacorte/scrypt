use crate::dissector::*;
use crate::model::*;
use nom::number::complete::be_u16;
use nom::IResult;
use sc_core::Protocol;

/// UDP datagram dissector.
pub struct UdpDissector;

struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

fn parse_udp(input: &[u8]) -> IResult<&[u8], UdpHeader> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    Ok((input, UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    }))
}

impl Dissector for UdpDissector {
    fn id(&self) -> DissectorId {
        DissectorId("udp".into())
    }

    fn name(&self) -> &str {
        "UDP"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Udp) && data.len() >= 8 {
            Confidence::Exact
        } else {
            Confidence::None
        }
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        context: &mut DissectionContext,
    ) -> sc_core::Result<DissectedLayer<'a>> {
        let (remaining, hdr) =
            parse_udp(data).map_err(|e| sc_core::ShadowError::Parse {
                message: format!("UDP parse error: {e}"),
            })?;

        context.src_port = Some(hdr.src_port);
        context.dst_port = Some(hdr.dst_port);

        let next_protocol = match (hdr.src_port, hdr.dst_port) {
            (53, _) | (_, 53) => Some(Protocol::Dns),
            (443, _) | (_, 443) => Some(Protocol::Quic),
            _ => None,
        };

        // Payload is length - 8 (header size)
        let payload_len = (hdr.length as usize).saturating_sub(8);
        let actual_remaining = if remaining.len() > payload_len {
            &remaining[..payload_len]
        } else {
            remaining
        };

        let node = ProtocolNode {
            protocol: "UDP".into(),
            byte_range: 0..8,
            fields: vec![
                Field {
                    name: "Source Port".into(),
                    display_value: format!("{}", hdr.src_port),
                    byte_range: 0..2,
                    field_type: FieldType::UInt16,
                },
                Field {
                    name: "Destination Port".into(),
                    display_value: format!("{}", hdr.dst_port),
                    byte_range: 2..4,
                    field_type: FieldType::UInt16,
                },
                Field {
                    name: "Length".into(),
                    display_value: format!("{}", hdr.length),
                    byte_range: 4..6,
                    field_type: FieldType::UInt16,
                },
                Field {
                    name: "Checksum".into(),
                    display_value: format!("0x{:04x}", hdr.checksum),
                    byte_range: 6..8,
                    field_type: FieldType::UInt16,
                },
            ],
            summary: format!(
                "{} → {}, Len={}",
                hdr.src_port, hdr.dst_port, hdr.length
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
    fn test_udp_dns() {
        let dissector = UdpDissector;

        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0xc0, 0x00, 0x00, 0x35,  // src=49152, dst=53 (DNS)
            0x00, 0x1c, 0x00, 0x00,  // length=28, checksum=0
            // 20 bytes of DNS payload
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
            0x06, 0x67, 0x6f, 0x6f,
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Udp);

        let layer = dissector.dissect(&packet, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "UDP");
        assert_eq!(layer.next_protocol, Some(Protocol::Dns));
        assert_eq!(layer.remaining.len(), 20);
    }
}
