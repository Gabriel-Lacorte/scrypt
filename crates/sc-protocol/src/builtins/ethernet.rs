use crate::dissector::*;
use crate::model::*;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use sc_core::Protocol;

/// Ethernet II frame dissector.
pub struct EthernetDissector;

fn parse_ethernet(input: &[u8]) -> IResult<&[u8], ((&[u8], &[u8]), u16)> {
    let (input, dst) = take(6usize)(input)?;
    let (input, src) = take(6usize)(input)?;
    let (input, ethertype) = be_u16(input)?;
    Ok((input, ((dst, src), ethertype)))
}

impl Dissector for EthernetDissector {
    fn id(&self) -> DissectorId {
        DissectorId("ethernet".into())
    }

    fn name(&self) -> &str {
        "Ethernet"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Ethernet) && data.len() >= 14 {
            Confidence::Exact
        } else if context.depth == 0 && data.len() >= 14 {
            Confidence::Medium
        } else {
            Confidence::None
        }
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> sc_core::Result<DissectedLayer<'a>> {
        let (remaining, ((dst, src), ethertype)) =
            parse_ethernet(data).map_err(|e| sc_core::ShadowError::Parse {
                message: format!("Ethernet parse error: {e}"),
            })?;

        let next_protocol = match ethertype {
            0x0800 => Some(Protocol::Ipv4),
            0x86DD => Some(Protocol::Ipv6),
            0x0806 => Some(Protocol::Arp),
            _ => None,
        };

        let ethertype_label = match ethertype {
            0x0800 => "IPv4",
            0x86DD => "IPv6",
            0x0806 => "ARP",
            0x8100 => "802.1Q VLAN",
            _ => "Unknown",
        };

        let node = ProtocolNode {
            protocol: "Ethernet".into(),
            byte_range: 0..14,
            fields: vec![
                Field {
                    name: "Destination".into(),
                    display_value: format_mac(dst),
                    byte_range: 0..6,
                    field_type: FieldType::MacAddress,
                },
                Field {
                    name: "Source".into(),
                    display_value: format_mac(src),
                    byte_range: 6..12,
                    field_type: FieldType::MacAddress,
                },
                Field {
                    name: "EtherType".into(),
                    display_value: format!("0x{ethertype:04x} ({ethertype_label})"),
                    byte_range: 12..14,
                    field_type: FieldType::Enum {
                        value: ethertype as u32,
                        label: ethertype_label.into(),
                    },
                },
            ],
            summary: format!(
                "{} → {}, Type: {ethertype_label}",
                format_mac(src),
                format_mac(dst)
            ),
        };

        Ok(DissectedLayer {
            node,
            remaining,
            next_protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_ipv4() {
        let dissector = EthernetDissector;

        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src
            0x08, 0x00,                            // IPv4
            0xde, 0xad, 0xbe, 0xef,               // payload
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Ethernet);

        let conf = dissector.can_dissect(&packet, &ctx);
        assert_eq!(conf, Confidence::Exact);

        let layer = dissector.dissect(&packet, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "Ethernet");
        assert_eq!(layer.node.fields.len(), 3);
        assert_eq!(layer.remaining, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(layer.next_protocol, Some(Protocol::Ipv4));
    }
}
