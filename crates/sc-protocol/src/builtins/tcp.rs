use crate::dissector::*;
use crate::model::*;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use sc_core::Protocol;

/// TCP segment dissector.
pub struct TcpDissector;

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_number: u32,
    ack_number: u32,
    data_offset: u8, // in 32-bit words
    flags: TcpFlags,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    header_len: usize,
}

#[derive(Debug, Clone)]
struct TcpFlags {
    ns: bool,
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

impl TcpFlags {
    fn to_string_short(&self) -> String {
        let mut s = String::with_capacity(9);
        if self.syn { s.push('S'); }
        if self.ack { s.push('A'); }
        if self.fin { s.push('F'); }
        if self.rst { s.push('R'); }
        if self.psh { s.push('P'); }
        if self.urg { s.push('U'); }
        if self.ece { s.push('E'); }
        if self.cwr { s.push('C'); }
        if self.ns { s.push('N'); }
        if s.is_empty() { s.push('.'); }
        s
    }

    fn to_field_flags(&self) -> Vec<(String, bool)> {
        vec![
            ("SYN".into(), self.syn),
            ("ACK".into(), self.ack),
            ("FIN".into(), self.fin),
            ("RST".into(), self.rst),
            ("PSH".into(), self.psh),
            ("URG".into(), self.urg),
            ("ECE".into(), self.ece),
            ("CWR".into(), self.cwr),
            ("NS".into(), self.ns),
        ]
    }
}

fn parse_tcp(input: &[u8]) -> IResult<&[u8], TcpHeader> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, seq_number) = be_u32(input)?;
    let (input, ack_number) = be_u32(input)?;
    let (input, offset_flags_byte) = be_u8(input)?;
    let data_offset = offset_flags_byte >> 4;
    let ns = (offset_flags_byte & 0x01) != 0;
    let (input, flags_byte) = be_u8(input)?;
    let flags = TcpFlags {
        ns,
        cwr: (flags_byte & 0x80) != 0,
        ece: (flags_byte & 0x40) != 0,
        urg: (flags_byte & 0x20) != 0,
        ack: (flags_byte & 0x10) != 0,
        psh: (flags_byte & 0x08) != 0,
        rst: (flags_byte & 0x04) != 0,
        syn: (flags_byte & 0x02) != 0,
        fin: (flags_byte & 0x01) != 0,
    };
    let (input, window_size) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, urgent_pointer) = be_u16(input)?;

    let header_len = (data_offset as usize) * 4;
    // Skip TCP options (header_len - 20 bytes already parsed)
    let options_len = header_len.saturating_sub(20);
    let (input, _options) = nom::bytes::complete::take(options_len)(input)?;

    Ok((input, TcpHeader {
        src_port,
        dst_port,
        seq_number,
        ack_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        header_len,
    }))
}

impl Dissector for TcpDissector {
    fn id(&self) -> DissectorId {
        DissectorId("tcp".into())
    }

    fn name(&self) -> &str {
        "TCP"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Tcp) && data.len() >= 20 {
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
            parse_tcp(data).map_err(|e| sc_core::ShadowError::Parse {
                message: format!("TCP parse error: {e}"),
            })?;

        // Update context with port info for application-layer dissection
        context.src_port = Some(hdr.src_port);
        context.dst_port = Some(hdr.dst_port);

        // Determine next protocol hint based on well-known ports
        let next_protocol = match (hdr.src_port, hdr.dst_port) {
            (80, _) | (_, 80) | (8080, _) | (_, 8080) => Some(Protocol::Http),
            (443, _) | (_, 443) => Some(Protocol::Tls),
            (53, _) | (_, 53) => Some(Protocol::Dns),
            _ => None,
        };

        let flags_str = hdr.flags.to_string_short();
        let node = ProtocolNode {
            protocol: "TCP".into(),
            byte_range: 0..hdr.header_len,
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
                    name: "Sequence Number".into(),
                    display_value: format!("{}", hdr.seq_number),
                    byte_range: 4..8,
                    field_type: FieldType::UInt32,
                },
                Field {
                    name: "Acknowledgment Number".into(),
                    display_value: format!("{}", hdr.ack_number),
                    byte_range: 8..12,
                    field_type: FieldType::UInt32,
                },
                Field {
                    name: "Flags".into(),
                    display_value: format!("[{flags_str}]"),
                    byte_range: 12..14,
                    field_type: FieldType::Flags(hdr.flags.to_field_flags()),
                },
                Field {
                    name: "Window Size".into(),
                    display_value: format!("{}", hdr.window_size),
                    byte_range: 14..16,
                    field_type: FieldType::UInt16,
                },
            ],
            summary: format!(
                "{} → {} [{flags_str}] Seq={} Ack={} Win={}",
                hdr.src_port, hdr.dst_port, hdr.seq_number, hdr.ack_number, hdr.window_size
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
    fn test_tcp_syn() {
        let dissector = TcpDissector;

        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            0x00, 0x50, 0xc0, 0x00,  // src=80, dst=49152
            0x00, 0x00, 0x00, 0x01,  // seq=1
            0x00, 0x00, 0x00, 0x00,  // ack=0
            0x50, 0x02, 0xff, 0xff,  // offset=5, SYN flag, window=65535
            0x00, 0x00, 0x00, 0x00,  // checksum, urgent
        ];

        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Tcp);

        let layer = dissector.dissect(&packet, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "TCP");
        assert!(layer.node.summary.contains("[S]"));
        assert_eq!(ctx.src_port, Some(80));
        assert_eq!(ctx.dst_port, Some(49152));
    }
}
