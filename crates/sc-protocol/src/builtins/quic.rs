use crate::dissector::*;
use crate::model::*;
use sc_core::Result;

/// Stub QUIC dissector that detects QUIC Initial packets by their header pattern.
///
/// QUIC long header format (RFC 9000):
/// - Bit 7 (Header Form): 1 = Long header
/// - Bit 6 (Fixed Bit): 1
/// - Bits 4-5 (Long Packet Type): 00 = Initial
/// - Version field at bytes 1..5
///
/// Known QUIC versions:
/// - 0x00000001 (RFC 9000)
/// - 0xff00001d..0xff000020 (draft versions 29-32)
pub struct QuicDissector;

impl Dissector for QuicDissector {
    fn id(&self) -> DissectorId {
        DissectorId("builtin:quic".into())
    }

    fn name(&self) -> &str {
        "QUIC"
    }

    fn can_dissect(&self, data: &[u8], _context: &DissectionContext) -> Confidence {
        if data.len() < 5 {
            return Confidence::None;
        }

        let first = data[0];
        // Long header: Form=1, Fixed=1
        if first & 0xC0 != 0xC0 {
            return Confidence::None;
        }

        // Check version field
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        match version {
            0x00000001 => Confidence::High, // QUIC v1
            0x6b3343cf => Confidence::High, // QUIC v2
            v if (0xff000000..=0xff0000ff).contains(&v) => Confidence::Medium, // Drafts
            _ => Confidence::None,
        }
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> Result<DissectedLayer<'a>> {
        if data.len() < 5 {
            return Err(sc_core::ShadowError::Dissection {
                message: "QUIC packet too short".into(),
            });
        }

        let first = data[0];
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        let packet_type = match (first >> 4) & 0x03 {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            3 => "Retry",
            _ => "Unknown",
        };

        let version_str = match version {
            0x00000001 => "1 (RFC 9000)".to_string(),
            0x6b3343cf => "2 (RFC 9369)".to_string(),
            v => format!("0x{v:08x}"),
        };

        let fields = vec![
            Field {
                name: "Packet Type".into(),
                display_value: packet_type.into(),
                byte_range: 0..1,
                field_type: FieldType::String,
            },
            Field {
                name: "Version".into(),
                display_value: version_str,
                byte_range: 1..5,
                field_type: FieldType::UInt32,
            },
        ];

        Ok(DissectedLayer {
            node: ProtocolNode {
                protocol: "QUIC".into(),
                byte_range: 0..data.len(),
                fields,
                summary: format!("QUIC {packet_type}"),
            },
            remaining: &[],
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DissectionTree;

    #[test]
    fn test_quic_v1_initial() {
        let dissector = QuicDissector;
        // Long header (0xC0) | Initial type (0x00) = 0xC0, version = 0x00000001
        let mut data = vec![0xC0];
        data.extend_from_slice(&0x00000001u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 20]); // payload stub

        let ctx = DissectionContext {
            next_protocol_hint: None,
            src_port: None,
            dst_port: None,
            depth: 0,
            max_depth: 16,
            tree: DissectionTree {
                top_protocol: String::new(),
                layers: vec![],
            },
        };

        assert!(matches!(
            dissector.can_dissect(&data, &ctx),
            Confidence::High
        ));
    }

    #[test]
    fn test_non_quic() {
        let dissector = QuicDissector;
        let data = vec![0x45, 0, 0, 0x28, 0, 0]; // IPv4-like

        let ctx = DissectionContext {
            next_protocol_hint: None,
            src_port: None,
            dst_port: None,
            depth: 0,
            max_depth: 16,
            tree: DissectionTree {
                top_protocol: String::new(),
                layers: vec![],
            },
        };

        assert!(matches!(
            dissector.can_dissect(&data, &ctx),
            Confidence::None
        ));
    }
}
