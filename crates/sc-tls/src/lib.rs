use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u24, be_u8};
use nom::IResult;
use sc_core::{Protocol, Result, ShadowError};
use sc_protocol::*;
use serde::{Deserialize, Serialize};

/// TLS content types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

impl From<u8> for ContentType {
    fn from(v: u8) -> Self {
        match v {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Unknown(v),
        }
    }
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::ChangeCipherSpec => write!(f, "ChangeCipherSpec"),
            ContentType::Alert => write!(f, "Alert"),
            ContentType::Handshake => write!(f, "Handshake"),
            ContentType::ApplicationData => write!(f, "ApplicationData"),
            ContentType::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// TLS handshake types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeType {
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    EncryptedExtensions,
    Unknown(u8),
}

impl From<u8> for HandshakeType {
    fn from(v: u8) -> Self {
        match v {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            11 => HandshakeType::Certificate,
            12 => HandshakeType::ServerKeyExchange,
            13 => HandshakeType::CertificateRequest,
            14 => HandshakeType::ServerHelloDone,
            15 => HandshakeType::CertificateVerify,
            16 => HandshakeType::ClientKeyExchange,
            20 => HandshakeType::Finished,
            8 => HandshakeType::EncryptedExtensions,
            _ => HandshakeType::Unknown(v),
        }
    }
}

impl std::fmt::Display for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeType::ClientHello => write!(f, "ClientHello"),
            HandshakeType::ServerHello => write!(f, "ServerHello"),
            HandshakeType::Certificate => write!(f, "Certificate"),
            HandshakeType::ServerKeyExchange => write!(f, "ServerKeyExchange"),
            HandshakeType::CertificateRequest => write!(f, "CertificateRequest"),
            HandshakeType::ServerHelloDone => write!(f, "ServerHelloDone"),
            HandshakeType::CertificateVerify => write!(f, "CertificateVerify"),
            HandshakeType::ClientKeyExchange => write!(f, "ClientKeyExchange"),
            HandshakeType::Finished => write!(f, "Finished"),
            HandshakeType::EncryptedExtensions => write!(f, "EncryptedExtensions"),
            HandshakeType::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

/// Parsed TLS record layer.
#[derive(Debug, Clone)]
pub struct TlsRecord<'a> {
    pub content_type: ContentType,
    pub version_major: u8,
    pub version_minor: u8,
    pub fragment: &'a [u8],
}

/// Parse a TLS record layer.
fn parse_tls_record(input: &[u8]) -> IResult<&[u8], TlsRecord<'_>> {
    let (input, content_type_byte) = be_u8(input)?;
    let (input, version_major) = be_u8(input)?;
    let (input, version_minor) = be_u8(input)?;
    let (input, length) = be_u16(input)?;
    let (input, fragment) = take(length)(input)?;

    Ok((input, TlsRecord {
        content_type: ContentType::from(content_type_byte),
        version_major,
        version_minor,
        fragment,
    }))
}

/// Parsed TLS ClientHello extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub name: String,
    pub data: Vec<u8>,
}

/// Parse SNI extension data.
fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // Skip server_name_list length (2) + name_type (1) + name length (2)
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() >= 5 + name_len {
        String::from_utf8(data[5..5 + name_len].to_vec()).ok()
    } else {
        None
    }
}

/// TLS 1.3 dissector implementing the Dissector trait.
pub struct TlsDissector;

impl Dissector for TlsDissector {
    fn id(&self) -> DissectorId {
        DissectorId("tls".into())
    }

    fn name(&self) -> &str {
        "TLS"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Tls) && data.len() >= 5 {
            return Confidence::Exact;
        }
        // Check for TLS record magic: content_type 20-23, version 0x0301-0x0304
        if data.len() >= 5 && (20..=23).contains(&data[0]) && data[1] == 0x03 && data[2] <= 0x04 {
            return Confidence::High;
        }
        Confidence::None
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> Result<DissectedLayer<'a>> {
        let (remaining, record) = parse_tls_record(data).map_err(|e| ShadowError::Tls {
            message: format!("TLS record parse error: {e}"),
        })?;

        let version_str = match (record.version_major, record.version_minor) {
            (3, 0) => "SSL 3.0",
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => "Unknown",
        };

        let mut fields = vec![
            Field {
                name: "Content Type".into(),
                display_value: format!("{}", record.content_type),
                byte_range: 0..1,
                field_type: FieldType::Enum {
                    value: data[0] as u32,
                    label: record.content_type.to_string(),
                },
            },
            Field {
                name: "Version".into(),
                display_value: version_str.into(),
                byte_range: 1..3,
                field_type: FieldType::UInt16,
            },
            Field {
                name: "Length".into(),
                display_value: format!("{}", record.fragment.len()),
                byte_range: 3..5,
                field_type: FieldType::UInt16,
            },
        ];

        let mut summary = format!("{}, {}", record.content_type, version_str);

        // If it's a handshake, try to parse the handshake type
        if record.content_type == ContentType::Handshake && !record.fragment.is_empty() {
            let hs_type = HandshakeType::from(record.fragment[0]);
            fields.push(Field {
                name: "Handshake Type".into(),
                display_value: format!("{hs_type}"),
                byte_range: 5..6,
                field_type: FieldType::Enum {
                    value: record.fragment[0] as u32,
                    label: hs_type.to_string(),
                },
            });
            summary = format!("{hs_type}, {version_str}");

            // Try to extract SNI from ClientHello
            if hs_type == HandshakeType::ClientHello && record.fragment.len() > 38 {
                // Scan for SNI extension (type 0x0000)
                let frag = record.fragment;
                // Skip: type(1)+length(3)+version(2)+random(32)=38
                if frag.len() > 38 {
                    // Simple scan for SNI — production code would parse extensions properly
                    for i in 38..frag.len().saturating_sub(4) {
                        if frag[i] == 0x00 && frag[i + 1] == 0x00 {
                            // Potential SNI extension
                            if let Some(sni) = parse_sni(&frag[i + 4..]) {
                                fields.push(Field {
                                    name: "SNI".into(),
                                    display_value: sni.clone(),
                                    byte_range: i..i + 4,
                                    field_type: FieldType::String,
                                });
                                summary = format!("{hs_type}, {version_str}, SNI={sni}");
                                break;
                            }
                        }
                    }
                }
            }
        }

        let record_len = 5 + record.fragment.len();
        let node = ProtocolNode {
            protocol: "TLS".into(),
            byte_range: 0..record_len,
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
    fn test_tls_record_parse() {
        // TLS 1.2 Handshake ClientHello
        #[rustfmt::skip]
        let data = vec![
            0x16,       // Handshake
            0x03, 0x03, // TLS 1.2
            0x00, 0x05, // length = 5
            // Fragment (ClientHello type + length)
            0x01, 0x00, 0x00, 0x01, 0x00,
        ];

        let dissector = TlsDissector;
        let mut ctx = DissectionContext::new(16);
        ctx.next_protocol_hint = Some(Protocol::Tls);

        let layer = dissector.dissect(&data, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "TLS");
        assert!(layer.node.summary.contains("ClientHello"));
    }
}
