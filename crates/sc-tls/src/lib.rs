use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;
use sc_core::{Protocol, Result, ShadowError};
use sc_crypto::{CipherKey, CipherSuite};
use sc_protocol::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::debug;

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

    Ok((
        input,
        TlsRecord {
            content_type: ContentType::from(content_type_byte),
            version_major,
            version_minor,
            fragment,
        },
    ))
}

// ---------------------------------------------------------------------------
// Extension parsing
// ---------------------------------------------------------------------------

/// Known TLS extension type IDs.
mod ext_types {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
}

/// Parsed TLS extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub name: String,
    pub data: Vec<u8>,
}

/// Human-readable name for an extension type.
fn extension_name(ext_type: u16) -> String {
    match ext_type {
        ext_types::SERVER_NAME => "server_name (SNI)".into(),
        ext_types::SUPPORTED_VERSIONS => "supported_versions".into(),
        ext_types::KEY_SHARE => "key_share".into(),
        ext_types::SIGNATURE_ALGORITHMS => "signature_algorithms".into(),
        ext_types::ALPN => "application_layer_protocol_negotiation".into(),
        0x0001 => "max_fragment_length".into(),
        0x0005 => "status_request".into(),
        0x000a => "supported_groups".into(),
        0x000b => "ec_point_formats".into(),
        0x0017 => "extended_master_secret".into(),
        0x0023 => "session_ticket".into(),
        0x002d => "psk_key_exchange_modes".into(),
        0xff01 => "renegotiation_info".into(),
        _ => format!("unknown (0x{ext_type:04x})"),
    }
}

/// Parse TLS extensions from a byte slice.
/// Returns a list of parsed extensions.
fn parse_extensions(data: &[u8]) -> Vec<TlsExtension> {
    let mut extensions = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > data.len() {
            break;
        }
        extensions.push(TlsExtension {
            ext_type,
            name: extension_name(ext_type),
            data: data[pos..pos + ext_len].to_vec(),
        });
        pos += ext_len;
    }
    extensions
}

/// Extract SNI hostname from an SNI extension's data.
fn parse_sni_from_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // server_name_list_length (2) + host_name type (1, must be 0) + name_length (2)
    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let name_type = data[2];
    if name_type != 0 {
        return None; // Only host_name type supported
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() >= 5 + name_len {
        String::from_utf8(data[5..5 + name_len].to_vec()).ok()
    } else {
        None
    }
}

/// Extract supported TLS versions from supported_versions extension.
fn parse_supported_versions(data: &[u8], is_server_hello: bool) -> Vec<String> {
    let mut versions = Vec::new();
    if is_server_hello {
        // ServerHello: selected_version is 2 bytes
        if data.len() >= 2 {
            versions.push(format_tls_version(data[0], data[1]));
        }
    } else {
        // ClientHello: 1-byte length + list of 2-byte versions
        if data.is_empty() {
            return versions;
        }
        let list_len = data[0] as usize;
        let mut pos = 1;
        while pos + 1 < data.len() && pos < 1 + list_len {
            versions.push(format_tls_version(data[pos], data[pos + 1]));
            pos += 2;
        }
    }
    versions
}

fn format_tls_version(major: u8, minor: u8) -> String {
    match (major, minor) {
        (3, 0) => "SSL 3.0".into(),
        (3, 1) => "TLS 1.0".into(),
        (3, 2) => "TLS 1.1".into(),
        (3, 3) => "TLS 1.2".into(),
        (3, 4) => "TLS 1.3".into(),
        _ => format!("0x{major:02x}{minor:02x}"),
    }
}

/// Extract ALPN protocol names from an ALPN extension.
fn parse_alpn(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    if data.len() < 2 {
        return protocols;
    }
    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    while pos < data.len() {
        let proto_len = data[pos] as usize;
        pos += 1;
        if pos + proto_len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[pos..pos + proto_len]) {
            protocols.push(s.to_string());
        }
        pos += proto_len;
    }
    protocols
}

// ---------------------------------------------------------------------------
// ClientHello / ServerHello parsing
// ---------------------------------------------------------------------------

/// Parsed ClientHello information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHelloInfo {
    pub version: String,
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub sni: Option<String>,
    pub supported_versions: Vec<String>,
    pub alpn_protocols: Vec<String>,
    pub extensions: Vec<TlsExtension>,
}

/// Parsed ServerHello information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHelloInfo {
    pub version: String,
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub selected_version: Option<String>,
    pub extensions: Vec<TlsExtension>,
}

/// Parse a ClientHello handshake message body (after the 4-byte handshake header).
pub fn parse_client_hello(data: &[u8]) -> std::result::Result<ClientHelloInfo, ShadowError> {
    if data.len() < 38 {
        return Err(ShadowError::Tls {
            message: "ClientHello too short".into(),
        });
    }

    let version = format_tls_version(data[0], data[1]);
    let random = data[2..34].to_vec();

    let mut pos = 34;
    // Session ID
    if pos >= data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated session_id".into(),
        });
    }
    let sid_len = data[pos] as usize;
    pos += 1;
    if pos + sid_len > data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated session_id data".into(),
        });
    }
    let session_id = data[pos..pos + sid_len].to_vec();
    pos += sid_len;

    // Cipher suites
    if pos + 2 > data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated cipher_suites".into(),
        });
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated cipher_suites data".into(),
        });
    }
    let mut cipher_suites = Vec::new();
    let cs_end = pos + cs_len;
    while pos + 1 < cs_end {
        cipher_suites.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    pos = cs_end;

    // Compression methods
    if pos >= data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated compression".into(),
        });
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    let extensions = if pos + 2 <= data.len() {
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + ext_len <= data.len() {
            parse_extensions(&data[pos..pos + ext_len])
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Extract high-level info from extensions
    let sni = extensions
        .iter()
        .find(|e| e.ext_type == ext_types::SERVER_NAME)
        .and_then(|e| parse_sni_from_extension(&e.data));

    let supported_versions = extensions
        .iter()
        .find(|e| e.ext_type == ext_types::SUPPORTED_VERSIONS)
        .map(|e| parse_supported_versions(&e.data, false))
        .unwrap_or_default();

    let alpn_protocols = extensions
        .iter()
        .find(|e| e.ext_type == ext_types::ALPN)
        .map(|e| parse_alpn(&e.data))
        .unwrap_or_default();

    Ok(ClientHelloInfo {
        version,
        random,
        session_id,
        cipher_suites,
        sni,
        supported_versions,
        alpn_protocols,
        extensions,
    })
}

/// Parse a ServerHello handshake message body (after the 4-byte handshake header).
pub fn parse_server_hello(data: &[u8]) -> std::result::Result<ServerHelloInfo, ShadowError> {
    if data.len() < 38 {
        return Err(ShadowError::Tls {
            message: "ServerHello too short".into(),
        });
    }

    let version = format_tls_version(data[0], data[1]);
    let random = data[2..34].to_vec();

    let mut pos = 34;
    // Session ID
    if pos >= data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated session_id".into(),
        });
    }
    let sid_len = data[pos] as usize;
    pos += 1;
    if pos + sid_len > data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated session_id data".into(),
        });
    }
    let session_id = data[pos..pos + sid_len].to_vec();
    pos += sid_len;

    // Cipher suite (2 bytes)
    if pos + 2 > data.len() {
        return Err(ShadowError::Tls {
            message: "Truncated cipher_suite".into(),
        });
    }
    let cipher_suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Compression method (1 byte)
    pos += 1;

    // Extensions
    let extensions = if pos + 2 <= data.len() {
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + ext_len <= data.len() {
            parse_extensions(&data[pos..pos + ext_len])
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let selected_version = extensions
        .iter()
        .find(|e| e.ext_type == ext_types::SUPPORTED_VERSIONS)
        .map(|e| parse_supported_versions(&e.data, true))
        .and_then(|v| v.into_iter().next());

    Ok(ServerHelloInfo {
        version,
        random,
        session_id,
        cipher_suite,
        selected_version,
        extensions,
    })
}

// ---------------------------------------------------------------------------
// Certificate parsing via x509-parser
// ---------------------------------------------------------------------------

/// Parsed certificate information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sans: Vec<String>,
    pub fingerprint_sha256: String,
}

/// Parse a TLS 1.3 Certificate handshake message body.
/// The format is: request_context(1) + cert_list_length(3) + entries.
/// Each entry: cert_data_length(3) + cert_data + extensions_length(2) + extensions.
pub fn parse_certificate_message(data: &[u8]) -> Vec<CertificateInfo> {
    let mut certs = Vec::new();
    if data.len() < 4 {
        return certs;
    }

    let ctx_len = data[0] as usize;
    let mut pos = 1 + ctx_len;

    if pos + 3 > data.len() {
        return certs;
    }
    let list_len =
        ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
    pos += 3;
    let list_end = (pos + list_len).min(data.len());

    while pos + 3 <= list_end {
        let cert_len = ((data[pos] as usize) << 16)
            | ((data[pos + 1] as usize) << 8)
            | (data[pos + 2] as usize);
        pos += 3;
        if pos + cert_len > list_end {
            break;
        }
        let cert_data = &data[pos..pos + cert_len];
        pos += cert_len;

        // TLS 1.3: skip per-certificate extensions
        if pos + 2 <= list_end {
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2 + ext_len;
        }

        if let Some(info) = parse_x509_cert(cert_data) {
            certs.push(info);
        }
    }

    certs
}

/// Parse a single DER-encoded X.509 certificate using x509-parser.
fn parse_x509_cert(der: &[u8]) -> Option<CertificateInfo> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();

    // Extract Subject Alternative Names
    let mut sans = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(dns) => {
                    sans.push(dns.to_string());
                }
                x509_parser::extensions::GeneralName::IPAddress(ip) => {
                    sans.push(format!("{ip:?}"));
                }
                _ => {}
            }
        }
    }

    // SHA-256 fingerprint
    let mut hasher = Sha256::new();
    hasher.update(der);
    let fp = hasher.finalize();
    let fingerprint_sha256 = fp
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    Some(CertificateInfo {
        subject,
        issuer,
        not_before,
        not_after,
        sans,
        fingerprint_sha256,
    })
}

// ---------------------------------------------------------------------------
// SSLKEYLOGFILE reader
// ---------------------------------------------------------------------------

/// An in-memory store of TLS session secrets parsed from an SSLKEYLOGFILE.
///
/// The file format (NSS key log) has lines like:
/// ```text
/// CLIENT_RANDOM <client_random_hex> <master_secret_hex>
/// CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
/// SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
/// CLIENT_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
/// SERVER_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
/// ```
#[derive(Debug, Clone, Default)]
pub struct KeyLog {
    /// Map: client_random (bytes) -> label -> secret (bytes)
    entries: HashMap<Vec<u8>, HashMap<String, Vec<u8>>>,
}

impl KeyLog {
    /// Load an SSLKEYLOGFILE from disk.
    pub fn load(path: &Path) -> std::result::Result<Self, ShadowError> {
        let content = std::fs::read_to_string(path).map_err(|e| ShadowError::Tls {
            message: format!("Failed to read SSLKEYLOGFILE: {e}"),
        })?;
        Self::parse(&content)
    }

    /// Parse SSLKEYLOGFILE content from a string.
    pub fn parse(content: &str) -> std::result::Result<Self, ShadowError> {
        let mut entries: HashMap<Vec<u8>, HashMap<String, Vec<u8>>> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() != 3 {
                continue;
            }
            let label = parts[0];
            let client_random = match hex_decode(parts[1]) {
                Some(v) => v,
                None => continue,
            };
            let secret = match hex_decode(parts[2]) {
                Some(v) => v,
                None => continue,
            };
            entries
                .entry(client_random)
                .or_default()
                .insert(label.to_string(), secret);
        }

        debug!(entries = entries.len(), "Parsed SSLKEYLOGFILE entries");
        Ok(Self { entries })
    }

    /// Look up a secret by client_random and label.
    pub fn get_secret(&self, client_random: &[u8], label: &str) -> Option<&Vec<u8>> {
        self.entries.get(client_random).and_then(|m| m.get(label))
    }

    /// Return number of unique client_random entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

// ---------------------------------------------------------------------------
// ApplicationData decryption
// ---------------------------------------------------------------------------

/// Decrypt a TLS 1.3 ApplicationData record.
///
/// The `traffic_secret` should be the appropriate client or server traffic secret.
/// The `sequence_number` is used to construct the per-record nonce.
/// Returns the decrypted inner plaintext (with padding and inner content type stripped).
pub fn decrypt_tls13_record(
    encrypted_fragment: &[u8],
    traffic_secret: &[u8],
    sequence_number: u64,
    suite: CipherSuite,
) -> std::result::Result<(ContentType, Vec<u8>), ShadowError> {
    // Derive key and IV from the traffic secret
    let (key_bytes, iv_bytes) = sc_crypto::tls_kdf::derive_traffic_keys(traffic_secret, suite)
        .map_err(|e| ShadowError::Tls {
            message: format!("Key derivation failed: {e}"),
        })?;

    // Construct per-record nonce: XOR the IV with the sequence number (padded to IV length)
    let mut nonce = iv_bytes.clone();
    let seq_bytes = sequence_number.to_be_bytes();
    let offset = nonce.len().saturating_sub(8);
    for i in 0..8 {
        nonce[offset + i] ^= seq_bytes[i];
    }

    // Construct AAD: the TLS record header for the outer record
    // content_type(1) = 0x17, version(2) = 0x0303, length(2) = encrypted_fragment.len()
    let record_len = encrypted_fragment.len() as u16;
    let aad = [
        0x17, // ApplicationData
        0x03,
        0x03, // TLS 1.2 (wire version for TLS 1.3)
        (record_len >> 8) as u8,
        (record_len & 0xff) as u8,
    ];

    // Decrypt using AEAD — for now we use the Cipher with key and nonce directly
    // Note: AEAD requires AAD, which aes-gcm/chacha20 support as associated data
    let cipher_key = CipherKey::new(key_bytes, suite).map_err(|e| ShadowError::Tls {
        message: format!("Invalid derived key: {e}"),
    })?;

    let plaintext = decrypt_aead_with_aad(&cipher_key, &nonce, encrypted_fragment, &aad, suite)?;

    // TLS 1.3: plaintext = content + content_type(1) + zeros (padding)
    // Strip trailing zeros (padding) then the last byte is the real content type
    let mut end = plaintext.len();
    while end > 0 && plaintext[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(ShadowError::Tls {
            message: "Decrypted record is empty after removing padding".into(),
        });
    }
    let inner_content_type = ContentType::from(plaintext[end - 1]);
    let content = plaintext[..end - 1].to_vec();

    Ok((inner_content_type, content))
}

/// AEAD decrypt with additional authenticated data.
fn decrypt_aead_with_aad(
    key: &CipherKey,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    suite: CipherSuite,
) -> std::result::Result<Vec<u8>, ShadowError> {
    use aes_gcm::aead::Payload;

    match suite {
        CipherSuite::Aes256Gcm => {
            use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
            let cipher = Aes256Gcm::new_from_slice(key.bytes()).map_err(|e| ShadowError::Tls {
                message: format!("AES key error: {e}"),
            })?;
            let nonce = Nonce::from_slice(nonce);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|e| ShadowError::Tls {
                    message: format!("AES-GCM decryption failed: {e}"),
                })
        }
        CipherSuite::ChaCha20Poly1305 => {
            use chacha20poly1305::{aead::Aead, aead::KeyInit, ChaCha20Poly1305};
            let cipher =
                ChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|e| ShadowError::Tls {
                    message: format!("ChaCha20 key error: {e}"),
                })?;
            let nonce = chacha20poly1305::Nonce::from_slice(nonce);
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher
                .decrypt(nonce, payload)
                .map_err(|e| ShadowError::Tls {
                    message: format!("ChaCha20-Poly1305 decryption failed: {e}"),
                })
        }
    }
}

// ---------------------------------------------------------------------------
// Dissector trait implementation
// ---------------------------------------------------------------------------

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

        let version_str = format_tls_version(record.version_major, record.version_minor);

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
                display_value: version_str.clone(),
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

        // Parse handshake messages
        if record.content_type == ContentType::Handshake && record.fragment.len() >= 4 {
            let hs_type = HandshakeType::from(record.fragment[0]);
            let hs_len = ((record.fragment[1] as usize) << 16)
                | ((record.fragment[2] as usize) << 8)
                | (record.fragment[3] as usize);
            let hs_body = if record.fragment.len() >= 4 + hs_len {
                &record.fragment[4..4 + hs_len]
            } else {
                &record.fragment[4..]
            };

            fields.push(Field {
                name: "Handshake Type".into(),
                display_value: format!("{hs_type}"),
                byte_range: 5..6,
                field_type: FieldType::Enum {
                    value: record.fragment[0] as u32,
                    label: hs_type.to_string(),
                },
            });

            match hs_type {
                HandshakeType::ClientHello => {
                    if let Ok(ch) = parse_client_hello(hs_body) {
                        if let Some(ref sni) = ch.sni {
                            fields.push(Field {
                                name: "SNI".into(),
                                display_value: sni.clone(),
                                byte_range: 0..0,
                                field_type: FieldType::String,
                            });
                        }
                        if !ch.supported_versions.is_empty() {
                            fields.push(Field {
                                name: "Supported Versions".into(),
                                display_value: ch.supported_versions.join(", "),
                                byte_range: 0..0,
                                field_type: FieldType::String,
                            });
                        }
                        if !ch.alpn_protocols.is_empty() {
                            fields.push(Field {
                                name: "ALPN".into(),
                                display_value: ch.alpn_protocols.join(", "),
                                byte_range: 0..0,
                                field_type: FieldType::String,
                            });
                        }
                        fields.push(Field {
                            name: "Cipher Suites".into(),
                            display_value: format!("{} suites", ch.cipher_suites.len()),
                            byte_range: 0..0,
                            field_type: FieldType::String,
                        });
                        let sni_part = ch.sni.as_deref().unwrap_or("(no SNI)");
                        summary = format!("ClientHello, {sni_part}");
                        if !ch.supported_versions.is_empty() {
                            summary = format!("{summary}, {}", ch.supported_versions.join("/"));
                        }
                    } else {
                        summary = format!("ClientHello, {version_str}");
                    }
                }
                HandshakeType::ServerHello => {
                    if let Ok(sh) = parse_server_hello(hs_body) {
                        let ver = sh.selected_version.as_deref().unwrap_or(&sh.version);
                        fields.push(Field {
                            name: "Selected Version".into(),
                            display_value: ver.to_string(),
                            byte_range: 0..0,
                            field_type: FieldType::String,
                        });
                        fields.push(Field {
                            name: "Cipher Suite".into(),
                            display_value: format!("0x{:04x}", sh.cipher_suite),
                            byte_range: 0..0,
                            field_type: FieldType::UInt16,
                        });
                        summary = format!("ServerHello, {ver}, cipher=0x{:04x}", sh.cipher_suite);
                    } else {
                        summary = format!("ServerHello, {version_str}");
                    }
                }
                HandshakeType::Certificate => {
                    let certs = parse_certificate_message(hs_body);
                    if !certs.is_empty() {
                        fields.push(Field {
                            name: "Certificates".into(),
                            display_value: format!("{} certificate(s)", certs.len()),
                            byte_range: 0..0,
                            field_type: FieldType::String,
                        });
                        for (i, cert) in certs.iter().enumerate() {
                            fields.push(Field {
                                name: format!("Cert[{i}] Subject"),
                                display_value: cert.subject.clone(),
                                byte_range: 0..0,
                                field_type: FieldType::String,
                            });
                            fields.push(Field {
                                name: format!("Cert[{i}] Issuer"),
                                display_value: cert.issuer.clone(),
                                byte_range: 0..0,
                                field_type: FieldType::String,
                            });
                            if !cert.sans.is_empty() {
                                fields.push(Field {
                                    name: format!("Cert[{i}] SANs"),
                                    display_value: cert.sans.join(", "),
                                    byte_range: 0..0,
                                    field_type: FieldType::String,
                                });
                            }
                            fields.push(Field {
                                name: format!("Cert[{i}] SHA-256"),
                                display_value: cert.fingerprint_sha256.clone(),
                                byte_range: 0..0,
                                field_type: FieldType::String,
                            });
                        }
                        summary = format!("Certificate, {} cert(s)", certs.len());
                        if let Some(first) = certs.first() {
                            summary = format!("{summary}, {}", first.subject);
                        }
                    } else {
                        summary = format!("Certificate, {version_str}");
                    }
                }
                _ => {
                    summary = format!("{hs_type}, {version_str}");
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
        // TLS 1.2 Handshake ClientHello (minimal)
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

    #[test]
    fn test_parse_client_hello_full() {
        // Construct a realistic ClientHello
        #[rustfmt::skip]
        let mut ch = vec![
            // client_version
            0x03, 0x03,
            // random (32 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            // session_id length = 0
            0x00,
            // cipher_suites length = 4 (2 suites)
            0x00, 0x04,
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            // compression_methods length = 1
            0x01,
            0x00, // null compression
        ];

        // Extensions: SNI + supported_versions + ALPN
        let sni_hostname = b"example.com";
        let sni_ext: Vec<u8> = {
            let mut e = Vec::new();
            // server_name_list_length
            let name_entry_len = 1 + 2 + sni_hostname.len(); // type(1)+len(2)+name
            e.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
            e.push(0x00); // host_name type
            e.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
            e.extend_from_slice(sni_hostname);
            e
        };

        let sv_ext: Vec<u8> = {
            let mut e = Vec::new();
            e.push(4); // list length = 4 (2 versions * 2 bytes)
            e.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
            e.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
            e
        };

        let alpn_ext: Vec<u8> = {
            let mut e = Vec::new();
            let proto = b"h2";
            let proto2 = b"http/1.1";
            let list_len = 1 + proto.len() + 1 + proto2.len();
            e.extend_from_slice(&(list_len as u16).to_be_bytes());
            e.push(proto.len() as u8);
            e.extend_from_slice(proto);
            e.push(proto2.len() as u8);
            e.extend_from_slice(proto2);
            e
        };

        // Build extensions block
        let mut exts = Vec::new();
        // SNI
        exts.extend_from_slice(&ext_types::SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        // supported_versions
        exts.extend_from_slice(&ext_types::SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&(sv_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sv_ext);
        // ALPN
        exts.extend_from_slice(&ext_types::ALPN.to_be_bytes());
        exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn_ext);

        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        let info = parse_client_hello(&ch).unwrap();
        assert_eq!(info.version, "TLS 1.2");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.cipher_suites, vec![0x1301, 0x1302]);
        assert!(info.supported_versions.contains(&"TLS 1.3".to_string()));
        assert!(info.supported_versions.contains(&"TLS 1.2".to_string()));
        assert!(info.alpn_protocols.contains(&"h2".to_string()));
        assert!(info.alpn_protocols.contains(&"http/1.1".to_string()));
    }

    #[test]
    fn test_parse_server_hello() {
        #[rustfmt::skip]
        let mut sh = vec![
            // server_version
            0x03, 0x03,
            // random (32 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            // session_id length = 0
            0x00,
            // cipher_suite
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            // compression_method
            0x00,
        ];

        // Extensions: supported_versions with TLS 1.3
        let sv_ext: Vec<u8> = vec![0x03, 0x04]; // TLS 1.3
        let mut exts = Vec::new();
        exts.extend_from_slice(&ext_types::SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&(sv_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sv_ext);

        sh.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh.extend_from_slice(&exts);

        let info = parse_server_hello(&sh).unwrap();
        assert_eq!(info.cipher_suite, 0x1301);
        assert_eq!(info.selected_version.as_deref(), Some("TLS 1.3"));
    }

    #[test]
    fn test_keylog_parse() {
        let content = "\
# comment line
CLIENT_RANDOM 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 aabbccdd
CLIENT_TRAFFIC_SECRET_0 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 deadbeef
";
        let keylog = KeyLog::parse(content).unwrap();
        assert_eq!(keylog.len(), 1);

        let cr =
            hex_decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
        let secret = keylog.get_secret(&cr, "CLIENT_RANDOM");
        assert!(secret.is_some());
        assert_eq!(secret.unwrap(), &hex_decode("aabbccdd").unwrap());

        let traffic = keylog.get_secret(&cr, "CLIENT_TRAFFIC_SECRET_0");
        assert!(traffic.is_some());
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("aabb"), Some(vec![0xaa, 0xbb]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode("abc"), None); // odd length
    }

    #[test]
    fn test_extension_parsing() {
        // Build a minimal extensions block with one unknown extension
        let data = vec![
            0x00, 0x01, // ext type = 1 (max_fragment_length)
            0x00, 0x01, // length = 1
            0x04, // data
            0xFF, 0x01, // ext type = renegotiation_info
            0x00, 0x01, // length = 1
            0x00, // data
        ];
        let exts = parse_extensions(&data);
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].ext_type, 0x0001);
        assert_eq!(exts[1].ext_type, 0xFF01);
    }
}
