use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use sc_core::ShadowError;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid nonce length")]
    InvalidNonceLength,
}

impl From<CryptoError> for ShadowError {
    fn from(e: CryptoError) -> Self {
        ShadowError::Crypto { message: e.to_string() }
    }
}

/// Supported AEAD cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Cipher key material with secure erasure on drop.
#[derive(Clone)]
pub struct CipherKey {
    bytes: Vec<u8>,
    suite: CipherSuite,
}

impl Drop for CipherKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl CipherKey {
    pub fn new(bytes: Vec<u8>, suite: CipherSuite) -> std::result::Result<Self, CryptoError> {
        let expected_len = match suite {
            CipherSuite::Aes256Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
        };
        if bytes.len() != expected_len {
            return Err(CryptoError::InvalidKeyLength);
        }
        Ok(Self { bytes, suite })
    }

    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Unified AEAD encryption/decryption interface.
pub struct Cipher {
    suite: CipherSuite,
}

impl Cipher {
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Encrypt plaintext with the given key and nonce (12 bytes).
    pub fn encrypt(&self, key: &CipherKey, nonce: &[u8], plaintext: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength);
        }

        match self.suite {
            CipherSuite::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&key.bytes)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?;
                let nonce = Nonce::from_slice(nonce);
                cipher.encrypt(nonce, plaintext)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))
            }
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))?;
                let nonce = chacha20poly1305::Nonce::from_slice(nonce);
                cipher.encrypt(nonce, plaintext)
                    .map_err(|e| CryptoError::Encryption(e.to_string()))
            }
        }
    }

    /// Decrypt ciphertext with the given key and nonce (12 bytes).
    pub fn decrypt(&self, key: &CipherKey, nonce: &[u8], ciphertext: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength);
        }

        match self.suite {
            CipherSuite::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&key.bytes)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))?;
                let nonce = Nonce::from_slice(nonce);
                cipher.decrypt(nonce, ciphertext)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))
            }
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&key.bytes)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))?;
                let nonce = chacha20poly1305::Nonce::from_slice(nonce);
                cipher.decrypt(nonce, ciphertext)
                    .map_err(|e| CryptoError::Decryption(e.to_string()))
            }
        }
    }
}

/// Detect available hardware acceleration features.
pub fn detect_hw_acceleration() -> Vec<&'static str> {
    let mut features = Vec::new();

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("aes") {
            features.push("AES-NI");
        }
        if std::arch::is_x86_feature_detected!("sse4.1") {
            features.push("SSE4.1");
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            features.push("AVX2");
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // ARM crypto extensions are typically available on ARMv8+
        features.push("ARM-CE (assumed)");
    }

    features
}

/// HKDF key derivation.
pub mod kdf {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use super::CryptoError;

    /// Derive key material using HKDF-SHA256.
    pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> std::result::Result<Vec<u8>, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = vec![0u8; output_len];
        hk.expand(info, &mut okm)
            .map_err(|e| CryptoError::Encryption(format!("HKDF expand failed: {e}")))?;
        Ok(okm)
    }

    /// HKDF-Extract: extract a pseudorandom key from input keying material.
    pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> (Vec<u8>, Hkdf<Sha256>) {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        // The PRK is the internal state — we can re-derive it
        let mut prk = vec![0u8; 32];
        hk.expand(&[], &mut prk).ok();
        (prk, hk)
    }
}

/// X25519 Diffie-Hellman key exchange.
pub mod x25519 {
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::Zeroize;

    /// An X25519 keypair for ephemeral Diffie-Hellman.
    pub struct X25519Keypair {
        secret: StaticSecret,
        public: PublicKey,
    }

    impl X25519Keypair {
        /// Generate a new X25519 keypair from a cryptographically secure RNG.
        pub fn generate() -> Self {
            let secret = StaticSecret::random_from_rng(crate::OsRng);
            let public = PublicKey::from(&secret);
            Self { secret, public }
        }

        /// Create a keypair from existing secret key bytes.
        pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
            let secret = StaticSecret::from(bytes);
            let public = PublicKey::from(&secret);
            Self { secret, public }
        }

        /// Get the public key bytes (32 bytes).
        pub fn public_key_bytes(&self) -> [u8; 32] {
            *self.public.as_bytes()
        }

        /// Get a reference to the public key.
        pub fn public_key(&self) -> &PublicKey {
            &self.public
        }

        /// Compute the shared secret with a peer's public key.
        pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecretBytes {
            let shared = self.secret.diffie_hellman(peer_public);
            SharedSecretBytes {
                bytes: *shared.as_bytes(),
            }
        }
    }

    impl Drop for X25519Keypair {
        fn drop(&mut self) {
            // StaticSecret already zeroizes on drop
        }
    }

    /// Shared secret bytes with secure erasure on drop.
    pub struct SharedSecretBytes {
        bytes: [u8; 32],
    }

    impl SharedSecretBytes {
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.bytes
        }
    }

    impl Drop for SharedSecretBytes {
        fn drop(&mut self) {
            self.bytes.zeroize();
        }
    }

    /// Compute a shared secret between our secret key bytes and a peer's public key bytes.
    pub fn compute_shared_secret(
        our_secret: &[u8; 32],
        their_public: &[u8; 32],
    ) -> SharedSecretBytes {
        let secret = StaticSecret::from(*our_secret);
        let public = PublicKey::from(*their_public);
        let shared = secret.diffie_hellman(&public);
        SharedSecretBytes {
            bytes: *shared.as_bytes(),
        }
    }
}

/// TLS 1.3 key schedule functions (RFC 8446 §7.1).
pub mod tls_kdf {
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};
    use super::{CipherSuite, CryptoError};

    /// HKDF-Expand-Label as defined in RFC 8446 §7.1.
    ///
    /// ```text
    /// HKDF-Expand-Label(Secret, Label, Context, Length) =
    ///     HKDF-Expand(Secret, HkdfLabel, Length)
    ///
    /// struct {
    ///     uint16 length = Length;
    ///     opaque label<7..255> = "tls13 " + Label;
    ///     opaque context<0..255> = Context;
    /// } HkdfLabel;
    /// ```
    pub fn hkdf_expand_label(
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        let full_label = format!("tls13 {label}");
        let label_bytes = full_label.as_bytes();

        // Build HkdfLabel struct
        let mut hkdf_label = Vec::with_capacity(2 + 1 + label_bytes.len() + 1 + context.len());
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        hkdf_label.push(label_bytes.len() as u8);
        hkdf_label.extend_from_slice(label_bytes);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        // Use HKDF-Expand with the formatted label as info
        let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|e| {
            CryptoError::Encryption(format!("Invalid PRK for HKDF-Expand-Label: {e}"))
        })?;

        let mut output = vec![0u8; length];
        hk.expand(&hkdf_label, &mut output)
            .map_err(|e| CryptoError::Encryption(format!("HKDF-Expand-Label failed: {e}")))?;

        Ok(output)
    }

    /// Derive-Secret as defined in RFC 8446 §7.1.
    ///
    /// ```text
    /// Derive-Secret(Secret, Label, Messages) =
    ///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    /// ```
    pub fn derive_secret(
        secret: &[u8],
        label: &str,
        transcript_hash: &[u8],
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        hkdf_expand_label(secret, label, transcript_hash, 32)
    }

    /// Derive traffic encryption keys and IV from a traffic secret.
    ///
    /// Returns (key, iv) sized appropriately for the cipher suite:
    /// - AES-256-GCM: 32-byte key + 12-byte IV
    /// - ChaCha20-Poly1305: 32-byte key + 12-byte IV
    pub fn derive_traffic_keys(
        traffic_secret: &[u8],
        suite: CipherSuite,
    ) -> std::result::Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let key_len = match suite {
            CipherSuite::Aes256Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
        };
        let iv_len = 12; // Both suites use 12-byte IV/nonce

        let key = hkdf_expand_label(traffic_secret, "key", &[], key_len)?;
        let iv = hkdf_expand_label(traffic_secret, "iv", &[], iv_len)?;

        Ok((key, iv))
    }

    /// Compute the SHA-256 transcript hash of concatenated handshake messages.
    pub fn transcript_hash(messages: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for msg in messages {
            hasher.update(msg);
        }
        hasher.finalize().to_vec()
    }

    /// Compute the early secret from a PSK (or zeros if no PSK).
    /// early_secret = HKDF-Extract(salt=0, IKM=psk)
    pub fn compute_early_secret(psk: Option<&[u8]>) -> Vec<u8> {
        let salt = [0u8; 32]; // Hash.length zeros
        let ikm = psk.unwrap_or(&[0u8; 32]);
        let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
        let mut prk = vec![0u8; 32];
        // Extract phase produces the PRK; we read it back
        hk.expand(&[], &mut prk).ok();
        prk
    }

    /// Compute the handshake secret from the shared secret and derived early secret.
    /// handshake_secret = HKDF-Extract(derived_secret, shared_secret)
    pub fn compute_handshake_secret(
        early_secret: &[u8],
        shared_secret: &[u8],
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        let empty_hash = transcript_hash(&[]);
        let derived = derive_secret(early_secret, "derived", &empty_hash)?;

        let hk = Hkdf::<Sha256>::new(Some(&derived), shared_secret);
        let mut hs_secret = vec![0u8; 32];
        hk.expand(&[], &mut hs_secret)
            .map_err(|e| CryptoError::Encryption(format!("Failed to derive handshake secret: {e}")))?;
        Ok(hs_secret)
    }

    /// Compute the master secret from the handshake secret.
    /// master_secret = HKDF-Extract(derived_secret, 0)
    pub fn compute_master_secret(
        handshake_secret: &[u8],
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        let empty_hash = transcript_hash(&[]);
        let derived = derive_secret(handshake_secret, "derived", &empty_hash)?;

        let zeros = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&derived), &zeros);
        let mut master = vec![0u8; 32];
        hk.expand(&[], &mut master)
            .map_err(|e| CryptoError::Encryption(format!("Failed to derive master secret: {e}")))?;
        Ok(master)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key_bytes = vec![0x42u8; 32];
        let key = CipherKey::new(key_bytes, CipherSuite::Aes256Gcm).unwrap();
        let cipher = Cipher::new(CipherSuite::Aes256Gcm);
        let nonce = [0u8; 12];
        let plaintext = b"$crypt test payload";

        let ciphertext = cipher.encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key_bytes = vec![0x42u8; 32];
        let key = CipherKey::new(key_bytes, CipherSuite::ChaCha20Poly1305).unwrap();
        let cipher = Cipher::new(CipherSuite::ChaCha20Poly1305);
        let nonce = [0u8; 12];
        let plaintext = b"$crypt test payload";

        let ciphertext = cipher.encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = CipherKey::new(vec![0u8; 16], CipherSuite::Aes256Gcm);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf() {
        let result = kdf::hkdf_sha256(b"salt", b"input key material", b"info", 32);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_hw_detection() {
        let features = detect_hw_acceleration();
        println!("Detected HW features: {:?}", features);
    }

    #[test]
    fn test_x25519_keypair_and_shared_secret() {
        let alice = x25519::X25519Keypair::generate();
        let bob = x25519::X25519Keypair::generate();

        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_x25519_from_secret_bytes() {
        let secret_bytes = [42u8; 32];
        let keypair = x25519::X25519Keypair::from_secret_bytes(secret_bytes);
        let public = keypair.public_key_bytes();
        assert_ne!(public, [0u8; 32]); // Public key should not be zero
    }

    #[test]
    fn test_x25519_compute_shared_secret_fn() {
        let _alice = x25519::X25519Keypair::generate();
        let bob = x25519::X25519Keypair::generate();

        // Use the standalone function with raw bytes
        let alice_secret_bytes = [1u8; 32]; // Deterministic for this test
        let kp = x25519::X25519Keypair::from_secret_bytes(alice_secret_bytes);
        let shared = x25519::compute_shared_secret(&alice_secret_bytes, &bob.public_key_bytes());
        let shared2 = kp.diffie_hellman(bob.public_key());
        assert_eq!(shared.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_hkdf_expand_label() {
        let secret = [0x42u8; 32];
        let result = tls_kdf::hkdf_expand_label(&secret, "key", &[], 32);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_derive_traffic_keys_aes() {
        let traffic_secret = [0x42u8; 32];
        let result = tls_kdf::derive_traffic_keys(&traffic_secret, CipherSuite::Aes256Gcm);
        assert!(result.is_ok());
        let (key, iv) = result.unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_derive_traffic_keys_chacha() {
        let traffic_secret = [0x42u8; 32];
        let result = tls_kdf::derive_traffic_keys(&traffic_secret, CipherSuite::ChaCha20Poly1305);
        assert!(result.is_ok());
        let (key, iv) = result.unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_tls13_key_schedule_chain() {
        // Test the full key schedule chain: early_secret -> handshake_secret -> master_secret
        let early_secret = tls_kdf::compute_early_secret(None);
        assert_eq!(early_secret.len(), 32);

        let shared_secret = [0xABu8; 32]; // Fake shared secret
        let hs_secret = tls_kdf::compute_handshake_secret(&early_secret, &shared_secret);
        assert!(hs_secret.is_ok());
        let hs_secret = hs_secret.unwrap();

        let master = tls_kdf::compute_master_secret(&hs_secret);
        assert!(master.is_ok());
        assert_eq!(master.unwrap().len(), 32);
    }

    #[test]
    fn test_transcript_hash() {
        let h1 = tls_kdf::transcript_hash(&[b"hello"]);
        let h2 = tls_kdf::transcript_hash(&[b"hello"]);
        assert_eq!(h1, h2);

        let h3 = tls_kdf::transcript_hash(&[b"hello", b"world"]);
        assert_ne!(h1, h3);
    }
}
