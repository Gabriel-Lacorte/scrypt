use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use sc_core::{Result, ShadowError};
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
}
