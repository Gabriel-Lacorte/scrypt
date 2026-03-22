use thiserror::Error;

/// Central error type for the $crypt framework.
#[derive(Debug, Error)]
pub enum ShadowError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {message}")]
    Parse { message: String },

    #[error("Plugin error: {message}")]
    Plugin { message: String },

    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Cryptographic error: {message}")]
    Crypto { message: String },

    #[error("Sandbox error: {message}")]
    Sandbox { message: String },

    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Protocol dissection error: {message}")]
    Dissection { message: String },

    #[error("PCAP error: {message}")]
    Pcap { message: String },

    #[error("TLS error: {message}")]
    Tls { message: String },
}

pub type Result<T> = std::result::Result<T, ShadowError>;
