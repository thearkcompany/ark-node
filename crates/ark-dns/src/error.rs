//! Error types for the ark-dns subsystem.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),

    #[error("Not a cryptographic domain name (expected prefix ark1...ark): {0}")]
    NotCryptographicName(String),

    #[error("Invalid Bech32 encoding or format: {0}")]
    InvalidBech32(String),

    #[error("Identity mismatch: domain identity hash {expected_hex} does not match public key hash {actual_hex}")]
    IdentityMismatch {
        expected_hex: String,
        actual_hex: String,
    },

    #[error("Invalid record data: {0}")]
    InvalidRecord(String),

    #[error("Storage error: {0}")]
    Storage(#[from] ark_storage::ArkStorageError),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, DnsError>;
