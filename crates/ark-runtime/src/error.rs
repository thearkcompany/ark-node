use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArkRuntimeError {
    #[error("Core protocol error: {0}")]
    Core(#[from] ark_core::error::ArkError),

    #[error("Storage error: {0}")]
    Storage(#[from] ark_storage::ArkStorageError),

    #[error("DNS error: {0}")]
    Dns(#[from] ark_dns::error::DnsError),

    #[error("WoT error: {0}")]
    Wot(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Quic transport error: {0}")]
    Quic(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Runtime error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ArkRuntimeError>;
