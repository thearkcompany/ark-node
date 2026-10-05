//! Canonical error types for the ARK Sovereign P2P Protocol.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArkError {
    #[error("Magic bytes mismatch: found 0x{0:08X}")]
    InvalidMagic(u32),

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u16),

    #[error("ALPN mismatch: expected strict 'ark-pqc/v1'")]
    ErrAlpnMismatch,

    #[error("Envelope exceeds hard limit: size {0} > max {1} bytes")]
    EnvelopeTooLarge(usize, usize),

    #[error("Payload exceeds budget: size {0} > max {1} bytes")]
    PayloadTooLarge(usize, usize),

    #[error("Cryptographic verification failure: {0}")]
    CryptoError(String),

    #[error("Replay attack detected: duplicate packet or sequence expired")]
    ReplayDetected,

    #[error("Clock drift too large: peer delta {0}s exceeds limit ±{1}s")]
    ClockDriftExceeded(i64, i64),

    #[error("Invalid retry cookie")]
    InvalidRetryCookie,

    #[error("Tag encoding/decoding error: {0}")]
    TagError(String),

    #[error("Protobuf serialization/deserialization failure: {0}")]
    SerializationError(String),

    #[error("Network I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ArkError>;
