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

    #[error("Invalid cryptographic signature: {0}")]
    InvalidSignature(String),

    #[error("Storage error: {0}")]
    Storage(#[from] ark_storage::ArkStorageError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Insufficient Proof-of-Work: expected at least {required_bits} leading zero bits, found {actual_bits}")]
    InsufficientProofOfWork {
        required_bits: usize,
        actual_bits: usize,
    },

    #[error("Missing required tag: 0x{0:04X}")]
    MissingTag(u32),

    #[error("Unverified L2 contract: {0}")]
    UnverifiedL2Contract(String),

    #[error("L2 verification failed: {0}")]
    L2VerificationFailed(String),

    #[error("Grace period renewal unauthorized: domain '{fqdn}' is owned by 0x{current_owner:x?}, cannot be renewed by 0x{attempted_by:x?}")]
    GracePeriodRenewalUnauthorized {
        fqdn: String,
        current_owner: [u8; 16],
        attempted_by: [u8; 16],
    },

    #[error("Renewal unauthorized: domain '{fqdn}' is owned by 0x{current_owner:x?}, cannot be renewed by 0x{attempted_by:x?}")]
    UnauthorizedRenewal {
        fqdn: String,
        current_owner: [u8; 16],
        attempted_by: [u8; 16],
    },

    #[error("Domain '{fqdn}' is already active and owned by 0x{current_owner:x?}")]
    DomainAlreadyActive {
        fqdn: String,
        current_owner: [u8; 16],
    },

    #[error("Invalid lease duration: {0}")]
    InvalidLeaseDuration(String),

    #[error("Domain '{0}' not found (NXDOMAIN)")]
    NotFound(String),
}


pub type Result<T> = std::result::Result<T, DnsError>;
