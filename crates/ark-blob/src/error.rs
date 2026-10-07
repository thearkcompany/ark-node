//! Error types for ark-blob.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlobError {
    #[error("Empty payload cannot be encoded")]
    EmptyPayload,

    #[error("Insufficient shards provided: {available} available, need at least {required}")]
    InsufficientShards { available: usize, required: usize },

    #[error("Duplicate shard index: {0}")]
    DuplicateShardIndex(usize),

    #[error("Invalid shard index: {0}")]
    InvalidShardIndex(usize),

    #[error("Inconsistent shard length or invalid shard buffer size")]
    ShardLengthMismatch,

    #[error("Singular matrix encountered during inversion")]
    SingularMatrix,

    #[error("Original payload length mismatch or invalid")]
    InvalidPayloadLength,

    #[error("Invalid shard count: expected {expected}, got {got}")]
    InvalidShardCount { expected: usize, got: usize },

    #[error("Invalid shard size: expected {expected} bytes, got {got} bytes")]
    InvalidShardSize { expected: usize, got: usize },

    #[error("Invalid sub-block index: {index} (max allowed {max})")]
    InvalidSubBlockIndex { index: usize, max: usize },

    #[error("Invalid sub-block size: expected {expected} bytes, got {got} bytes")]
    InvalidSubBlockSize { expected: usize, got: usize },

    #[error("Shard Merkle proof verification failed")]
    InvalidMerkleProof,

    #[error("Shard not found: {0}")]
    ShardNotFound(String),

    #[error("Corrupted shard {hash}: expected hash {expected}, got {got}")]
    CorruptedShard {
        hash: String,
        expected: String,
        got: String,
    },

    #[error("Manifest not found for blob CID: {0}")]
    ManifestNotFound(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Proof serialization error: {0}")]
    SerializationError(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Invalid custody state transition from {from} to {to}")]
    InvalidCustodyTransition { from: String, to: String },

    #[error("File size {size} bytes exceeds maximum staged custody limit of {max} bytes (<25 MB)")]
    IneligibleForStagedCustody { size: u64, max: u64 },

    #[error("Invalid envelope format or kind: {0}")]
    InvalidEnvelope(String),

    #[error("Cryptographic signature verification failed: {0}")]
    InvalidSignature(String),

    #[error("Safe-ghost lock is active: eviction prevented (homelab ACK not confirmed, PoR challenges: {challenges}/{required})")]
    SafeGhostLocked {
        challenges: usize,
        required: usize,
    },
}

impl From<std::io::Error> for BlobError {
    fn from(err: std::io::Error) -> Self {
        BlobError::Io(err.to_string())
    }
}

impl From<ark_storage::ArkStorageError> for BlobError {
    fn from(err: ark_storage::ArkStorageError) -> Self {
        BlobError::Storage(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, BlobError>;
