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

    #[error("Proof serialization error: {0}")]
    SerializationError(String),

    #[error("I/O error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, BlobError>;
