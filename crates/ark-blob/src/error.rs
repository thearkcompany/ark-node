//! Error types for ark-blob.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlobError {
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
}

pub type Result<T> = std::result::Result<T, BlobError>;
