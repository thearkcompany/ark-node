use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArkCrdtError {
    #[error("Storage error: {0}")]
    Storage(#[from] ark_storage::ArkStorageError),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Invalid node hash: expected {expected}, actual {actual}")]
    InvalidNodeHash { expected: String, actual: String },

    #[error("Depth limit exceeded: {0}")]
    DepthLimitExceeded(u32),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

pub type Result<T> = std::result::Result<T, ArkCrdtError>;
