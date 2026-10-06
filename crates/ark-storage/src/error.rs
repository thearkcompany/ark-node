use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArkStorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("WORM violation: tampering or deletion attempted on write-once record ({0})")]
    WormViolation(String),

    #[error("Storage corrupted: {0}")]
    Corrupted(String),
}

pub type Result<T> = std::result::Result<T, ArkStorageError>;
