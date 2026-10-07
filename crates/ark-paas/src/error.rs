use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArkQueueError {
    #[error("Storage error: {0}")]
    Storage(#[from] ark_storage::ArkStorageError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Task not found: {0}")]
    TaskNotFound(String),

    #[error("Lease error: {0}")]
    LeaseExpired(String),

    #[error("Invalid state transition for task {0}: from {1:?} to {2:?}")]
    InvalidStateTransition(String, crate::queue::TaskStatus, crate::queue::TaskStatus),
}

pub type Result<T> = std::result::Result<T, ArkQueueError>;
