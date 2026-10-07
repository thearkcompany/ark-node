use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PaasError {
    #[error("Compilation error: {0}")]
    CompilationFailed(String),

    #[error("Instantiation error: {0}")]
    InstantiationFailed(String),

    #[error("Execution error: {0}")]
    ExecutionFailed(String),

    #[error("CPU fuel exhausted during execution")]
    CpuFuelExhausted,

    #[error("Memory allocation ceiling exceeded (limit: {limit_bytes} bytes, requested/allocated: {requested_bytes} bytes)")]
    MemoryLimitExceeded {
        limit_bytes: usize,
        requested_bytes: usize,
    },

    #[error("Epoch deadline exceeded: worker preemptively halted")]
    EpochDeadlineExceeded,

    #[error("I/O fuel exhausted (budget: {limit_bytes} bytes)")]
    IoFuelExhausted {
        limit_bytes: usize,
    },

    #[error("Missing exported entrypoint: '{0}'")]
    ExportNotFound(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Sandbox violation: {0}")]
    SandboxViolation(String),

    #[error("Worker not found: '{0}'")]
    WorkerNotFound(String),

    #[error("Protobuf error: {0}")]
    Protobuf(String),

    #[error("Queue error: {0}")]
    QueueError(String),
}


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

pub type Result<T> = std::result::Result<T, PaasError>;
pub type QueueResult<T> = std::result::Result<T, ArkQueueError>;
