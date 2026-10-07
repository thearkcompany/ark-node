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
}

pub type Result<T> = std::result::Result<T, PaasError>;
