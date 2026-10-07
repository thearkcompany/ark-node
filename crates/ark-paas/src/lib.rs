//! [Preparação para v1.0] Gestor Wasmtime, Ark Queue e Cron.

pub mod error;
pub mod lease;
pub mod queue;

pub use error::{ArkQueueError, Result};
pub use lease::JobLease;
pub use queue::{ArkQueue, QueueConfig, Task, TaskStatus};

pub struct PaasEngine {
    // Wasmtime, queue, and scheduler state
}

impl PaasEngine {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for PaasEngine {
    fn default() -> Self {
        Self::new()
    }
}
