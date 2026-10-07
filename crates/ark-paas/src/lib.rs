//! [AEP-01] ark-paas: Sovereign Sandboxed Compute & Execution Engine
//!
//! Provides WebAssembly sandboxed runtime (Wasmtime) for `wasm32-unknown-unknown`
//! modules with deterministic dual-pool fuel metering (CPU fuel and I/O fuel),
//! strict memory ceilings (64 MB via StoreLimitsBuilder), and epoch deadline timers.

pub mod error;
pub mod worker;

pub use error::{PaasError, Result};
pub use worker::{
    WasmWorker, WasmWorkerConfig, WorkerStoreData, DEFAULT_CPU_FUEL, DEFAULT_EPOCH_TICKS,
    DEFAULT_MEMORY_LIMIT_BYTES,
};

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
