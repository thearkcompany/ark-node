pub mod error;
pub mod traits;
pub mod host_abi;
pub mod worker;

pub use error::{PaasError, Result};
pub use host_abi::{
    HostAbiState, DEFAULT_IO_FUEL_BYTES,
    register_host_abi,
};
pub use traits::{
    BlobReaderBackend, EnvelopeEmitterBackend, InMemoryBlobReader,
    InMemoryEnvelopeEmitter, InMemoryKvStore, InMemoryPmtClock,
    KvStoreBackend, PmtClockBackend,
};
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
