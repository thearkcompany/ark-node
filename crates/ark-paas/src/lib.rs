//! [AEP-01] ark-paas: Sovereign Sandboxed Compute & Execution Engine
//!
//! Provides WebAssembly sandboxed runtime (Wasmtime) for `wasm32-unknown-unknown`
//! modules with deterministic dual-pool fuel metering (CPU fuel and I/O fuel),
//! strict memory ceilings (64 MB via StoreLimitsBuilder), and epoch deadline timers,
//! alongside Ark Queue (Fjall LSM with in-memory ACK elision), Capability Host-ABI,
//! and Ark Cron (PMT-driven).

pub mod cron;
pub mod engine;
pub mod error;
pub mod host_abi;
pub mod lease;
pub mod proto;
pub mod queue;
pub mod traits;
pub mod worker;

pub use cron::{ArkCron, CronJob, CronSchedule, MockPmtClock, PmtClock, UtcDateTime};
pub use engine::{CronPayload, EnvelopePayload, ManualPayload, PaasEngine, Trigger, TriggerSource};
pub use error::{ArkQueueError, PaasError, QueueResult, Result};
pub use host_abi::{register_host_abi, HostAbiState, DEFAULT_IO_FUEL_BYTES};
pub use lease::JobLease;
pub use proto::{
    ExecutionStatus, ExecutionTelemetry, TriggerPayload, TriggerType, WorkerConfig, WorkerManifest,
};
pub use queue::{ArkQueue, QueueConfig, Task, TaskStatus};
pub use traits::{
    BlobReaderBackend, EnvelopeEmitterBackend, InMemoryBlobReader, InMemoryEnvelopeEmitter,
    InMemoryKvStore, InMemoryPmtClock, KvStoreBackend,
};
pub use worker::{
    WasmWorker, WasmWorkerConfig, WorkerStoreData, DEFAULT_CPU_FUEL, DEFAULT_EPOCH_TICKS,
    DEFAULT_MEMORY_LIMIT_BYTES,
};
