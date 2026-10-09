//! Unified PaasEngine and TriggerSource dispatcher implementation.
//!
//! Provides the primary public facade integrating:
//! - Wasm worker registry and sandboxed execution pool.
//! - Capability Host-ABI state with configurable backends (KV, Blob, Envelope, PMT clock).
//! - Persistent Ark Queue (Fjall LSM with in-memory ACK elision).
//! - PMT-driven Ark Cron with strict Skip-Missed intervals policy.
//! - Unified `TriggerSource` dispatcher handling `Trigger::Cron`, `Trigger::EnvelopeReceived`,
//!   and `Trigger::ManualInvocation`.
//! - Protobuf schema definitions for manifests, configurations, telemetry, and status receipts.

use dashmap::DashMap;
use parking_lot::RwLock;
use prost::Message;
use sha3::{Digest, Sha3_256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ark_protocol::envelope::ArkEnvelope;

use crate::cron::{ArkCron, CronJob, CronSchedule, PmtClock};
use crate::error::{PaasError, Result};
use crate::host_abi::HostAbiState;
use crate::lease::JobLease;
use crate::proto::{
    ExecutionStatus, ExecutionTelemetry, TriggerPayload, TriggerType, WorkerManifest,
};
use crate::queue::{ArkQueue, Task};
use crate::traits::{BlobReaderBackend, EnvelopeEmitterBackend, InMemoryPmtClock, KvStoreBackend};
use crate::worker::{WasmWorker, WasmWorkerConfig};

/// Trigger event representing an execution stimulus in ark-paas.
#[derive(Debug, Clone)]
pub enum Trigger {
    /// PMT-driven recurring cron schedule trigger.
    Cron(CronPayload),
    /// Inbound network envelope matching worker tag mask or recipient.
    EnvelopeReceived(EnvelopePayload),
    /// Direct synchronous invocation via local API or node command.
    ManualInvocation(ManualPayload),
}

/// Payload context for Trigger::Cron.
#[derive(Debug, Clone)]
pub struct CronPayload {
    pub job_id: String,
    pub target_worker_id: String,
    pub trigger_pmt: u64,
    pub data: Vec<u8>,
}

/// Payload context for Trigger::EnvelopeReceived.
#[derive(Debug, Clone)]
pub struct EnvelopePayload {
    pub envelope: ArkEnvelope,
    pub target_worker_id: Option<String>,
}

/// Payload context for Trigger::ManualInvocation.
#[derive(Debug, Clone)]
pub struct ManualPayload {
    pub target_worker_id: String,
    pub payload: Vec<u8>,
    pub invocation_id: Option<String>,
}

/// Dispatcher interface for turning external triggers into queued or dispatched tasks.
pub trait TriggerSource {
    /// Ingest a trigger event, mapping it into an enqueued Task within ArkQueue.
    /// Returns the enqueued task ID(s).
    fn ingest_trigger(&self, trigger: Trigger) -> Result<Vec<String>>;
}

/// Registered worker registration entry.
struct RegisteredWorker {
    manifest: WorkerManifest,
    worker: Arc<WasmWorker>,
}

/// Unified Sovereign Compute Engine facade.
pub struct PaasEngine<C: PmtClock + 'static = InMemoryPmtClock> {
    queue: Arc<ArkQueue>,
    cron: Arc<ArkCron<C>>,
    clock: Arc<C>,
    kv_backend: Arc<dyn KvStoreBackend>,
    blob_backend: Arc<dyn BlobReaderBackend>,
    envelope_backend: Arc<dyn EnvelopeEmitterBackend>,
    workers: Arc<DashMap<String, RegisteredWorker>>,
    tag_routes: Arc<RwLock<Vec<(u64, String)>>>,
    execution_seq: AtomicU64,
}

impl<C: PmtClock + 'static> PaasEngine<C> {
    /// Create a new PaasEngine with custom components.
    pub fn new(
        queue: Arc<ArkQueue>,
        clock: Arc<C>,
        kv_backend: Arc<dyn KvStoreBackend>,
        blob_backend: Arc<dyn BlobReaderBackend>,
        envelope_backend: Arc<dyn EnvelopeEmitterBackend>,
    ) -> Self {
        let cron = Arc::new(ArkCron::new(clock.clone()));
        Self {
            queue,
            cron,
            clock,
            kv_backend,
            blob_backend,
            envelope_backend,
            workers: Arc::new(DashMap::new()),
            tag_routes: Arc::new(RwLock::new(Vec::new())),
            execution_seq: AtomicU64::new(1),
        }
    }

    /// Access the underlying ArkQueue.
    pub fn queue(&self) -> &Arc<ArkQueue> {
        &self.queue
    }

    /// Access the underlying ArkCron.
    pub fn cron(&self) -> &Arc<ArkCron<C>> {
        &self.cron
    }

    /// Access the consensus PMT clock.
    pub fn clock(&self) -> &Arc<C> {
        &self.clock
    }

    /// Register a guest WebAssembly worker module bytecode and manifest.
    pub fn register_worker(&self, wasm_bytes: &[u8], mut manifest: WorkerManifest) -> Result<()> {
        let worker_id = manifest.worker_id.clone();
        if worker_id.is_empty() {
            return Err(PaasError::InvalidArgument(
                "Worker ID cannot be empty".to_string(),
            ));
        }

        // Calculate and set SHA3-256 hash if empty or verify
        let hash = Sha3_256::digest(wasm_bytes).to_vec();
        if manifest.wasm_sha3_256.is_empty() {
            manifest.wasm_sha3_256 = hash.clone();
        } else if manifest.wasm_sha3_256 != hash {
            return Err(PaasError::InvalidArgument(
                "Worker manifest wasm_sha3_256 mismatch with provided bytecode".to_string(),
            ));
        }

        // Default entrypoint if empty
        if manifest.entrypoint.is_empty() {
            manifest.entrypoint = "ark_main".to_string();
        }

        // Configure WasmWorkerConfig from WorkerConfig
        let mut worker_config = WasmWorkerConfig::default();
        if let Some(cfg) = &manifest.config {
            if cfg.memory_limit_bytes > 0 {
                worker_config.memory_limit_bytes = cfg.memory_limit_bytes as usize;
            }
            if cfg.initial_cpu_fuel > 0 {
                worker_config.initial_cpu_fuel = cfg.initial_cpu_fuel;
            }
            if cfg.initial_io_fuel > 0 {
                worker_config.initial_io_fuel = cfg.initial_io_fuel as usize;
            }
            worker_config.enable_epoch_interruption = cfg.enable_epoch_interruption;
            if cfg.epoch_deadline_ticks > 0 {
                worker_config.epoch_deadline_ticks = cfg.epoch_deadline_ticks;
            }
        }

        let worker = WasmWorker::compile_with_config(wasm_bytes, worker_config)?;

        // If worker specifies a cron schedule, register recurring cron job
        if !manifest.cron_schedule.is_empty() {
            let schedule = CronSchedule::parse(&manifest.cron_schedule)?;
            let cron_job = CronJob::new(
                manifest.worker_id.clone(),
                schedule,
                manifest.worker_id.as_bytes().to_vec(),
            );
            self.cron.add_job(cron_job);
        }

        // If worker specifies trigger tag mask, register tag route
        if manifest.trigger_tag_mask > 0 {
            self.tag_routes
                .write()
                .push((manifest.trigger_tag_mask, worker_id.clone()));
        }

        self.workers.insert(
            worker_id,
            RegisteredWorker {
                manifest,
                worker: Arc::new(worker),
            },
        );

        Ok(())
    }

    /// Retrieve a registered worker manifest.
    pub fn get_manifest(&self, worker_id: &str) -> Option<WorkerManifest> {
        self.workers.get(worker_id).map(|w| w.manifest.clone())
    }

    /// Number of registered workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Evaluate cron schedules at current PMT and enqueue matching jobs into ArkQueue.
    /// Returns the number of enqueued tasks.
    pub fn tick_cron(&self) -> Result<Vec<String>> {
        self.cron.tick(&self.queue)
    }

    /// Build a HostAbiState for worker execution using engine's backends.
    pub fn build_abi_state(&self, io_fuel_limit: usize) -> HostAbiState {
        HostAbiState::new(
            self.kv_backend.clone(),
            self.blob_backend.clone(),
            self.envelope_backend.clone(),
            self.clock.clone(),
            io_fuel_limit,
        )
    }

    /// Poll and execute the next available task from ArkQueue.
    /// Returns Ok(Some(telemetry)) if a task was dispatched and run,
    /// Ok(None) if the queue was empty.
    pub fn poll_and_execute_next(&self) -> Result<Option<ExecutionTelemetry>> {
        let lease_opt = self
            .queue
            .dispatch()
            .map_err(|e| PaasError::QueueError(e.to_string()))?;
        let lease = match lease_opt {
            Some(l) => l,
            None => return Ok(None),
        };

        let telemetry = self.dispatch_lease(lease)?;
        Ok(Some(telemetry))
    }

    /// Execute a task given an active JobLease.
    pub fn dispatch_lease(&self, lease: JobLease) -> Result<ExecutionTelemetry> {
        let task = lease.task();
        let task_id = task.id.clone();
        let start_time = Instant::now();

        // Decode TriggerPayload from task payload
        let trigger_payload = match TriggerPayload::decode(task.payload.as_slice()) {
            Ok(tp) => tp,
            Err(_) => {
                // If payload is not valid protobuf TriggerPayload, attempt raw fallback
                TriggerPayload {
                    trigger_type: TriggerType::Unspecified as i32,
                    target_worker_id: String::new(),
                    payload: task.payload.clone(),
                    timestamp: PmtClock::now_pmt(&*self.clock),
                }
            }
        };

        // Determine worker ID: target_worker_id or parse from cron task id
        let worker_id = if !trigger_payload.target_worker_id.is_empty() {
            trigger_payload.target_worker_id.clone()
        } else if let Some(stripped) = task_id.strip_prefix("cron-") {
            // cron task id format: cron-<job_id>-<pmt> where job_id can itself contain '-'
            if let Some(last_dash) = stripped.rfind('-') {
                stripped[..last_dash].to_string()
            } else {
                stripped.to_string()
            }
        } else {
            // Default or empty worker
            return self.handle_execution_failure(
                &lease,
                "",
                ExecutionStatus::Trap,
                PaasError::WorkerNotFound("No worker ID specified".to_string()),
                0,
                0,
                start_time.elapsed().as_micros() as u64,
            );
        };

        let registered = match self.workers.get(&worker_id) {
            Some(w) => w,
            None => {
                return self.handle_execution_failure(
                    &lease,
                    &worker_id,
                    ExecutionStatus::Trap,
                    PaasError::WorkerNotFound(format!("Worker '{}' not found", worker_id)),
                    0,
                    0,
                    start_time.elapsed().as_micros() as u64,
                );
            }
        };

        let worker = registered.worker.clone();
        let entrypoint = registered.manifest.entrypoint.clone();
        let initial_cpu = worker.config().initial_cpu_fuel;
        let initial_io = worker.config().initial_io_fuel;

        let abi_state = self.build_abi_state(initial_io);

        // Execute worker
        let exec_result: Result<(i32, u64, u64, u32)> =
            worker.execute_with_state(Some(abi_state), |store, instance| {
                // Check if entrypoint takes (ptr, len) or is simple nullary
                let return_code = if let Ok(func) =
                    instance.get_typed_func::<(u32, u32), i32>(&mut *store, &entrypoint)
                {
                    // Entrypoint accepts payload pointer and len
                    let payload = &trigger_payload.payload;
                    let payload_len = payload.len() as u32;

                    // Allocate memory in guest if ark_alloc is available
                    let ptr = if let Ok(alloc_fn) =
                        instance.get_typed_func::<u32, u32>(&mut *store, "ark_alloc")
                    {
                        let p = alloc_fn.call(&mut *store, payload_len)?;
                        if let Some(wasmtime::Extern::Memory(mem)) =
                            instance.get_export(&mut *store, "memory")
                        {
                            mem.write(&mut *store, p as usize, payload)?;
                        }
                        p
                    } else {
                        // Offset 0 fallback if memory exists and fits
                        if let Some(wasmtime::Extern::Memory(mem)) =
                            instance.get_export(&mut *store, "memory")
                        {
                            let data = mem.data_mut(&mut *store);
                            if (payload_len as usize) <= data.len() {
                                data[..payload_len as usize].copy_from_slice(payload);
                            }
                        }
                        0
                    };

                    let res = func.call(&mut *store, (ptr, payload_len));
                    if ptr != 0 {
                        if let Ok(dealloc_fn) =
                            instance.get_typed_func::<(u32, u32), ()>(&mut *store, "ark_dealloc")
                        {
                            let _ = dealloc_fn.call(&mut *store, (ptr, payload_len));
                        }
                    }
                    res?
                } else if let Ok(func) =
                    instance.get_typed_func::<(), i32>(&mut *store, &entrypoint)
                {
                    func.call(&mut *store, ())?
                } else if let Ok(func) = instance.get_typed_func::<(), ()>(&mut *store, &entrypoint)
                {
                    func.call(&mut *store, ())?;
                    0
                } else {
                    return Err(wasmtime::Error::msg(format!(
                        "Entrypoint '{}' not found in module",
                        entrypoint
                    )));
                };

                let remaining_cpu = store.get_fuel().unwrap_or(0);
                let remaining_io = store.data().abi_state.io_fuel_remaining as u64;
                let log_count = store.data().abi_state.logs.len() as u32;

                Ok((return_code, remaining_cpu, remaining_io, log_count))
            });

        let duration_micros = start_time.elapsed().as_micros() as u64;

        match exec_result {
            Ok((ret_code, rem_cpu, rem_io, log_count)) => {
                // Success: complete lease with in-memory ACK elision
                self.queue
                    .complete(&lease)
                    .map_err(|e| PaasError::QueueError(e.to_string()))?;

                let telemetry = ExecutionTelemetry {
                    task_id: task_id.clone(),
                    worker_id: worker_id.clone(),
                    status: ExecutionStatus::Success as i32,
                    cpu_fuel_consumed: initial_cpu.saturating_sub(rem_cpu),
                    cpu_fuel_remaining: rem_cpu,
                    io_fuel_consumed: (initial_io as u64).saturating_sub(rem_io),
                    io_fuel_remaining: rem_io,
                    return_code: ret_code,
                    duration_micros,
                    error_message: String::new(),
                    log_count,
                };

                Ok(telemetry)
            }
            Err(err) => {
                let status = match &err {
                    PaasError::CpuFuelExhausted => ExecutionStatus::CpuFuelExhausted,
                    PaasError::IoFuelExhausted { .. } => ExecutionStatus::IoFuelExhausted,
                    PaasError::MemoryLimitExceeded { .. } => ExecutionStatus::MemoryLimitExceeded,
                    PaasError::EpochDeadlineExceeded => ExecutionStatus::EpochDeadlineExceeded,
                    PaasError::QueueError(_) => ExecutionStatus::QueueFailure,
                    _ => ExecutionStatus::Trap,
                };

                self.handle_execution_failure(
                    &lease,
                    &worker_id,
                    status,
                    err,
                    initial_cpu,
                    initial_io as u64,
                    duration_micros,
                )
            }
        }
    }

    /// Handle execution failure: manage attempts, dead-letter routing, and return telemetry.
    #[allow(clippy::too_many_arguments)]
    fn handle_execution_failure(
        &self,
        lease: &JobLease,
        worker_id: &str,
        status: ExecutionStatus,
        error: PaasError,
        initial_cpu: u64,
        initial_io: u64,
        duration_micros: u64,
    ) -> Result<ExecutionTelemetry> {
        let task = lease.task();
        let task_id = task.id.clone();
        let err_msg = error.to_string();

        let telemetry = ExecutionTelemetry {
            task_id,
            worker_id: worker_id.to_string(),
            status: status as i32,
            cpu_fuel_consumed: initial_cpu,
            cpu_fuel_remaining: 0,
            io_fuel_consumed: initial_io,
            io_fuel_remaining: 0,
            return_code: -1,
            duration_micros,
            error_message: err_msg,
            log_count: 0,
        };

        // Note: The lease is not acked; when lease expires, process_expired_leases()
        // will either re-enqueue for retry or route to DLQ when max_attempts is reached.
        Ok(telemetry)
    }
}

impl<C: PmtClock + 'static> TriggerSource for PaasEngine<C> {
    fn ingest_trigger(&self, trigger: Trigger) -> Result<Vec<String>> {
        let current_pmt = PmtClock::now_pmt(&*self.clock);
        let seq = self.execution_seq.fetch_add(1, Ordering::SeqCst);

        match trigger {
            Trigger::Cron(cron_payload) => {
                let task_id = format!("cron-{}-{}", cron_payload.job_id, cron_payload.trigger_pmt);
                let proto_payload = TriggerPayload {
                    trigger_type: TriggerType::Cron as i32,
                    target_worker_id: cron_payload.target_worker_id,
                    payload: cron_payload.data,
                    timestamp: cron_payload.trigger_pmt,
                };
                let bytes = proto_payload.encode_to_vec();
                let task = Task::new(&task_id, 0, bytes);
                self.queue
                    .enqueue(task)
                    .map_err(|e| PaasError::QueueError(e.to_string()))?;
                Ok(vec![task_id])
            }
            Trigger::EnvelopeReceived(envelope_payload) => {
                let env = envelope_payload.envelope;
                let env_bytes = env
                    .encode_to_vec()
                    .map_err(|e| PaasError::Protobuf(e.to_string()))?;

                // Determine target workers:
                // 1. If explicit target_worker_id provided, dispatch to it.
                // 2. Otherwise match tag_mask against registered worker tag routes.
                let mut target_workers = Vec::new();
                if let Some(target) = envelope_payload.target_worker_id {
                    target_workers.push(target);
                } else {
                    let routes = self.tag_routes.read();
                    for (mask, worker_id) in routes.iter() {
                        if (env.core_tag_mask & *mask) != 0 {
                            target_workers.push(worker_id.clone());
                        }
                    }
                }

                if target_workers.is_empty() {
                    return Ok(Vec::new());
                }

                let mut task_ids = Vec::new();
                for worker_id in target_workers {
                    let task_id = format!("env-{}-{}-{}", worker_id, env.timestamp, seq);
                    let proto_payload = TriggerPayload {
                        trigger_type: TriggerType::Envelope as i32,
                        target_worker_id: worker_id,
                        payload: env_bytes.clone(),
                        timestamp: current_pmt,
                    };
                    let bytes = proto_payload.encode_to_vec();
                    let task = Task::new(&task_id, 0, bytes);
                    self.queue
                        .enqueue(task)
                        .map_err(|e| PaasError::QueueError(e.to_string()))?;
                    task_ids.push(task_id);
                }

                Ok(task_ids)
            }
            Trigger::ManualInvocation(manual_payload) => {
                let invocation_id = manual_payload.invocation_id.unwrap_or_else(|| {
                    format!("manual-{}-{}", manual_payload.target_worker_id, seq)
                });

                let proto_payload = TriggerPayload {
                    trigger_type: TriggerType::Manual as i32,
                    target_worker_id: manual_payload.target_worker_id,
                    payload: manual_payload.payload,
                    timestamp: current_pmt,
                };
                let bytes = proto_payload.encode_to_vec();
                let task = Task::new(&invocation_id, 0, bytes);
                self.queue
                    .enqueue(task)
                    .map_err(|e| PaasError::QueueError(e.to_string()))?;

                Ok(vec![invocation_id])
            }
        }
    }
}
