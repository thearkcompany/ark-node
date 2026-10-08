//! Hermetic Capability-Based Host-ABI layer (`ark_host_*`) and I/O Fuel accounting.

use std::sync::Arc;
use wasmtime::{Caller, Linker};

use crate::error::{PaasError, Result};
use crate::traits::{
    BlobReaderBackend, EnvelopeEmitterBackend, InMemoryBlobReader,
    InMemoryEnvelopeEmitter, InMemoryKvStore, InMemoryPmtClock,
    KvStoreBackend,
};
use crate::worker::WorkerStoreData;

/// Default I/O fuel budget: 1 MB = 1,048,576 bytes.
pub const DEFAULT_IO_FUEL_BYTES: usize = 1024 * 1024;

/// State holding Host-ABI capabilities and I/O fuel accounting.
pub struct HostAbiState {
    pub io_fuel_limit: usize,
    pub io_fuel_remaining: usize,
    pub kv_backend: Arc<dyn KvStoreBackend>,
    pub blob_backend: Arc<dyn BlobReaderBackend>,
    pub envelope_backend: Arc<dyn EnvelopeEmitterBackend>,
    pub pmt_backend: Arc<dyn ark_time::PmtClock>,
    pub logs: Vec<(u32, String)>,
}

impl HostAbiState {
    pub fn new(
        kv_backend: Arc<dyn KvStoreBackend>,
        blob_backend: Arc<dyn BlobReaderBackend>,
        envelope_backend: Arc<dyn EnvelopeEmitterBackend>,
        pmt_backend: Arc<dyn ark_time::PmtClock>,
        io_fuel_limit: usize,
    ) -> Self {
        Self {
            io_fuel_limit,
            io_fuel_remaining: io_fuel_limit,
            kv_backend,
            blob_backend,
            envelope_backend,
            pmt_backend,
            logs: Vec::new(),
        }
    }

    /// Deduct bytes from the remaining I/O fuel pool.
    /// Returns PaasError::IoFuelExhausted if requested bytes exceed remaining budget.
    pub fn deduct_io_fuel(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.io_fuel_remaining {
            self.io_fuel_remaining = 0;
            return Err(PaasError::IoFuelExhausted {
                limit_bytes: self.io_fuel_limit,
            });
        }
        self.io_fuel_remaining -= bytes;
        Ok(())
    }
}

impl Default for HostAbiState {
    fn default() -> Self {
        Self::new(
            Arc::new(InMemoryKvStore::new()),
            Arc::new(InMemoryBlobReader::new()),
            Arc::new(InMemoryEnvelopeEmitter::new()),
            Arc::new(InMemoryPmtClock::default()),
            DEFAULT_IO_FUEL_BYTES,
        )
    }
}

/// Helper function to read a slice from guest linear memory.
pub fn read_guest_memory<T>(
    caller: &mut Caller<'_, T>,
    ptr: u32,
    len: u32,
) -> std::result::Result<Vec<u8>, wasmtime::Error> {
    let memory = match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(mem)) => mem,
        _ => return Err(wasmtime::Error::msg("Missing 'memory' export")),
    };

    let start = ptr as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or_else(|| wasmtime::Error::msg("Guest memory offset overflow"))?;

    let data = memory.data(caller);
    if end > data.len() {
        return Err(wasmtime::Error::msg("Guest memory access out of bounds"));
    }

    Ok(data[start..end].to_vec())
}

/// Helper function to write a slice into guest linear memory.
pub fn write_guest_memory<T>(
    caller: &mut Caller<'_, T>,
    ptr: u32,
    bytes: &[u8],
) -> std::result::Result<(), wasmtime::Error> {
    let memory = match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(mem)) => mem,
        _ => return Err(wasmtime::Error::msg("Missing 'memory' export")),
    };

    let start = ptr as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| wasmtime::Error::msg("Guest memory offset overflow"))?;

    let data = memory.data_mut(caller);
    if end > data.len() {
        return Err(wasmtime::Error::msg("Guest memory write out of bounds"));
    }

    data[start..end].copy_from_slice(bytes);
    Ok(())
}

/// Register canonical Host-ABI functions (`ark_host_*`) on a Wasmtime Linker.
pub fn register_host_abi(linker: &mut Linker<WorkerStoreData>) -> Result<()> {
    // 1. ark_host_kv_get(key_ptr: u32, key_len: u32, out_ptr: u32, out_max_len: u32) -> i32
    // Returns number of bytes written, -1 if key not found, or -2 if out buffer too small.
    // Errors during I/O fuel deduction trap the execution.
    linker
        .func_wrap(
            "env",
            "ark_host_kv_get",
            |mut caller: Caller<'_, WorkerStoreData>,
             key_ptr: u32,
             key_len: u32,
             out_ptr: u32,
             out_max_len: u32|
             -> std::result::Result<i32, wasmtime::Error> {
                // Deduct key read fuel
                caller.data_mut().abi_state.deduct_io_fuel(key_len as usize)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                let key = read_guest_memory(&mut caller, key_ptr, key_len)?;
                let kv_backend = Arc::clone(&caller.data().abi_state.kv_backend);

                let val_opt = kv_backend.get(&key)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                match val_opt {
                    Some(val) => {
                        let val_len = val.len();
                        if val_len > out_max_len as usize {
                            return Ok(-2);
                        }

                        // Deduct value write fuel
                        caller.data_mut().abi_state.deduct_io_fuel(val_len)
                            .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                        write_guest_memory(&mut caller, out_ptr, &val)?;
                        Ok(val_len as i32)
                    }
                    None => Ok(-1),
                }
            },
        )
        .map_err(|e| PaasError::InstantiationFailed(format!("Failed to bind ark_host_kv_get: {e}")))?;

    // 2. ark_host_kv_set(key_ptr: u32, key_len: u32, val_ptr: u32, val_len: u32) -> i32
    // Returns 0 on success.
    linker
        .func_wrap(
            "env",
            "ark_host_kv_set",
            |mut caller: Caller<'_, WorkerStoreData>,
             key_ptr: u32,
             key_len: u32,
             val_ptr: u32,
             val_len: u32|
             -> std::result::Result<i32, wasmtime::Error> {
                // Deduct both key and value bytes from I/O fuel pool
                let total_bytes = (key_len as usize)
                    .checked_add(val_len as usize)
                    .ok_or_else(|| wasmtime::Error::msg("Length overflow"))?;
                caller.data_mut().abi_state.deduct_io_fuel(total_bytes)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                let key = read_guest_memory(&mut caller, key_ptr, key_len)?;
                let val = read_guest_memory(&mut caller, val_ptr, val_len)?;

                let kv_backend = Arc::clone(&caller.data().abi_state.kv_backend);
                kv_backend.set(&key, &val)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                Ok(0)
            },
        )
        .map_err(|e| PaasError::InstantiationFailed(format!("Failed to bind ark_host_kv_set: {e}")))?;

    // 3. ark_host_blob_read(cid_ptr: u32, cid_len: u32, offset: u64, out_ptr: u32, out_max_len: u32) -> i32
    // Returns number of bytes written, -1 if cid not found.
    linker
        .func_wrap(
            "env",
            "ark_host_blob_read",
            |mut caller: Caller<'_, WorkerStoreData>,
             cid_ptr: u32,
             cid_len: u32,
             offset: u64,
             out_ptr: u32,
             out_max_len: u32|
             -> std::result::Result<i32, wasmtime::Error> {
                // Deduct CID read fuel
                caller.data_mut().abi_state.deduct_io_fuel(cid_len as usize)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                let cid = read_guest_memory(&mut caller, cid_ptr, cid_len)?;
                let blob_backend = Arc::clone(&caller.data().abi_state.blob_backend);

                let chunk_opt = blob_backend.read(&cid, offset, out_max_len as usize)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                match chunk_opt {
                    Some(chunk) => {
                        let chunk_len = chunk.len();
                        // Deduct blob payload write fuel
                        caller.data_mut().abi_state.deduct_io_fuel(chunk_len)
                            .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                        write_guest_memory(&mut caller, out_ptr, &chunk)?;
                        Ok(chunk_len as i32)
                    }
                    None => Ok(-1),
                }
            },
        )
        .map_err(|e| PaasError::InstantiationFailed(format!("Failed to bind ark_host_blob_read: {e}")))?;

    // 4. ark_host_envelope_emit(env_ptr: u32, env_len: u32) -> i32
    // Returns 0 on success.
    linker
        .func_wrap(
            "env",
            "ark_host_envelope_emit",
            |mut caller: Caller<'_, WorkerStoreData>,
             env_ptr: u32,
             env_len: u32|
             -> std::result::Result<i32, wasmtime::Error> {
                // Deduct envelope bytes from I/O fuel pool
                caller.data_mut().abi_state.deduct_io_fuel(env_len as usize)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                let env_bytes = read_guest_memory(&mut caller, env_ptr, env_len)?;
                let envelope_backend = Arc::clone(&caller.data().abi_state.envelope_backend);

                envelope_backend.emit(&env_bytes)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                Ok(0)
            },
        )
        .map_err(|e| PaasError::InstantiationFailed(format!("Failed to bind ark_host_envelope_emit: {e}")))?;

    // 5. ark_host_now_pmt() -> u64
    // Returns PMT timestamp.
    linker
        .func_wrap(
            "env",
            "ark_host_now_pmt",
            |caller: Caller<'_, WorkerStoreData>| -> u64 {
                caller.data().abi_state.pmt_backend.now_pmt()
            },
        )
        .map_err(|e| PaasError::InstantiationFailed(format!("Failed to bind ark_host_now_pmt: {e}")))?;

    // 6. ark_host_log(level: u32, msg_ptr: u32, msg_len: u32)
    // Logs guest message and tracks in host state.
    linker
        .func_wrap(
            "env",
            "ark_host_log",
            |mut caller: Caller<'_, WorkerStoreData>,
             level: u32,
             msg_ptr: u32,
             msg_len: u32|
             -> std::result::Result<(), wasmtime::Error> {
                // Log messages also consume I/O fuel to prevent log DoS
                caller.data_mut().abi_state.deduct_io_fuel(msg_len as usize)
                    .map_err(|e| wasmtime::Error::msg(e.to_string()))?;

                let msg_bytes = read_guest_memory(&mut caller, msg_ptr, msg_len)?;
                let msg_str = String::from_utf8_lossy(&msg_bytes).into_owned();

                match level {
                    0 => tracing::error!(target: "ark_guest", "{msg_str}"),
                    1 => tracing::warn!(target: "ark_guest", "{msg_str}"),
                    2 => tracing::info!(target: "ark_guest", "{msg_str}"),
                    3 => tracing::debug!(target: "ark_guest", "{msg_str}"),
                    _ => tracing::trace!(target: "ark_guest", "{msg_str}"),
                }

                caller.data_mut().abi_state.logs.push((level, msg_str));
                Ok(())
            },
        )
        .map_err(|e| PaasError::InstantiationFailed(format!("Failed to bind ark_host_log: {e}")))?;

    Ok(())
}
