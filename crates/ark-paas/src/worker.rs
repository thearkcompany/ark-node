use crate::error::{PaasError, Result};
use wasmtime::{
    Config, Engine, Instance, Linker, Module, ResourceLimiter, Store, StoreLimits,
    StoreLimitsBuilder, Trap,
};

/// Default memory allocation ceiling per worker instance: 64 MB.
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Default CPU fuel units: 10,000,000 instructions/fuel.
pub const DEFAULT_CPU_FUEL: u64 = 10_000_000;

/// Default epoch deadline ticks.
pub const DEFAULT_EPOCH_TICKS: u64 = 1;

/// Configuration for the sandboxed WasmWorker runtime.
#[derive(Clone, Debug)]
pub struct WasmWorkerConfig {
    /// Maximum linear memory allocation ceiling in bytes.
    pub memory_limit_bytes: usize,
    /// Maximum initial CPU fuel units metered deterministically.
    pub initial_cpu_fuel: u64,
    /// Whether epoch deadline interruption is enabled.
    pub enable_epoch_interruption: bool,
    /// Preemptive epoch deadline ticks budget before interruption trap.
    pub epoch_deadline_ticks: u64,
}

impl Default for WasmWorkerConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            initial_cpu_fuel: DEFAULT_CPU_FUEL,
            enable_epoch_interruption: true,
            epoch_deadline_ticks: DEFAULT_EPOCH_TICKS,
        }
    }
}

/// Internal store data containing resource limiter and execution metadata.
pub struct WorkerStoreData {
    pub limits: StoreLimits,
    pub memory_limit_bytes: usize,
    pub memory_limit_hit: bool,
}

impl ResourceLimiter for WorkerStoreData {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        let ok = self.limits.memory_growing(current, desired, maximum)?;
        if !ok {
            self.memory_limit_hit = true;
        }
        Ok(ok)
    }

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        self.limits.table_growing(current, desired, maximum)
    }
}

/// Sandboxed WebAssembly worker for executing untrusted guest bytecode.
pub struct WasmWorker {
    engine: Engine,
    module: Module,
    config: WasmWorkerConfig,
}

impl WasmWorker {
    /// Create a new WasmWorker by compiling arbitrary valid wasm32 bytecode
    /// using default configuration.
    pub fn compile(wasm_bytes: &[u8]) -> Result<Self> {
        Self::compile_with_config(wasm_bytes, WasmWorkerConfig::default())
    }

    /// Create a new WasmWorker with custom configuration.
    pub fn compile_with_config(wasm_bytes: &[u8], config: WasmWorkerConfig) -> Result<Self> {
        let mut wasm_cfg = Config::new();
        // Deterministic instruction-level CPU fuel consumption
        wasm_cfg.consume_fuel(true);

        // Preemptive interruption via epoch deadline timers
        if config.enable_epoch_interruption {
            wasm_cfg.epoch_interruption(true);
        }

        // Hermetic isolation: no WASI, no direct network sockets, no filesystem access.
        // Standard cranelift backend for deterministic wasm32 execution.
        let engine = Engine::new(&wasm_cfg)
            .map_err(|e| PaasError::CompilationFailed(format!("Failed to create engine: {e}")))?;

        let module = Module::new(&engine, wasm_bytes)
            .map_err(|e| PaasError::CompilationFailed(format!("Bytecode compilation failed: {e}")))?;

        Ok(Self {
            engine,
            module,
            config,
        })
    }

    /// Access the underlying Wasmtime Engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Access the compiled Module.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Access the worker configuration.
    pub fn config(&self) -> &WasmWorkerConfig {
        &self.config
    }

    /// Helper to increment the engine's epoch tick (used for epoch timer interruption).
    pub fn increment_epoch(&self) {
        self.engine.increment_epoch();
    }

    /// Build a new Store configured with memory limits and fuel.
    fn create_store(&self) -> Result<Store<WorkerStoreData>> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.memory_limit_bytes)
            .build();

        let data = WorkerStoreData {
            limits,
            memory_limit_bytes: self.config.memory_limit_bytes,
            memory_limit_hit: false,
        };

        let mut store = Store::new(&self.engine, data);
        store.limiter(|data| data as &mut dyn ResourceLimiter);

        // Set CPU fuel
        store
            .set_fuel(self.config.initial_cpu_fuel)
            .map_err(|e| PaasError::ExecutionFailed(format!("Failed to set CPU fuel: {e}")))?;

        // Set epoch deadline budget if enabled
        if self.config.enable_epoch_interruption {
            store.set_epoch_deadline(self.config.epoch_deadline_ticks);
        }

        Ok(store)
    }

    /// Execute a nullary exported function returning an i32 (or no return / arbitrary).
    /// Returns the remaining fuel upon successful completion.
    pub fn call_simple(&self, func_name: &str) -> Result<(i32, u64)> {
        let mut store = self.create_store()?;
        let linker = Linker::new(&self.engine);

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| self.map_wasm_error(&store, e))?;

        let func = instance
            .get_typed_func::<(), i32>(&mut store, func_name)
            .map_err(|e| PaasError::ExportNotFound(format!("{func_name}: {e}")))?;

        let result = func
            .call(&mut store, ())
            .map_err(|e| self.map_wasm_error(&store, e))?;

        let remaining_fuel = store.get_fuel().unwrap_or(0);
        Ok((result, remaining_fuel))
    }

    /// Instantiate and execute an arbitrary function with full access to store, linker, and fuel.
    pub fn execute<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Store<WorkerStoreData>, Instance) -> std::result::Result<R, wasmtime::Error>,
    {
        let mut store = self.create_store()?;
        let linker = Linker::new(&self.engine);

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| self.map_wasm_error(&store, e))?;

        f(&mut store, instance).map_err(|e| self.map_wasm_error(&store, e))
    }

    /// Classify wasmtime error / trap into canonical PaasError.
    pub fn map_wasm_error(&self, store: &Store<WorkerStoreData>, err: wasmtime::Error) -> PaasError {
        // Check if fuel is exhausted
        if let Ok(fuel) = store.get_fuel() {
            if fuel == 0 {
                return PaasError::CpuFuelExhausted;
            }
        }

        // Check if memory ceiling was hit in store data
        if store.data().memory_limit_hit {
            return PaasError::MemoryLimitExceeded {
                limit_bytes: store.data().memory_limit_bytes,
                requested_bytes: store.data().memory_limit_bytes + 1,
            };
        }

        // Check Trap variants
        if let Some(trap) = err.downcast_ref::<Trap>() {
            match trap {
                Trap::OutOfFuel => return PaasError::CpuFuelExhausted,
                Trap::Interrupt => return PaasError::EpochDeadlineExceeded,
                Trap::MemoryOutOfBounds => {
                    return PaasError::MemoryLimitExceeded {
                        limit_bytes: store.data().memory_limit_bytes,
                        requested_bytes: store.data().memory_limit_bytes,
                    };
                }
                _ => {}
            }
        }

        let err_str = err.to_string();
        if err_str.contains("fuel") || err_str.contains("all fuel consumed") {
            return PaasError::CpuFuelExhausted;
        }
        if err_str.contains("interrupt") || err_str.contains("epoch") {
            return PaasError::EpochDeadlineExceeded;
        }
        if err_str.contains("memory minimum size")
            || err_str.contains("memory allocation")
            || err_str.contains("out of bounds")
            || err_str.contains("grow")
        {
            return PaasError::MemoryLimitExceeded {
                limit_bytes: store.data().memory_limit_bytes,
                requested_bytes: store.data().memory_limit_bytes,
            };
        }

        PaasError::ExecutionFailed(err_str)
    }
}
