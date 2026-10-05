//! Sandboxed Wasmtime worker satellite execution environment.

pub struct WasmWorker {
    // Wasmtime engine configuration
}

impl WasmWorker {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for WasmWorker {
    fn default() -> Self {
        Self::new()
    }
}
