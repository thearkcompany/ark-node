use ark_paas::{
    PaasError, WasmWorker, WasmWorkerConfig, DEFAULT_CPU_FUEL, DEFAULT_MEMORY_LIMIT_BYTES,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_compile_arbitrary_valid_wasm() {
    let wat = r#"
        (module
            (func (export "add") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add)
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");

    let worker = WasmWorker::compile(&wasm).expect("compilation failed");
    let (res, remaining_fuel) = worker
        .execute(|store, instance| {
            let func = instance.get_typed_func::<(i32, i32), i32>(&mut *store, "add")?;
            let r = func.call(&mut *store, (40, 2))?;
            let fuel = store.get_fuel().unwrap_or(0);
            Ok((r, fuel))
        })
        .expect("execution failed");

    assert_eq!(res, 42);
    assert!(remaining_fuel < DEFAULT_CPU_FUEL);
    assert!(remaining_fuel > 0);
}

#[test]
fn test_instruction_level_cpu_fuel_consumption() {
    // A simple function that does some math should consume measurable fuel
    let wat = r#"
        (module
            (func (export "compute") (result i32)
                (local $i i32)
                (local $acc i32)
                (loop $l
                    local.get $i
                    i32.const 1
                    i32.add
                    local.set $i

                    local.get $acc
                    local.get $i
                    i32.add
                    local.set $acc

                    local.get $i
                    i32.const 100
                    i32.lt_s
                    br_if $l
                )
                local.get $acc
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");

    let config = WasmWorkerConfig {
        initial_cpu_fuel: 100_000,
        ..Default::default()
    };
    let worker = WasmWorker::compile_with_config(&wasm, config).expect("compilation failed");
    let (res, remaining_fuel) = worker.call_simple("compute").expect("compute failed");

    assert_eq!(res, 5050);
    let consumed_fuel = 100_000 - remaining_fuel;
    assert!(
        consumed_fuel > 100,
        "Fuel must be deducted instruction-by-instruction: consumed {}",
        consumed_fuel
    );
}

#[test]
fn test_cpu_fuel_exhaustion_on_infinite_loop() {
    let wat = r#"
        (module
            (func (export "infinite_loop")
                (loop $loop
                    br $loop
                )
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");

    // Give limited fuel
    let config = WasmWorkerConfig {
        initial_cpu_fuel: 5_000,
        ..Default::default()
    };
    let worker = WasmWorker::compile_with_config(&wasm, config).expect("compilation failed");

    let result = worker.execute(|store, instance| {
        let func = instance.get_typed_func::<(), ()>(&mut *store, "infinite_loop")?;
        func.call(&mut *store, ())
    });

    match result {
        Err(PaasError::CpuFuelExhausted) => {
            // Expected deterministic halt
        }
        other => panic!("Expected PaasError::CpuFuelExhausted, got {:?}", other),
    }
}

#[test]
fn test_memory_allocation_ceiling_enforced_at_64mb() {
    // 64 MB = 1024 WebAssembly pages (each 64 KB).
    // Initial memory 1 page (64 KB).
    // Attempting to grow beyond 1024 pages must fail.
    let wat = r#"
        (module
            (memory (export "mem") 1)
            (func (export "grow_memory") (param i32) (result i32)
                local.get 0
                memory.grow)
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");

    let worker = WasmWorker::compile(&wasm).expect("compilation failed");
    assert_eq!(
        worker.config().memory_limit_bytes,
        DEFAULT_MEMORY_LIMIT_BYTES
    );

    // 1. Growing to 100 pages (~6.4 MB) succeeds
    let res = worker
        .execute(|store, instance| {
            let func = instance.get_typed_func::<i32, i32>(&mut *store, "grow_memory")?;
            let prev = func.call(&mut *store, 99)?; // 1 + 99 = 100 pages
            Ok(prev)
        })
        .expect("growing to 100 pages should succeed");
    assert_eq!(res, 1);

    // 2. Growing beyond 1024 pages (e.g. 1500 pages = ~96 MB) fails with memory.grow returning -1
    // or when calling memory.grow beyond store limits.
    let res_large = worker
        .execute(|store, instance| {
            let func = instance.get_typed_func::<i32, i32>(&mut *store, "grow_memory")?;
            let prev = func.call(&mut *store, 2000)?;
            Ok(prev)
        })
        .expect("memory.grow returns -1 in guest when store limiter rejects growth");
    assert_eq!(
        res_large, -1,
        "Wasm memory.grow returns -1 when exceeding limiter ceiling"
    );

    // 3. Directly requiring initial memory > 64 MB (1025 pages) in the module bytecode
    // must fail instantiation / compilation or exceed memory ceiling.
    let wat_oversized = r#"
        (module
            (memory (export "mem") 1025)
        )
    "#;
    let wasm_oversized = wat::parse_str(wat_oversized).expect("wat parse failed");
    let worker_oversized = WasmWorker::compile(&wasm_oversized).expect("module compilation");
    let init_result = worker_oversized.execute(|_store, _instance| Ok(()));
    match init_result {
        Err(PaasError::MemoryLimitExceeded { .. }) => {
            // Expected: instantiation memory minimum exceeds ceiling
        }
        other => panic!("Expected PaasError::MemoryLimitExceeded, got {:?}", other),
    }
}

#[test]
fn test_preemptive_termination_via_epoch_deadline() {
    let wat = r#"
        (module
            (func (export "run_long")
                (loop $loop
                    br $loop
                )
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");

    // Worker with ample CPU fuel so fuel exhaustion doesn't trigger first,
    // but epoch deadline is set to 1 tick.
    let config = WasmWorkerConfig {
        initial_cpu_fuel: 1_000_000_000,
        enable_epoch_interruption: true,
        epoch_deadline_ticks: 1,
        ..Default::default()
    };
    let worker =
        Arc::new(WasmWorker::compile_with_config(&wasm, config).expect("compilation failed"));

    // Spawn a background thread that will increment the epoch after 20ms
    let worker_clone = Arc::clone(&worker);
    let stop_thread = Arc::new(AtomicBool::new(false));

    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        worker_clone.increment_epoch();
    });

    let result = worker.execute(|store, instance| {
        let func = instance.get_typed_func::<(), ()>(&mut *store, "run_long")?;
        func.call(&mut *store, ())
    });

    stop_thread.store(true, Ordering::Relaxed);
    handle.join().unwrap();

    match result {
        Err(PaasError::EpochDeadlineExceeded) => {
            // Preemptively interrupted as expected!
        }
        other => panic!("Expected PaasError::EpochDeadlineExceeded, got {:?}", other),
    }
}

#[test]
fn test_absence_of_os_sockets_and_filesystem() {
    // Untrusted wasm bytecode compiled to wasm32-unknown-unknown has no WASI or host socket imports.
    // An attempt to link or call non-existent host system imports without explicit linker bindings
    // fails at instantiation with Linker / Instantiation error.
    let wat_unauthorized_import = r#"
        (module
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (func (export "try_syscall") (result i32)
                i32.const 1
                i32.const 0
                i32.const 0
                i32.const 0
                call $fd_write
            )
        )
    "#;
    let wasm = wat::parse_str(wat_unauthorized_import).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("compilation");

    let result = worker.call_simple("try_syscall");
    match result {
        Err(PaasError::InstantiationFailed(msg)) | Err(PaasError::ExecutionFailed(msg)) => {
            assert!(
                msg.contains("unknown import") || msg.contains("wasi_snapshot_preview1"),
                "Must reject OS imports: {}",
                msg
            );
        }
        other => panic!(
            "Expected instantiation failure on unauthorized OS import, got {:?}",
            other
        ),
    }
}
