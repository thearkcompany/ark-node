use std::sync::Arc;
use ark_paas::{
    HostAbiState, InMemoryBlobReader,
    InMemoryEnvelopeEmitter, InMemoryKvStore, InMemoryPmtClock, KvStoreBackend,
    PaasError, WasmWorker,
};

#[test]
fn test_host_abi_kv_get_and_set() {
    // Guest Wasm that writes key "alpha" -> "omega" via ark_host_kv_set,
    // then reads it back via ark_host_kv_get into an output buffer.
    let wat = r#"
        (module
            (import "env" "ark_host_kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
            (import "env" "ark_host_kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)

            ;; Offset 0: key "alpha" (5 bytes)
            (data (i32.const 0) "alpha")
            ;; Offset 16: val "omega" (5 bytes)
            (data (i32.const 16) "omega")

            (func (export "test_set") (result i32)
                i32.const 0   ;; key_ptr
                i32.const 5   ;; key_len
                i32.const 16  ;; val_ptr
                i32.const 5   ;; val_len
                call $kv_set
            )

            (func (export "test_get") (result i32)
                i32.const 0   ;; key_ptr
                i32.const 5   ;; key_len
                i32.const 32  ;; out_ptr
                i32.const 16  ;; out_max_len
                call $kv_get
            )

            (func (export "test_get_missing") (result i32)
                i32.const 16  ;; key_ptr ("omega" is not a key)
                i32.const 5   ;; key_len
                i32.const 32  ;; out_ptr
                i32.const 16  ;; out_max_len
                call $kv_get
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("worker compilation");

    let kv_store = Arc::new(InMemoryKvStore::new());
    let mut state = HostAbiState::default();
    state.kv_backend = kv_store.clone();

    // 1. Initially "omega" does not exist
    let get_missing_res = worker
        .execute_with_state(Some(state), |store, instance| {
            let func = instance.get_typed_func::<(), i32>(&mut *store, "test_get_missing")?;
            func.call(&mut *store, ())
        })
        .expect("execution failed");
    assert_eq!(get_missing_res, -1, "Missing key should return -1");

    // 2. Set key "alpha" = "omega"
    let mut state = HostAbiState::default();
    state.kv_backend = kv_store.clone();
    let set_res = worker
        .execute_with_state(Some(state), |store, instance| {
            let func = instance.get_typed_func::<(), i32>(&mut *store, "test_set")?;
            func.call(&mut *store, ())
        })
        .expect("execution failed");
    assert_eq!(set_res, 0, "kv_set should return 0");

    // Verify backend received it
    let stored_val = kv_store.get(b"alpha").expect("get failed");
    assert_eq!(stored_val, Some(b"omega".to_vec()));

    // 3. Get key "alpha"
    let mut state = HostAbiState::default();
    state.kv_backend = kv_store.clone();
    let (get_res, read_bytes) = worker
        .execute_with_state(Some(state), |store, instance| {
            let func = instance.get_typed_func::<(), i32>(&mut *store, "test_get")?;
            let r = func.call(&mut *store, ())?;
            let mem = instance.get_memory(&mut *store, "memory").unwrap();
            let mut out = vec![0u8; 5];
            mem.read(&mut *store, 32, &mut out)?;
            Ok((r, out))
        })
        .expect("execution failed");
    assert_eq!(get_res, 5, "kv_get should return length of value");
    assert_eq!(read_bytes, b"omega");
}

#[test]
fn test_host_abi_blob_read() {
    let wat = r#"
        (module
            (import "env" "ark_host_blob_read" (func $blob_read (param i32 i32 i64 i32 i32) (result i32)))
            (memory (export "memory") 1)

            ;; CID at offset 0: "cid-123456" (10 bytes)
            (data (i32.const 0) "cid-123456")

            (func (export "read_chunk") (param i64 i32) (result i32)
                i32.const 0   ;; cid_ptr
                i32.const 10  ;; cid_len
                local.get 0   ;; offset
                i32.const 64  ;; out_ptr
                local.get 1   ;; out_max_len
                call $blob_read
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("worker compilation");

    let blob_backend = Arc::new(InMemoryBlobReader::new());
    let sample_payload = b"HelloWorldFromArkBlobStorageShardedChunk!".to_vec();
    blob_backend.insert(b"cid-123456".to_vec(), sample_payload.clone());

    let mut state = HostAbiState::default();
    state.blob_backend = blob_backend.clone();

    // Read first 10 bytes at offset 0
    let (len1, chunk1) = worker
        .execute_with_state(Some(state), |store, instance| {
            let func = instance.get_typed_func::<(u64, i32), i32>(&mut *store, "read_chunk")?;
            let r = func.call(&mut *store, (0, 10))?;
            let mem = instance.get_memory(&mut *store, "memory").unwrap();
            let mut buf = vec![0u8; 10];
            mem.read(&mut *store, 64, &mut buf)?;
            Ok((r, buf))
        })
        .expect("read_chunk failed");
    assert_eq!(len1, 10);
    assert_eq!(chunk1, b"HelloWorld");

    // Read offset 10 with max_len 100 (should read remaining 31 bytes)
    let mut state2 = HostAbiState::default();
    state2.blob_backend = blob_backend.clone();
    let (len2, chunk2) = worker
        .execute_with_state(Some(state2), |store, instance| {
            let func = instance.get_typed_func::<(u64, i32), i32>(&mut *store, "read_chunk")?;
            let r = func.call(&mut *store, (10, 100))?;
            let mem = instance.get_memory(&mut *store, "memory").unwrap();
            let mut buf = vec![0u8; 31];
            mem.read(&mut *store, 64, &mut buf)?;
            Ok((r, buf))
        })
        .expect("read_chunk 2 failed");
    assert_eq!(len2, 31);
    assert_eq!(chunk2, b"FromArkBlobStorageShardedChunk!");
}

#[test]
fn test_host_abi_envelope_emit() {
    let wat = r#"
        (module
            (import "env" "ark_host_envelope_emit" (func $emit (param i32 i32) (result i32)))
            (memory (export "memory") 1)

            (data (i32.const 0) "MOCK_ENVELOPE_BINARY_BYTES")

            (func (export "emit_envelope") (result i32)
                i32.const 0
                i32.const 26
                call $emit
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("worker compilation");

    let emitter = Arc::new(InMemoryEnvelopeEmitter::new());
    let mut state = HostAbiState::default();
    state.envelope_backend = emitter.clone();

    let res = worker
        .execute_with_state(Some(state), |store, instance| {
            let func = instance.get_typed_func::<(), i32>(&mut *store, "emit_envelope")?;
            func.call(&mut *store, ())
        })
        .expect("emit execution failed");
    assert_eq!(res, 0);

    let emitted = emitter.get_emitted();
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], b"MOCK_ENVELOPE_BINARY_BYTES");
}

#[test]
fn test_host_abi_now_pmt_clock() {
    let wat = r#"
        (module
            (import "env" "ark_host_now_pmt" (func $now_pmt (result i64)))
            (memory (export "memory") 1)

            (func (export "get_pmt") (result i64)
                call $now_pmt
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("worker compilation");

    let clock = Arc::new(InMemoryPmtClock::new(1710005555));
    let mut state = HostAbiState::default();
    state.pmt_backend = clock.clone();

    let pmt_time = worker
        .execute_with_state(Some(state), |store, instance| {
            let func = instance.get_typed_func::<(), u64>(&mut *store, "get_pmt")?;
            func.call(&mut *store, ())
        })
        .expect("now_pmt failed");
    assert_eq!(pmt_time, 1710005555);

    // Update clock and verify guest receives new consensus time
    clock.set_time(1710009999);
    let mut state2 = HostAbiState::default();
    state2.pmt_backend = clock.clone();
    let pmt_time2 = worker
        .execute_with_state(Some(state2), |store, instance| {
            let func = instance.get_typed_func::<(), u64>(&mut *store, "get_pmt")?;
            func.call(&mut *store, ())
        })
        .expect("now_pmt 2 failed");
    assert_eq!(pmt_time2, 1710009999);
}

#[test]
fn test_host_abi_log() {
    let wat = r#"
        (module
            (import "env" "ark_host_log" (func $log (param i32 i32 i32)))
            (memory (export "memory") 1)

            (data (i32.const 0) "Worker starting computation")

            (func (export "emit_log")
                i32.const 2   ;; Info level
                i32.const 0   ;; msg_ptr
                i32.const 27  ;; msg_len
                call $log
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("worker compilation");

    let logs = worker
        .execute(|store, instance| {
            let func = instance.get_typed_func::<(), ()>(&mut *store, "emit_log")?;
            func.call(&mut *store, ())?;
            Ok(store.data().abi_state.logs.clone())
        })
        .expect("log execution failed");

    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].0, 2);
    assert_eq!(logs[0].1, "Worker starting computation");
}

#[test]
fn test_io_fuel_deduction_and_exhaustion() {
    // Guest Wasm that attempts to write a 100-byte value to KV store.
    let wat = r#"
        (module
            (import "env" "ark_host_kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)

            ;; Offset 0: key (10 bytes)
            (data (i32.const 0) "0123456789")

            (func (export "write_kv") (param i32) (result i32)
                i32.const 0   ;; key_ptr
                i32.const 10  ;; key_len
                i32.const 10  ;; val_ptr
                local.get 0   ;; val_len
                call $kv_set
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("compilation");

    // Case 1: Budget is 60 bytes.
    // Writing 10 bytes key + 30 bytes val = 40 bytes -> Succeeds, 20 bytes remaining.
    let mut state = HostAbiState::default();
    state.io_fuel_limit = 60;
    state.io_fuel_remaining = 60;

    let res = worker
        .execute_with_state(Some(state), |store, instance| {
            let func = instance.get_typed_func::<i32, i32>(&mut *store, "write_kv")?;
            let r = func.call(&mut *store, 30)?;
            assert_eq!(store.data().abi_state.io_fuel_remaining, 20);
            Ok(r)
        })
        .expect("should succeed within I/O fuel");
    assert_eq!(res, 0);

    // Case 2: Budget is 60 bytes.
    // Writing 10 bytes key + 60 bytes val = 70 bytes > 60 bytes -> Fails deterministically with IoFuelExhausted.
    let mut state_exhaust = HostAbiState::default();
    state_exhaust.io_fuel_limit = 60;
    state_exhaust.io_fuel_remaining = 60;

    let result = worker
        .execute_with_state(Some(state_exhaust), |store, instance| {
            let func = instance.get_typed_func::<i32, i32>(&mut *store, "write_kv")?;
            func.call(&mut *store, 60)
        });

    match result {
        Err(PaasError::IoFuelExhausted { limit_bytes }) => {
            assert_eq!(limit_bytes, 60);
        }
        other => panic!("Expected PaasError::IoFuelExhausted, got {:?}", other),
    }
}

#[test]
fn test_guest_linear_memory_exchange_with_alloc_dealloc() {
    // Module that exports guest allocator `ark_alloc` and `ark_dealloc` (bump allocator style)
    // and interacts with Host-ABI.
    let wat = r#"
        (module
            (import "env" "ark_host_kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
            (import "env" "ark_host_kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)

            (global $heap (mut i32) (i32.const 1024))

            ;; Exported ark_alloc: bump allocator
            (func $ark_alloc (export "ark_alloc") (param $size i32) (result i32)
                (local $old i32)
                global.get $heap
                local.set $old
                global.get $heap
                local.get $size
                i32.add
                global.set $heap
                local.get $old
            )

            ;; Exported ark_dealloc: no-op in simple bump allocator
            (func $ark_dealloc (export "ark_dealloc") (param $ptr i32) (param $size i32)
                ;; no-op
            )

            (func (export "alloc_and_store") (result i32)
                (local $k_ptr i32)
                (local $v_ptr i32)

                ;; allocate 4 bytes for key
                i32.const 4
                call $ark_alloc
                local.set $k_ptr

                ;; write key "test"
                local.get $k_ptr
                i32.const 0x74736574  ;; 't' 'e' 's' 't' in little endian
                i32.store

                ;; allocate 4 bytes for val
                i32.const 4
                call $ark_alloc
                local.set $v_ptr

                ;; write val "pass"
                local.get $v_ptr
                i32.const 0x73736170  ;; 'p' 'a' 's' 's' in little endian
                i32.store

                ;; call host kv_set
                local.get $k_ptr
                i32.const 4
                local.get $v_ptr
                i32.const 4
                call $kv_set
            )
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse failed");
    let worker = WasmWorker::compile(&wasm).expect("compilation");

    let kv_store = Arc::new(InMemoryKvStore::new());
    let mut state = HostAbiState::default();
    state.kv_backend = kv_store.clone();

    let res = worker
        .execute_with_state(Some(state), |store, instance| {
            // Verify ark_alloc and ark_dealloc are exported
            let alloc_fn = instance.get_typed_func::<u32, u32>(&mut *store, "ark_alloc")?;
            let dealloc_fn = instance.get_typed_func::<(u32, u32), ()>(&mut *store, "ark_dealloc")?;

            let ptr = alloc_fn.call(&mut *store, 64)?;
            assert!(ptr >= 1024);
            dealloc_fn.call(&mut *store, (ptr, 64))?;

            let run_fn = instance.get_typed_func::<(), i32>(&mut *store, "alloc_and_store")?;
            run_fn.call(&mut *store, ())
        })
        .expect("execution failed");

    assert_eq!(res, 0);
    assert_eq!(kv_store.get(b"test").unwrap(), Some(b"pass".to_vec()));
}
