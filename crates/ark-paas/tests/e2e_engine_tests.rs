use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use prost::Message;

use ark_protocol::envelope::ArkEnvelope;
use ark_storage::{StorageConfig, StorageEngine};
use ark_paas::{
    ArkQueue, EnvelopePayload, ExecutionStatus, InMemoryBlobReader,
    InMemoryEnvelopeEmitter, InMemoryKvStore, KvStoreBackend, ManualPayload,
    MockPmtClock, PaasEngine, QueueConfig, Trigger, TriggerSource,
    WorkerConfig, WorkerManifest,
};


fn create_test_engine() -> (
    PaasEngine<MockPmtClock>,
    Arc<InMemoryKvStore>,
    Arc<InMemoryBlobReader>,
    Arc<InMemoryEnvelopeEmitter>,
    Arc<MockPmtClock>,
    tempfile::TempDir,
) {
    let tmp = tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(tmp.path(), StorageConfig::frugal()).unwrap());
    let queue = Arc::new(ArkQueue::open(storage, QueueConfig {
        lease_duration: Duration::from_millis(100),
        max_attempts: 3,
        keyspace_name: "paas_engine_tasks".to_string(),
    }).unwrap());

    let clock = Arc::new(MockPmtClock::new(1791331200)); // 2026-10-07 00:00:00 UTC
    let kv_store = Arc::new(InMemoryKvStore::new());
    let blob_reader = Arc::new(InMemoryBlobReader::new());
    let envelope_emitter = Arc::new(InMemoryEnvelopeEmitter::new());

    let engine = PaasEngine::new(
        queue,
        clock.clone(),
        kv_store.clone(),
        blob_reader.clone(),
        envelope_emitter.clone(),
    );

    (engine, kv_store, blob_reader, envelope_emitter, clock, tmp)
}

#[test]
fn test_protobuf_manifest_and_telemetry_roundtrip() {
    let manifest = WorkerManifest {
        worker_id: "worker-demo-42".to_string(),
        version: "1.2.3".to_string(),
        wasm_sha3_256: vec![0xAA; 32],
        config: Some(WorkerConfig {
            memory_limit_bytes: 32 * 1024 * 1024,
            initial_cpu_fuel: 5_000_000,
            initial_io_fuel: 512 * 1024,
            enable_epoch_interruption: true,
            epoch_deadline_ticks: 2,
        }),
        entrypoint: "ark_main".to_string(),
        trigger_tag_mask: 0x01,
        cron_schedule: "*/5 * * * *".to_string(),
        description: "Test sovereign worker manifest".to_string(),
    };

    // Serialize to Protobuf
    let mut buf = Vec::new();
    manifest.encode(&mut buf).expect("encode manifest");

    // Deserialize from Protobuf
    let decoded = WorkerManifest::decode(buf.as_slice()).expect("decode manifest");
    assert_eq!(decoded.worker_id, "worker-demo-42");
    assert_eq!(decoded.version, "1.2.3");
    assert_eq!(decoded.wasm_sha3_256, vec![0xAA; 32]);
    assert_eq!(decoded.entrypoint, "ark_main");
    assert_eq!(decoded.trigger_tag_mask, 0x01);
    assert_eq!(decoded.cron_schedule, "*/5 * * * *");

    let cfg = decoded.config.expect("config present");
    assert_eq!(cfg.memory_limit_bytes, 32 * 1024 * 1024);
    assert_eq!(cfg.initial_cpu_fuel, 5_000_000);
    assert_eq!(cfg.initial_io_fuel, 512 * 1024);
    assert!(cfg.enable_epoch_interruption);
    assert_eq!(cfg.epoch_deadline_ticks, 2);

    // Telemetry roundtrip
    let telemetry = ark_paas::ExecutionTelemetry {
        task_id: "task-test-1".to_string(),
        worker_id: "worker-demo-42".to_string(),
        status: ExecutionStatus::Success as i32,
        cpu_fuel_consumed: 12345,
        cpu_fuel_remaining: 4987655,
        io_fuel_consumed: 1024,
        io_fuel_remaining: 523264,
        return_code: 0,
        duration_micros: 250,
        error_message: String::new(),
        log_count: 2,
    };

    let mut tele_buf = Vec::new();
    telemetry.encode(&mut tele_buf).expect("encode telemetry");
    let decoded_tele = ark_paas::ExecutionTelemetry::decode(tele_buf.as_slice()).expect("decode telemetry");
    assert_eq!(decoded_tele.task_id, "task-test-1");
    assert_eq!(decoded_tele.status, ExecutionStatus::Success as i32);
    assert_eq!(decoded_tele.cpu_fuel_consumed, 12345);
    assert_eq!(decoded_tele.return_code, 0);
    assert_eq!(decoded_tele.log_count, 2);
}

#[test]
fn test_e2e_full_chain_cron_tick_queue_wasm_with_host_abi_and_ack_elision() {
    let (engine, kv_store, _blob, _emitter, clock, _tmp) = create_test_engine();

    // Guest Wasm:
    // Reads PMT time via ark_host_now_pmt(), writes key "cron-executed" -> value "success" via ark_host_kv_set,
    // and emits a log via ark_host_log. Returns 0 on success.
    let wat = r#"
        (module
            (import "env" "ark_host_now_pmt" (func $now_pmt (result i64)))
            (import "env" "ark_host_kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
            (import "env" "ark_host_log" (func $log (param i32 i32 i32)))
            (memory (export "memory") 1)

            (data (i32.const 0) "cron-executed")
            (data (i32.const 16) "success")
            (data (i32.const 32) "cron job finished")

            (func (export "ark_main") (result i32)
                ;; Check now_pmt call
                call $now_pmt
                drop

                ;; Set KV store
                i32.const 0   ;; key ptr
                i32.const 13  ;; key len ("cron-executed")
                i32.const 16  ;; val ptr
                i32.const 7   ;; val len ("success")
                call $kv_set
                drop

                ;; Log message
                i32.const 2   ;; Info level
                i32.const 32  ;; msg ptr
                i32.const 17  ;; msg len ("cron job finished")
                call $log

                i32.const 0   ;; return success 0
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("wat parse failed");

    // Register worker with 5-minute recurring cron schedule
    let manifest = WorkerManifest {
        worker_id: "cron-worker-1".to_string(),
        version: "1.0.0".to_string(),
        wasm_sha3_256: Vec::new(),
        config: Some(WorkerConfig {
            memory_limit_bytes: 64 * 1024 * 1024,
            initial_cpu_fuel: 1_000_000,
            initial_io_fuel: 100_000,
            enable_epoch_interruption: false,
            epoch_deadline_ticks: 0,
        }),
        entrypoint: "ark_main".to_string(),
        trigger_tag_mask: 0,
        cron_schedule: "*/5 * * * *".to_string(),
        description: "Periodic cron worker with host ABI".to_string(),
    };

    engine.register_worker(&wasm_bytes, manifest).expect("register worker");
    assert_eq!(engine.worker_count(), 1);

    // Initial state: KV store is empty
    assert_eq!(kv_store.get(b"cron-executed").unwrap(), None);

    // Advance clock by 5 minutes (300s): 1791331200 + 300 = 1791331500
    clock.advance(300);

    // 1. Cron tick: ArkCron detects trigger and enqueues task into ArkQueue
    let enqueued = engine.tick_cron().expect("cron tick");
    assert_eq!(enqueued.len(), 1);
    let task_id = &enqueued[0];
    assert!(task_id.starts_with("cron-cron-worker-1-"));

    let sync_writes_before = engine.queue().disk_sync_writes_count();

    // 2. Poll and execute next task from ArkQueue
    let telemetry_opt = engine.poll_and_execute_next().expect("poll and execute");
    assert!(telemetry_opt.is_some());
    let telemetry = telemetry_opt.unwrap();

    // Verify telemetry
    assert_eq!(telemetry.task_id, *task_id);
    assert_eq!(telemetry.worker_id, "cron-worker-1");
    assert_eq!(telemetry.status, ExecutionStatus::Success as i32);
    assert_eq!(telemetry.return_code, 0);
    assert!(telemetry.cpu_fuel_consumed > 0);
    assert!(telemetry.io_fuel_consumed > 0);
    assert_eq!(telemetry.log_count, 1);

    // 3. Verify Capability Host-ABI state mutation in KV store
    let kv_val = kv_store.get(b"cron-executed").expect("kv get");
    assert_eq!(kv_val, Some(b"success".to_vec()));

    // 4. Verify in-memory ACK elision: completed in RAM without disk sync writes
    assert!(engine.queue().is_completed_in_memory(task_id));
    assert_eq!(engine.queue().disk_sync_writes_count(), sync_writes_before);

    // Further poll returns None (queue empty)
    assert!(engine.poll_and_execute_next().expect("poll empty").is_none());
}

#[test]
fn test_e2e_envelope_trigger_ingestion_and_dispatch() {
    let (engine, _kv, _blob, emitter, _clock, _tmp) = create_test_engine();

    // Guest Wasm that emits a response envelope when triggered by an inbound envelope
    let wat = r#"
        (module
            (import "env" "ark_host_envelope_emit" (func $emit (param i32 i32) (result i32)))
            (memory (export "memory") 1)

            (data (i32.const 0) "MOCK_RESPONSE_ENVELOPE")

            (func (export "ark_main") (result i32)
                i32.const 0   ;; ptr
                i32.const 22  ;; len ("MOCK_RESPONSE_ENVELOPE")
                call $emit
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("wat parse failed");

    // Worker registers for trigger_tag_mask 0x01 (TAG_MASK_ENCRYPTED)
    let manifest = WorkerManifest {
        worker_id: "envelope-worker".to_string(),
        version: "1.0.0".to_string(),
        wasm_sha3_256: Vec::new(),
        config: None,
        entrypoint: "ark_main".to_string(),
        trigger_tag_mask: 0x01,
        cron_schedule: String::new(),
        description: "Envelope reactive worker".to_string(),
    };
    engine.register_worker(&wasm_bytes, manifest).expect("register worker");

    // Create an inbound envelope with core_tag_mask = 0x01
    let env = ArkEnvelope::new(
        [0u8; 64],
        [0xAA; 32],
        [0xBB; 32],
        b"inbound request".to_vec(),
        vec![],
        0x01, // matching tag mask
        vec![],
        1791331200,
    ).expect("create envelope");

    // 1. Ingest Trigger::EnvelopeReceived via TriggerSource trait
    let enqueued_tasks = engine.ingest_trigger(Trigger::EnvelopeReceived(EnvelopePayload {
        envelope: env,
        target_worker_id: None, // routes automatically via tag mask!
    })).expect("ingest envelope trigger");

    assert_eq!(enqueued_tasks.len(), 1);
    assert!(enqueued_tasks[0].starts_with("env-envelope-worker-"));

    // 2. Poll and execute
    let telemetry = engine.poll_and_execute_next().unwrap().expect("executed");
    assert_eq!(telemetry.worker_id, "envelope-worker");
    assert_eq!(telemetry.status, ExecutionStatus::Success as i32);
    assert_eq!(telemetry.return_code, 0);

    // 3. Verify envelope was emitted through Host-ABI backend
    let emitted = emitter.get_emitted();
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0], b"MOCK_RESPONSE_ENVELOPE");
}

#[test]
fn test_e2e_manual_invocation_trigger() {
    let (engine, kv_store, _blob, _emitter, _clock, _tmp) = create_test_engine();

    let wat = r#"
        (module
            (import "env" "ark_host_kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)

            (data (i32.const 0) "manual-res")
            (data (i32.const 16) "done")

            (func (export "ark_main") (result i32)
                i32.const 0
                i32.const 10
                i32.const 16
                i32.const 4
                call $kv_set
                drop
                i32.const 42
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("wat parse failed");

    let manifest = WorkerManifest {
        worker_id: "manual-worker".to_string(),
        version: "1.0.0".to_string(),
        wasm_sha3_256: Vec::new(),
        config: None,
        entrypoint: "ark_main".to_string(),
        trigger_tag_mask: 0,
        cron_schedule: String::new(),
        description: "Manual invocation worker".to_string(),
    };
    engine.register_worker(&wasm_bytes, manifest).expect("register worker");

    // Ingest Trigger::ManualInvocation
    let task_ids = engine.ingest_trigger(Trigger::ManualInvocation(ManualPayload {
        target_worker_id: "manual-worker".to_string(),
        payload: b"manual input".to_vec(),
        invocation_id: Some("manual-task-999".to_string()),
    })).expect("ingest manual trigger");

    assert_eq!(task_ids, vec!["manual-task-999"]);

    let telemetry = engine.poll_and_execute_next().unwrap().expect("execute");
    assert_eq!(telemetry.task_id, "manual-task-999");
    assert_eq!(telemetry.worker_id, "manual-worker");
    assert_eq!(telemetry.status, ExecutionStatus::Success as i32);
    assert_eq!(telemetry.return_code, 42);

    assert_eq!(kv_store.get(b"manual-res").unwrap(), Some(b"done".to_vec()));
}

#[test]
fn test_e2e_cpu_fuel_exhaustion_retry_and_dlq_routing() {
    let (engine, _kv, _blob, _emitter, _clock, _tmp) = create_test_engine();

    // Guest Wasm with infinite loop
    let wat = r#"
        (module
            (func (export "ark_main") (result i32)
                (loop $l
                    br $l
                )
                i32.const 0
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("wat parse failed");

    // Low CPU fuel so it exhausts rapidly
    let manifest = WorkerManifest {
        worker_id: "infinite-loop-worker".to_string(),
        version: "1.0.0".to_string(),
        wasm_sha3_256: Vec::new(),
        config: Some(WorkerConfig {
            memory_limit_bytes: 16 * 1024 * 1024,
            initial_cpu_fuel: 1_000,
            initial_io_fuel: 10_000,
            enable_epoch_interruption: false,
            epoch_deadline_ticks: 0,
        }),
        entrypoint: "ark_main".to_string(),
        trigger_tag_mask: 0,
        cron_schedule: String::new(),
        description: "Infinite loop worker".to_string(),
    };
    engine.register_worker(&wasm_bytes, manifest).expect("register worker");

    // Ingest manual trigger
    engine.ingest_trigger(Trigger::ManualInvocation(ManualPayload {
        target_worker_id: "infinite-loop-worker".to_string(),
        payload: vec![],
        invocation_id: Some("task-infinite-1".to_string()),
    })).expect("ingest");

    // Attempt 1: Execute -> Fails with CpuFuelExhausted
    let tele1 = engine.poll_and_execute_next().unwrap().expect("dispatched attempt 1");
    assert_eq!(tele1.status, ExecutionStatus::CpuFuelExhausted as i32);
    assert_eq!(tele1.worker_id, "infinite-loop-worker");
    assert!(tele1.error_message.contains("CPU fuel exhausted"));

    // Lease was not completed; wait for lease timeout (100ms)
    std::thread::sleep(Duration::from_millis(110));
    let timed_out = engine.queue().process_expired_leases().unwrap();
    assert_eq!(timed_out, 1);

    // Attempt 2: Re-enqueued for retry -> Fails again with CpuFuelExhausted
    let tele2 = engine.poll_and_execute_next().unwrap().expect("dispatched attempt 2");
    assert_eq!(tele2.status, ExecutionStatus::CpuFuelExhausted as i32);

    std::thread::sleep(Duration::from_millis(110));
    let timed_out2 = engine.queue().process_expired_leases().unwrap();
    assert_eq!(timed_out2, 1);

    // Attempt 3: Re-enqueued for retry -> Fails (reaches max_attempts = 3)
    let tele3 = engine.poll_and_execute_next().unwrap().expect("dispatched attempt 3");
    assert_eq!(tele3.status, ExecutionStatus::CpuFuelExhausted as i32);

    std::thread::sleep(Duration::from_millis(110));
    let timed_out3 = engine.queue().process_expired_leases().unwrap();
    assert_eq!(timed_out3, 1);

    // Main queue is now empty
    assert!(engine.poll_and_execute_next().unwrap().is_none());

    // Task is now routed to Dead-Letter Queue (DLQ)!
    assert_eq!(engine.queue().dlq_len(), 1);
    let dlq_task = engine.queue().pop_dlq().expect("dlq task present");
    assert_eq!(dlq_task.id, "task-infinite-1");
    assert_eq!(dlq_task.attempts, 3);
}

#[test]
fn test_e2e_io_fuel_exhaustion_mapping() {
    let (engine, _kv, _blob, _emitter, _clock, _tmp) = create_test_engine();

    // Guest Wasm that attempts to write 1,000 bytes into KV store
    let wat = r#"
        (module
            (import "env" "ark_host_kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)

            (func (export "ark_main") (result i32)
                i32.const 0     ;; key ptr
                i32.const 10    ;; key len
                i32.const 10    ;; val ptr
                i32.const 1000  ;; val len (total 1010 bytes)
                call $kv_set
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("wat parse failed");

    // Very low I/O fuel limit: 50 bytes
    let manifest = WorkerManifest {
        worker_id: "io-heavy-worker".to_string(),
        version: "1.0.0".to_string(),
        wasm_sha3_256: Vec::new(),
        config: Some(WorkerConfig {
            memory_limit_bytes: 16 * 1024 * 1024,
            initial_cpu_fuel: 1_000_000,
            initial_io_fuel: 50,
            enable_epoch_interruption: false,
            epoch_deadline_ticks: 0,
        }),
        entrypoint: "ark_main".to_string(),
        trigger_tag_mask: 0,
        cron_schedule: String::new(),
        description: "IO fuel test worker".to_string(),
    };
    engine.register_worker(&wasm_bytes, manifest).expect("register worker");

    engine.ingest_trigger(Trigger::ManualInvocation(ManualPayload {
        target_worker_id: "io-heavy-worker".to_string(),
        payload: vec![],
        invocation_id: Some("task-io-1".to_string()),
    })).expect("ingest");

    let telemetry = engine.poll_and_execute_next().unwrap().expect("execute");
    assert_eq!(telemetry.status, ExecutionStatus::IoFuelExhausted as i32);
    assert!(telemetry.error_message.contains("I/O fuel exhausted"));
}
