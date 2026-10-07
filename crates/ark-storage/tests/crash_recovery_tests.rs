use ark_core::constants::MAGIC_BYTES;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_storage::{
    compute_envelope_id, RetentionOutcome, StorageConfig, StorageEngine, TAG_EXPIRATION,
    TAG_PARAM_D,
};
use std::sync::Arc;
use tempfile::tempdir;

fn create_test_envelope(kind: u32, timestamp: u64, tags: Vec<BinaryTag>, payload: &[u8]) -> ArkEnvelope {
    let header = ark_core::fast_header::FastHeader::new(
        0,
        100,
        kind,
        [0xAA; 16],
        [0xBB; 16],
        timestamp,
    );
    let fast_header = header.to_bytes().to_vec();

    ArkEnvelope {
        magic: MAGIC_BYTES.to_vec(),
        fast_header,
        sender_id: vec![0xAA; 32],
        recipient_id: vec![0xBB; 32],
        payload: payload.to_vec(),
        signature: vec![0; 64],
        core_tag_mask: 0,
        tags,
        timestamp,
    }
}

#[test]
fn test_crash_recovery_and_reopen_persistence() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().to_path_buf();
    let config = StorageConfig::frugal();

    let id_class1;
    let sender = [0xAA; 16];
    let kind_class2 = 10005;
    let kind_class3 = 30005;
    let id_class5;

    // --- SESSION 1: Store data across all persistent classes and close engine ---
    {
        let engine = StorageEngine::open(&path, config.clone()).expect("open session 1");

        // 1. Class 1 Append-Only
        let env1 = create_test_envelope(1001, 100, vec![], b"crash-proof class 1 payload");
        id_class1 = compute_envelope_id(&env1).unwrap();
        assert_eq!(engine.put_envelope(&env1).unwrap(), RetentionOutcome::Stored);

        // 2. Class 2 Replaceable
        let env2 = create_test_envelope(kind_class2, 200, vec![], b"crash-proof class 2 profile");
        assert_eq!(engine.put_envelope(&env2).unwrap(), RetentionOutcome::Stored);

        // 3. Class 3 Parameterized
        let env3 = create_test_envelope(
            kind_class3,
            300,
            vec![BinaryTag::new(TAG_PARAM_D, b"domain/ark".to_vec())],
            b"crash-proof class 3 dns",
        );
        assert_eq!(engine.put_envelope(&env3).unwrap(), RetentionOutcome::Stored);

        // 4. Class 4 TTL
        let env4 = create_test_envelope(
            1001,
            400,
            vec![BinaryTag::new(TAG_EXPIRATION, 9_999_999_999u64.to_be_bytes().to_vec())],
            b"crash-proof class 4 cache",
        );
        assert_eq!(engine.put_envelope(&env4).unwrap(), RetentionOutcome::Stored);

        // 5. Class 5 Strict WORM
        let env5 = create_test_envelope(40001, 500, vec![], b"crash-proof class 5 equivocation");
        id_class5 = compute_envelope_id(&env5).unwrap();
        assert_eq!(engine.put_envelope(&env5).unwrap(), RetentionOutcome::Stored);

        // Drop engine handle simulating clean/sudden shutdown
        drop(engine);
    }

    // --- SESSION 2: Reopen engine from identical directory and verify all data survived ---
    {
        let engine = StorageEngine::open(&path, config).expect("reopen session 2");

        // Verify Class 1
        let f1 = engine.get_envelope(&id_class1).expect("get").expect("found class 1");
        assert_eq!(f1.payload, b"crash-proof class 1 payload");

        // Verify Class 2
        let f2 = engine.get_replaceable(&sender, kind_class2).expect("get").expect("found class 2");
        assert_eq!(f2.payload, b"crash-proof class 2 profile");

        // Verify Class 3
        let f3 = engine.get_param_d(&sender, kind_class3, b"domain/ark").expect("get").expect("found class 3");
        assert_eq!(f3.payload, b"crash-proof class 3 dns");

        // Verify Class 5
        let f5 = engine.get_envelope(&id_class5).expect("get").expect("found class 5");
        assert_eq!(f5.payload, b"crash-proof class 5 equivocation");

        // Class 5 immutability still enforced after restart
        let dup = create_test_envelope(40001, 500, vec![], b"crash-proof class 5 equivocation");
        assert_eq!(engine.put_envelope(&dup).unwrap(), RetentionOutcome::IdempotentDuplicate);
    }
}

#[test]
fn test_concurrent_multithreaded_ingest_and_reads() {
    let dir = tempdir().expect("temp dir");
    let engine = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open"));

    let num_threads = 8;
    let items_per_thread = 50;
    let mut handles = Vec::new();

    for t in 0..num_threads {
        let eng = Arc::clone(&engine);
        let handle = std::thread::spawn(move || {
            for i in 0..items_per_thread {
                let kind = 1000 + t as u32;
                let payload = format!("thread-{}-item-{}", t, i).into_bytes();
                let env = create_test_envelope(kind, (t * 1000 + i) as u64, vec![], &payload);
                let id = compute_envelope_id(&env).unwrap();

                let out = eng.put_envelope(&env).unwrap();
                assert_eq!(out, RetentionOutcome::Stored);

                let fetched = eng.get_envelope(&id).unwrap().unwrap();
                assert_eq!(fetched.payload, payload);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("thread finished cleanly");
    }
}
