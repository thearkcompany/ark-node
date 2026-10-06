use ark_core::constants::MAGIC_BYTES;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_storage::{
    compute_envelope_id, RetentionOutcome, StorageConfig, StorageEngine, TAG_EXPIRATION,
};
use tempfile::tempdir;

fn create_ttl_envelope(expiration_ts: u64, payload: &[u8]) -> ArkEnvelope {
    let header = ark_core::fast_header::FastHeader::new(
        0,
        100,
        1000, // base kind
        [1u8; 16],
        [2u8; 16],
        1,
    );
    let fast_header = header.to_bytes().to_vec();

    let tags = vec![
        BinaryTag::new(0, 1000u32.to_be_bytes().to_vec()),
        BinaryTag::new(TAG_EXPIRATION, expiration_ts.to_be_bytes().to_vec()),
    ];

    ArkEnvelope {
        magic: MAGIC_BYTES.to_vec(),
        fast_header,
        sender_id: vec![1u8; 32],
        recipient_id: vec![2u8; 32],
        payload: payload.to_vec(),
        signature: vec![0u8; 64],
        core_tag_mask: 0,
        tags,
        timestamp: 1_700_000_000,
    }
}

#[test]
fn test_class4_bounded_ttl_lazy_expiration() {
    let dir = tempdir().expect("temp dir");
    let engine = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine");

    let exp_ts = 2_000_000_000u64;
    let env = create_ttl_envelope(exp_ts, b"ttl cached item");
    let id = compute_envelope_id(&env).expect("id");

    let out = engine.put_envelope(&env).expect("put");
    assert_eq!(out, RetentionOutcome::Stored);

    // Read before expiration -> should be found
    let res_before = engine.get_envelope_at_time(&id, 1_999_999_999).expect("get");
    assert!(res_before.is_some());
    assert_eq!(res_before.unwrap().payload, b"ttl cached item");

    // Read at or after expiration -> lazy expiration returns None
    let res_after = engine.get_envelope_at_time(&id, 2_000_000_000).expect("get");
    assert!(res_after.is_none());
}

#[test]
fn test_class4_sweeper_disk_reclamation() {
    let dir = tempdir().expect("temp dir");
    let engine = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine");

    let env1 = create_ttl_envelope(100, b"expire at 100");
    let env2 = create_ttl_envelope(200, b"expire at 200");
    let env3 = create_ttl_envelope(300, b"expire at 300");

    let id1 = compute_envelope_id(&env1).unwrap();
    let id2 = compute_envelope_id(&env2).unwrap();
    let id3 = compute_envelope_id(&env3).unwrap();

    engine.put_envelope(&env1).unwrap();
    engine.put_envelope(&env2).unwrap();
    engine.put_envelope(&env3).unwrap();

    // Sweep up to t=150: should prune only env1
    let reclaimed = engine.sweep_expired(150).expect("sweep");
    assert_eq!(reclaimed, 1);

    assert!(engine.get_envelope_at_time(&id1, 50).unwrap().is_none());
    assert!(engine.get_envelope_at_time(&id2, 50).unwrap().is_some());
    assert!(engine.get_envelope_at_time(&id3, 50).unwrap().is_some());

    // Sweep up to t=350: should prune env2 and env3
    let reclaimed2 = engine.sweep_expired(350).expect("sweep");
    assert_eq!(reclaimed2, 2);

    assert!(engine.get_envelope_at_time(&id2, 50).unwrap().is_none());
    assert!(engine.get_envelope_at_time(&id3, 50).unwrap().is_none());
}

#[test]
fn test_class4_background_sweeper_thread() {
    let dir = tempdir().expect("temp dir");
    let engine = std::sync::Arc::new(
        StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine"),
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Past expiration timestamp
    let env = create_ttl_envelope(now - 10, b"expired item");
    let id = compute_envelope_id(&env).unwrap();

    engine.put_envelope(&env).unwrap();
    assert!(engine.get_envelope_at_time(&id, 0).unwrap().is_some());

    // Spawn background sweeper with 50ms interval
    let sweeper = StorageEngine::spawn_background_sweeper(
        engine.clone(),
        std::time::Duration::from_millis(50),
    );

    // Give sweeper thread time to execute
    std::thread::sleep(std::time::Duration::from_millis(200));
    sweeper.stop();

    // Verify it was automatically pruned by the background sweeper
    assert!(engine.get_envelope_at_time(&id, 0).unwrap().is_none());
}
