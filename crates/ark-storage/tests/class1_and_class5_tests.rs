use ark_core::constants::MAGIC_BYTES;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_storage::{
    compute_envelope_id, ArkStorageError, RetentionOutcome, StorageConfig, StorageEngine,
};
use tempfile::tempdir;

fn create_envelope(kind: u32, payload: &[u8]) -> ArkEnvelope {
    let header = ark_core::fast_header::FastHeader::new(
        0,
        100,
        kind,
        [1u8; 16],
        [2u8; 16],
        1,
    );
    let fast_header = header.to_bytes().to_vec();

    ArkEnvelope {
        magic: MAGIC_BYTES.to_vec(),
        fast_header,
        sender_id: vec![1u8; 32],
        recipient_id: vec![2u8; 32],
        payload: payload.to_vec(),
        signature: vec![0u8; 64],
        core_tag_mask: 0,
        tags: vec![BinaryTag::new(0, kind.to_be_bytes().to_vec())],
        timestamp: 1_700_000_000,
    }
}

#[test]
fn test_class1_append_only_persistence_and_retrieval() {
    let dir = tempdir().expect("temp dir");
    let engine = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine");

    let env = create_envelope(1001, b"class 1 immutable content");
    let id = compute_envelope_id(&env).expect("id");

    let outcome = engine.put_envelope(&env).expect("put");
    assert_eq!(outcome, RetentionOutcome::Stored);

    let fetched = engine.get_envelope(&id).expect("get").expect("found");
    assert_eq!(fetched.payload, b"class 1 immutable content");
    assert_eq!(fetched.timestamp, 1_700_000_000);

    // Can delete Class 1
    let deleted = engine.delete_envelope(&id).expect("delete");
    assert!(deleted);
    assert!(engine.get_envelope(&id).expect("get").is_none());
}

#[test]
fn test_class5_strict_worm_immutability_and_idempotency() {
    let dir = tempdir().expect("temp dir");
    let engine = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine");

    // Kind 40001 -> Class 5 Strict WORM
    let env_worm = create_envelope(40001, b"equivocation proof receipt #42");
    let id = compute_envelope_id(&env_worm).expect("id");

    // First write: Stored with synchronous fsync
    let outcome1 = engine.put_envelope(&env_worm).expect("first write");
    assert_eq!(outcome1, RetentionOutcome::Stored);

    // Duplicate write of identical bytes: IdempotentDuplicate
    let outcome2 = engine.put_envelope(&env_worm).expect("second identical write");
    assert_eq!(outcome2, RetentionOutcome::IdempotentDuplicate);

    // Retrieve and verify
    let fetched = engine.get_envelope(&id).expect("get").expect("found");
    assert_eq!(fetched.payload, b"equivocation proof receipt #42");

    // Deletion attempt must fail with WormViolation
    let del_res = engine.delete_envelope(&id);
    match del_res {
        Err(ArkStorageError::WormViolation(_)) => {}
        other => panic!("Expected WormViolation on deletion, got: {:?}", other),
    }

    // Re-verify it still exists
    assert!(engine.get_envelope(&id).expect("get").is_some());
}
