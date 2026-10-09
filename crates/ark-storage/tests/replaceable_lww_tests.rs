use ark_core::constants::MAGIC_BYTES;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_storage::{
    compute_envelope_id, RetentionOutcome, StorageConfig, StorageEngine, TAG_PARAM_D,
};
use tempfile::tempdir;

fn create_replaceable_envelope(
    sender_key_id: [u8; 16],
    kind: u32,
    param_d: Option<&[u8]>,
    timestamp: u64,
    payload: &[u8],
) -> ArkEnvelope {
    let header = ark_core::fast_header::FastHeader::new(0, 100, kind, sender_key_id, [2u8; 16], 1);
    let fast_header = header.to_bytes().to_vec();

    let mut tags = vec![BinaryTag::new(0, kind.to_be_bytes().to_vec())];
    if let Some(param) = param_d {
        tags.push(BinaryTag::new(TAG_PARAM_D, param.to_vec()));
    }

    ArkEnvelope {
        magic: MAGIC_BYTES.to_vec(),
        fast_header,
        sender_id: sender_key_id.repeat(2),
        recipient_id: vec![2u8; 32],
        payload: payload.to_vec(),
        signature: vec![0u8; 64],
        core_tag_mask: 0,
        tags,
        timestamp,
    }
}

#[test]
fn test_class2_replaceable_bivariate_lww() {
    let dir = tempdir().expect("temp dir");
    let engine = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine");
    let sender = [0x42u8; 16];
    let kind = 10001; // Class 2

    // 1. Initial write at t=100
    let env_v1 = create_replaceable_envelope(sender, kind, None, 100, b"profile v1");
    let out1 = engine.put_envelope(&env_v1).expect("put v1");
    assert_eq!(out1, RetentionOutcome::Stored);

    let fetched = engine
        .get_replaceable(&sender, kind)
        .expect("get")
        .expect("found");
    assert_eq!(fetched.payload, b"profile v1");

    // 2. Newer write at t=200 -> Replaced
    let env_v2 = create_replaceable_envelope(sender, kind, None, 200, b"profile v2");
    let out2 = engine.put_envelope(&env_v2).expect("put v2");
    assert_eq!(out2, RetentionOutcome::Replaced);

    let fetched = engine
        .get_replaceable(&sender, kind)
        .expect("get")
        .expect("found");
    assert_eq!(fetched.payload, b"profile v2");

    // 3. Stale write at t=50 -> SupersededLww
    let env_stale = create_replaceable_envelope(sender, kind, None, 50, b"profile stale");
    let out_stale = engine.put_envelope(&env_stale).expect("put stale");
    assert_eq!(out_stale, RetentionOutcome::SupersededLww);

    // Current state should still be v2
    let fetched = engine
        .get_replaceable(&sender, kind)
        .expect("get")
        .expect("found");
    assert_eq!(fetched.payload, b"profile v2");

    // 4. Equal timestamp tie-breaking by digest
    let env_tie_a = create_replaceable_envelope(sender, kind, None, 300, b"tie payload A");
    let env_tie_b = create_replaceable_envelope(sender, kind, None, 300, b"tie payload B");
    let id_a = compute_envelope_id(&env_tie_a).unwrap();
    let id_b = compute_envelope_id(&env_tie_b).unwrap();

    let (winner, loser, expected_second_outcome) = if id_a > id_b {
        (&env_tie_a, &env_tie_b, RetentionOutcome::SupersededLww)
    } else {
        (&env_tie_b, &env_tie_a, RetentionOutcome::SupersededLww)
    };

    // Put winner first, then loser
    let _ = engine.put_envelope(winner).expect("put winner");
    let out_loser = engine.put_envelope(loser).expect("put loser");
    assert_eq!(out_loser, expected_second_outcome);

    let fetched = engine
        .get_replaceable(&sender, kind)
        .expect("get")
        .expect("found");
    assert_eq!(fetched.payload, winner.payload);
}

#[test]
fn test_class3_parameterized_replaceable_isolation() {
    let dir = tempdir().expect("temp dir");
    let engine = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine");
    let sender = [0x55u8; 16];
    let kind = 30001; // Class 3

    // Store dns/ark
    let env_dns = create_replaceable_envelope(sender, kind, Some(b"dns/ark"), 100, b"1.1.1.1");
    let out1 = engine.put_envelope(&env_dns).expect("put dns");
    assert_eq!(out1, RetentionOutcome::Stored);

    // Store dns/eth (different param_d)
    let env_eth = create_replaceable_envelope(sender, kind, Some(b"dns/eth"), 100, b"2.2.2.2");
    let out2 = engine.put_envelope(&env_eth).expect("put eth");
    assert_eq!(out2, RetentionOutcome::Stored);

    // Verify isolation
    let fetched_dns = engine
        .get_param_d(&sender, kind, b"dns/ark")
        .expect("get")
        .expect("found");
    assert_eq!(fetched_dns.payload, b"1.1.1.1");

    let fetched_eth = engine
        .get_param_d(&sender, kind, b"dns/eth")
        .expect("get")
        .expect("found");
    assert_eq!(fetched_eth.payload, b"2.2.2.2");

    // Update dns/ark at t=150
    let env_dns_updated =
        create_replaceable_envelope(sender, kind, Some(b"dns/ark"), 150, b"8.8.8.8");
    let out_up = engine.put_envelope(&env_dns_updated).expect("update");
    assert_eq!(out_up, RetentionOutcome::Replaced);

    let fetched_dns_updated = engine
        .get_param_d(&sender, kind, b"dns/ark")
        .expect("get")
        .expect("found");
    assert_eq!(fetched_dns_updated.payload, b"8.8.8.8");

    // dns/eth remains unchanged
    let fetched_eth_unchanged = engine
        .get_param_d(&sender, kind, b"dns/eth")
        .expect("get")
        .expect("found");
    assert_eq!(fetched_eth_unchanged.payload, b"2.2.2.2");
}

#[test]
fn test_replaceable_unified_get_and_delete() {
    let dir = tempdir().expect("temp dir");
    let engine = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open engine");
    let sender = [0x77u8; 16];
    let kind = 10001; // Class 2

    let env = create_replaceable_envelope(sender, kind, None, 100, b"initial payload");
    let id = compute_envelope_id(&env).expect("id");

    engine.put_envelope(&env).expect("put");

    // Unified get_envelope(&id) finds Class 2 record
    let found = engine.get_envelope(&id).expect("get").expect("found");
    assert_eq!(found.payload, b"initial payload");

    // Unified delete_envelope(&id) deletes Class 2 record
    let deleted = engine.delete_envelope(&id).expect("delete");
    assert!(deleted);
    assert!(engine.get_envelope(&id).expect("get").is_none());
    assert!(engine
        .get_replaceable(&sender, kind)
        .expect("get")
        .is_none());

    // Test Class 3
    let kind3 = 30005;
    let env3 = create_replaceable_envelope(sender, kind3, Some(b"key1"), 100, b"param payload");
    let id3 = compute_envelope_id(&env3).expect("id");

    engine.put_envelope(&env3).expect("put");
    let found3 = engine.get_envelope(&id3).expect("get").expect("found");
    assert_eq!(found3.payload, b"param payload");

    let deleted3 = engine.delete_envelope(&id3).expect("delete");
    assert!(deleted3);
    assert!(engine.get_envelope(&id3).expect("get").is_none());
    assert!(engine
        .get_param_d(&sender, kind3, b"key1")
        .expect("get")
        .is_none());
}
