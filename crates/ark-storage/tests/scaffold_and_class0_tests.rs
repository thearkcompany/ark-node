use ark_core::constants::MAGIC_BYTES;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::{BinaryTag, TAG_MASK_ROUTING};
use ark_storage::{
    classify_retention, compute_envelope_id, RetentionClass, RetentionOutcome, StorageConfig,
    StorageEngine, TAG_EXPIRATION, TAG_PARAM_D,
};
use tempfile::tempdir;

fn dummy_envelope(fast_tag: u32, mask: u64, mut tags: Vec<BinaryTag>) -> ArkEnvelope {
    let header = ark_core::fast_header::FastHeader::new(0, 100, fast_tag, [1u8; 16], [2u8; 16], 1);
    let fast_header = header.to_bytes().to_vec();
    if fast_tag == 0 && tags.is_empty() {
        tags.push(BinaryTag::new(0, vec![]));
    }

    ArkEnvelope {
        magic: MAGIC_BYTES.to_vec(),
        fast_header,
        sender_id: vec![1u8; 32],
        recipient_id: vec![2u8; 32],
        payload: b"hello ark storage".to_vec(),
        signature: vec![0u8; 64],
        core_tag_mask: mask,
        tags,
        timestamp: 1_700_000_000,
    }
}

#[test]
fn test_storage_config_frugal_bounds() {
    let config = StorageConfig::frugal();
    assert!(config.block_cache_mb <= 32);
    assert!(config.write_buffer_mb <= 16);
    assert!(config.block_cache_mb + config.write_buffer_mb <= 64);
}

#[test]
fn test_classify_retention_all_classes() {
    // Class 0 Ephemeral: kind in 20000..30000 or TAG_MASK_ROUTING
    let env_ephemeral_kind = dummy_envelope(20001, 0, vec![]);
    assert_eq!(
        classify_retention(&env_ephemeral_kind),
        RetentionClass::Class0Ephemeral
    );

    let env_ephemeral_mask = dummy_envelope(1, TAG_MASK_ROUTING, vec![]);
    assert_eq!(
        classify_retention(&env_ephemeral_mask),
        RetentionClass::Class0Ephemeral
    );

    // Class 0 Ephemeral: VPN data (0x0008) and VPN handshake (0x0009)
    let env_vpn_data = dummy_envelope(0x0008, 0, vec![]);
    assert_eq!(
        classify_retention(&env_vpn_data),
        RetentionClass::Class0Ephemeral
    );

    let env_vpn_handshake = dummy_envelope(0x0009, 0, vec![]);
    assert_eq!(
        classify_retention(&env_vpn_handshake),
        RetentionClass::Class0Ephemeral
    );

    // Class 4 Bounded TTL: carries TAG_EXPIRATION
    let env_ttl = dummy_envelope(
        1001,
        0,
        vec![BinaryTag::new(
            TAG_EXPIRATION,
            1_800_000_000u64.to_be_bytes().to_vec(),
        )],
    );
    assert_eq!(
        classify_retention(&env_ttl),
        RetentionClass::Class4BoundedTtl
    );

    // Class 3 Parameterized: carries TAG_PARAM_D or kind in 30000..40000
    let env_param_tag = dummy_envelope(
        1001,
        0,
        vec![BinaryTag::new(TAG_PARAM_D, b"dns/ark".to_vec())],
    );
    assert_eq!(
        classify_retention(&env_param_tag),
        RetentionClass::Class3ParamReplaceable
    );

    let env_param_kind = dummy_envelope(30005, 0, vec![]);
    assert_eq!(
        classify_retention(&env_param_kind),
        RetentionClass::Class3ParamReplaceable
    );

    // Class 5 Strict WORM: kind >= 40000
    let env_worm = dummy_envelope(40001, 0, vec![]);
    assert_eq!(
        classify_retention(&env_worm),
        RetentionClass::Class5StrictWorm
    );

    // Class 2 Replaceable: kind 0 or 10000..20000
    let env_repl_0 = dummy_envelope(0, 0, vec![]);
    assert_eq!(
        classify_retention(&env_repl_0),
        RetentionClass::Class2Replaceable
    );

    let env_repl_range = dummy_envelope(10001, 0, vec![]);
    assert_eq!(
        classify_retention(&env_repl_range),
        RetentionClass::Class2Replaceable
    );

    // Class 1 Append-Only: default kinds (e.g. 1, 1000)
    let env_append = dummy_envelope(1, 0, vec![]);
    assert_eq!(
        classify_retention(&env_append),
        RetentionClass::Class1AppendOnly
    );
}

#[test]
fn test_open_engine_and_ephemeral_bypass() {
    let dir = tempdir().expect("create temp dir");
    let engine =
        StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage engine");

    assert_eq!(engine.keyspace_count(), 6);

    // Ingest Class 0 envelope
    let ephemeral_env = dummy_envelope(25000, 0, vec![]);
    let outcome = engine
        .put_envelope(&ephemeral_env)
        .expect("put ephemeral envelope");
    assert_eq!(outcome, RetentionOutcome::EphemeralPassed);

    // Verify envelope is not persisted to disk
    let id = compute_envelope_id(&ephemeral_env).expect("compute id");
    let retrieved = engine.get_envelope(&id).expect("get envelope");
    assert!(retrieved.is_none());
}
