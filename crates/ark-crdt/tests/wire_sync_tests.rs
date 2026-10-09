use ark_crdt::error::ArkCrdtError;
use ark_crdt::mst::{MstEntry, MstNode};
use ark_crdt::store::{MstStore, MstStoreConfig};
use ark_crdt::sync::{
    apply_sync_response, handle_sync_request, node_to_wire, wire_to_node, MAX_SYNC_BATCH_NODES,
};
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_protocol::{MstSyncRequest, MstSyncResponse};
use ark_storage::{compute_envelope_id, StorageConfig, StorageEngine};
use std::sync::Arc;
use tempfile::tempdir;

fn create_test_envelope(kind: u32, timestamp: u64, payload: &[u8]) -> ArkEnvelope {
    let mut sender_key_id = [1u8; 16];
    let payload_len = payload.len().min(16);
    sender_key_id[..payload_len].copy_from_slice(&payload[..payload_len]);

    let header = ark_core::fast_header::FastHeader::new(1, 0, kind, sender_key_id, [2u8; 16], 1);
    let mut sender_id = vec![0u8; 32];
    sender_id[..16].copy_from_slice(&sender_key_id);

    ArkEnvelope {
        magic: ark_core::constants::MAGIC_BYTES.to_vec(),
        fast_header: header.to_bytes().to_vec(),
        sender_id,
        recipient_id: vec![2u8; 32],
        payload: payload.to_vec(),
        signature: vec![0u8; 64],
        core_tag_mask: 0,
        tags: vec![BinaryTag::new(0, kind.to_be_bytes().to_vec())],
        timestamp,
    }
}

#[test]
fn test_wire_translation_roundtrip() {
    let mut node = MstNode::new(2);
    let entry1 = MstEntry::new(b"key1".to_vec(), [0xAA; 32], 1000);
    let entry2 = MstEntry::new(b"key2".to_vec(), [0xBB; 32], 2000);
    node.entries.push(entry1);
    node.entries.push(entry2);
    node.children = vec![None, None, None];
    let expected_hash = node.hash();

    let wire = node_to_wire(&mut node);
    assert_eq!(wire.node_hash, expected_hash.to_vec());
    assert_eq!(wire.level, 2);
    assert_eq!(wire.entries.len(), 2);
    assert_eq!(wire.child_hashes.len(), 3);

    let (mut decoded_node, child_hashes) = wire_to_node(&wire).expect("decode wire");
    assert_eq!(decoded_node.level, 2);
    assert_eq!(decoded_node.entries.len(), 2);
    assert_eq!(decoded_node.entries[0].key, b"key1");
    assert_eq!(decoded_node.entries[0].envelope_id, [0xAA; 32]);
    assert_eq!(decoded_node.entries[0].timestamp, 1000);
    assert_eq!(decoded_node.hash(), expected_hash);
    assert_eq!(child_hashes.len(), 3);
}

#[test]
fn test_handle_sync_request_bounded_nodes() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap());
    let store = MstStore::open(storage.clone(), MstStoreConfig::default()).unwrap();
    let ns = "test-dns";

    // Populate store with nodes
    for i in 0..100 {
        let key = format!("ark.domain.{:03}", i).into_bytes();
        let env = create_test_envelope(10001, 1000 + i, b"value");
        let env_id = compute_envelope_id(&env).unwrap();
        storage.put_envelope(&env).unwrap();
        store.put(ns, key, env_id, 1000 + i).unwrap();
    }

    let root_hash = store.root_hash(ns).unwrap().unwrap();

    // Request 70 node hashes (more than safety limit 64)
    let requested_hashes: Vec<Vec<u8>> = (0..70).map(|i| vec![i as u8; 32]).collect();
    let req = MstSyncRequest {
        namespace: ns.to_string(),
        root_hash: root_hash.to_vec(),
        requested_node_hashes: requested_hashes,
        key_range_start: vec![],
        key_range_end: vec![],
    };

    let resp = handle_sync_request(&req, &store, &storage).expect("handle request");
    // Response nodes strictly bounded by MAX_SYNC_BATCH_NODES (64)
    assert!(resp.nodes.len() <= MAX_SYNC_BATCH_NODES);
    assert_eq!(resp.namespace, ns);
}

#[test]
fn test_apply_sync_response_rejects_hash_mismatch() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap());
    let store = MstStore::open(storage.clone(), MstStoreConfig::default()).unwrap();
    let ns = "test-validation";

    let mut node = MstNode::new(1);
    node.entries
        .push(MstEntry::new(b"tampered".to_vec(), [1u8; 32], 100));
    node.children = vec![None, None];
    let _real_hash = node.hash();

    let mut wire = node_to_wire(&mut node);
    // Tamper with claimed hash
    wire.node_hash = vec![0x99u8; 32];

    let resp = MstSyncResponse {
        namespace: ns.to_string(),
        root_hash: wire.node_hash.clone(),
        nodes: vec![wire],
        missing_envelopes: vec![],
    };

    let result = apply_sync_response(&resp, &store, &storage);
    assert!(result.is_err(), "must reject mismatched node hash");
    match result.err().unwrap() {
        ArkCrdtError::InvalidNodeHash { .. } | ArkCrdtError::ValidationError(_) => {}
        other => panic!(
            "expected InvalidNodeHash or ValidationError, got {:?}",
            other
        ),
    }
}

#[test]
fn test_apply_sync_response_rejects_depth_limit() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap());
    let store = MstStore::open(storage.clone(), MstStoreConfig::default()).unwrap();
    let ns = "test-depth";

    // Depth > 16 (level 17)
    let mut node = MstNode::new(17);
    node.entries
        .push(MstEntry::new(b"deep".to_vec(), [1u8; 32], 100));
    node.children = vec![None, None];
    let wire = node_to_wire(&mut node);

    let resp = MstSyncResponse {
        namespace: ns.to_string(),
        root_hash: wire.node_hash.clone(),
        nodes: vec![wire],
        missing_envelopes: vec![],
    };

    let result = apply_sync_response(&resp, &store, &storage);
    assert!(result.is_err(), "must reject depth > 16");
    match result.err().unwrap() {
        ArkCrdtError::DepthLimitExceeded(d) => assert!(d > 16),
        ArkCrdtError::ValidationError(msg) => {
            assert!(msg.contains("depth") || msg.contains("level"))
        }
        other => panic!(
            "expected DepthLimitExceeded or ValidationError, got {:?}",
            other
        ),
    }
}

#[test]
fn test_end_to_end_sync_convergence() {
    let dir_a = tempdir().expect("tempdir a");
    let dir_b = tempdir().expect("tempdir b");

    let storage_a = Arc::new(StorageEngine::open(dir_a.path(), StorageConfig::frugal()).unwrap());
    let store_a = MstStore::open(storage_a.clone(), MstStoreConfig::default()).unwrap();

    let storage_b = Arc::new(StorageEngine::open(dir_b.path(), StorageConfig::frugal()).unwrap());
    let store_b = MstStore::open(storage_b.clone(), MstStoreConfig::default()).unwrap();

    let ns = "test-replicate";

    // Node A writes keys
    for i in 0..20 {
        let key = format!("cluster/key/a_{}", i).into_bytes();
        let env = create_test_envelope(
            10001,
            1000 + i as u64,
            format!("payload_a_{}", i).as_bytes(),
        );
        let env_id = compute_envelope_id(&env).unwrap();
        storage_a.put_envelope(&env).unwrap();
        store_a.put(ns, key, env_id, 1000 + i as u64).unwrap();
    }

    // Node B writes keys
    for i in 0..20 {
        let key = format!("cluster/key/b_{}", i).into_bytes();
        let env = create_test_envelope(
            10001,
            2000 + i as u64,
            format!("payload_b_{}", i).as_bytes(),
        );
        let env_id = compute_envelope_id(&env).unwrap();
        storage_b.put_envelope(&env).unwrap();
        store_b.put(ns, key, env_id, 2000 + i as u64).unwrap();
    }

    let root_a_init = store_a.root_hash(ns).unwrap().unwrap();
    let root_b_init = store_b.root_hash(ns).unwrap().unwrap();
    assert_ne!(root_a_init, root_b_init);

    // Sync exchange: B syncs to A, then A syncs to B (or mutual exchange)
    // Step 1: B asks A for missing state
    let req_b_to_a = MstSyncRequest {
        namespace: ns.to_string(),
        root_hash: root_b_init.to_vec(),
        requested_node_hashes: vec![],
        key_range_start: vec![],
        key_range_end: vec![],
    };
    let resp_a = handle_sync_request(&req_b_to_a, &store_a, &storage_a).unwrap();
    apply_sync_response(&resp_a, &store_b, &storage_b).unwrap();

    // Step 2: A asks B for missing state
    let req_a_to_b = MstSyncRequest {
        namespace: ns.to_string(),
        root_hash: store_a.root_hash(ns).unwrap().unwrap().to_vec(),
        requested_node_hashes: vec![],
        key_range_start: vec![],
        key_range_end: vec![],
    };
    let resp_b = handle_sync_request(&req_a_to_b, &store_b, &storage_b).unwrap();
    apply_sync_response(&resp_b, &store_a, &storage_a).unwrap();

    // Assert convergence: root hashes must be identical
    let root_a_final = store_a.root_hash(ns).unwrap().unwrap();
    let root_b_final = store_b.root_hash(ns).unwrap().unwrap();
    assert_eq!(
        root_a_final, root_b_final,
        "Roots must converge to identical hash"
    );

    // Point queries on both nodes must return the same data
    for i in 0..20 {
        let key_a = format!("cluster/key/a_{}", i).into_bytes();
        let val_a_on_a = store_a.get(ns, &key_a).unwrap().unwrap();
        let val_a_on_b = store_b.get(ns, &key_a).unwrap().unwrap();
        assert_eq!(val_a_on_a, val_a_on_b);

        let key_b = format!("cluster/key/b_{}", i).into_bytes();
        let val_b_on_a = store_a.get(ns, &key_b).unwrap().unwrap();
        let val_b_on_b = store_b.get(ns, &key_b).unwrap().unwrap();
        assert_eq!(val_b_on_a, val_b_on_b);

        // Envelopes must exist in both storage engines
        assert!(storage_a.get_envelope(&val_b_on_a.0).unwrap().is_some());
        assert!(storage_b.get_envelope(&val_a_on_b.0).unwrap().is_some());
    }
}
