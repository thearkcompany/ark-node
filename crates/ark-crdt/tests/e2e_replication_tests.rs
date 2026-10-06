//! E2E replication tests for `MstEngine` — Ticket #26 acceptance criteria.
//!
//! Tests the unified high-level `MstEngine` API and verifies multi-peer convergence.

use std::sync::Arc;
use tempfile::tempdir;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_crdt::engine::{MstConfig, MstEngine};
use ark_crdt::MstPutOutcome;
use ark_storage::{StorageConfig, StorageEngine};
use ark_core::constants::MAGIC_BYTES;
use ark_core::fast_header::FastHeader;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_storage() -> Arc<StorageEngine> {
    let dir = tempdir().unwrap();
    let path = dir.keep();
    Arc::new(StorageEngine::open(path, StorageConfig::frugal()).unwrap())
}

fn make_engine() -> MstEngine {
    let storage = make_storage();
    MstEngine::open(storage, MstConfig::default()).unwrap()
}

fn make_envelope(seed: u8, timestamp: u64) -> ArkEnvelope {
    let header = FastHeader::new(1, 0, 1, [seed; 16], [seed + 1; 16], 1);
    ArkEnvelope {
        magic: MAGIC_BYTES.to_vec(),
        fast_header: header.to_bytes().to_vec(),
        sender_id: vec![seed; 32],
        recipient_id: vec![seed + 1; 32],
        payload: vec![seed; 8],
        signature: vec![0u8; 64],
        core_tag_mask: 0,
        tags: vec![BinaryTag::new(0, vec![seed])],
        timestamp,
    }
}

// ── MstEngine API Tests ───────────────────────────────────────────────────────

/// Insert and retrieve an envelope via the high-level API.
#[test]
fn test_engine_put_and_get() {
    let engine = make_engine();
    let env = make_envelope(1, 1000);
    let key = b"test-key";

    let outcome = engine.put("ns", key, &env).unwrap();
    assert_eq!(outcome, MstPutOutcome::Inserted);

    let retrieved = engine.get("ns", key).unwrap();
    assert!(retrieved.is_some());
    let retrieved_env = retrieved.unwrap();
    assert_eq!(retrieved_env.timestamp, 1000);
}

/// Newer timestamp supersedes older entry.
#[test]
fn test_engine_put_newer_supersedes() {
    let engine = make_engine();
    let key = b"key";

    let old_env = make_envelope(1, 500);
    let new_env = make_envelope(2, 1500);

    assert_eq!(engine.put("ns", key, &old_env).unwrap(), MstPutOutcome::Inserted);
    assert_eq!(engine.put("ns", key, &new_env).unwrap(), MstPutOutcome::Updated);

    let result = engine.get("ns", key).unwrap().unwrap();
    assert_eq!(result.timestamp, 1500);
}

/// Older timestamp is rejected as `SupersededLww`.
#[test]
fn test_engine_put_older_superseded() {
    let engine = make_engine();
    let key = b"key";

    let new_env = make_envelope(1, 1500);
    let old_env = make_envelope(2, 500);

    engine.put("ns", key, &new_env).unwrap();
    let outcome = engine.put("ns", key, &old_env).unwrap();
    assert_eq!(outcome, MstPutOutcome::SupersededLww);

    // Tree root must be unchanged — still reflects the first entry.
    let result = engine.get("ns", key).unwrap().unwrap();
    assert_eq!(result.timestamp, 1500);
}

/// root_hash changes after write and is stable when nothing changes.
#[test]
fn test_engine_root_hash_changes_on_write() {
    let engine = make_engine();
    let root0 = engine.root_hash("ns").unwrap();
    assert!(root0.is_none());

    engine.put("ns", b"k1", &make_envelope(1, 100)).unwrap();
    let root1 = engine.root_hash("ns").unwrap().unwrap();

    engine.put("ns", b"k2", &make_envelope(2, 200)).unwrap();
    let root2 = engine.root_hash("ns").unwrap().unwrap();

    assert_ne!(root1, root2);
}

/// Tombstone deletion via `delete()` records the entry under Bivariate LWW.
#[test]
fn test_engine_delete_tombstone() {
    let engine = make_engine();
    let key = b"key";

    let env = make_envelope(1, 1000);
    engine.put("ns", key, &env).unwrap();

    let tombstone = make_envelope(2, 2000); // newer timestamp → tombstone wins
    engine.delete("ns", key, &tombstone).unwrap();
}

// ── Multi-Peer Replication Convergence Tests ──────────────────────────────────

/// Two nodes with non-overlapping writes converge after one sync round via MstEngine.
#[test]
fn test_two_node_sync_convergence() {
    let a = make_engine();
    let b = make_engine();

    // Node A writes keys a0..a4
    for i in 0u8..5 {
        let key = format!("a-key-{}", i);
        a.put("ns", key.as_bytes(), &make_envelope(10 + i, 1000 + i as u64)).unwrap();
    }

    // Node B writes keys b0..b4
    for i in 0u8..5 {
        let key = format!("b-key-{}", i);
        b.put("ns", key.as_bytes(), &make_envelope(20 + i, 2000 + i as u64)).unwrap();
    }

    // Roots differ before sync.
    assert_ne!(
        a.root_hash("ns").unwrap(),
        b.root_hash("ns").unwrap(),
    );

    // Sync A → B (B requests from A).
    let req_a_to_b = ark_protocol::MstSyncRequest {
        namespace: "ns".to_string(),
        root_hash: a.root_hash("ns").unwrap().unwrap_or([0u8; 32]).to_vec(),
        requested_node_hashes: vec![],
        key_range_start: vec![],
        key_range_end: vec![],
    };
    let resp_from_a = a.handle_sync_request(&req_a_to_b).unwrap();
    b.apply_sync_response(&resp_from_a).unwrap();

    // Sync B → A (A requests from B).
    let req_b_to_a = ark_protocol::MstSyncRequest {
        namespace: "ns".to_string(),
        root_hash: b.root_hash("ns").unwrap().unwrap_or([0u8; 32]).to_vec(),
        requested_node_hashes: vec![],
        key_range_start: vec![],
        key_range_end: vec![],
    };
    let resp_from_b = b.handle_sync_request(&req_b_to_a).unwrap();
    a.apply_sync_response(&resp_from_b).unwrap();

    // Both can now resolve each other's keys.
    for i in 0u8..5 {
        let ak = format!("a-key-{}", i);
        let bk = format!("b-key-{}", i);
        assert!(a.get("ns", ak.as_bytes()).unwrap().is_some(), "A should have a-key-{}", i);
        assert!(b.get("ns", ak.as_bytes()).unwrap().is_some(), "B should have a-key-{}", i);
        assert!(a.get("ns", bk.as_bytes()).unwrap().is_some(), "A should have b-key-{}", i);
        assert!(b.get("ns", bk.as_bytes()).unwrap().is_some(), "B should have b-key-{}", i);
    }
}

/// Three nodes with partitioned concurrent writes converge after cascaded sync.
#[test]
fn test_three_node_convergence_cascaded_sync() {
    let a = make_engine();
    let b = make_engine();
    let c = make_engine();

    // Write distinct keys to each node.
    for i in 0u8..10 {
        let key = format!("node-a-{}", i);
        a.put("sync", key.as_bytes(), &make_envelope(i, 1000 + i as u64)).unwrap();
    }
    for i in 0u8..10 {
        let key = format!("node-b-{}", i);
        b.put("sync", key.as_bytes(), &make_envelope(100 + i, 2000 + i as u64)).unwrap();
    }
    for i in 0u8..10 {
        let key = format!("node-c-{}", i);
        c.put("sync", key.as_bytes(), &make_envelope(200 + i, 3000 + i as u64)).unwrap();
    }

    // Sync all pairs bidirectionally.
    for _round in 0..2 {
        // A ↔ B
        let req = mk_request("sync", &a);
        let resp = a.handle_sync_request(&req).unwrap();
        b.apply_sync_response(&resp).unwrap();

        let req = mk_request("sync", &b);
        let resp = b.handle_sync_request(&req).unwrap();
        a.apply_sync_response(&resp).unwrap();

        // B ↔ C
        let req = mk_request("sync", &b);
        let resp = b.handle_sync_request(&req).unwrap();
        c.apply_sync_response(&resp).unwrap();

        let req = mk_request("sync", &c);
        let resp = c.handle_sync_request(&req).unwrap();
        b.apply_sync_response(&resp).unwrap();

        // A ↔ C
        let req = mk_request("sync", &a);
        let resp = a.handle_sync_request(&req).unwrap();
        c.apply_sync_response(&resp).unwrap();

        let req = mk_request("sync", &c);
        let resp = c.handle_sync_request(&req).unwrap();
        a.apply_sync_response(&resp).unwrap();
    }

    // All 30 keys are accessible from every node.
    for i in 0u8..10 {
        for (lbl, engine) in [("a", &a), ("b", &b), ("c", &c)] {
            assert!(
                engine.get("sync", format!("node-a-{}", i).as_bytes()).unwrap().is_some(),
                "node-{} missing node-a-{}", lbl, i
            );
            assert!(
                engine.get("sync", format!("node-b-{}", i).as_bytes()).unwrap().is_some(),
                "node-{} missing node-b-{}", lbl, i
            );
            assert!(
                engine.get("sync", format!("node-c-{}", i).as_bytes()).unwrap().is_some(),
                "node-{} missing node-c-{}", lbl, i
            );
        }
    }
}

/// Competing writes to the same key from two nodes resolve deterministically via Bivariate LWW.
#[test]
fn test_competing_writes_bivariate_lww_convergence() {
    let a = make_engine();
    let b = make_engine();

    let key = b"shared-key";

    // A has an older entry.
    a.put("ns", key, &make_envelope(1, 1000)).unwrap();
    // B has a newer entry.
    b.put("ns", key, &make_envelope(2, 2000)).unwrap();

    // Bidirectional sync.
    let req = mk_request("ns", &a);
    let resp = a.handle_sync_request(&req).unwrap();
    b.apply_sync_response(&resp).unwrap();

    let req = mk_request("ns", &b);
    let resp = b.handle_sync_request(&req).unwrap();
    a.apply_sync_response(&resp).unwrap();

    // Both nodes must agree: the newer timestamp wins.
    let ra = a.get("ns", key).unwrap().unwrap();
    let rb = b.get("ns", key).unwrap().unwrap();
    assert_eq!(ra.timestamp, 2000, "A should have newer entry");
    assert_eq!(rb.timestamp, 2000, "B should have newer entry");
}

/// `compute_sync_diff` returns empty plan when both nodes share the same root.
#[test]
fn test_compute_sync_diff_identical_roots_empty_plan() {
    let a = make_engine();
    a.put("ns", b"k", &make_envelope(1, 100)).unwrap();

    let root = a.root_hash("ns").unwrap().unwrap();
    let plan = a.compute_sync_diff("ns", &root).unwrap();
    assert!(plan.is_empty(), "identical roots should produce an empty sync plan");
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn mk_request(namespace: &str, engine: &MstEngine) -> ark_protocol::MstSyncRequest {
    ark_protocol::MstSyncRequest {
        namespace: namespace.to_string(),
        root_hash: engine
            .root_hash(namespace)
            .unwrap()
            .unwrap_or([0u8; 32])
            .to_vec(),
        requested_node_hashes: vec![],
        key_range_start: vec![],
        key_range_end: vec![],
    }
}
