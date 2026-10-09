//! Unit and integration tests for Máquina de Estados de Custódia, Staged Custody & Safe-Ghost Locking (Issue #40).

use std::sync::Arc;
use tempfile::tempdir;

use ark_blob::constants::{
    DATA_SHARDS, KIND_HOMELAB_ACK, PARITY_SHARDS, SHARD_SIZE, STAGED_CUSTODY_TTL_SECS,
    STAGED_MAX_FILE_SIZE, TAG_CONTENT_CID, TOTAL_SHARDS,
};
use ark_blob::custody::{CustodyState, CustodyStateMachine};
use ark_blob::error::BlobError;
use ark_blob::ghost_lock::SafeGhostLock;
use ark_blob::manifest::{BlobManifest, ShardStatus};
use ark_blob::merkle::{compute_blob_cid, compute_shard_merkle_roots};
use ark_blob::store::HybridBlobStore;
use ark_blob::CauchyReedSolomon;
use ark_core::FastHeader;
use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_storage::{StorageConfig, StorageEngine};
use rand::rngs::OsRng;

fn setup_store() -> (tempfile::TempDir, HybridBlobStore) {
    let dir = tempdir().expect("create tempdir");
    let storage_dir = dir.path().join("fjall");
    let cas_dir = dir.path().join("cas");

    let storage = Arc::new(
        StorageEngine::open(storage_dir, StorageConfig::frugal()).expect("open storage engine"),
    );
    let store = HybridBlobStore::new(cas_dir, storage).expect("open hybrid blob store");
    (dir, store)
}

fn create_sample_manifest(store: &HybridBlobStore, size: usize) -> BlobManifest {
    let codec = CauchyReedSolomon::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
    let data = vec![0x37u8; size];
    let shards = codec.encode_with_shard_len(&data, SHARD_SIZE).unwrap();

    let mut shard_hashes = Vec::new();
    for shard in &shards {
        let hash = store.put_shard(shard).expect("put shard in CAS");
        shard_hashes.push(hash);
    }

    let shard_roots = compute_shard_merkle_roots(&shards).unwrap();
    let blob_cid = compute_blob_cid(&data);

    BlobManifest {
        blob_cid,
        total_size: size as u64,
        data_shards: DATA_SHARDS,
        parity_shards: PARITY_SHARDS,
        shard_hashes,
        shard_roots,
        created_at: 1_700_000_000,
    }
}

fn build_homelab_ack_envelope(
    blob_cid: &[u8; 32],
    homelab_keypair: &FnDsaKeyPair,
    timestamp: u64,
) -> ArkEnvelope {
    let homelab_id = ark_crypto::Identity::from_public_key(&homelab_keypair.public_key);
    let fast_header = FastHeader::new(
        0,
        0,
        KIND_HOMELAB_ACK,
        homelab_id.sender_key_id,
        [0u8; 16],
        1,
    );

    let tags = vec![
        BinaryTag::new(TAG_CONTENT_CID, blob_cid.to_vec()),
        BinaryTag::new(0x0001, homelab_keypair.public_key.to_vec()), // carries public key
        BinaryTag::new(0, KIND_HOMELAB_ACK.to_be_bytes().to_vec()),
    ];

    let mut env = ArkEnvelope::new(
        fast_header.to_bytes(),
        homelab_id.ark_id,
        [0u8; 32],
        vec![],
        vec![],
        0,
        tags,
        timestamp,
    )
    .unwrap();

    // Sign canonical ID using Homelab keypair
    let canonical_id = ark_protocol::hashing::calculate_canonical_id(&env);
    let sig = homelab_keypair.sign(&canonical_id).unwrap();
    env.signature = sig;

    env
}

// =========================================================================
// Custody State Machine & Staged Custody Tests
// =========================================================================

#[test]
fn test_staged_full_custody_entry_under_25mb() {
    let (_dir, store) = setup_store();
    let csm = CustodyStateMachine::new(&store);

    // Payload < 25 MB (e.g., 5 MB)
    let manifest = create_sample_manifest(&store, 5 * 1024 * 1024);
    let now = 1_700_000_000;

    let record = csm
        .enter_staged_custody(&manifest, now)
        .expect("enter staged custody");

    assert_eq!(record.state, CustodyState::StagedFullCustody);
    assert_eq!(record.blob_cid, manifest.blob_cid);
    assert_eq!(record.created_at, now);
    assert_eq!(record.expires_at, now + STAGED_CUSTODY_TTL_SECS);

    // All 14 shards must be present on disk CAS and marked Present in LSM
    let statuses = store
        .list_blob_shard_statuses(&manifest.blob_cid)
        .expect("list shard statuses");
    assert_eq!(statuses.len(), TOTAL_SHARDS);
    for (idx, status) in statuses {
        assert_eq!(status, ShardStatus::Present, "Shard {} not Present", idx);
        let hash = &manifest.shard_hashes[idx as usize];
        assert!(
            store.has_shard(hash),
            "Shard payload {} missing in CAS",
            idx
        );
    }
}

#[test]
fn test_staged_full_custody_rejection_at_or_above_25mb() {
    let (_dir, store) = setup_store();
    let csm = CustodyStateMachine::new(&store);

    // Exactly 25 MB
    let mut manifest = create_sample_manifest(&store, 1024 * 1024);
    manifest.total_size = STAGED_MAX_FILE_SIZE; // 25 MB
    let res = csm.enter_staged_custody(&manifest, 1_700_000_000);
    assert!(
        matches!(res, Err(BlobError::IneligibleForStagedCustody { .. })),
        "Should reject file size >= 25 MB, got {:?}",
        res
    );

    // 30 MB
    manifest.total_size = 30 * 1024 * 1024;
    let res2 = csm.enter_staged_custody(&manifest, 1_700_000_000);
    assert!(
        matches!(res2, Err(BlobError::IneligibleForStagedCustody { .. })),
        "Should reject file size > 25 MB, got {:?}",
        res2
    );
}

#[test]
fn test_homelab_ack_atomic_discard_of_shards_0_to_9() {
    let (_dir, store) = setup_store();
    let csm = CustodyStateMachine::new(&store);

    let manifest = create_sample_manifest(&store, 2 * 1024 * 1024);
    let now = 1_700_000_000;
    csm.enter_staged_custody(&manifest, now)
        .expect("enter staged custody");

    // Pre-condition: all 14 shards exist in CAS
    for hash in &manifest.shard_hashes {
        assert!(store.has_shard(hash));
    }

    // Generate Homelab ACK envelope signed by valid FN-DSA keypair
    let mut rng = OsRng;
    let homelab_keypair = FnDsaKeyPair::generate(&mut rng);
    let ack_env = build_homelab_ack_envelope(&manifest.blob_cid, &homelab_keypair, now + 100);

    // Process ACK
    let updated_record = csm
        .handle_homelab_ack(&ack_env, Some(&homelab_keypair.public_key))
        .expect("handle valid homelab ack");

    assert_eq!(updated_record.state, CustodyState::HomelabConfirmed);
    let expected_homelab_id = ark_crypto::Identity::from_public_key(&homelab_keypair.public_key);
    assert_eq!(updated_record.homelab_id, Some(expected_homelab_id.ark_id));

    // Post-condition: Data shards (0..9) must be discarded from CAS and marked Purged in LSM
    for idx in 0..DATA_SHARDS {
        let hash = &manifest.shard_hashes[idx];
        assert!(
            !store.has_shard(hash),
            "Data shard {} should be removed from CAS disk",
            idx
        );
        let status = store
            .get_shard_status(&manifest.blob_cid, idx as u32)
            .expect("get shard status");
        assert_eq!(
            status,
            Some(ShardStatus::Purged),
            "Data shard {} should be marked Purged",
            idx
        );
    }

    // Parity shards (10..13) must be RETAINED in CAS and marked Present in LSM (40% overhead)
    for idx in DATA_SHARDS..TOTAL_SHARDS {
        let hash = &manifest.shard_hashes[idx];
        assert!(
            store.has_shard(hash),
            "Parity shard {} must be retained on CAS disk",
            idx
        );
        let status = store
            .get_shard_status(&manifest.blob_cid, idx as u32)
            .expect("get shard status");
        assert_eq!(
            status,
            Some(ShardStatus::Present),
            "Parity shard {} should be Present",
            idx
        );
    }
}

#[test]
fn test_homelab_ack_with_invalid_signature_fails_and_does_not_purge() {
    let (_dir, store) = setup_store();
    let csm = CustodyStateMachine::new(&store);

    let manifest = create_sample_manifest(&store, 1024 * 1024);
    let now = 1_700_000_000;
    csm.enter_staged_custody(&manifest, now).unwrap();

    let mut rng = OsRng;
    let homelab_keypair = FnDsaKeyPair::generate(&mut rng);
    let mut ack_env = build_homelab_ack_envelope(&manifest.blob_cid, &homelab_keypair, now + 100);

    // Corrupt signature
    ack_env.signature[10] ^= 0xFF;

    let res = csm.handle_homelab_ack(&ack_env, Some(&homelab_keypair.public_key));
    assert!(
        matches!(res, Err(BlobError::InvalidSignature(_))),
        "Must fail with InvalidSignature, got {:?}",
        res
    );

    // Shards must remain untouched
    for idx in 0..DATA_SHARDS {
        let hash = &manifest.shard_hashes[idx];
        assert!(
            store.has_shard(hash),
            "Data shard must NOT be removed on failed signature"
        );
    }
}

#[test]
fn test_gc_pruning_after_72_hours_window() {
    let (_dir, store) = setup_store();
    let csm = CustodyStateMachine::new(&store);

    let manifest = create_sample_manifest(&store, 2 * 1024 * 1024);
    let t0 = 1_700_000_000;
    csm.enter_staged_custody(&manifest, t0).unwrap();

    // 1. Time at 71 hours: not expired yet
    let t_71h = t0 + (71 * 3600);
    let pruned = csm.prune_expired_staged(t_71h).expect("prune at 71h");
    assert!(
        pruned.is_empty(),
        "Nothing should be pruned before 72 hours"
    );
    for idx in 0..DATA_SHARDS {
        assert!(store.has_shard(&manifest.shard_hashes[idx]));
    }

    // 2. Time at 72 hours + 1 sec: expired
    let t_72h = t0 + STAGED_CUSTODY_TTL_SECS + 1;
    let pruned = csm.prune_expired_staged(t_72h).expect("prune at 72h+");
    assert_eq!(pruned, vec![manifest.blob_cid]);

    // Data shards 0..9 must now be purged from CAS
    for idx in 0..DATA_SHARDS {
        assert!(
            !store.has_shard(&manifest.shard_hashes[idx]),
            "Data shard {} should be purged after GC expiration",
            idx
        );
        let status = store
            .get_shard_status(&manifest.blob_cid, idx as u32)
            .unwrap();
        assert_eq!(status, Some(ShardStatus::Purged));
    }

    // Custody state updated to Expired
    let record = csm
        .get_custody_record(&manifest.blob_cid)
        .unwrap()
        .expect("record exists");
    assert_eq!(record.state, CustodyState::Expired);
}

// =========================================================================
// Safe-Ghost Locking Tests
// =========================================================================

#[test]
fn test_safe_ghost_lock_prohibits_eviction_initially() {
    let ghost = SafeGhostLock::new();
    let blob_cid = [0xAAu8; 32];

    ghost.lock(blob_cid);
    assert!(ghost.is_locked(&blob_cid));

    // Attempting eviction must return SafeGhostLocked error
    let res = ghost.check_and_evict(&blob_cid);
    assert!(
        matches!(
            res,
            Err(BlobError::SafeGhostLocked {
                challenges: 0,
                required: 10
            })
        ),
        "Expected SafeGhostLocked, got {:?}",
        res
    );
    assert!(ghost.is_locked(&blob_cid));
}

#[test]
fn test_safe_ghost_lock_unlocked_by_homelab_ack() {
    let ghost = SafeGhostLock::new();
    let blob_cid = [0xBBu8; 32];

    ghost.lock(blob_cid);
    assert!(ghost.is_locked(&blob_cid));

    // Receive Homelab ACK
    ghost.record_homelab_ack(&blob_cid);
    assert!(!ghost.is_locked(&blob_cid));

    // Eviction now succeeds
    let res = ghost.check_and_evict(&blob_cid);
    assert!(
        res.is_ok(),
        "Eviction should succeed after Homelab ACK: {:?}",
        res
    );
    assert!(!ghost.is_locked(&blob_cid));
}

#[test]
fn test_safe_ghost_lock_unlocked_by_10_por_challenges() {
    let ghost = SafeGhostLock::new();
    let blob_cid = [0xCCu8; 32];

    ghost.lock(blob_cid);

    // Pass 9 challenges: still locked
    for i in 0..9 {
        let mut keeper_id = [0u8; 32];
        keeper_id[0] = i as u8;
        ghost.record_por_challenge_success(&blob_cid, keeper_id);
    }
    assert!(ghost.is_locked(&blob_cid));
    let err = ghost.check_and_evict(&blob_cid).unwrap_err();
    assert!(
        matches!(
            err,
            BlobError::SafeGhostLocked {
                challenges: 9,
                required: 10
            }
        ),
        "Expected SafeGhostLocked with 9/10, got {:?}",
        err
    );

    // Duplicate challenge from same keeper does not increment count
    let mut dup_keeper = [0u8; 32];
    dup_keeper[0] = 0;
    ghost.record_por_challenge_success(&blob_cid, dup_keeper);
    assert!(ghost.is_locked(&blob_cid));

    // 10th distinct keeper challenge succeeds
    let mut tenth_keeper = [0u8; 32];
    tenth_keeper[0] = 9;
    ghost.record_por_challenge_success(&blob_cid, tenth_keeper);

    assert!(!ghost.is_locked(&blob_cid));
    let res = ghost.check_and_evict(&blob_cid);
    assert!(
        res.is_ok(),
        "Eviction should succeed after 10 distinct PoR challenges: {:?}",
        res
    );
}
