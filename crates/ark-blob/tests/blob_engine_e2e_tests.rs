//! End-to-end integration tests for Fachada Unificada BlobEngine (Issue #42).
//!
//! Tests verify:
//! - Deep module facade BlobEngine aggregating all ark-blob modules (Cauchy RS 10+4, Two-Tier Merkle,
//!   CAS disk storage, Fjall LSM manifest indexing, CustodyStateMachine, SafeGhostLock, PoR auditing engine).
//! - Protobuf wire schemas (ArkBlobManifest, BlobShardDescriptor, DepinPorChallenge, DepinPorResponse).
//! - Pluggable L2 Escrow Verification via BlobEscrowVerifier trait (validating TAG_L2_CONTRACT 0x000F).
//! - Rejection of unsponsored manifests by MockBlobEscrowVerifier.
//! - QUIC FastHeader shard streaming framing (64-byte FastHeader framing line-rate 1 MB shard transfers).
//! - Full E2E lifecycle: encode_and_store, retrieve_and_decode, stage_upload, custody transitions,
//!   PoR challenge/response, and recovery workflow.

use std::sync::Arc;
use tempfile::tempdir;

use ark_blob::constants::{
    DATA_SHARDS, KIND_HOMELAB_ACK, PARITY_SHARDS, SHARD_SIZE, TAG_CONTENT_CID, TAG_L2_CONTRACT,
    TOTAL_SHARDS,
};
use ark_blob::custody::CustodyState;
use ark_blob::error::BlobError;
use ark_blob::escrow::{BlobEscrowVerifier, MockBlobEscrowVerifier, PermissiveBlobEscrowVerifier};
use ark_blob::framing::{ShardStreamFrame, FAST_HEADER_FLAG_BLOB_STREAM};
use ark_blob::manifest::{BlobManifest, ShardStatus};
use ark_blob::por::{DePINChallenge, DePINChallengeResponse};
use ark_blob::store::HybridBlobStore;
use ark_blob::BlobEngine;

use ark_core::FastHeader;
use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_storage::{StorageConfig, StorageEngine};
use rand::rngs::OsRng;

fn setup_engine<V: BlobEscrowVerifier>(verifier: V) -> (tempfile::TempDir, BlobEngine<V>) {
    let dir = tempdir().expect("create tempdir");
    let storage_dir = dir.path().join("fjall");
    let cas_dir = dir.path().join("cas");

    let storage =
        Arc::new(StorageEngine::open(storage_dir, StorageConfig::frugal()).expect("open storage"));
    let store = HybridBlobStore::new(cas_dir, storage).expect("open hybrid store");
    let engine = BlobEngine::new(store, verifier);
    (dir, engine)
}

fn build_homelab_ack(blob_cid: &[u8; 32], keypair: &FnDsaKeyPair, timestamp: u64) -> ArkEnvelope {
    let homelab_id = ark_crypto::Identity::from_public_key(&keypair.public_key);
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
        BinaryTag::new(0x0001, keypair.public_key.to_vec()),
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

    let canonical_id = ark_protocol::hashing::calculate_canonical_id(&env);
    let sig = keypair.sign(&canonical_id).unwrap();
    env.signature = sig;
    env
}

#[test]
fn test_blob_engine_full_e2e_encode_and_reconstruct() {
    let (_dir, engine) = setup_engine(PermissiveBlobEscrowVerifier::new());

    // 1.5 MB payload (> 1 shard)
    let payload_size = 1_500_000;
    let payload = vec![0x5Au8; payload_size];

    // Ingest and encode
    let ingest = engine
        .encode_and_store(&payload, None)
        .expect("encode and store succeeds");

    assert_eq!(ingest.total_size, payload_size as u64);
    assert_eq!(ingest.shard_hashes.len(), TOTAL_SHARDS);
    assert_eq!(ingest.shard_roots.len(), TOTAL_SHARDS);
    assert!(ingest.custody.is_some());
    assert_eq!(
        ingest.custody.as_ref().unwrap().state,
        CustodyState::StagedFullCustody
    );

    // Verify all 14 shards stored in CAS
    for hash in &ingest.shard_hashes {
        assert!(engine.store().has_shard(hash));
    }

    // Verify manifest index in Fjall LSM
    let fetched_manifest = engine
        .store()
        .get_manifest(&ingest.blob_cid)
        .expect("get manifest")
        .expect("manifest found");
    assert_eq!(fetched_manifest.blob_cid, ingest.blob_cid);
    assert_eq!(fetched_manifest.total_size, payload_size as u64);

    // Reconstruct directly via BlobEngine
    let recovered = engine
        .retrieve_and_decode(&ingest.blob_cid)
        .expect("retrieve and decode succeeds");
    assert_eq!(recovered, payload);
}

#[test]
fn test_l2_escrow_verification_rejection_and_acceptance() {
    let mock_verifier = MockBlobEscrowVerifier::new();
    let (_dir, engine) = setup_engine(mock_verifier.clone());

    let payload = vec![0x42u8; 100_000];
    let contract_id = b"ark-pay-contract-valid-123";
    let fake_contract_id = b"unauthorized-contract-456";

    // Compute expected CID
    let blob_cid = ark_blob::compute_blob_cid(&payload);

    // Whitelist only the valid contract for this blob
    mock_verifier.allow_blob_contract(contract_id, &blob_cid);

    // 1. Ingest with unauthorized contract must fail
    let err = engine
        .encode_and_store(&payload, Some(fake_contract_id))
        .unwrap_err();
    match err {
        BlobError::EscrowVerificationFailed(_) => (),
        other => panic!("Expected EscrowVerificationFailed, got {:?}", other),
    }

    // 2. Ingest with whitelisted contract must succeed
    let result = engine
        .encode_and_store(&payload, Some(contract_id))
        .expect("ingest with valid contract succeeds");
    assert_eq!(result.blob_cid, blob_cid);

    // 3. Test manifest envelope ingestion with L2 verification
    let envelope = result
        .manifest
        .to_envelope_with_escrow(&[0x11u8; 32], Some(contract_id))
        .unwrap();
    let ingested_manifest = engine
        .ingest_manifest_envelope(&envelope, true)
        .expect("valid escrow envelope accepted");
    assert_eq!(ingested_manifest.blob_cid, blob_cid);

    // 4. Test manifest envelope missing escrow when required
    let unsponsored_envelope = result.manifest.to_envelope(&[0x11u8; 32]).unwrap();
    let err_missing = engine
        .ingest_manifest_envelope(&unsponsored_envelope, true)
        .unwrap_err();
    match err_missing {
        BlobError::MissingTag(TAG_L2_CONTRACT) => (),
        other => panic!("Expected MissingTag(TAG_L2_CONTRACT), got {:?}", other),
    }
}

#[test]
fn test_protobuf_wire_schemas_roundtrip() {
    let manifest = BlobManifest {
        blob_cid: [0x88u8; 32],
        total_size: 2_000_000,
        data_shards: DATA_SHARDS,
        parity_shards: PARITY_SHARDS,
        shard_hashes: vec![[0x11u8; 32]; TOTAL_SHARDS],
        shard_roots: vec![[0x22u8; 32]; TOTAL_SHARDS],
        created_at: 1_700_000_200,
    };

    let contract = b"l2-escrow-sub";

    // 1. ArkBlobManifest Protobuf roundtrip
    let proto_bytes = manifest.to_proto_bytes(Some(contract));
    let decoded_manifest = BlobManifest::from_proto_bytes(&proto_bytes).expect("proto decode");
    assert_eq!(decoded_manifest, manifest);

    // 2. DepinPorChallenge Protobuf roundtrip
    let challenge = DePINChallenge::new([0x33u8; 32], 5, 42, [0x44u8; 32]);
    let challenge_proto_bytes = challenge.to_proto_bytes();
    let decoded_challenge =
        DePINChallenge::from_proto_bytes(&challenge_proto_bytes).expect("challenge proto decode");
    assert_eq!(decoded_challenge, challenge);

    // 3. DepinPorResponse Protobuf roundtrip
    let dummy_shard = vec![0x12u8; SHARD_SIZE];
    let por_response = DePINChallengeResponse::generate(&dummy_shard, &challenge).unwrap();
    let response_proto_bytes = por_response.to_proto_bytes();
    let decoded_response = DePINChallengeResponse::from_proto_bytes(&response_proto_bytes)
        .expect("response proto decode");
    assert_eq!(decoded_response, por_response);
}

#[test]
fn test_quic_fastheader_shard_streaming() {
    let (_dir, engine) = setup_engine(PermissiveBlobEscrowVerifier::new());

    let payload = vec![0x77u8; 1_000_000];
    let ingest = engine.encode_and_store(&payload, None).unwrap();

    let shard_index = 3;
    let shard_hash = &ingest.shard_hashes[shard_index];
    let sender_prefix = [0xAAu8; 16];
    let recipient_prefix = [0xBBu8; 16];

    // Frame shard into QUIC FastHeader wire format
    let frame_bytes = engine
        .frame_shard_stream(
            shard_hash,
            shard_index as u32,
            sender_prefix,
            recipient_prefix,
        )
        .expect("frame shard stream");

    // Inspect FastHeader (first 64 bytes)
    let (header, decoded_idx, decoded_len) =
        ShardStreamFrame::inspect_header(&frame_bytes).expect("inspect header");
    assert_eq!(decoded_idx, shard_index as u32);
    assert_eq!(decoded_len, SHARD_SIZE as u32);
    assert_eq!(header.flags, FAST_HEADER_FLAG_BLOB_STREAM);
    assert_eq!(header.sender_key_id, sender_prefix);
    assert_eq!(header.recipient_key_id, recipient_prefix);
    assert_eq!(header.sequence_nonce, shard_index as u64);

    // Ingest frame into another engine instance
    let (_dir2, receiving_engine) = setup_engine(PermissiveBlobEscrowVerifier::new());
    let (ingested_idx, ingested_hash) = receiving_engine
        .ingest_shard_stream_frame(&frame_bytes)
        .expect("ingest shard stream frame");

    assert_eq!(ingested_idx, shard_index as u32);
    assert_eq!(ingested_hash, *shard_hash);
    assert!(receiving_engine.store().has_shard(shard_hash));
}

#[test]
fn test_full_staged_custody_homelab_ack_lifecycle() {
    let (_dir, engine) = setup_engine(PermissiveBlobEscrowVerifier::new());

    let payload = vec![0x99u8; 500_000];
    let ingest = engine.stage_upload(&payload, None).unwrap();

    // Verify safe-ghost lock active
    assert!(engine.ghost_lock().is_locked(&ingest.blob_cid));
    let err_evict = engine.evict_cached_blob(&ingest.blob_cid).unwrap_err();
    match err_evict {
        BlobError::SafeGhostLocked { .. } => (),
        other => panic!("Expected SafeGhostLocked, got {:?}", other),
    }

    // Verify Phase 1: All 14 shards present
    let statuses = engine
        .store()
        .list_blob_shard_statuses(&ingest.blob_cid)
        .unwrap();
    assert_eq!(statuses.len(), TOTAL_SHARDS);
    for (_idx, status) in statuses {
        assert_eq!(status, ShardStatus::Present);
    }

    // Phase 2: Homelab confirms receipt
    let mut rng = OsRng;
    let homelab_keypair = FnDsaKeyPair::generate(&mut rng);
    let ack_envelope = build_homelab_ack(&ingest.blob_cid, &homelab_keypair, 1_700_000_500);

    let custody_rec = engine
        .handle_homelab_ack(&ack_envelope, None)
        .expect("homelab ack succeeds");
    assert_eq!(custody_rec.state, CustodyState::HomelabConfirmed);

    // SafeGhostLock is now unlocked
    assert!(!engine.ghost_lock().is_locked(&ingest.blob_cid));

    // Data shards 0..9 are purged; parity shards 10..13 retained (40% overhead)
    for idx in 0..DATA_SHARDS {
        let hash = &ingest.shard_hashes[idx];
        assert!(!engine.store().has_shard(hash));
        assert_eq!(
            engine
                .store()
                .get_shard_status(&ingest.blob_cid, idx as u32)
                .unwrap(),
            Some(ShardStatus::Purged)
        );
    }
    for idx in DATA_SHARDS..TOTAL_SHARDS {
        let hash = &ingest.shard_hashes[idx];
        assert!(engine.store().has_shard(hash));
        assert_eq!(
            engine
                .store()
                .get_shard_status(&ingest.blob_cid, idx as u32)
                .unwrap(),
            Some(ShardStatus::Present)
        );
    }
}

#[test]
fn test_safe_ghost_lock_unlocked_via_10_por_challenges() {
    let (_dir, engine) = setup_engine(PermissiveBlobEscrowVerifier::new());

    let payload = vec![0x12u8; 300_000];
    let ingest = engine.stage_upload(&payload, None).unwrap();

    assert!(engine.ghost_lock().is_locked(&ingest.blob_cid));

    // Perform 10 distinct PoR challenges across 10 distinct keepers
    for i in 0..10 {
        let keeper_id = [i as u8 + 1; 32];
        let challenge =
            engine.create_por_challenge(ingest.blob_cid, (i % 4) as u32, [i as u8; 32], None);
        let response = engine.handle_depin_challenge(&challenge).unwrap();

        let valid = engine
            .verify_depin_response(&response, &challenge, Some(keeper_id))
            .expect("verify response");
        assert!(valid);
    }

    // Now unlocked via 10 PoR keeper confirmations
    assert!(!engine.ghost_lock().is_locked(&ingest.blob_cid));
    engine
        .evict_cached_blob(&ingest.blob_cid)
        .expect("eviction succeeds once unlocked");
}
