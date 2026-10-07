use ark_blob::{
    derive_sub_block_index, generate_depin_challenge, verify_depin_challenge_response,
    BlobError, DePINChallenge, DePINChallengeResponse, HybridBlobStore,
    KIND_DEPIN_CHALLENGE, KIND_DEPIN_RESPONSE, SHARD_SIZE, SUB_BLOCKS_PER_SHARD,
    SUB_BLOCK_SIZE, TAG_CHALLENGE_SEED, TAG_CONTENT_CID, TAG_SHARD_INDEX, TAG_SUB_BLOCK_INDEX,
};
use ark_storage::{StorageConfig, StorageEngine};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn test_challenge_generation_and_deterministic_sample() {
    let blob_cid = [0x42u8; 32];
    let seed = [0x12u8; 32];
    let shard_idx = 3u32;
    let sample_idx = 100u32;

    let challenge = DePINChallenge::new(blob_cid, shard_idx, sample_idx, seed);
    assert_eq!(challenge.blob_cid, blob_cid);
    assert_eq!(challenge.shard_index, shard_idx);
    assert_eq!(challenge.sub_block_index, sample_idx);
    assert_eq!(challenge.seed, seed);

    // Envelope serialization check
    let sender_id = [0x01u8; 32];
    let env = challenge.to_envelope(&sender_id).expect("envelope serialization");
    assert_eq!(env.tags.len(), 4);

    let decoded_challenge = DePINChallenge::from_envelope(&env).expect("decode envelope");
    assert_eq!(decoded_challenge, challenge);

    // Test deterministic sampling derivation
    let derived_idx = derive_sub_block_index(&seed, shard_idx);
    assert!((derived_idx as usize) < SUB_BLOCKS_PER_SHARD);
    let sampled_challenge = DePINChallenge::new_sampled(blob_cid, shard_idx, seed);
    assert_eq!(sampled_challenge.sub_block_index, derived_idx);

    // Test convenience helper generate_depin_challenge
    let helper_env = generate_depin_challenge(blob_cid, shard_idx, seed, None, &sender_id)
        .expect("helper challenge envelope");
    let decoded_helper = DePINChallenge::from_envelope(&helper_env).expect("decode helper envelope");
    assert_eq!(decoded_helper, sampled_challenge);
}

#[test]
fn test_keeper_proof_generation_and_auditor_verification() {
    let dir = tempdir().unwrap();
    let storage_dir = dir.path().join("storage");
    let cas_dir = dir.path().join("cas");

    let storage = Arc::new(StorageEngine::open(storage_dir, StorageConfig::frugal()).unwrap());
    let store = HybridBlobStore::new(cas_dir, storage).unwrap();

    // Prepare a mock 1 MB shard
    let mut shard = vec![0u8; SHARD_SIZE];
    for (i, b) in shard.iter_mut().enumerate() {
        *b = ((i * 37 + 13) % 256) as u8;
    }
    let shard_hash = store.put_shard(&shard).unwrap();
    assert!(store.has_shard(&shard_hash));

    let blob_cid = [0xAAu8; 32];
    let shard_idx = 2u32;
    let sample_idx = 45u32;
    let seed = [0x77u8; 32];

    let challenge = DePINChallenge::new(blob_cid, shard_idx, sample_idx, seed);

    // Keeper generates proof
    let response = DePINChallengeResponse::generate(&shard, &challenge).expect("generate response");
    assert_eq!(response.shard_index, shard_idx);
    assert_eq!(response.sub_block_index, sample_idx);
    assert_eq!(response.sub_block.len(), SUB_BLOCK_SIZE);

    // Auditor verifies proof
    let shard_root = ark_blob::compute_single_shard_root(&shard).unwrap();
    let is_valid = response.verify(&shard_root, &challenge);
    assert!(is_valid);
    assert!(verify_depin_challenge_response(&response, &shard_root, &challenge));

    // Response envelope roundtrip
    let sender_id = [0x02u8; 32];
    let resp_env = response.to_envelope(&sender_id).expect("response envelope");
    let decoded_resp = DePINChallengeResponse::from_envelope(&resp_env).expect("decode response env");
    assert_eq!(decoded_resp, response);
    assert!(verify_depin_challenge_response(&decoded_resp, &shard_root, &challenge));
}

#[test]
fn test_rejection_of_tampered_sub_block() {
    let shard = vec![0x11u8; SHARD_SIZE];
    let blob_cid = [0xAAu8; 32];
    let shard_idx = 1u32;
    let sample_idx = 10u32;
    let seed = [0x77u8; 32];

    let challenge = DePINChallenge::new(blob_cid, shard_idx, sample_idx, seed);
    let mut response = DePINChallengeResponse::generate(&shard, &challenge).unwrap();
    let shard_root = ark_blob::compute_single_shard_root(&shard).unwrap();

    // Tamper with mac response
    response.mac[0] ^= 0xFF;
    assert!(!response.verify(&shard_root, &challenge));
    assert!(!verify_depin_challenge_response(&response, &shard_root, &challenge));

    // Tamper with sub_block bytes inside response
    let mut response2 = DePINChallengeResponse::generate(&shard, &challenge).unwrap();
    response2.sub_block[0] ^= 0x01;
    assert!(!response2.verify(&shard_root, &challenge));

    // Tamper with challenge seed
    let mut bad_challenge = challenge.clone();
    bad_challenge.seed[0] ^= 0x55;
    let response3 = DePINChallengeResponse::generate(&shard, &challenge).unwrap();
    assert!(!response3.verify(&shard_root, &bad_challenge));

    // Tamper with shard index or sub block index
    let mut bad_challenge_idx = challenge.clone();
    bad_challenge_idx.sub_block_index = 11;
    assert!(!response3.verify(&shard_root, &bad_challenge_idx));
}

#[test]
fn test_rejection_of_invalid_merkle_path() {
    let shard = vec![0x22u8; SHARD_SIZE];
    let blob_cid = [0xBBu8; 32];
    let shard_idx = 0u32;
    let sample_idx = 5u32;
    let seed = [0x99u8; 32];

    let challenge = DePINChallenge::new(blob_cid, shard_idx, sample_idx, seed);
    let mut response = DePINChallengeResponse::generate(&shard, &challenge).unwrap();
    let shard_root = ark_blob::compute_single_shard_root(&shard).unwrap();

    // Tamper with Merkle proof audit path
    response.proof.audit_path[0].hash[0] ^= 0xAA;
    assert!(!response.verify(&shard_root, &challenge));

    // Tamper with shard root
    let mut bad_shard_root = shard_root;
    bad_shard_root[0] ^= 0xEE;
    let response2 = DePINChallengeResponse::generate(&shard, &challenge).unwrap();
    assert!(!response2.verify(&bad_shard_root, &challenge));
}

#[test]
fn test_verification_performance_microseconds() {
    let shard = vec![0x55u8; SHARD_SIZE];
    let blob_cid = [0xCCu8; 32];
    let challenge = DePINChallenge::new(blob_cid, 0, 12, [0x11u8; 32]);
    let response = DePINChallengeResponse::generate(&shard, &challenge).unwrap();
    let shard_root = ark_blob::compute_single_shard_root(&shard).unwrap();

    // Warm up
    assert!(response.verify(&shard_root, &challenge));

    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        assert!(response.verify(&shard_root, &challenge));
    }
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    #[cfg(debug_assertions)]
    let max_allowed = 5000.0;
    #[cfg(not(debug_assertions))]
    let max_allowed = 50.0;

    assert!(avg_micros < max_allowed, "Verification too slow: {:.2} µs", avg_micros);
}

#[test]
fn test_invalid_parameters_boundaries() {
    let short_shard = vec![0u8; 500];
    let challenge = DePINChallenge::new([0u8; 32], 0, 0, [1u8; 32]);
    let err = DePINChallengeResponse::generate(&short_shard, &challenge).unwrap_err();
    assert_eq!(
        err,
        BlobError::InvalidShardSize {
            expected: SHARD_SIZE,
            got: 500
        }
    );

    let valid_shard = vec![0u8; SHARD_SIZE];
    let oob_challenge = DePINChallenge::new([0u8; 32], 0, 300, [1u8; 32]);
    let err_oob = DePINChallengeResponse::generate(&valid_shard, &oob_challenge).unwrap_err();
    assert_eq!(
        err_oob,
        BlobError::InvalidSubBlockIndex {
            index: 300,
            max: SUB_BLOCKS_PER_SHARD - 1
        }
    );
}

#[test]
fn test_constants_and_tags() {
    assert_eq!(KIND_DEPIN_CHALLENGE, 0x4000_0002);
    assert_eq!(KIND_DEPIN_RESPONSE, 0x4000_0003);
    assert_eq!(TAG_CONTENT_CID, 0x0002);
    assert_eq!(TAG_SHARD_INDEX, 0x0015);
    assert_eq!(TAG_CHALLENGE_SEED, 0x0016);
    assert_eq!(TAG_SUB_BLOCK_INDEX, 0x0017);
    assert_eq!(SUB_BLOCK_SIZE, 4096);
    assert_eq!(SUB_BLOCKS_PER_SHARD, 256);
}
