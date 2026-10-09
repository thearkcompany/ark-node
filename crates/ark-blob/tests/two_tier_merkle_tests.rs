use ark_blob::{
    compute_blob_cid, compute_shard_merkle_roots, compute_single_shard_root, hash_pair, BlobError,
    ShardMerkleProof, DATA_SHARDS, PARITY_SHARDS, SHARD_SIZE, SUB_BLOCKS_PER_SHARD, SUB_BLOCK_SIZE,
    SUB_CHUNK_SIZE, TAG_CONTENT_CID, TOTAL_SHARDS,
};
use sha3::{Digest, Sha3_256};
use std::time::Instant;

#[test]
fn test_tier1_canonical_blob_cid_deterministic() {
    let data = vec![42u8; 150_000]; // spans across multiple 64 KB sub-chunks
    let cid1 = compute_blob_cid(&data);
    let cid2 = compute_blob_cid(&data);

    assert_eq!(cid1, cid2);
    assert_ne!(cid1, [0u8; 32]);
    assert_eq!(TAG_CONTENT_CID, 0x0002);
    assert_eq!(SUB_CHUNK_SIZE, 64 * 1024);
}

#[test]
fn test_tier1_empty_and_small_data() {
    let empty_cid = compute_blob_cid(&[]);
    let expected_empty: [u8; 32] = Sha3_256::digest(b"").into();
    assert_eq!(empty_cid, expected_empty);

    let small_data = b"hello ark-blob world";
    let small_cid = compute_blob_cid(small_data);
    let expected_small: [u8; 32] = Sha3_256::digest(small_data).into();
    assert_eq!(small_cid, expected_small);
}

#[test]
fn test_tier1_multi_chunk_exact_tree_structure() {
    // 3 chunks of exactly 64 KB
    let chunk0 = vec![0x11u8; SUB_CHUNK_SIZE];
    let chunk1 = vec![0x22u8; SUB_CHUNK_SIZE];
    let chunk2 = vec![0x33u8; SUB_CHUNK_SIZE];

    let mut full_data = Vec::with_capacity(SUB_CHUNK_SIZE * 3);
    full_data.extend_from_slice(&chunk0);
    full_data.extend_from_slice(&chunk1);
    full_data.extend_from_slice(&chunk2);

    let h0: [u8; 32] = Sha3_256::digest(&chunk0).into();
    let h1: [u8; 32] = Sha3_256::digest(&chunk1).into();
    let h2: [u8; 32] = Sha3_256::digest(&chunk2).into();

    let h01 = hash_pair(&h0, &h1);
    let expected_root = hash_pair(&h01, &h2);

    let computed_cid = compute_blob_cid(&full_data);
    assert_eq!(computed_cid, expected_root);
}

#[test]
fn test_tier2_shard_roots_count_and_sizing() {
    assert_eq!(DATA_SHARDS, 10);
    assert_eq!(PARITY_SHARDS, 4);
    assert_eq!(TOTAL_SHARDS, 14);
    assert_eq!(SHARD_SIZE, 1024 * 1024);
    assert_eq!(SUB_BLOCK_SIZE, 4 * 1024);
    assert_eq!(SUB_BLOCKS_PER_SHARD, 256);

    // Create 14 valid 1 MB shards
    let shards: Vec<Vec<u8>> = (0..TOTAL_SHARDS)
        .map(|i| vec![i as u8; SHARD_SIZE])
        .collect();

    let roots = compute_shard_merkle_roots(&shards).expect("should compute shard roots");
    assert_eq!(roots.len(), TOTAL_SHARDS);

    // Each root should be unique since shards have distinct byte patterns
    for i in 0..TOTAL_SHARDS {
        for j in (i + 1)..TOTAL_SHARDS {
            assert_ne!(roots[i], roots[j]);
        }
    }
}

#[test]
fn test_tier2_invalid_shard_count_or_size() {
    // Only 10 shards instead of 14
    let few_shards: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; SHARD_SIZE]).collect();
    let err = compute_shard_merkle_roots(&few_shards).unwrap_err();
    assert_eq!(
        err,
        BlobError::InvalidShardCount {
            expected: 14,
            got: 10
        }
    );

    // 14 shards but one has incorrect size
    let mut bad_shards: Vec<Vec<u8>> = (0..14).map(|_| vec![0u8; SHARD_SIZE]).collect();
    bad_shards[5] = vec![0u8; 500];
    let err2 = compute_shard_merkle_roots(&bad_shards).unwrap_err();
    assert_eq!(
        err2,
        BlobError::InvalidShardSize {
            expected: SHARD_SIZE,
            got: 500
        }
    );
}

#[test]
fn test_shard_merkle_proof_generation_and_verification() {
    // Construct a pseudo-random 1 MB shard
    let mut shard = vec![0u8; SHARD_SIZE];
    for (i, byte) in shard.iter_mut().enumerate() {
        *byte = ((i * 31 + 7) % 251) as u8;
    }

    let shard_root = compute_single_shard_root(&shard).expect("root should compute");

    // Test proof generation and verification for several sub-blocks (beginning, middle, end)
    let test_indices = [0, 1, 42, 127, 128, 200, 255];
    for &block_idx in &test_indices {
        let proof = ShardMerkleProof::generate(&shard, 3, block_idx).expect("proof generation");
        assert_eq!(proof.shard_index, 3);
        assert_eq!(proof.sub_block_index, block_idx as u32);
        // 256 leaves in a balanced binary tree -> depth 8
        assert_eq!(proof.audit_path.len(), 8);

        let sub_block = &shard[block_idx * SUB_BLOCK_SIZE..(block_idx + 1) * SUB_BLOCK_SIZE];
        assert!(proof.verify_sub_block(&shard_root, sub_block));
        assert!(proof.verify_hash(&shard_root));

        // Negative check: wrong sub_block content
        let mut corrupted_block = sub_block.to_vec();
        corrupted_block[0] ^= 0xFF;
        assert!(!proof.verify_sub_block(&shard_root, &corrupted_block));

        // Negative check: wrong root
        let mut wrong_root = shard_root;
        wrong_root[0] ^= 0xFF;
        assert!(!proof.verify_sub_block(&wrong_root, sub_block));
        assert!(!proof.verify_hash(&wrong_root));

        // Negative check: corrupted audit path
        let mut corrupted_proof = proof.clone();
        corrupted_proof.audit_path[0].hash[0] ^= 0xAA;
        assert!(!corrupted_proof.verify_sub_block(&shard_root, sub_block));
        assert!(!corrupted_proof.verify_hash(&shard_root));
    }
}

#[test]
fn test_shard_merkle_proof_verification_performance_microseconds() {
    // Acceptance criteria: O(log N) microsecond verification
    let mut shard = vec![0u8; SHARD_SIZE];
    for (i, byte) in shard.iter_mut().enumerate() {
        *byte = (i % 255) as u8;
    }
    let shard_root = compute_single_shard_root(&shard).unwrap();
    let proof = ShardMerkleProof::generate(&shard, 0, 100).unwrap();
    let sub_block = &shard[100 * SUB_BLOCK_SIZE..101 * SUB_BLOCK_SIZE];

    // Warm-up
    assert!(proof.verify_sub_block(&shard_root, sub_block));

    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        assert!(proof.verify_sub_block(&shard_root, sub_block));
    }
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;
    // In debug mode with unoptimized Keccak permutations, 4 KB SHA3-256 + 8 tree levels
    // takes ~900-1400 µs; in release mode with optimizations it takes ~7 µs (< 50 µs).
    #[cfg(debug_assertions)]
    let max_allowed_micros = 5000.0;
    #[cfg(not(debug_assertions))]
    let max_allowed_micros = 50.0;

    assert!(
        avg_micros < max_allowed_micros,
        "Verification took too long: {:.2} µs (expected < {:.2} µs)",
        avg_micros,
        max_allowed_micros
    );
}

#[test]
fn test_shard_merkle_proof_codec() {
    let shard = vec![0xABu8; SHARD_SIZE];
    let proof = ShardMerkleProof::generate(&shard, 7, 123).unwrap();

    let bytes = proof.to_bytes();
    let decoded = ShardMerkleProof::from_bytes(&bytes).expect("decoding proof");

    assert_eq!(proof, decoded);
}
