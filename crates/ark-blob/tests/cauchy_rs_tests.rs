use ark_blob::{BlobError, CauchyReedSolomon};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

#[test]
fn test_default_parameters() {
    let rs = CauchyReedSolomon::default();
    assert_eq!(rs.data_shards, 10);
    assert_eq!(rs.parity_shards, 4);
    assert_eq!(rs.total_shards(), 14);
}

#[test]
fn test_encode_empty_payload_fails() {
    let rs = CauchyReedSolomon::default();
    let res = rs.encode(&[]);
    assert!(matches!(res, Err(BlobError::EmptyPayload)));
}

#[test]
fn test_encode_and_reconstruct_exact_data() {
    let rs = CauchyReedSolomon::default();
    let original = b"Hello world! Testing Cauchy Reed-Solomon 10+4 erasure coding.".to_vec();

    let shards = rs.encode(&original).expect("encode should succeed");
    assert_eq!(shards.len(), 14);

    // Reconstruct with first 10 shards (data shards 0..10)
    let subset: Vec<(usize, Vec<u8>)> = shards[0..10]
        .iter()
        .cloned()
        .enumerate()
        .collect();

    let recovered = rs.reconstruct(&subset, original.len()).expect("reconstruct should succeed");
    assert_eq!(recovered, original);
}

#[test]
fn test_reconstruct_with_insufficient_shards_fails() {
    let rs = CauchyReedSolomon::default();
    let original = vec![0x42; 1000];
    let shards = rs.encode(&original).unwrap();

    // 9 shards should fail with InsufficientShards
    let subset: Vec<(usize, Vec<u8>)> = shards[0..9]
        .iter()
        .cloned()
        .enumerate()
        .collect();

    let res = rs.reconstruct(&subset, original.len());
    assert!(matches!(res, Err(BlobError::InsufficientShards { available: 9, required: 10 })));
}

#[test]
fn test_reconstruct_with_duplicate_shards_fails() {
    let rs = CauchyReedSolomon::default();
    let original = vec![0x42; 1000];
    let shards = rs.encode(&original).unwrap();

    // 10 entries but duplicate index 0
    let mut subset: Vec<(usize, Vec<u8>)> = shards[0..10]
        .iter()
        .cloned()
        .enumerate()
        .collect();
    subset[1] = (0, shards[0].clone());

    let res = rs.reconstruct(&subset, original.len());
    assert!(matches!(res, Err(BlobError::DuplicateShardIndex(0))));
}

#[test]
fn test_reconstruct_with_invalid_shard_index_fails() {
    let rs = CauchyReedSolomon::default();
    let original = vec![0x42; 1000];
    let shards = rs.encode(&original).unwrap();

    let mut subset: Vec<(usize, Vec<u8>)> = shards[0..10]
        .iter()
        .cloned()
        .enumerate()
        .collect();
    subset[0] = (14, shards[0].clone()); // Index 14 is invalid for 10+4 (indices are 0..14, so max is 13)

    let res = rs.reconstruct(&subset, original.len());
    assert!(matches!(res, Err(BlobError::InvalidShardIndex(14))));
}

#[test]
fn test_reconstruct_with_mismatched_shard_lengths_fails() {
    let rs = CauchyReedSolomon::default();
    let original = vec![0x42; 1000];
    let shards = rs.encode(&original).unwrap();

    let mut subset: Vec<(usize, Vec<u8>)> = shards[0..10]
        .iter()
        .cloned()
        .enumerate()
        .collect();
    subset[0].1.pop(); // Corrupt shard length

    let res = rs.reconstruct(&subset, original.len());
    assert!(matches!(res, Err(BlobError::ShardLengthMismatch)));
}

#[test]
fn test_reconstruct_all_combinations_of_4_erasures() {
    let rs = CauchyReedSolomon::default();
    // Test a payload with diverse bytes
    let mut original = Vec::with_capacity(100_000);
    for i in 0..100_000 {
        original.push((i % 251) as u8);
    }

    let shards = rs.encode(&original).expect("encode should succeed");
    assert_eq!(shards.len(), 14);

    // Test a few specific loss patterns including all parity, all first 4 data, interleaved
    let loss_patterns: Vec<Vec<usize>> = vec![
        vec![10, 11, 12, 13], // Lose all parity shards
        vec![0, 1, 2, 3],     // Lose first 4 data shards
        vec![0, 3, 7, 9],     // Lose 4 random data shards
        vec![0, 5, 10, 13],   // Lose 2 data and 2 parity shards
        vec![6, 7, 8, 9],     // Lose last 4 data shards
        vec![1, 2, 11, 12],   // Mixed
    ];

    for missing in loss_patterns {
        let available: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .enumerate()
            .filter(|(idx, _)| !missing.contains(idx))
            .take(10)
            .map(|(idx, shard)| (idx, shard.clone()))
            .collect();

        assert_eq!(available.len(), 10);
        let recovered = rs.reconstruct(&available, original.len()).expect("reconstruction should succeed");
        assert_eq!(recovered, original, "Failed to reconstruct when missing {:?}", missing);
    }
}

#[test]
fn test_encode_shards_1mb_standard() {
    let rs = CauchyReedSolomon::default();
    assert_eq!(CauchyReedSolomon::STANDARD_SHARD_SIZE, 1_048_576);

    // Encode with 1 MB standard shard size:
    // Original payload of 5 MB (smaller than 10 MB = 10 * 1 MB)
    let original = vec![0xAB; 5 * 1024 * 1024];
    let shards = rs.encode_standard(&original).expect("encode_standard should succeed");
    assert_eq!(shards.len(), 14);
    for shard in &shards {
        assert_eq!(shard.len(), 1_048_576);
    }

    // Reconstruct with 4 parity shards + 6 data shards (missing data shards 0, 1, 2, 3)
    let available: Vec<(usize, Vec<u8>)> = shards
        .iter()
        .enumerate()
        .skip(4) // shards 4..14 (6 data + 4 parity = 10 shards)
        .map(|(idx, s)| (idx, s.clone()))
        .collect();

    assert_eq!(available.len(), 10);
    let recovered = rs.reconstruct(&available, original.len()).expect("reconstruct standard should succeed");
    assert_eq!(recovered, original);
}

#[test]
fn test_exhaustive_erasure_combinations_property() {
    // Generate all (14 choose 4) = 1001 possible subsets of 4 missing shards.
    // Verify that every single 10-shard combination perfectly reconstructs the payload!
    let rs = CauchyReedSolomon::default();
    let mut rng = StdRng::seed_from_u64(0x1337_CAFE);
    let mut payload = vec![0u8; 1234];
    rng.fill_bytes(&mut payload);

    let shards = rs.encode(&payload).expect("encode should succeed");
    assert_eq!(shards.len(), 14);

    let mut count = 0;
    // Iterate over all combinations of 4 missing shards out of 14:
    for i in 0..14 {
        for j in (i + 1)..14 {
            for k in (j + 1)..14 {
                for l in (k + 1)..14 {
                    let missing = [i, j, k, l];
                    let available: Vec<(usize, Vec<u8>)> = shards
                        .iter()
                        .enumerate()
                        .filter(|(idx, _)| !missing.contains(idx))
                        .map(|(idx, s)| (idx, s.clone()))
                        .collect();

                    assert_eq!(available.len(), 10);
                    let recovered = rs.reconstruct(&available, payload.len())
                        .unwrap_or_else(|e| panic!("Failed at missing {:?}: {:?}", missing, e));
                    assert_eq!(recovered, payload, "Payload mismatch for missing {:?}", missing);
                    count += 1;
                }
            }
        }
    }

    // 14 choose 4 = 14*13*12*11 / (4*3*2*1) = 1001
    assert_eq!(count, 1001);
}

#[test]
fn test_property_various_payload_sizes() {
    let rs = CauchyReedSolomon::default();
    let mut rng = StdRng::seed_from_u64(0xDEADC0DE);

    let sizes = [1, 2, 7, 9, 10, 11, 64, 1024, 65536, 131072, 500000];
    for &size in &sizes {
        let mut payload = vec![0u8; size];
        rng.fill_bytes(&mut payload);

        let shards = rs.encode(&payload).unwrap();

        // Pick 4 random erased shards
        let mut indices: Vec<usize> = (0..14).collect();
        // Take 10 random
        let mut selected = Vec::new();
        for _ in 0..10 {
            let pick = rng.gen_range(0..indices.len());
            let shard_idx = indices.remove(pick);
            selected.push((shard_idx, shards[shard_idx].clone()));
        }

        let recovered = rs.reconstruct(&selected, size).unwrap();
        assert_eq!(recovered, payload, "Failed at size {}", size);
    }
}
