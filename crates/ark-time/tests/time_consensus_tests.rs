use ark_core::error::ArkError;
use ark_core::traits::AntiReplayFilter;
use ark_time::drift::DriftValidator;
use ark_time::peer_median::PeerMedianTime;
use ark_time::cuckoo::DualCuckooAntiReplay;

#[test]
fn test_dual_cuckoo_filter_allocation_bounds() {
    let filter = DualCuckooAntiReplay::new();
    let mem = filter.estimated_memory_bytes();
    assert!(mem > 0);
    assert!(mem <= 24 * 1024 * 1024, "Filter memory ({mem} bytes) exceeds 24 MB ceiling");
}

#[test]
fn test_dual_cuckoo_filter_replay_detection() {
    let filter = DualCuckooAntiReplay::new();
    let nonce = b"unique-nonce-001";

    // First insertion should succeed
    assert!(filter.check_and_insert(nonce).unwrap());

    // Immediate replay should be detected
    match filter.check_and_insert(nonce) {
        Err(ArkError::ReplayDetected) => {}
        other => panic!("Expected ReplayDetected, got: {:?}", other),
    }
}

#[test]
fn test_dual_cuckoo_filter_generation_rotation() {
    let filter = DualCuckooAntiReplay::new();
    let nonce1 = b"epoch1-nonce";
    let nonce2 = b"epoch2-nonce";

    assert!(filter.check_and_insert(nonce1).unwrap());

    // Rotate generation: nonce1 moves to previous filter
    filter.rotate_generation();

    // Replay of nonce1 should still be detected from previous generation
    match filter.check_and_insert(nonce1) {
        Err(ArkError::ReplayDetected) => {}
        other => panic!("Expected ReplayDetected from previous generation, got: {:?}", other),
    }

    // Insert new nonce in current generation
    assert!(filter.check_and_insert(nonce2).unwrap());

    // Rotate generation again: nonce1 is cleared, nonce2 moves to previous
    filter.rotate_generation();

    // nonce2 still detected
    match filter.check_and_insert(nonce2) {
        Err(ArkError::ReplayDetected) => {}
        other => panic!("Expected ReplayDetected for nonce2, got: {:?}", other),
    }

    // nonce1 has been aged out and can be inserted again
    assert!(filter.check_and_insert(nonce1).unwrap());
}

#[test]
fn test_dual_cuckoo_filter_saturation_drop_policy() {
    // Construct small filter to saturate it quickly
    let small_filter = DualCuckooAntiReplay::with_capacity(8);

    let mut saturated = false;
    for i in 0..10_000 {
        let nonce = format!("flood-nonce-{i}");
        match small_filter.check_and_insert(nonce.as_bytes()) {
            Ok(_) => {}
            Err(ArkError::ReplayFilterFull) => {
                saturated = true;
                break;
            }
            Err(other) => panic!("Unexpected error on saturation: {:?}", other),
        }
    }

    assert!(saturated, "Filter must reject with ReplayFilterFull when saturated");
}

#[test]
fn test_drift_validator_boundaries() {
    let ref_time = 1_700_000_000u64;

    // Exact matches and bounds: <= 30s
    assert!(DriftValidator::validate_timestamp(ref_time, ref_time).is_ok());
    assert!(DriftValidator::validate_timestamp(ref_time + 30, ref_time).is_ok());
    assert!(DriftValidator::validate_timestamp(ref_time - 30, ref_time).is_ok());

    // Over boundaries: > 30s
    match DriftValidator::validate_timestamp(ref_time + 31, ref_time) {
        Err(ArkError::ClockDriftExceeded(delta, max)) => {
            assert_eq!(delta, 31);
            assert_eq!(max, 30);
        }
        other => panic!("Expected ClockDriftExceeded, got {:?}", other),
    }

    match DriftValidator::validate_timestamp(ref_time - 31, ref_time) {
        Err(ArkError::ClockDriftExceeded(delta, max)) => {
            assert_eq!(delta, -31);
            assert_eq!(max, 30);
        }
        other => panic!("Expected ClockDriftExceeded, got {:?}", other),
    }
}

#[test]
fn test_peer_median_time_consensus() {
    let pmt = PeerMedianTime::new();
    let local_now = 1_000_000u64;

    // No peers: median offset is 0
    assert_eq!(pmt.calculate_median_offset(), 0);
    assert_eq!(pmt.network_time_secs(local_now), local_now);

    // Single peer (+10s)
    let peer1 = [1u8; 16];
    pmt.record_peer_offset(peer1, 10);
    assert_eq!(pmt.calculate_median_offset(), 10);
    assert_eq!(pmt.network_time_secs(local_now), local_now + 10);

    // Two peers (+10s, -4s) -> median is (10 + -4) / 2 = 3
    let peer2 = [2u8; 16];
    pmt.record_peer_offset(peer2, -4);
    assert_eq!(pmt.calculate_median_offset(), 3);
    assert_eq!(pmt.network_time_secs(local_now), local_now + 3);

    // Three peers (+10s, -4s, +20s) -> sorted: [-4, 10, 20] -> median is 10
    let peer3 = [3u8; 16];
    pmt.record_peer_offset(peer3, 20);
    assert_eq!(pmt.calculate_median_offset(), 10);
    assert_eq!(pmt.network_time_secs(local_now), local_now + 10);

    // Five peers: [-15, -4, 5, 10, 20] -> median is 5
    let peer4 = [4u8; 16];
    let peer5 = [5u8; 16];
    pmt.record_peer_offset(peer4, -15);
    pmt.record_peer_offset(peer5, 5);
    assert_eq!(pmt.calculate_median_offset(), 5);
    assert_eq!(pmt.network_time_secs(local_now), local_now + 5);
}
