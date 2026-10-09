use ark_time::{MockPmtClock, PeerMedianTime, PmtClock, SystemPmtClock};
use std::sync::Arc;

#[test]
fn test_mock_pmt_clock_operations() {
    let clock = MockPmtClock::new(1_000);
    assert_eq!(clock.now_pmt(), 1_000);

    clock.set_time(2_000);
    assert_eq!(clock.now_pmt(), 2_000);

    let advanced = clock.advance(500);
    assert_eq!(advanced, 2_500);
    assert_eq!(clock.now_pmt(), 2_500);

    // Dynamic dispatch compatibility
    let trait_clock: Arc<dyn PmtClock> = Arc::new(clock);
    assert_eq!(trait_clock.now_pmt(), 2_500);
}

#[test]
fn test_system_pmt_clock_operations() {
    let pmt = Arc::new(PeerMedianTime::new());
    let clock = SystemPmtClock::new(pmt.clone());

    let t1 = clock.now_pmt();
    assert!(t1 > 0);

    // With peer offset
    let peer_id = [7u8; 16];
    pmt.record_peer_offset(peer_id, 100);
    let t2 = clock.now_pmt();
    assert!(t2 >= t1 + 90);

    let trait_clock: Arc<dyn PmtClock> = Arc::new(clock);
    assert!(trait_clock.now_pmt() >= t2);
}
