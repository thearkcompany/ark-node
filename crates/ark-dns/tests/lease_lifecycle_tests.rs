use std::sync::Arc;
use ark_dns::error::DnsError;
use ark_dns::lifecycle::{
    DomainLeaseState, LeaseLifecycleEngine, MockPmtClock, PmtClock,
    GRACE_PERIOD_SECS, MAX_LEASE_DURATION_SECS,
};
use ark_dns::record::DomainRoutingRecord;
use ark_dns::SovereignDnsTrie;

fn sample_record(fqdn: &str, owner_key_id: [u8; 16], registered_at: u64, expires_at: u64) -> DomainRoutingRecord {
    DomainRoutingRecord {
        fqdn: fqdn.to_string(),
        owner_key_id,
        target_peer_id: [9u8; 32],
        routing_addrs: vec!["/ip4/127.0.0.1/udp/4433/quic-v1".to_string()],
        expires_at,
        in_grace_period: false,
        epoch_timestamp: registered_at,
        ech_public_key: vec![1, 2, 3],
    }
}

#[test]
fn test_state_machine_transitions() {
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let trie = Arc::new(SovereignDnsTrie::new());
    let engine = LeaseLifecycleEngine::with_time_provider(trie.clone(), clock.clone());

    let owner_a = [1u8; 16];
    let registered_at = 1_000_000;
    let expires_at = registered_at + 86400 * 30; // 30 days
    let record = sample_record("alice.ark", owner_a, registered_at, expires_at);

    // Initial registration
    engine.register(record.clone()).expect("registration should succeed");

    // 1. Active: now <= T_expire
    clock.set_time(expires_at - 10);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::Active));
    let resolved = engine.resolve("alice.ark").expect("lookup should succeed");
    assert!(resolved.is_some());
    assert!(!resolved.unwrap().in_grace_period);

    // Exactly at T_expire -> still Active
    clock.set_time(expires_at);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::Active));
    assert!(engine.resolve("alice.ark").unwrap().is_some());

    // 2. Grace Period: T_expire < now <= T_expire + 14 days
    clock.set_time(expires_at + 1);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::GracePeriod));
    // External resolution returns in_grace_period = true (or NXDOMAIN)
    let res_grace = engine.resolve("alice.ark").expect("lookup in grace period");
    assert!(res_grace.is_some());
    assert!(res_grace.unwrap().in_grace_period);

    // Mid grace period
    clock.set_time(expires_at + 7 * 86400);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::GracePeriod));

    // Exactly at boundary: T_expire + 14 days
    clock.set_time(expires_at + GRACE_PERIOD_SECS);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::GracePeriod));
    assert!(engine.resolve("alice.ark").unwrap().unwrap().in_grace_period);

    // 3. Expired: now > T_expire + 14 days
    clock.set_time(expires_at + GRACE_PERIOD_SECS + 1);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::Expired));
    // Resolution returns None (NXDOMAIN)
    assert!(engine.resolve("alice.ark").unwrap().is_none());
}

#[test]
fn test_grace_period_monopoly_enforcement() {
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let trie = Arc::new(SovereignDnsTrie::new());
    let engine = LeaseLifecycleEngine::with_time_provider(trie.clone(), clock.clone());

    let owner_a = [1u8; 16];
    let owner_b = [2u8; 16];
    let registered_at = 1_000_000;
    let expires_at = registered_at + 86400 * 30; // 30 days
    let record = sample_record("alice.ark", owner_a, registered_at, expires_at);

    engine.register(record).expect("registration ok");

    // Move clock into Grace Period
    clock.set_time(expires_at + 3600);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::GracePeriod));

    // Owner B attempts renewal during grace period -> Rejected!
    let new_expires_at = clock.now_pmt() + 86400 * 30;
    let renewal_b = sample_record("alice.ark", owner_b, clock.now_pmt(), new_expires_at);
    let err = engine.renew(renewal_b).expect_err("should reject renewal by non-owner");
    match err {
        DnsError::GracePeriodRenewalUnauthorized { fqdn, current_owner, attempted_by } => {
            assert_eq!(fqdn, "alice.ark");
            assert_eq!(current_owner, owner_a);
            assert_eq!(attempted_by, owner_b);
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Owner A attempts renewal during grace period -> Accepted!
    let renewal_a = sample_record("alice.ark", owner_a, clock.now_pmt(), new_expires_at);
    engine.renew(renewal_a).expect("owner renewal must succeed");

    // After renewal, domain is back to Active and in_grace_period = false
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::Active));
    let res = engine.resolve("alice.ark").unwrap().unwrap();
    assert!(!res.in_grace_period);
    assert_eq!(res.expires_at, new_expires_at);
}

#[test]
fn test_early_renewal_by_owner() {
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let trie = Arc::new(SovereignDnsTrie::new());
    let engine = LeaseLifecycleEngine::with_time_provider(trie.clone(), clock.clone());

    let owner_a = [1u8; 16];
    let owner_b = [2u8; 16];
    let registered_at = 1_000_000;
    let expires_at = registered_at + 86400 * 30;
    let record = sample_record("alice.ark", owner_a, registered_at, expires_at);
    engine.register(record).expect("initial register ok");

    // 10 days in, still Active
    clock.set_time(registered_at + 10 * 86400);

    // Attempted renewal by owner B during Active state should also be rejected
    let renewal_b = sample_record("alice.ark", owner_b, clock.now_pmt(), clock.now_pmt() + 86400 * 30);
    let err = engine.renew(renewal_b).expect_err("non-owner cannot renew active domain");
    match err {
        DnsError::UnauthorizedRenewal { fqdn, current_owner, attempted_by } => {
            assert_eq!(fqdn, "alice.ark");
            assert_eq!(current_owner, owner_a);
            assert_eq!(attempted_by, owner_b);
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Owner A renews early
    let renewal_a = sample_record("alice.ark", owner_a, clock.now_pmt(), clock.now_pmt() + 86400 * 60);
    engine.renew(renewal_a).expect("owner can renew early");
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::Active));
}

#[test]
fn test_post_grace_eviction_and_new_owner_registration() {
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let trie = Arc::new(SovereignDnsTrie::new());
    let engine = LeaseLifecycleEngine::with_time_provider(trie.clone(), clock.clone());

    let owner_a = [1u8; 16];
    let owner_b = [2u8; 16];
    let registered_at = 1_000_000;
    let expires_at = registered_at + 86400 * 10;
    let record = sample_record("alice.ark", owner_a, registered_at, expires_at);
    engine.register(record).expect("initial register ok");

    // Advance clock past 14 days grace period
    clock.set_time(expires_at + GRACE_PERIOD_SECS + 100);
    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::Expired));

    // Try to register "alice.ark" with new owner B
    let reg_b = sample_record("alice.ark", owner_b, clock.now_pmt(), clock.now_pmt() + 86400 * 30);
    engine.register(reg_b).expect("new owner should be able to register expired domain");

    assert_eq!(engine.state_of("alice.ark"), Some(DomainLeaseState::Active));
    let resolved = engine.resolve("alice.ark").unwrap().unwrap();
    assert_eq!(resolved.owner_key_id, owner_b);
    assert!(!resolved.in_grace_period);
}

#[test]
fn test_evict_expired_sweep() {
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let trie = Arc::new(SovereignDnsTrie::new());
    let engine = LeaseLifecycleEngine::with_time_provider(trie.clone(), clock.clone());

    let r1 = sample_record("active.ark", [1; 16], 1_000_000, 1_000_000 + 86400 * 10);
    let r2 = sample_record("grace.ark", [2; 16], 1_000_000, 1_000_000 + 86400 * 2);
    let r3 = sample_record("expired.ark", [3; 16], 1_000_000, 1_000_000 + 86400);

    engine.register(r1).unwrap();
    engine.register(r2).unwrap();
    engine.register(r3).unwrap();
    assert_eq!(trie.len(), 3);

    // At now = 1_000_000 + 86400 + GRACE_PERIOD_SECS + 1:
    // expired.ark is Expired.
    // grace.ark is in Grace Period (1 day into grace).
    // active.ark is Active.
    clock.set_time(1_000_000 + 86400 + GRACE_PERIOD_SECS + 1);

    let evicted = engine.evict_expired();
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0].fqdn, "expired.ark");
    assert_eq!(trie.len(), 2);

    assert!(engine.get_record("expired.ark").is_none());
    assert!(engine.get_record("grace.ark").is_some());
    assert!(engine.get_record("active.ark").is_some());
}

#[test]
fn test_lease_duration_bounds() {
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let trie = Arc::new(SovereignDnsTrie::new());
    let engine = LeaseLifecycleEngine::with_time_provider(trie.clone(), clock.clone());

    let owner = [1u8; 16];

    // Expiration in the past
    let past_rec = sample_record("alice.ark", owner, 1_000_000, 999_999);
    let err_past = engine.register(past_rec).expect_err("should reject expiration in the past");
    match err_past {
        DnsError::InvalidLeaseDuration(msg) => assert!(msg.contains("future")),
        other => panic!("Unexpected error: {:?}", other),
    }

    // Expiration > 365 days
    let too_long_rec = sample_record("alice.ark", owner, 1_000_000, 1_000_000 + MAX_LEASE_DURATION_SECS + 1);
    let err_long = engine.register(too_long_rec).expect_err("should reject duration > 365 days");
    match err_long {
        DnsError::InvalidLeaseDuration(msg) => assert!(msg.contains("exceeds")),
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_register_from_validated_claim() {
    use ark_dns::anti_sybil::ValidatedDnsClaim;

    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let trie = Arc::new(SovereignDnsTrie::new());
    let engine = LeaseLifecycleEngine::with_time_provider(trie.clone(), clock.clone());

    let claim = ValidatedDnsClaim {
        fqdn: "carol.ark".to_string(),
        lease_epoch: 1_000_000 + 86400 * 30,
        contract_id: vec![0x11, 0x22],
        owner_key_id: [5u8; 16],
        envelope_id: [0u8; 32],
    };

    let target_peer = [8u8; 32];
    let routing_addrs = vec!["/ip4/192.168.1.1/udp/4433/quic-v1".to_string()];
    let ech = vec![0xaa, 0xbb];

    engine
        .register_claim(&claim, target_peer, routing_addrs.clone(), ech.clone())
        .expect("claim registration must succeed");

    assert_eq!(engine.state_of("carol.ark"), Some(DomainLeaseState::Active));
    let resolved = engine.resolve("carol.ark").unwrap().unwrap();
    assert_eq!(resolved.fqdn, "carol.ark");
    assert_eq!(resolved.owner_key_id, [5u8; 16]);
    assert_eq!(resolved.target_peer_id, target_peer);
    assert_eq!(resolved.routing_addrs, routing_addrs);
    assert_eq!(resolved.ech_public_key, ech);
    assert!(!resolved.in_grace_period);

    // Advance clock past expiration into grace period
    clock.advance(86400 * 30 + 1);
    assert_eq!(engine.state_of("carol.ark"), Some(DomainLeaseState::GracePeriod));
    let resolved_grace = engine.resolve("carol.ark").unwrap().unwrap();
    assert!(resolved_grace.in_grace_period);

    // Renew via renew_claim with owner 5
    let renew_claim = ValidatedDnsClaim {
        fqdn: "carol.ark".to_string(),
        lease_epoch: clock.now_pmt() + 86400 * 30,
        contract_id: vec![0x33, 0x44],
        owner_key_id: [5u8; 16],
        envelope_id: [0u8; 32],
    };
    engine
        .renew_claim(&renew_claim, target_peer, routing_addrs, ech)
        .expect("claim renewal must succeed");

    assert_eq!(engine.state_of("carol.ark"), Some(DomainLeaseState::Active));
}
