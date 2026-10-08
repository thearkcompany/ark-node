use std::sync::Arc;
use tempfile::tempdir;
use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_crypto::identity::Identity;
use ark_storage::{StorageConfig, StorageEngine};
use ark_wot::crypto::{CapabilityScope, CapabilityScopes, TrustAttestation, TrustRevocation};
use ark_wot::engine::WotEngine;
use ark_wot::graph::TrustTier;
use rand::rngs::OsRng;

#[test]
fn test_wot_engine_e2e_lifecycle_and_subsystem_adapters() {
    let mut rng = OsRng;
    let local_key = FnDsaKeyPair::generate(&mut rng);
    let peer_a_key = FnDsaKeyPair::generate(&mut rng);
    let peer_b_key = FnDsaKeyPair::generate(&mut rng);

    let local_id = Identity::from_public_key(&local_key.public_key).ark_id;
    let peer_a = Identity::from_public_key(&peer_a_key.public_key).ark_id;
    let peer_b = Identity::from_public_key(&peer_b_key.public_key).ark_id;

    let dir = tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::default()).unwrap());
    let clock = Arc::new(ark_time::MockPmtClock::new(1000));

    let engine = WotEngine::open(local_id, storage, clock.clone()).unwrap();

    // 1. Initial trust evaluation: unknown peer is Untrusted
    let eval_init = engine.evaluate_trust(&peer_a);
    assert_eq!(eval_init.tier, TrustTier::Untrusted);

    // Cross-subsystem policy check: VPN denied, Blob upload denied, PaaS rejected
    assert!(!engine.is_vpn_allowed(&peer_a));
    assert!(!engine.is_storage_allowed(&peer_a));
    assert!(!engine.is_compute_allowed(&peer_a));

    // 2. Issue attestation to peer_a with RELAY + STORAGE capabilities
    let mut scopes_a = CapabilityScopes::empty();
    scopes_a.insert(CapabilityScope::RELAY);
    scopes_a.insert(CapabilityScope::STORAGE);

    let att_a = TrustAttestation::create_and_sign(
        local_id,
        peer_a,
        0.9,
        scopes_a,
        1000,
        1000 + 30 * 86400,
        1,
        &local_key,
    ).unwrap();

    engine.record_attestation(att_a, &local_key.public_key).unwrap();

    // Evaluation after attestation: Trusted
    let eval_a = engine.evaluate_trust(&peer_a);
    assert_eq!(eval_a.tier, TrustTier::Trusted);
    assert!(engine.is_vpn_allowed(&peer_a));
    assert!(engine.is_storage_allowed(&peer_a));
    assert!(!engine.is_compute_allowed(&peer_a));

    // Test evaluate_trust_pair and time decay via MockPmtClock
    let pair_score_initial = engine.evaluate_trust_pair(&local_id, &peer_a).unwrap();
    assert!((pair_score_initial - 0.9).abs() < 1e-4);

    // Advance clock by half-life (30 days) and verify decay
    clock.advance(30 * 86400);
    let pair_score_decayed = engine.evaluate_trust_pair(&local_id, &peer_a).unwrap();
    assert!((pair_score_decayed - 0.45).abs() < 1e-4);

    // Reset clock back for rest of lifecycle test
    clock.set_time(1000);

    // 3. Issue attestation peer_a -> peer_b
    let mut scopes_b = CapabilityScopes::empty();
    scopes_b.insert(CapabilityScope::COMPUTE);

    let att_b = TrustAttestation::create_and_sign(
        peer_a,
        peer_b,
        0.8,
        scopes_b,
        1000,
        1000 + 30 * 86400,
        2,
        &peer_a_key,
    ).unwrap();

    engine.record_attestation(att_b, &peer_a_key.public_key).unwrap();

    // Subgraph anti-entropy synchronization over MST CRDT
    let sync_items = engine.sync_subgraph(1000);
    assert_eq!(sync_items.len(), 2);

    // 4. Revocation of peer_a
    let rev_a = TrustRevocation::create_and_sign(
        local_id,
        peer_a,
        1100,
        "compromised".into(),
        3,
        &local_key,
    ).unwrap();

    engine.revoke_attestation(rev_a, &local_key.public_key).unwrap();

    // Immediately cuts off peer_a and transitively breaks peer_b
    assert!(!engine.is_vpn_allowed(&peer_a));
    let eval_a_after = engine.evaluate_trust(&peer_a);
    assert_eq!(eval_a_after.tier, TrustTier::Untrusted);

    let eval_b_after = engine.evaluate_trust(&peer_b);
    assert_eq!(eval_b_after.tier, TrustTier::Untrusted);
}
