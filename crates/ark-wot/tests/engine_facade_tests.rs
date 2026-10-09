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

#[test]
fn test_wot_engine_ingest_envelope_lifecycle_and_adversarial_rejection() {
    let mut rng = OsRng;
    let local_key = FnDsaKeyPair::generate(&mut rng);
    let peer_key = FnDsaKeyPair::generate(&mut rng);
    let attacker_key = FnDsaKeyPair::generate(&mut rng);

    let local_id = Identity::from_public_key(&local_key.public_key).ark_id;
    let peer_id = Identity::from_public_key(&peer_key.public_key).ark_id;

    let dir = tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::default()).unwrap());
    let clock = Arc::new(ark_time::MockPmtClock::new(2000));

    let engine = WotEngine::open(local_id, storage.clone(), clock.clone()).unwrap();

    // 1. Initial state: peer_id is Untrusted
    assert_eq!(engine.evaluate_trust(&peer_id).tier, TrustTier::Untrusted);

    // 2. Create valid attestation envelope
    let mut scopes = CapabilityScopes::empty();
    scopes.insert(CapabilityScope::RELAY);
    scopes.insert(CapabilityScope::STORAGE);

    let att = TrustAttestation::create_and_sign(
        local_id,
        peer_id,
        0.95,
        scopes,
        2000,
        2000 + 30 * 86400,
        1,
        &local_key,
    ).unwrap();

    let att_envelope = att.to_envelope(&local_key.public_key).unwrap();

    // Adversarial test: Missing TAG_WOT_PUBKEY
    let mut bad_envelope_no_pubkey = att_envelope.clone();
    bad_envelope_no_pubkey.tags.retain(|tag| tag.tag_type != ark_wot::crypto::TAG_WOT_PUBKEY);
    let err_no_pubkey = engine.ingest_envelope(&bad_envelope_no_pubkey);
    assert!(err_no_pubkey.is_err(), "Must reject envelope missing TAG_WOT_PUBKEY");
    // Ensure graph/storage was not updated
    assert_eq!(engine.evaluate_trust(&peer_id).tier, TrustTier::Untrusted);

    // Adversarial test: Pubkey does not derive issuer_id
    let mut bad_envelope_wrong_key = att_envelope.clone();
    for tag in bad_envelope_wrong_key.tags.iter_mut() {
        if tag.tag_type == ark_wot::crypto::TAG_WOT_PUBKEY {
            tag.tag_value = attacker_key.public_key.to_vec();
        }
    }
    let err_wrong_key = engine.ingest_envelope(&bad_envelope_wrong_key);
    assert!(err_wrong_key.is_err(), "Must reject envelope where pubkey != issuer_id");
    assert_eq!(engine.evaluate_trust(&peer_id).tier, TrustTier::Untrusted);

    // Adversarial test: Corrupted signature
    let mut bad_envelope_corrupt_sig = att_envelope.clone();
    let mut tampered_att = att.clone();
    tampered_att.signature[0] ^= 0xFF;
    bad_envelope_corrupt_sig.payload = tampered_att.to_cbor().unwrap();
    let err_corrupt_sig = engine.ingest_envelope(&bad_envelope_corrupt_sig);
    assert!(err_corrupt_sig.is_err(), "Must reject envelope with corrupted signature");
    assert_eq!(engine.evaluate_trust(&peer_id).tier, TrustTier::Untrusted);

    // Adversarial test: Unsupported envelope kind
    let mut bad_envelope_wrong_kind = att_envelope.clone();
    for tag in bad_envelope_wrong_kind.tags.iter_mut() {
        if tag.tag_type == 0 {
            tag.tag_value = 0x9999_u32.to_be_bytes().to_vec();
        }
    }
    bad_envelope_wrong_kind.fast_header = ark_core::fast_header::FastHeader::new(
        0,
        bad_envelope_wrong_kind.payload.len() as u32,
        0x9999,
        [0u8; 16],
        [0u8; 16],
        0,
    ).to_bytes().to_vec();
    let err_wrong_kind = engine.ingest_envelope(&bad_envelope_wrong_kind);
    assert!(err_wrong_kind.is_err(), "Must reject envelope with unsupported kind");
    assert_eq!(engine.evaluate_trust(&peer_id).tier, TrustTier::Untrusted);

    // 3. Successful ingestion of valid attestation envelope
    engine.ingest_envelope(&att_envelope).expect("Valid attestation ingestion must succeed");

    // Evaluation updated immediately: Trusted / CorePeer
    let eval_trusted = engine.evaluate_trust(&peer_id);
    assert_eq!(eval_trusted.tier, TrustTier::Trusted);
    assert!(engine.is_vpn_allowed(&peer_id));
    assert!(engine.is_storage_allowed(&peer_id));

    // Ensure synced subgraph has it
    let sync_items = engine.sync_subgraph(2000);
    assert_eq!(sync_items.len(), 1);

    // 4. Ingestion of valid revocation envelope
    let rev = TrustRevocation::create_and_sign(
        local_id,
        peer_id,
        2100,
        "test revocation".into(),
        2,
        &local_key,
    ).unwrap();

    let rev_envelope = rev.to_envelope(&local_key.public_key).unwrap();

    // Adversarial test on revocation: tampered signature
    let mut bad_rev_corrupt_sig = rev_envelope.clone();
    let mut tampered_rev = rev.clone();
    tampered_rev.signature[0] ^= 0xFF;
    bad_rev_corrupt_sig.payload = tampered_rev.to_cbor().unwrap();
    let err_rev_sig = engine.ingest_envelope(&bad_rev_corrupt_sig);
    assert!(err_rev_sig.is_err(), "Must reject revocation with corrupted signature");
    assert_eq!(engine.evaluate_trust(&peer_id).tier, TrustTier::Trusted);

    // Advance clock to match revocation timestamp (2100)
    clock.set_time(2100);

    // Ingest valid revocation
    engine.ingest_envelope(&rev_envelope).expect("Valid revocation ingestion must succeed");

    // Verification: immediate edge truncation and cache refresh
    let eval_after_rev = engine.evaluate_trust(&peer_id);
    assert_eq!(eval_after_rev.tier, TrustTier::Untrusted);
    assert_eq!(eval_after_rev.score, 0.0);
    assert!(!engine.is_vpn_allowed(&peer_id));
}

