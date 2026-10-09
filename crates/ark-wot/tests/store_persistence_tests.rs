use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_crypto::identity::Identity;
use ark_storage::{StorageConfig, StorageEngine};
use ark_wot::crypto::{CapabilityScopes, TrustAttestation, TrustRevocation};
use ark_wot::graph::TrustTier;
use ark_wot::store::WotStore;
use rand::rngs::OsRng;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_wot_store_persistence_and_cache_recovery() {
    let mut rng = OsRng;
    let local_key = FnDsaKeyPair::generate(&mut rng);
    let peer_key = FnDsaKeyPair::generate(&mut rng);

    let local_id = Identity::from_public_key(&local_key.public_key).ark_id;
    let peer_id = Identity::from_public_key(&peer_key.public_key).ark_id;

    let dir = tempdir().unwrap();

    // 1. First session: open store, insert attestation, recalculate cache
    {
        let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::default()).unwrap());
        let store = WotStore::open(local_id, storage).unwrap();

        let attestation = TrustAttestation::create_and_sign(
            local_id,
            peer_id,
            0.9,
            CapabilityScopes::empty(),
            1000,
            1000 + 30 * 86400,
            1,
            &local_key,
        )
        .unwrap();

        store
            .save_attestation(&attestation, &local_key.public_key)
            .unwrap();

        // Check in-memory O(1) cache evaluation
        let eval = store.evaluate_cached(&peer_id, 1000);
        assert_eq!(eval.tier, TrustTier::Trusted);
        assert_eq!(eval.distance, 1);
        assert!(eval.score >= 0.50);
    }

    // 2. Second session (crash-recovery / restart): reopen and verify state reloaded
    {
        let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::default()).unwrap());
        let store = WotStore::open(local_id, storage).unwrap();

        // In-memory cache should be populated from persistent Fjall LSM keyspaces
        let eval = store.evaluate_cached(&peer_id, 1000);
        assert_eq!(eval.tier, TrustTier::Trusted);
        assert_eq!(eval.distance, 1);

        // Record a revocation and verify cache is invalidated/updated
        let revocation = TrustRevocation::create_and_sign(
            local_id,
            peer_id,
            1100,
            "revoked".into(),
            2,
            &local_key,
        )
        .unwrap();

        store
            .save_revocation(&revocation, &local_key.public_key)
            .unwrap();

        let eval_rev = store.evaluate_cached(&peer_id, 1200);
        assert_eq!(eval_rev.tier, TrustTier::Untrusted);
        assert_eq!(eval_rev.score, 0.0);
    }
}

#[test]
fn test_wot_store_internalized_mst_and_single_pass_persistence() {
    use ark_wot::CRDT_NAMESPACE_WOT;

    let mut rng = OsRng;
    let local_key = FnDsaKeyPair::generate(&mut rng);
    let peer_key = FnDsaKeyPair::generate(&mut rng);

    let local_id = Identity::from_public_key(&local_key.public_key).ark_id;
    let peer_id = Identity::from_public_key(&peer_key.public_key).ark_id;

    let dir = tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::default()).unwrap());

    // 1. WotStore::open initializes MstEngine internally
    let store = WotStore::open(local_id, storage.clone()).unwrap();
    let mst_engine = store.mst_engine();

    // 2. save_attestation writes to Fjall LSM and MstEngine simultaneously
    let attestation = TrustAttestation::create_and_sign(
        local_id,
        peer_id,
        0.85,
        CapabilityScopes::empty(),
        1000,
        1000 + 30 * 86400,
        1,
        &local_key,
    )
    .unwrap();

    store
        .save_attestation(&attestation, &local_key.public_key)
        .unwrap();

    let compound_key = WotStore::make_relation_key(&local_id, &peer_id);
    let fetched_env = mst_engine.get(CRDT_NAMESPACE_WOT, &compound_key).unwrap();
    assert!(
        fetched_env.is_some(),
        "Attestation envelope must be indexed in MstEngine"
    );

    // 3. Test WotStore::with_mst_engine injection
    let custom_mst = Arc::new(
        ark_crdt::MstEngine::open(storage.clone(), ark_crdt::MstConfig::default()).unwrap(),
    );
    let custom_store =
        WotStore::with_mst_engine(local_id, storage.clone(), custom_mst.clone()).unwrap();
    assert!(Arc::ptr_eq(custom_store.mst_engine(), &custom_mst));

    // save_revocation writes to MstEngine
    let revocation =
        TrustRevocation::create_and_sign(local_id, peer_id, 1050, "revoked".into(), 2, &local_key)
            .unwrap();

    custom_store
        .save_revocation(&revocation, &local_key.public_key)
        .unwrap();

    let fetched_rev_env = custom_mst.get(CRDT_NAMESPACE_WOT, &compound_key).unwrap();
    assert!(
        fetched_rev_env.is_some(),
        "Revocation envelope must be indexed in MstEngine"
    );
}

#[test]
fn test_wot_store_ingest_crdt_envelope_and_adversarial_rejection() {
    let mut rng = OsRng;
    let local_key = FnDsaKeyPair::generate(&mut rng);
    let peer_key = FnDsaKeyPair::generate(&mut rng);
    let attacker_key = FnDsaKeyPair::generate(&mut rng);

    let local_id = Identity::from_public_key(&local_key.public_key).ark_id;
    let peer_id = Identity::from_public_key(&peer_key.public_key).ark_id;

    let dir = tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::default()).unwrap());
    let store = WotStore::open(local_id, storage.clone()).unwrap();

    let now_pmt = 2000u64;

    // 1. Initial state: peer_id is Untrusted
    assert_eq!(
        store.evaluate_cached(&peer_id, now_pmt).tier,
        TrustTier::Untrusted
    );

    // 2. Create valid attestation envelope from peer_key asserting trust in local_id or another peer
    let att = TrustAttestation::create_and_sign(
        local_id,
        peer_id,
        0.9,
        CapabilityScopes::empty(),
        now_pmt,
        now_pmt + 30 * 86400,
        1,
        &local_key,
    )
    .unwrap();
    let valid_envelope = att.to_envelope(&local_key.public_key).unwrap();

    // Adversarial test: Missing TAG_WOT_PUBKEY
    let mut bad_no_pubkey = valid_envelope.clone();
    bad_no_pubkey
        .tags
        .retain(|tag| tag.tag_type != ark_wot::crypto::TAG_WOT_PUBKEY);
    let err_no_pubkey = store.ingest_crdt_envelope(&bad_no_pubkey, now_pmt);
    assert!(
        err_no_pubkey.is_err(),
        "Must reject envelope without TAG_WOT_PUBKEY"
    );
    assert_eq!(
        store.evaluate_cached(&peer_id, now_pmt).tier,
        TrustTier::Untrusted
    );

    // Adversarial test: Mismatched issuer public key (issuer_id != SHA3-256(pubkey))
    let mut bad_mismatched_key = valid_envelope.clone();
    for tag in bad_mismatched_key.tags.iter_mut() {
        if tag.tag_type == ark_wot::crypto::TAG_WOT_PUBKEY {
            tag.tag_value = attacker_key.public_key.to_vec();
        }
    }
    let err_mismatched = store.ingest_crdt_envelope(&bad_mismatched_key, now_pmt);
    assert!(
        err_mismatched.is_err(),
        "Must reject envelope where pubkey != issuer_id"
    );
    assert_eq!(
        store.evaluate_cached(&peer_id, now_pmt).tier,
        TrustTier::Untrusted
    );

    // Adversarial test: Corrupted cryptographic signature
    let mut bad_corrupt_sig = valid_envelope.clone();
    let mut tampered_att = att.clone();
    tampered_att.signature[0] ^= 0xFF;
    bad_corrupt_sig.payload = tampered_att.to_cbor().unwrap();
    let err_corrupt = store.ingest_crdt_envelope(&bad_corrupt_sig, now_pmt);
    assert!(
        err_corrupt.is_err(),
        "Must reject envelope with corrupted signature"
    );
    assert_eq!(
        store.evaluate_cached(&peer_id, now_pmt).tier,
        TrustTier::Untrusted
    );

    // Adversarial test: Temporal drift violations outside ±30s
    let mut drift_past_att = att.clone();
    drift_past_att.issued_at_pmt = now_pmt - 35;
    let drift_past_envelope = drift_past_att.to_envelope(&local_key.public_key).unwrap();
    let err_past = store.ingest_crdt_envelope(&drift_past_envelope, now_pmt);
    assert!(
        err_past.is_err(),
        "Must reject attestation older than consensus drift boundary (>30s)"
    );

    let mut drift_future_att = att.clone();
    drift_future_att.issued_at_pmt = now_pmt + 35;
    let drift_future_envelope = drift_future_att.to_envelope(&local_key.public_key).unwrap();
    let err_future = store.ingest_crdt_envelope(&drift_future_envelope, now_pmt);
    assert!(
        err_future.is_err(),
        "Must reject attestation ahead of consensus drift boundary (>30s)"
    );

    // 3. Ingest valid attestation envelope
    store
        .ingest_crdt_envelope(&valid_envelope, now_pmt)
        .expect("Valid attestation CRDT envelope must succeed");

    // Evaluation updated immediately in graph & cache
    let eval = store.evaluate_cached(&peer_id, now_pmt);
    assert_eq!(eval.tier, TrustTier::Trusted);

    // Indexed in MST
    let compound_key = WotStore::make_relation_key(&local_id, &peer_id);
    let in_mst = store
        .mst_engine()
        .get(ark_wot::CRDT_NAMESPACE_WOT, &compound_key)
        .unwrap();
    assert!(in_mst.is_some(), "Must be indexed in MST");

    // 4. Ingest valid revocation envelope
    let rev = TrustRevocation::create_and_sign(
        local_id,
        peer_id,
        now_pmt,
        "compromised".into(),
        2,
        &local_key,
    )
    .unwrap();
    let rev_envelope = rev.to_envelope(&local_key.public_key).unwrap();

    // Adversarial test on revocation: Corrupted signature
    let mut bad_rev_sig = rev_envelope.clone();
    let mut tampered_rev = rev.clone();
    tampered_rev.signature[0] ^= 0xFF;
    bad_rev_sig.payload = tampered_rev.to_cbor().unwrap();
    let err_rev_sig = store.ingest_crdt_envelope(&bad_rev_sig, now_pmt);
    assert!(
        err_rev_sig.is_err(),
        "Must reject revocation with corrupted signature"
    );
    assert_eq!(
        store.evaluate_cached(&peer_id, now_pmt).tier,
        TrustTier::Trusted
    );

    // Temporal drift violation on revocation (>30s)
    let mut drift_rev = rev.clone();
    drift_rev.revoked_at_pmt = now_pmt + 40;
    let drift_rev_envelope = drift_rev.to_envelope(&local_key.public_key).unwrap();
    let err_drift_rev = store.ingest_crdt_envelope(&drift_rev_envelope, now_pmt);
    assert!(
        err_drift_rev.is_err(),
        "Must reject revocation outside drift bounds"
    );

    // Valid revocation ingestion
    store
        .ingest_crdt_envelope(&rev_envelope, now_pmt)
        .expect("Valid revocation CRDT envelope must succeed");

    // Cache and graph updated immediately
    let eval_after = store.evaluate_cached(&peer_id, now_pmt + 1);
    assert_eq!(eval_after.tier, TrustTier::Untrusted);
    assert_eq!(eval_after.score, 0.0);
}
