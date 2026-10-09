use std::sync::Arc;
use tempfile::tempdir;
use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_crypto::identity::Identity;
use ark_storage::{StorageConfig, StorageEngine};
use ark_wot::crypto::{CapabilityScopes, TrustAttestation, TrustRevocation};
use ark_wot::graph::TrustTier;
use ark_wot::store::WotStore;
use rand::rngs::OsRng;

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
        ).unwrap();

        store.save_attestation(&attestation, &local_key.public_key).unwrap();

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
        ).unwrap();

        store.save_revocation(&revocation, &local_key.public_key).unwrap();

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
    ).unwrap();

    store.save_attestation(&attestation, &local_key.public_key).unwrap();

    // Verify presence in MstEngine under CRDT_NAMESPACE_WOT with key [issuer: 32B] || [subject: 32B]
    let mut compound_key = Vec::with_capacity(64);
    compound_key.extend_from_slice(&local_id);
    compound_key.extend_from_slice(&peer_id);

    let fetched_env = mst_engine.get(CRDT_NAMESPACE_WOT, &compound_key).unwrap();
    assert!(fetched_env.is_some(), "Attestation envelope must be indexed in MstEngine");

    // 3. Test WotStore::with_mst_engine injection
    let custom_mst = Arc::new(ark_crdt::MstEngine::open(storage.clone(), ark_crdt::MstConfig::default()).unwrap());
    let custom_store = WotStore::with_mst_engine(local_id, storage.clone(), custom_mst.clone()).unwrap();
    assert!(Arc::ptr_eq(custom_store.mst_engine(), &custom_mst));

    // save_revocation writes to MstEngine
    let revocation = TrustRevocation::create_and_sign(
        local_id,
        peer_id,
        1050,
        "revoked".into(),
        2,
        &local_key,
    ).unwrap();

    custom_store.save_revocation(&revocation, &local_key.public_key).unwrap();

    let fetched_rev_env = custom_mst.get(CRDT_NAMESPACE_WOT, &compound_key).unwrap();
    assert!(fetched_rev_env.is_some(), "Revocation envelope must be indexed in MstEngine");
}

