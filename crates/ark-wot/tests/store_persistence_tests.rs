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
