use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_crypto::identity::Identity;
use ark_wot::crypto::{CapabilityScopes, TrustAttestation, TrustRevocation};
use ark_wot::temporal::{compute_decayed_weight, RevocationIndex, TemporalValidator, HALF_LIFE_SECS};
use rand::rngs::OsRng;

#[test]
fn test_temporal_half_life_decay() {
    let w0 = 1.0;
    // At delta_t = 0: weight is w0
    let w_current = compute_decayed_weight(w0, 1000, 1000);
    assert!((w_current - 1.0).abs() < 1e-6);

    // At delta_t = HALF_LIFE_SECS (30 days): weight is w0 / 2
    let w_half = compute_decayed_weight(w0, 1000, 1000 + HALF_LIFE_SECS);
    assert!((w_half - 0.5).abs() < 1e-4);

    // At delta_t = 2 * HALF_LIFE_SECS: weight is w0 / 4
    let w_quarter = compute_decayed_weight(w0, 1000, 1000 + 2 * HALF_LIFE_SECS);
    assert!((w_quarter - 0.25).abs() < 1e-4);

    // If PMT is before issued_at (e.g. clock drift edge case), weight capped at w0
    let w_early = compute_decayed_weight(w0, 1000, 500);
    assert_eq!(w_early, 1.0);
}

#[test]
fn test_temporal_validator_expiration_and_revocation_precedence() {
    let mut rng = OsRng;
    let issuer_key = FnDsaKeyPair::generate(&mut rng);
    let subject_key = FnDsaKeyPair::generate(&mut rng);

    let issuer_id = Identity::from_public_key(&issuer_key.public_key).ark_id;
    let subject_id = Identity::from_public_key(&subject_key.public_key).ark_id;

    let validator = TemporalValidator::new();

    let issued_pmt = 1_000_000;
    let expires_pmt = 1_000_000 + 10 * 86400; // 10 days validity

    let attestation = TrustAttestation::create_and_sign(
        issuer_id,
        subject_id,
        0.8,
        CapabilityScopes::empty(),
        issued_pmt,
        expires_pmt,
        1,
        &issuer_key,
    )
    .unwrap();

    // 1. Valid attestation at t = issued_pmt + 1 day
    let eval_t1 = validator.evaluate_attestation(&attestation, issued_pmt + 86400);
    assert!(eval_t1.is_some());
    let weight_t1 = eval_t1.unwrap();
    assert!(weight_t1 > 0.0 && weight_t1 < 0.8);

    // 2. Expired attestation at t = expires_pmt + 1 sec
    let eval_expired = validator.evaluate_attestation(&attestation, expires_pmt + 1);
    assert_eq!(eval_expired, None, "Expired attestation must be rejected/filtered");

    // 3. Register revocation at t = issued_pmt + 2 days
    let revocation = TrustRevocation::create_and_sign(
        issuer_id,
        subject_id,
        issued_pmt + 2 * 86400,
        "key compromised".into(),
        2,
        &issuer_key,
    )
    .unwrap();

    validator.record_revocation(revocation);

    // Revocation must take absolute priority: even before expiration timestamp, returns None
    let eval_revoked = validator.evaluate_attestation(&attestation, issued_pmt + 3 * 86400);
    assert_eq!(eval_revoked, None, "Revoked attestation must return None");

    // Check O(1) revocation lookup table directly
    assert!(validator.is_revoked(&issuer_id, &subject_id));
}

#[test]
fn test_simulated_time_travel_and_adversarial_revocation() {
    let mut rng = OsRng;
    let issuer_key = FnDsaKeyPair::generate(&mut rng);
    let subject_key = FnDsaKeyPair::generate(&mut rng);

    let issuer_id = Identity::from_public_key(&issuer_key.public_key).ark_id;
    let subject_id = Identity::from_public_key(&subject_key.public_key).ark_id;

    let index = RevocationIndex::new();
    assert!(!index.is_revoked(&issuer_id, &subject_id));

    // Adversarial: replaying older revocation when newer exists
    let rev_new = TrustRevocation::create_and_sign(
        issuer_id,
        subject_id,
        2_000_000,
        "second revocation".into(),
        2,
        &issuer_key,
    ).unwrap();

    let rev_old = TrustRevocation::create_and_sign(
        issuer_id,
        subject_id,
        1_000_000,
        "first revocation".into(),
        1,
        &issuer_key,
    ).unwrap();

    index.record(rev_new.clone());
    assert_eq!(index.len(), 1);
    assert_eq!(index.get_revocation(&issuer_id, &subject_id).unwrap().reason, "second revocation");

    // Recording older should not supersede newer
    index.record(rev_old);
    assert_eq!(index.get_revocation(&issuer_id, &subject_id).unwrap().reason, "second revocation");
}
