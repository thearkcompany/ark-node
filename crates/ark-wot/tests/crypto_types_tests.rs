use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_wot::crypto::{
    CapabilityScope, CapabilityScopes, TrustAttestation, TrustRevocation,
    KIND_WOT_ATTESTATION, KIND_WOT_REVOCATION,
};
use ark_crypto::identity::Identity;
use rand::rngs::OsRng;

#[test]
fn test_attestation_and_revocation_signing_roundtrip() {
    let mut rng = OsRng;
    let issuer_key = FnDsaKeyPair::generate(&mut rng);
    let subject_key = FnDsaKeyPair::generate(&mut rng);

    let issuer_id = Identity::from_public_key(&issuer_key.public_key).ark_id;
    let subject_id = Identity::from_public_key(&subject_key.public_key).ark_id;

    let mut scopes = CapabilityScopes::empty();
    scopes.insert(CapabilityScope::RELAY);
    scopes.insert(CapabilityScope::STORAGE);

    let attestation = TrustAttestation::create_and_sign(
        issuer_id,
        subject_id,
        0.85,
        scopes,
        1_000_000,
        1_000_000 + 30 * 86400,
        42,
        &issuer_key,
    )
    .expect("Failed to create signed attestation");

    // Verify valid signature
    assert!(attestation.verify_signature(&issuer_key.public_key).is_ok());

    // Tamper with score
    let mut tampered = attestation.clone();
    tampered.score_weight = 0.99;
    assert!(tampered.verify_signature(&issuer_key.public_key).is_err());

    // Wrong public key
    assert!(attestation.verify_signature(&subject_key.public_key).is_err());

    // Envelope packaging
    let envelope = attestation.to_envelope(&issuer_key.public_key)
        .expect("to_envelope failed");
    assert_eq!(ark_storage::get_envelope_kind(&envelope), KIND_WOT_ATTESTATION);
    assert_eq!(envelope.sender_id, issuer_id);
    assert_eq!(envelope.recipient_id, subject_id);

    // Decode from envelope
    let decoded = TrustAttestation::from_envelope(&envelope)
        .expect("from_envelope failed");
    assert_eq!(decoded.issuer_id, issuer_id);
    assert_eq!(decoded.subject_id, subject_id);
    assert_eq!(decoded.score_weight, 0.85);
    assert_eq!(decoded.nonce, 42);

    // Revocation roundtrip
    let revocation = TrustRevocation::create_and_sign(
        issuer_id,
        subject_id,
        1_000_100,
        "compromised_key".to_string(),
        101,
        &issuer_key,
    )
    .expect("Failed to create signed revocation");

    assert!(revocation.verify_signature(&issuer_key.public_key).is_ok());

    let rev_envelope = revocation.to_envelope(&issuer_key.public_key)
        .expect("to_envelope failed");
    assert_eq!(ark_storage::get_envelope_kind(&rev_envelope), KIND_WOT_REVOCATION);

    let decoded_rev = TrustRevocation::from_envelope(&rev_envelope)
        .expect("from_envelope failed");
    assert_eq!(decoded_rev.issuer_id, issuer_id);
    assert_eq!(decoded_rev.subject_id, subject_id);
    assert_eq!(decoded_rev.reason, "compromised_key");
}

#[test]
fn test_rejection_of_corrupted_signature_and_invalid_score() {
    let mut rng = OsRng;
    let issuer_key = FnDsaKeyPair::generate(&mut rng);
    let issuer_id = Identity::from_public_key(&issuer_key.public_key).ark_id;
    let subject_id = [0x99; 32];

    // Invalid score weight (> 1.0)
    assert!(TrustAttestation::create_and_sign(
        issuer_id,
        subject_id,
        1.5,
        CapabilityScopes::empty(),
        100,
        200,
        1,
        &issuer_key
    ).is_err());

    // Invalid score weight (< 0.0)
    assert!(TrustAttestation::create_and_sign(
        issuer_id,
        subject_id,
        -0.1,
        CapabilityScopes::empty(),
        100,
        200,
        1,
        &issuer_key
    ).is_err());

    let mut attestation = TrustAttestation::create_and_sign(
        issuer_id,
        subject_id,
        0.5,
        CapabilityScopes::empty(),
        100,
        200,
        1,
        &issuer_key
    ).unwrap();

    // Corrupted signature bytes
    attestation.signature[0] ^= 0xFF;
    assert!(attestation.verify_signature(&issuer_key.public_key).is_err());

    // Public key size mismatch
    assert!(attestation.verify_signature(&[0u8; 32]).is_err());
}

#[test]
fn test_retention_classification_of_wot_envelopes() {
    let mut rng = OsRng;
    let issuer_key = FnDsaKeyPair::generate(&mut rng);
    let issuer_id = Identity::from_public_key(&issuer_key.public_key).ark_id;
    let subject_id = [0x55; 32];

    let attestation = TrustAttestation::create_and_sign(
        issuer_id,
        subject_id,
        0.75,
        CapabilityScopes::empty(),
        500,
        1500,
        1,
        &issuer_key,
    ).unwrap();

    let att_env = attestation.to_envelope(&issuer_key.public_key).unwrap();
    assert_eq!(
        ark_storage::classify_retention(&att_env),
        ark_storage::RetentionClass::Class3ParamReplaceable
    );

    let revocation = TrustRevocation::create_and_sign(
        issuer_id,
        subject_id,
        600,
        "revoked".into(),
        2,
        &issuer_key,
    ).unwrap();

    let rev_env = revocation.to_envelope(&issuer_key.public_key).unwrap();
    assert_eq!(
        ark_storage::classify_retention(&rev_env),
        ark_storage::RetentionClass::Class1AppendOnly
    );
}
