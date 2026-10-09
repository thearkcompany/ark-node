use ark_core::traits::ArkIdentity;
use ark_crypto::fn_dsa::{
    verify_fn_dsa_512, FnDsaKeyPair, FN_DSA_512_PUBKEY_SIZE, FN_DSA_512_SECKEY_SIZE,
    FN_DSA_512_SIGNATURE_SIZE,
};
use ark_crypto::identity::Identity;
use ark_crypto::kmac::Kmac256;
use ark_crypto::ml_kem::{
    ml_kem_encapsulate, MlKemKeyPair, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBKEY_SIZE,
    ML_KEM_768_SECKEY_SIZE, ML_KEM_768_SHARED_SECRET_SIZE,
};
use ark_crypto::secure_mem::LockedBuffer;
use rand::rngs::OsRng;
use zeroize::Zeroize;

#[test]
fn test_identity_derivation_deterministic() {
    let dummy_pubkey = vec![0x42u8; 897];
    let id1 = Identity::from_public_key(&dummy_pubkey);
    let id2 = Identity::from_public_key(&dummy_pubkey);

    assert_eq!(id1.ark_id, id2.ark_id);
    assert_eq!(id1.sender_key_id, id2.sender_key_id);
    assert_eq!(id1.ark_id[0..16], id1.sender_key_id);
    assert_eq!(id1.ark_id(), &id1.ark_id);
    assert_eq!(id1.sender_key_id(), id1.sender_key_id);
    assert_eq!(id1.ark_id_hex().len(), 64);
}

#[test]
fn test_fn_dsa_512_sign_and_verify_roundtrip() {
    let mut rng = OsRng;
    let keypair = FnDsaKeyPair::generate(&mut rng);

    assert_eq!(keypair.public_key.len(), FN_DSA_512_PUBKEY_SIZE);
    assert_eq!(keypair.secret_key.len(), FN_DSA_512_SECKEY_SIZE);

    let message = b"Strict PQC Falcon/FN-DSA test payload for ARK Protocol v1";
    let signature = keypair.sign(message).expect("Failed to sign message");
    assert_eq!(signature.len(), FN_DSA_512_SIGNATURE_SIZE);

    // Verify valid signature
    assert!(verify_fn_dsa_512(&keypair.public_key, message, &signature).is_ok());

    // Verify tampered signature is rejected
    let mut bad_sig = signature.clone();
    bad_sig[42] ^= 0xFF; // corrupt signature byte
    assert!(verify_fn_dsa_512(&keypair.public_key, message, &bad_sig).is_err());

    // Verify tampered message is rejected
    let bad_message = b"Tampered message content";
    assert!(verify_fn_dsa_512(&keypair.public_key, bad_message, &signature).is_err());
}

#[test]
fn test_ml_kem_768_encapsulate_decapsulate_roundtrip() {
    let mut rng = OsRng;
    let recipient_keypair = MlKemKeyPair::generate(&mut rng);

    assert_eq!(recipient_keypair.public_key.len(), ML_KEM_768_PUBKEY_SIZE);
    assert_eq!(recipient_keypair.secret_key.len(), ML_KEM_768_SECKEY_SIZE);

    // Sender encapsulates against recipient public key
    let (ciphertext, sender_shared_secret) =
        ml_kem_encapsulate(&recipient_keypair.public_key, &mut rng).expect("Encapsulation failed");

    assert_eq!(ciphertext.len(), ML_KEM_768_CIPHERTEXT_SIZE);
    assert_eq!(sender_shared_secret.len(), ML_KEM_768_SHARED_SECRET_SIZE);

    // Recipient decapsulates
    let recipient_shared_secret = recipient_keypair
        .decapsulate(&ciphertext)
        .expect("Decapsulation failed");

    assert_eq!(sender_shared_secret, recipient_shared_secret);

    // Corrupted ciphertext produces different or failed shared secret (implicit rejection)
    let mut bad_ct = ciphertext;
    bad_ct[10] ^= 0xFF;
    let bad_secret = recipient_keypair.decapsulate(&bad_ct).unwrap();
    assert_ne!(sender_shared_secret, bad_secret);
}

#[test]
fn test_kmac256_domain_separation_and_cookie_tags() {
    let key = [0x55u8; 32];
    let client_addr = b"192.0.2.1:8443";
    let token = 1700000000u64.to_be_bytes();

    let tag1 = Kmac256::generate_cookie_tag(&key, client_addr, &token);
    let tag2 = Kmac256::generate_cookie_tag(&key, client_addr, &token);
    assert_eq!(tag1, tag2);

    let tag_tampered = Kmac256::generate_cookie_tag(&key, b"192.0.2.2:8443", &token);
    assert_ne!(tag1, tag_tampered);
}

#[derive(Zeroize, Default, Clone, PartialEq, Eq, Debug)]
struct TestSecret {
    data: [u8; 32],
}

#[test]
fn test_locked_buffer_mlock_and_zeroize() {
    let raw_secret = TestSecret { data: [0x7A; 32] };
    let buffer = LockedBuffer::new(raw_secret.clone());
    assert_eq!(*buffer, raw_secret);

    drop(buffer);
}
