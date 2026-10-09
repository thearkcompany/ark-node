use ark_crypto::fn_dsa::FN_DSA_512_PUBKEY_SIZE;
use ark_crypto::identity::PersistentIdentity;
use ark_crypto::ml_kem::ML_KEM_768_PUBKEY_SIZE;
use rand::rngs::OsRng;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_persistent_identity_keygen_and_ark_id() {
    let mut rng = OsRng;
    let identity = PersistentIdentity::generate(&mut rng);

    assert_eq!(
        identity.fn_dsa_keypair.public_key.len(),
        FN_DSA_512_PUBKEY_SIZE
    );
    assert_eq!(
        identity.ml_kem_keypair.public_key.len(),
        ML_KEM_768_PUBKEY_SIZE
    );
    assert_eq!(identity.ark_id.len(), 32);
    assert_eq!(identity.sender_key_id.len(), 16);
    assert_eq!(identity.ark_id[0..16], identity.sender_key_id);
    assert_eq!(identity.ark_id_hex().len(), 64);
}

#[test]
fn test_persistent_identity_save_load_and_file_permissions_0600() {
    let mut rng = OsRng;
    let identity = PersistentIdentity::generate(&mut rng);

    let temp_dir = std::env::temp_dir().join(format!("ark_test_{}", rand::random::<u64>()));
    fs::create_dir_all(&temp_dir).unwrap();
    let key_path = temp_dir.join("test_identity.key");

    // Save key
    identity
        .save_to_file(&key_path)
        .expect("Failed to save identity to file");

    // Assert strict POSIX permissions 0600 (user read/write only)
    let metadata = fs::metadata(&key_path).expect("Metadata missing");
    let permissions = metadata.permissions();
    let mode = permissions.mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "File permissions must be strictly 0600, got {:o}",
        mode
    );

    // Load key and verify roundtrip
    let loaded =
        PersistentIdentity::load_from_file(&key_path).expect("Failed to load identity from file");
    assert_eq!(identity.ark_id, loaded.ark_id);
    assert_eq!(identity.sender_key_id, loaded.sender_key_id);
    assert_eq!(
        identity.fn_dsa_keypair.public_key,
        loaded.fn_dsa_keypair.public_key
    );
    assert_eq!(&*identity.fn_dsa_secret_key, &*loaded.fn_dsa_secret_key);
    assert_eq!(
        identity.ml_kem_keypair.public_key,
        loaded.ml_kem_keypair.public_key
    );
    assert_eq!(&*identity.ml_kem_secret_key, &*loaded.ml_kem_secret_key);

    // Clean up
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_dir_all(&temp_dir);
}
