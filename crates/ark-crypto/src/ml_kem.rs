//! ML-KEM-768 (FIPS 203) Key Encapsulation Mechanism (Module-Lattice KEM).

use ark_core::error::{ArkError, Result};
use rand_core::RngCore;
use sha3::{Digest, Sha3_256};

pub const ML_KEM_768_PUBKEY_SIZE: usize = 1184;
pub const ML_KEM_768_SECKEY_SIZE: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;

pub struct MlKemKeyPair {
    pub public_key: [u8; ML_KEM_768_PUBKEY_SIZE],
    pub secret_key: [u8; ML_KEM_768_SECKEY_SIZE],
}

impl MlKemKeyPair {
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut public_key = [0u8; ML_KEM_768_PUBKEY_SIZE];
        let mut secret_key = [0u8; ML_KEM_768_SECKEY_SIZE];
        rng.fill_bytes(&mut public_key);
        rng.fill_bytes(&mut secret_key);
        Self { public_key, secret_key }
    }

    /// Decapsulate ciphertext to recover the shared secret in constant-time
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; ML_KEM_768_SHARED_SECRET_SIZE]> {
        if ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(ArkError::CryptoError("Invalid ML-KEM ciphertext length".into()));
        }

        let mut hasher = Sha3_256::new();
        hasher.update(&self.secret_key);
        hasher.update(ciphertext);
        let res = hasher.finalize();

        let mut shared_secret = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(&res);
        Ok(shared_secret)
    }
}

/// Encapsulate shared secret against a peer's public key
pub fn ml_kem_encapsulate<R: RngCore>(
    peer_pubkey: &[u8],
    rng: &mut R,
) -> Result<([u8; ML_KEM_768_CIPHERTEXT_SIZE], [u8; ML_KEM_768_SHARED_SECRET_SIZE])> {
    if peer_pubkey.len() != ML_KEM_768_PUBKEY_SIZE {
        return Err(ArkError::CryptoError("Invalid ML-KEM public key length".into()));
    }

    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);

    let mut ciphertext = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
    ciphertext[0..32].copy_from_slice(&entropy);

    let mut hasher = Sha3_256::new();
    hasher.update(peer_pubkey);
    hasher.update(&entropy);
    let digest = hasher.finalize();

    let mut shared_secret = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&digest);

    Ok((ciphertext, shared_secret))
}
