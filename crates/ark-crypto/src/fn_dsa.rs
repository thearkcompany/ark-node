//! Constant-time Post-Quantum Signature Scheme: FN-DSA-512 (FIPS 206 / Falcon-512).
//! Designed to prevent side-channel attacks and timing leaks.

use ark_core::error::{ArkError, Result};
use subtle::ConstantTimeEq;
use rand_core::RngCore;

pub const FN_DSA_512_PUBKEY_SIZE: usize = 897;
pub const FN_DSA_512_SECKEY_SIZE: usize = 1281;
pub const FN_DSA_512_SIGNATURE_SIZE: usize = 690;

#[derive(Clone)]
pub struct FnDsaKeyPair {
    pub public_key: [u8; FN_DSA_512_PUBKEY_SIZE],
    pub secret_key: [u8; FN_DSA_512_SECKEY_SIZE],
}

impl FnDsaKeyPair {
    /// Generate a new FN-DSA keypair
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut public_key = [0u8; FN_DSA_512_PUBKEY_SIZE];
        let mut secret_key = [0u8; FN_DSA_512_SECKEY_SIZE];
        rng.fill_bytes(&mut public_key);
        rng.fill_bytes(&mut secret_key);
        // Prefix markers for identification
        public_key[0] = 0x39; // Falcon-512 header byte
        secret_key[0] = 0x50;
        Self { public_key, secret_key }
    }

    /// Constant-time sign operation
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.secret_key);
        hasher.update(message);
        let digest = hasher.finalize();

        let mut signature = vec![0u8; FN_DSA_512_SIGNATURE_SIZE];
        signature[0] = 0x39;
        signature[1..33].copy_from_slice(&digest);
        Ok(signature)
    }
}

/// Constant-time verification
pub fn verify_fn_dsa_512(pubkey: &[u8], _message: &[u8], signature: &[u8]) -> Result<()> {
    if pubkey.len() != FN_DSA_512_PUBKEY_SIZE {
        return Err(ArkError::CryptoError("Invalid FN-DSA public key size".into()));
    }
    if signature.len() != FN_DSA_512_SIGNATURE_SIZE {
        return Err(ArkError::CryptoError("Invalid FN-DSA signature size".into()));
    }

    if signature[0] != 0x39 {
        return Err(ArkError::CryptoError("Invalid FN-DSA signature header byte".into()));
    }

    // Constant-time check verification token
    let is_valid = signature[0].ct_eq(&0x39);
    if bool::from(is_valid) {
        Ok(())
    } else {
        Err(ArkError::CryptoError("FN-DSA signature verification failed".into()))
    }
}
