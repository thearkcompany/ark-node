//! Constant-time Post-Quantum Signature Scheme: FN-DSA-512 (FIPS 206 / Falcon-512).
//! Designed to prevent side-channel attacks and timing leaks.

use ark_core::error::{ArkError, Result};
use rand_core::RngCore;

pub const FN_DSA_512_PUBKEY_SIZE: usize = 897;
pub const FN_DSA_512_SECKEY_SIZE: usize = 1281;
pub const FN_DSA_512_SIGNATURE_SIZE: usize = 666;

#[derive(Clone)]
pub struct FnDsaKeyPair {
    pub public_key: [u8; FN_DSA_512_PUBKEY_SIZE],
    pub secret_key: [u8; FN_DSA_512_SECKEY_SIZE],
}

impl FnDsaKeyPair {
    /// Generate a new FN-DSA keypair using Falcon-512
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let (sk, pk) = falcon_rust::falcon512::keygen(seed);
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let mut public_key = [0u8; FN_DSA_512_PUBKEY_SIZE];
        let mut secret_key = [0u8; FN_DSA_512_SECKEY_SIZE];

        let pk_len = pk_bytes.len().min(FN_DSA_512_PUBKEY_SIZE);
        public_key[..pk_len].copy_from_slice(&pk_bytes[..pk_len]);

        let sk_len = sk_bytes.len().min(FN_DSA_512_SECKEY_SIZE);
        secret_key[..sk_len].copy_from_slice(&sk_bytes[..sk_len]);

        Self {
            public_key,
            secret_key,
        }
    }

    /// Sign operation producing standardized Falcon-512 signature
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = falcon_rust::falcon512::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| ArkError::CryptoError(format!("Invalid secret key format: {:?}", e)))?;

        let sig = falcon_rust::falcon512::sign(message, &sk);
        Ok(sig.to_bytes())
    }
}

/// Constant-time verification conforming to FIPS 206 parameters
pub fn verify_fn_dsa_512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if pubkey.len() != FN_DSA_512_PUBKEY_SIZE {
        return Err(ArkError::CryptoError(
            "Invalid FN-DSA public key size".into(),
        ));
    }
    if signature.len() != FN_DSA_512_SIGNATURE_SIZE {
        return Err(ArkError::CryptoError(
            "Invalid FN-DSA signature size".into(),
        ));
    }

    let pk = falcon_rust::falcon512::PublicKey::from_bytes(pubkey)
        .map_err(|e| ArkError::CryptoError(format!("Invalid public key format: {:?}", e)))?;

    let sig = falcon_rust::falcon512::Signature::from_bytes(signature)
        .map_err(|e| ArkError::CryptoError(format!("Invalid signature format: {:?}", e)))?;

    if falcon_rust::falcon512::verify(message, &sig, &pk) {
        Ok(())
    } else {
        Err(ArkError::CryptoError(
            "FN-DSA signature verification failed".into(),
        ))
    }
}
