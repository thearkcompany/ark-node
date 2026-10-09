//! ML-KEM-768 (FIPS 203) Key Encapsulation Mechanism (Module-Lattice KEM).

use ark_core::error::{ArkError, Result};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::CryptoRngCore;

pub const ML_KEM_768_PUBKEY_SIZE: usize = 1184;
pub const ML_KEM_768_SECKEY_SIZE: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;

pub struct MlKemKeyPair {
    pub public_key: [u8; ML_KEM_768_PUBKEY_SIZE],
    pub secret_key: [u8; ML_KEM_768_SECKEY_SIZE],
}

impl MlKemKeyPair {
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (ek, dk) =
            ml_kem_768::KG::try_keygen_with_rng(rng).expect("ML-KEM key generation failed");

        let ek_bytes = ek.into_bytes();
        let dk_bytes = dk.into_bytes();

        Self {
            public_key: ek_bytes,
            secret_key: dk_bytes,
        }
    }

    /// Decapsulate ciphertext to recover the shared secret in constant-time
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; ML_KEM_768_SHARED_SECRET_SIZE]> {
        if ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(ArkError::CryptoError(
                "Invalid ML-KEM ciphertext length".into(),
            ));
        }

        let ct_arr: [u8; ML_KEM_768_CIPHERTEXT_SIZE] = ciphertext
            .try_into()
            .map_err(|_| ArkError::CryptoError("Malformed ciphertext slice".into()))?;

        let dk = ml_kem_768::DecapsKey::try_from_bytes(self.secret_key)
            .map_err(|e| ArkError::CryptoError(format!("Invalid ML-KEM decaps key: {:?}", e)))?;

        let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr).map_err(|e| {
            ArkError::CryptoError(format!("Invalid ML-KEM ciphertext bytes: {:?}", e))
        })?;

        let ssk = dk
            .try_decaps(&ct)
            .map_err(|e| ArkError::CryptoError(format!("ML-KEM decapsulation failed: {:?}", e)))?;

        Ok(ssk.into_bytes())
    }
}

/// Encapsulate shared secret against a peer's public key
pub fn ml_kem_encapsulate<R: CryptoRngCore>(
    peer_pubkey: &[u8],
    rng: &mut R,
) -> Result<(
    [u8; ML_KEM_768_CIPHERTEXT_SIZE],
    [u8; ML_KEM_768_SHARED_SECRET_SIZE],
)> {
    if peer_pubkey.len() != ML_KEM_768_PUBKEY_SIZE {
        return Err(ArkError::CryptoError(
            "Invalid ML-KEM public key length".into(),
        ));
    }

    let ek_arr: [u8; ML_KEM_768_PUBKEY_SIZE] = peer_pubkey
        .try_into()
        .map_err(|_| ArkError::CryptoError("Malformed public key slice".into()))?;

    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr)
        .map_err(|e| ArkError::CryptoError(format!("Invalid ML-KEM encaps key: {:?}", e)))?;

    let (ssk, ct) = ek
        .try_encaps_with_rng(rng)
        .map_err(|e| ArkError::CryptoError(format!("ML-KEM encapsulation failed: {:?}", e)))?;

    Ok((ct.into_bytes(), ssk.into_bytes()))
}
