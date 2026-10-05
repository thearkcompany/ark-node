//! Encrypted Client Hello (ECH) and SNI masking for censorship resistance in ARK v1.

use sha3::{Digest, Sha3_256};

pub struct EchConfig {
    pub public_name: String,
    pub kem_public_key: Vec<u8>,
}

impl EchConfig {
    pub fn new(public_name: impl Into<String>, kem_public_key: Vec<u8>) -> Self {
        Self {
            public_name: public_name.into(),
            kem_public_key,
        }
    }

    /// Mask inner sovereign destination identity into outer cover SNI
    pub fn mask_destination(&self, real_destination_id: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.kem_public_key);
        hasher.update(real_destination_id);
        let digest = hasher.finalize();
        format!("{}.ech.{}", hex_prefix(&digest[0..8]), self.public_name)
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
