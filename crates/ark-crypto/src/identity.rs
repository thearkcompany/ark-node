//! Cryptographic identity management and ArkID derivation.
//! ArkID = SHA3-256(PublicKey)
//! SenderKeyID = First 16 bytes of ArkID

use sha3::{Digest, Sha3_256};
use ark_core::traits::ArkIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub ark_id: [u8; 32],
    pub sender_key_id: [u8; 16],
    pub public_key: Vec<u8>,
}

impl Identity {
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();

        let mut ark_id = [0u8; 32];
        ark_id.copy_from_slice(&hash);

        let mut sender_key_id = [0u8; 16];
        sender_key_id.copy_from_slice(&hash[0..16]);

        Self {
            ark_id,
            sender_key_id,
            public_key: pubkey.to_vec(),
        }
    }

    pub fn ark_id_hex(&self) -> String {
        hex_fmt(&self.ark_id)
    }
}

impl ArkIdentity for Identity {
    fn ark_id(&self) -> &[u8; 32] {
        &self.ark_id
    }

    fn sender_key_id(&self) -> [u8; 16] {
        self.sender_key_id
    }
}

fn hex_fmt(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
