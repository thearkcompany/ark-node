//! Canonical message ID hashing using Encrypt-then-Sign principle.
//! ID = SHA3-256(FastHeader || SenderID || RecipientID || EncryptedPayload || TagMask)

use crate::envelope::ArkEnvelope;
use sha3::{Digest, Sha3_256};

pub fn calculate_canonical_id(envelope: &ArkEnvelope) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(&envelope.magic);
    hasher.update(&envelope.fast_header);
    hasher.update(&envelope.sender_id);
    hasher.update(&envelope.recipient_id);
    hasher.update(&envelope.payload);
    hasher.update(envelope.core_tag_mask.to_be_bytes());
    hasher.update(envelope.timestamp.to_be_bytes());

    let res = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&res);
    id
}
