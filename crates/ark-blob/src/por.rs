//! Proof-of-Retrievability (PoR) & DePIN Audit Engine (GCP-10, ADR-0011).
//!
//! Provides cryptographic, sub-millisecond (<50 µs) auditing of DePIN storage keepers:
//! - Auditor issues `KIND_DEPIN_CHALLENGE` (0x4000_0002) containing `TAG_CHALLENGE_SEED` (0x0016),
//!   `blob_cid`, `shard_idx`, and 4 KB sub-block index.
//! - Keeper samples the designated 4 KB sub-block in the 1 MB shard, computes KMAC256(seed, sub_block),
//!   and attaches a compact `ShardMerkleProof` audit path.
//! - Auditor verifies KMAC256 and validates the inclusion path against `shard_merkle_roots[shard_idx]`
//!   without transferring the full 1 MB shard.

use ark_core::FastHeader;
use ark_crypto::Kmac256;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::constants::{
    KIND_DEPIN_CHALLENGE, KIND_DEPIN_RESPONSE, SHARD_SIZE, SUB_BLOCKS_PER_SHARD, SUB_BLOCK_SIZE,
    TAG_CHALLENGE_SEED, TAG_CONTENT_CID, TAG_SHARD_INDEX, TAG_SUB_BLOCK_INDEX,
};
use crate::error::{BlobError, Result};
use crate::merkle::ShardMerkleProof;

/// Computes a deterministic pseudo-random 4 KB sub-block index from a challenge seed.
///
/// Uses the first 8 bytes of `SHA3-256(seed || shard_index)` modulo 256.
pub fn derive_sub_block_index(seed: &[u8; 32], shard_index: u32) -> u32 {
    let mut hasher = Sha3_256::new();
    hasher.update(&seed[..]);
    hasher.update(shard_index.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let num = u64::from_be_bytes(digest[0..8].try_into().unwrap());
    (num % (SUB_BLOCKS_PER_SHARD as u64)) as u32
}

/// Computes KMAC256 authentication response over a 4 KB sub-block with a given challenge seed.
///
/// KMAC256 uses the protocol customization string `"ARK-KMAC256-V1"` with `seed` as key
/// and outputs a 32-byte authentication digest.
pub fn compute_sub_block_kmac(seed: &[u8; 32], sub_block: &[u8]) -> [u8; 32] {
    let mut kmac = Kmac256::new(seed);
    kmac.update(sub_block);
    let mut mac = [0u8; 32];
    kmac.finalize(&mut mac);
    mac
}

/// DePIN audit challenge sent by an auditor to a storage keeper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DePINChallenge {
    /// 32-byte canonical BlobCID (Tier 1 Merkle root).
    pub blob_cid: [u8; 32],
    /// Index of the shard (0..14).
    pub shard_index: u32,
    /// Sampled 4 KB sub-block index (0..255).
    pub sub_block_index: u32,
    /// 32-byte pseudo-random challenge seed.
    pub seed: [u8; 32],
}

impl DePINChallenge {
    /// Creates a new challenge with an explicit sub-block index.
    pub fn new(
        blob_cid: [u8; 32],
        shard_index: u32,
        sub_block_index: u32,
        seed: [u8; 32],
    ) -> Self {
        Self {
            blob_cid,
            shard_index,
            sub_block_index,
            seed,
        }
    }

    /// Creates a new challenge with a deterministically derived sub-block index from the seed.
    pub fn new_sampled(blob_cid: [u8; 32], shard_index: u32, seed: [u8; 32]) -> Self {
        let sub_block_index = derive_sub_block_index(&seed, shard_index);
        Self::new(blob_cid, shard_index, sub_block_index, seed)
    }

    /// Encapsulates this challenge into a canonical `ArkEnvelope` with kind `KIND_DEPIN_CHALLENGE`.
    pub fn to_envelope(&self, sender_id: &[u8; 32]) -> Result<ArkEnvelope> {
        let payload = serde_json::to_vec(self)
            .map_err(|e| BlobError::SerializationError(e.to_string()))?;

        let mut sender_key_id = [0u8; 16];
        sender_key_id.copy_from_slice(&sender_id[..16]);

        let fast_header = FastHeader::new(
            0,
            payload.len() as u32,
            KIND_DEPIN_CHALLENGE,
            sender_key_id,
            [0u8; 16],
            1,
        );

        let tags = vec![
            BinaryTag::new(TAG_CONTENT_CID, self.blob_cid.to_vec()),
            BinaryTag::new(TAG_SHARD_INDEX, self.shard_index.to_be_bytes().to_vec()),
            BinaryTag::new(TAG_SUB_BLOCK_INDEX, self.sub_block_index.to_be_bytes().to_vec()),
            BinaryTag::new(TAG_CHALLENGE_SEED, self.seed.to_vec()),
        ];

        ArkEnvelope::new(
            fast_header.to_bytes(),
            *sender_id,
            [0u8; 32],
            payload,
            vec![],
            0,
            tags,
            0,
        )
        .map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    /// Converts this challenge to Protobuf wire type `DepinPorChallenge`.
    pub fn to_proto(&self) -> ark_protocol::DepinPorChallenge {
        ark_protocol::DepinPorChallenge {
            blob_cid: self.blob_cid.to_vec(),
            shard_index: self.shard_index,
            sub_block_index: self.sub_block_index,
            challenge_seed: self.seed.to_vec(),
        }
    }

    /// Converts a Protobuf `DepinPorChallenge` into `DePINChallenge`.
    pub fn from_proto(proto: &ark_protocol::DepinPorChallenge) -> Result<Self> {
        if proto.blob_cid.len() != 32 {
            return Err(BlobError::SerializationError("Invalid proto blob_cid length".into()));
        }
        let mut blob_cid = [0u8; 32];
        blob_cid.copy_from_slice(&proto.blob_cid);

        if proto.challenge_seed.len() != 32 {
            return Err(BlobError::SerializationError("Invalid proto challenge_seed length".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&proto.challenge_seed);

        Ok(Self {
            blob_cid,
            shard_index: proto.shard_index,
            sub_block_index: proto.sub_block_index,
            seed,
        })
    }

    /// Serializes challenge to Protobuf binary bytes.
    pub fn to_proto_bytes(&self) -> Vec<u8> {
        use ark_protocol::prost::Message;
        self.to_proto().encode_to_vec()
    }

    /// Deserializes challenge from Protobuf binary bytes.
    pub fn from_proto_bytes(bytes: &[u8]) -> Result<Self> {
        use ark_protocol::prost::Message;
        let proto = ark_protocol::DepinPorChallenge::decode(bytes)
            .map_err(|e| BlobError::SerializationError(e.to_string()))?;
        Self::from_proto(&proto)
    }

    /// Extracts a `DePINChallenge` from a canonical `ArkEnvelope`.
    pub fn from_envelope(envelope: &ArkEnvelope) -> Result<Self> {
        // First try to parse payload as protobuf or json
        if !envelope.payload.is_empty() {
            if let Ok(challenge) = Self::from_proto_bytes(&envelope.payload) {
                return Ok(challenge);
            }
            if let Ok(challenge) = serde_json::from_slice::<Self>(&envelope.payload) {
                return Ok(challenge);
            }
        }

        // Otherwise extract from tags
        let blob_cid_bytes = envelope
            .tags
            .iter()
            .find(|t| t.tag_type == TAG_CONTENT_CID)
            .ok_or(BlobError::MissingTag(TAG_CONTENT_CID))?
            .tag_value
            .as_slice();

        if blob_cid_bytes.len() != 32 {
            return Err(BlobError::SerializationError("Invalid TAG_CONTENT_CID length".to_string()));
        }
        let mut blob_cid = [0u8; 32];
        blob_cid.copy_from_slice(blob_cid_bytes);

        let shard_index_bytes = envelope
            .tags
            .iter()
            .find(|t| t.tag_type == TAG_SHARD_INDEX)
            .ok_or(BlobError::MissingTag(TAG_SHARD_INDEX))?
            .tag_value
            .as_slice();

        if shard_index_bytes.len() != 4 {
            return Err(BlobError::SerializationError("Invalid TAG_SHARD_INDEX length".to_string()));
        }
        let shard_index = u32::from_be_bytes(shard_index_bytes.try_into().unwrap());

        let seed_bytes = envelope
            .tags
            .iter()
            .find(|t| t.tag_type == TAG_CHALLENGE_SEED)
            .ok_or(BlobError::MissingTag(TAG_CHALLENGE_SEED))?
            .tag_value
            .as_slice();

        if seed_bytes.len() != 32 {
            return Err(BlobError::SerializationError("Invalid TAG_CHALLENGE_SEED length".to_string()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);

        let sub_block_index = if let Some(tag) = envelope.tags.iter().find(|t| t.tag_type == TAG_SUB_BLOCK_INDEX) {
            if tag.tag_value.len() != 4 {
                return Err(BlobError::SerializationError("Invalid TAG_SUB_BLOCK_INDEX length".to_string()));
            }
            u32::from_be_bytes(tag.tag_value.as_slice().try_into().unwrap())
        } else {
            derive_sub_block_index(&seed, shard_index)
        };

        Ok(Self {
            blob_cid,
            shard_index,
            sub_block_index,
            seed,
        })
    }
}

/// DePIN audit challenge response produced by a keeper node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DePINChallengeResponse {
    /// 32-byte canonical BlobCID.
    pub blob_cid: [u8; 32],
    /// Index of the shard (0..14).
    pub shard_index: u32,
    /// Sampled 4 KB sub-block index (0..255).
    pub sub_block_index: u32,
    /// Sampled 4 KB sub-block raw bytes.
    pub sub_block: Vec<u8>,
    /// 32-byte KMAC256(seed, sub_block) authentication digest.
    pub mac: [u8; 32],
    /// Two-Tier Merkle inclusion proof for the 4 KB sub-block.
    pub proof: ShardMerkleProof,
}

impl DePINChallengeResponse {
    /// Generates a proof-of-retrievability response for a 1 MB shard given a challenge.
    pub fn generate(shard: &[u8], challenge: &DePINChallenge) -> Result<Self> {
        if shard.len() != SHARD_SIZE {
            return Err(BlobError::InvalidShardSize {
                expected: SHARD_SIZE,
                got: shard.len(),
            });
        }
        if challenge.sub_block_index as usize >= SUB_BLOCKS_PER_SHARD {
            return Err(BlobError::InvalidSubBlockIndex {
                index: challenge.sub_block_index as usize,
                max: SUB_BLOCKS_PER_SHARD - 1,
            });
        }

        let start = challenge.sub_block_index as usize * SUB_BLOCK_SIZE;
        let end = start + SUB_BLOCK_SIZE;
        let sub_block = shard[start..end].to_vec();

        // KMAC256 authentication
        let mac = compute_sub_block_kmac(&challenge.seed, &sub_block);

        // Merkle proof inclusion
        let proof = ShardMerkleProof::generate(shard, challenge.shard_index, challenge.sub_block_index as usize)?;

        Ok(Self {
            blob_cid: challenge.blob_cid,
            shard_index: challenge.shard_index,
            sub_block_index: challenge.sub_block_index,
            sub_block,
            mac,
            proof,
        })
    }

    /// Verifies the challenge response against the expected shard Merkle root in microseconds (<50 µs).
    pub fn verify(&self, shard_root: &[u8; 32], challenge: &DePINChallenge) -> bool {
        // 1. Check metadata matching
        if self.blob_cid != challenge.blob_cid
            || self.shard_index != challenge.shard_index
            || self.sub_block_index != challenge.sub_block_index
            || self.proof.shard_index != challenge.shard_index
            || self.proof.sub_block_index != challenge.sub_block_index
        {
            return false;
        }

        // 2. Check sub-block size
        if self.sub_block.len() != SUB_BLOCK_SIZE {
            return false;
        }

        // 3. Verify KMAC256 authentication digest
        let expected_mac = compute_sub_block_kmac(&challenge.seed, &self.sub_block);
        if self.mac != expected_mac {
            return false;
        }

        // 4. Verify Merkle inclusion path against shard_root
        self.proof.verify_sub_block(shard_root, &self.sub_block)
    }

    /// Serializes response to compact binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    /// Deserializes response from compact binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    /// Encapsulates this response into a canonical `ArkEnvelope` with kind `KIND_DEPIN_RESPONSE`.
    pub fn to_envelope(&self, sender_id: &[u8; 32]) -> Result<ArkEnvelope> {
        let payload = self.to_bytes()?;
        let mut sender_key_id = [0u8; 16];
        sender_key_id.copy_from_slice(&sender_id[..16]);

        let fast_header = FastHeader::new(
            0,
            payload.len() as u32,
            KIND_DEPIN_RESPONSE,
            sender_key_id,
            [0u8; 16],
            1,
        );

        let tags = vec![
            BinaryTag::new(TAG_CONTENT_CID, self.blob_cid.to_vec()),
            BinaryTag::new(TAG_SHARD_INDEX, self.shard_index.to_be_bytes().to_vec()),
            BinaryTag::new(TAG_SUB_BLOCK_INDEX, self.sub_block_index.to_be_bytes().to_vec()),
        ];

        ArkEnvelope::new(
            fast_header.to_bytes(),
            *sender_id,
            [0u8; 32],
            payload,
            vec![],
            0,
            tags,
            0,
        )
        .map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    /// Converts this response to Protobuf wire type `DepinPorResponse`.
    pub fn to_proto(&self) -> ark_protocol::DepinPorResponse {
        ark_protocol::DepinPorResponse {
            blob_cid: self.blob_cid.to_vec(),
            shard_index: self.shard_index,
            sub_block_index: self.sub_block_index,
            sub_block_payload: self.sub_block.clone(),
            kmac_digest: self.mac.to_vec(),
            merkle_proof_bytes: self.proof.to_bytes(),
        }
    }

    /// Converts a Protobuf `DepinPorResponse` into `DePINChallengeResponse`.
    pub fn from_proto(proto: &ark_protocol::DepinPorResponse) -> Result<Self> {
        if proto.blob_cid.len() != 32 {
            return Err(BlobError::SerializationError("Invalid proto blob_cid length".into()));
        }
        let mut blob_cid = [0u8; 32];
        blob_cid.copy_from_slice(&proto.blob_cid);

        if proto.kmac_digest.len() != 32 {
            return Err(BlobError::SerializationError("Invalid proto kmac_digest length".into()));
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&proto.kmac_digest);

        let proof = ShardMerkleProof::from_bytes(&proto.merkle_proof_bytes)?;

        Ok(Self {
            blob_cid,
            shard_index: proto.shard_index,
            sub_block_index: proto.sub_block_index,
            sub_block: proto.sub_block_payload.clone(),
            mac,
            proof,
        })
    }

    /// Serializes response to Protobuf binary bytes.
    pub fn to_proto_bytes(&self) -> Vec<u8> {
        use ark_protocol::prost::Message;
        self.to_proto().encode_to_vec()
    }

    /// Deserializes response from Protobuf binary bytes.
    pub fn from_proto_bytes(bytes: &[u8]) -> Result<Self> {
        use ark_protocol::prost::Message;
        let proto = ark_protocol::DepinPorResponse::decode(bytes)
            .map_err(|e| BlobError::SerializationError(e.to_string()))?;
        Self::from_proto(&proto)
    }

    /// Extracts a `DePINChallengeResponse` from a canonical `ArkEnvelope`.
    pub fn from_envelope(envelope: &ArkEnvelope) -> Result<Self> {
        if let Ok(res) = Self::from_proto_bytes(&envelope.payload) {
            return Ok(res);
        }
        Self::from_bytes(&envelope.payload)
    }
}

/// Convenience helper for an auditor to generate a challenge envelope.
pub fn generate_depin_challenge(
    blob_cid: [u8; 32],
    shard_index: u32,
    seed: [u8; 32],
    sub_block_index: Option<u32>,
    sender_id: &[u8; 32],
) -> Result<ArkEnvelope> {
    let challenge = match sub_block_index {
        Some(idx) => DePINChallenge::new(blob_cid, shard_index, idx, seed),
        None => DePINChallenge::new_sampled(blob_cid, shard_index, seed),
    };
    challenge.to_envelope(sender_id)
}

/// Convenience helper for an auditor to verify a response against expected shard root and challenge.
pub fn verify_depin_challenge_response(
    response: &DePINChallengeResponse,
    shard_root: &[u8; 32],
    challenge: &DePINChallenge,
) -> bool {
    response.verify(shard_root, challenge)
}
