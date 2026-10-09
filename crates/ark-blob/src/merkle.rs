//! Two-Tier Merkle Tree implementation adhering to GCP-10 & ADR-0011.
//!
//! - Tier 1: Canonical BlobCID computed over 64 KB sub-chunks of original pre-coding data.
//! - Tier 2: 14 individual shard roots computed over 4 KB sub-blocks of each 1 MB shard.
//! - ShardMerkleProof: generation and verification of inclusion proof in O(log N) microseconds.

use crate::constants::{
    SHARD_SIZE, SUB_BLOCKS_PER_SHARD, SUB_BLOCK_SIZE, SUB_CHUNK_SIZE, TOTAL_SHARDS,
};
use crate::error::{BlobError, Result};
use sha3::{Digest, Sha3_256};

/// Computes the SHA3-256 hash of two child digests.
#[inline]
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Computes the Merkle root over a sequence of leaf hashes.
/// If the leaves list is empty, returns the SHA3-256 hash of empty input.
/// When the number of nodes at a level is odd (and > 1), the last node is promoted to the next level.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha3_256::digest(b"").into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(hash_pair(&current_level[i], &current_level[i + 1]));
                i += 2;
            } else {
                next_level.push(current_level[i]);
                i += 1;
            }
        }
        current_level = next_level;
    }

    current_level[0]
}

/// Tier 1: Computes the canonical `BlobCID` (TAG_CONTENT_CID: 0x0002) directly
/// as the SHA3-256 Merkle root over 64 KB sub-chunks of original contiguous pre-coding data.
pub fn compute_blob_cid(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return Sha3_256::digest(b"").into();
    }

    let mut leaf_hashes = Vec::with_capacity(data.len().div_ceil(SUB_CHUNK_SIZE));
    for chunk in data.chunks(SUB_CHUNK_SIZE) {
        let leaf_hash: [u8; 32] = Sha3_256::digest(chunk).into();
        leaf_hashes.push(leaf_hash);
    }

    compute_merkle_root(&leaf_hashes)
}

/// Tier 2: Computes the 14 individual shard roots (each representing a 1 MB shard
/// partitioned into 256 sub-blocks of 4 KB).
pub fn compute_shard_merkle_roots(shards: &[Vec<u8>]) -> Result<Vec<[u8; 32]>> {
    if shards.len() != TOTAL_SHARDS {
        return Err(BlobError::InvalidShardCount {
            expected: TOTAL_SHARDS,
            got: shards.len(),
        });
    }

    let mut roots = Vec::with_capacity(TOTAL_SHARDS);
    for shard in shards {
        if shard.len() != SHARD_SIZE {
            return Err(BlobError::InvalidShardSize {
                expected: SHARD_SIZE,
                got: shard.len(),
            });
        }
        roots.push(compute_single_shard_root(shard)?);
    }

    Ok(roots)
}

/// Computes the Merkle root of a single 1 MB shard over its 256 sub-blocks of 4 KB.
pub fn compute_single_shard_root(shard: &[u8]) -> Result<[u8; 32]> {
    if shard.len() != SHARD_SIZE {
        return Err(BlobError::InvalidShardSize {
            expected: SHARD_SIZE,
            got: shard.len(),
        });
    }

    let mut leaves = Vec::with_capacity(SUB_BLOCKS_PER_SHARD);
    for chunk in shard.chunks(SUB_BLOCK_SIZE) {
        leaves.push(Sha3_256::digest(chunk).into());
    }

    Ok(compute_merkle_root(&leaves))
}

use serde::{Deserialize, Serialize};

/// Direction of a sibling node in a Merkle audit path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiblingPosition {
    Left,
    Right,
}

/// A step in the Merkle audit path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofNode {
    pub hash: [u8; 32],
    pub position: SiblingPosition,
}

/// Shard Merkle inclusion proof for a 4 KB sub-block within a 1 MB shard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardMerkleProof {
    pub shard_index: u32,
    pub sub_block_index: u32,
    pub sub_block_hash: [u8; 32],
    pub audit_path: Vec<MerkleProofNode>,
}

impl ShardMerkleProof {
    /// Generates an inclusion proof for the specified sub-block within a 1 MB shard.
    pub fn generate(shard: &[u8], shard_index: u32, sub_block_index: usize) -> Result<Self> {
        if shard.len() != SHARD_SIZE {
            return Err(BlobError::InvalidShardSize {
                expected: SHARD_SIZE,
                got: shard.len(),
            });
        }
        if sub_block_index >= SUB_BLOCKS_PER_SHARD {
            return Err(BlobError::InvalidSubBlockIndex {
                index: sub_block_index,
                max: SUB_BLOCKS_PER_SHARD - 1,
            });
        }

        let mut current_level: Vec<[u8; 32]> = shard
            .chunks(SUB_BLOCK_SIZE)
            .map(|chunk| Sha3_256::digest(chunk).into())
            .collect();

        let sub_block_hash = current_level[sub_block_index];
        let mut audit_path = Vec::new();
        let mut idx = sub_block_index;

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            let mut i = 0;
            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    if i == idx {
                        // idx is left, sibling is right
                        audit_path.push(MerkleProofNode {
                            hash: current_level[i + 1],
                            position: SiblingPosition::Right,
                        });
                    } else if i + 1 == idx {
                        // idx is right, sibling is left
                        audit_path.push(MerkleProofNode {
                            hash: current_level[i],
                            position: SiblingPosition::Left,
                        });
                    }
                    next_level.push(hash_pair(&current_level[i], &current_level[i + 1]));
                    i += 2;
                } else {
                    // Odd node promoted without sibling; if idx is this odd node, no sibling added
                    next_level.push(current_level[i]);
                    i += 1;
                }
            }
            idx /= 2;
            current_level = next_level;
        }

        Ok(ShardMerkleProof {
            shard_index,
            sub_block_index: sub_block_index as u32,
            sub_block_hash,
            audit_path,
        })
    }

    /// Verifies the inclusion proof for a 4 KB sub-block against a shard Merkle root in microseconds.
    pub fn verify_sub_block(&self, shard_root: &[u8; 32], sub_block: &[u8]) -> bool {
        if sub_block.len() != SUB_BLOCK_SIZE {
            return false;
        }
        let computed_hash: [u8; 32] = Sha3_256::digest(sub_block).into();
        if computed_hash != self.sub_block_hash {
            return false;
        }
        self.verify_hash(shard_root)
    }

    /// Verifies the inclusion proof using the stored sub_block_hash against a shard Merkle root.
    pub fn verify_hash(&self, shard_root: &[u8; 32]) -> bool {
        let mut current_hash = self.sub_block_hash;
        for node in &self.audit_path {
            current_hash = match node.position {
                SiblingPosition::Left => hash_pair(&node.hash, &current_hash),
                SiblingPosition::Right => hash_pair(&current_hash, &node.hash),
            };
        }
        &current_hash == shard_root
    }

    /// Encodes the proof to compact binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 4 + 32 + 2 + self.audit_path.len() * 33);
        buf.extend_from_slice(&self.shard_index.to_be_bytes());
        buf.extend_from_slice(&self.sub_block_index.to_be_bytes());
        buf.extend_from_slice(&self.sub_block_hash);
        buf.extend_from_slice(&(self.audit_path.len() as u16).to_be_bytes());
        for node in &self.audit_path {
            let pos_byte = match node.position {
                SiblingPosition::Left => 0u8,
                SiblingPosition::Right => 1u8,
            };
            buf.push(pos_byte);
            buf.extend_from_slice(&node.hash);
        }
        buf
    }

    /// Decodes the proof from compact binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 42 {
            return Err(BlobError::SerializationError(
                "Buffer too short".to_string(),
            ));
        }
        let shard_index = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let sub_block_index = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let mut sub_block_hash = [0u8; 32];
        sub_block_hash.copy_from_slice(&bytes[8..40]);
        let path_len = u16::from_be_bytes(bytes[40..42].try_into().unwrap()) as usize;

        let expected_total = 42 + path_len * 33;
        if bytes.len() < expected_total {
            return Err(BlobError::SerializationError(
                "Buffer truncated".to_string(),
            ));
        }

        let mut offset = 42;
        let mut audit_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let pos = match bytes[offset] {
                0 => SiblingPosition::Left,
                1 => SiblingPosition::Right,
                other => {
                    return Err(BlobError::SerializationError(format!(
                        "Invalid sibling position: {}",
                        other
                    )))
                }
            };
            offset += 1;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            audit_path.push(MerkleProofNode {
                hash,
                position: pos,
            });
        }

        Ok(ShardMerkleProof {
            shard_index,
            sub_block_index,
            sub_block_hash,
            audit_path,
        })
    }
}
