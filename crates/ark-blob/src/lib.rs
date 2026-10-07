//! Cauchy RS 10+4 e Two-Tier Merkle Engine para ark-blob (GCP-10).

pub mod constants;
pub mod error;
pub mod merkle;

pub use constants::*;
pub use error::{BlobError, Result};
pub use merkle::{
    compute_blob_cid, compute_merkle_root, compute_shard_merkle_roots,
    compute_single_shard_root, hash_pair, MerkleProofNode, ShardMerkleProof,
    SiblingPosition,
};

pub struct CauchyReedSolomon {
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Default for CauchyReedSolomon {
    fn default() -> Self {
        Self {
            data_shards: DATA_SHARDS,
            parity_shards: PARITY_SHARDS,
        }
    }
}
