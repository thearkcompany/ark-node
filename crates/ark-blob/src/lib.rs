//! Cauchy RS 10+4, Two-Tier Merkle Engine e Blob Storage (GCP-10, ACP-0010).

pub mod cas;
pub mod constants;
pub mod custody;
pub mod error;
pub mod gf;
pub mod ghost_lock;
pub mod manifest;
pub mod matrix;
pub mod merkle;
pub mod por;
pub mod store;

pub use cas::{CasDiskStore, StoragePaths};
pub use constants::*;
pub use custody::{CustodyRecord, CustodyState, CustodyStateMachine};
pub use error::{BlobError, Result};
pub use gf::{mul_slice, mul_slice_add};
pub use ghost_lock::{GhostLockEntry, SafeGhostLock};
pub use manifest::{BlobManifest, ShardStatus};
pub use merkle::{
    compute_blob_cid, compute_merkle_root, compute_shard_merkle_roots,
    compute_single_shard_root, hash_pair, MerkleProofNode, ShardMerkleProof,
    SiblingPosition,
};
pub use por::{
    compute_sub_block_kmac, derive_sub_block_index, generate_depin_challenge,
    verify_depin_challenge_response, DePINChallenge, DePINChallengeResponse,
};
pub use store::{HybridBlobStore, KEYSPACE_BLOB_MANIFESTS, KEYSPACE_BLOB_SHARDS};

use matrix::Matrix;

/// Cauchy Reed-Solomon Erasure Coding Engine.
///
/// Implements standard canonical parameters:
/// - `data_shards` (k) = 10
/// - `parity_shards` (m) = 4
/// - Standard shard size = 1 MB (1,048,576 bytes)
pub struct CauchyReedSolomon {
    pub data_shards: usize,
    pub parity_shards: usize,
    /// Precomputed canonical Cauchy parity generator matrix: (m x k)
    parity_matrix: Matrix,
}

impl CauchyReedSolomon {
    /// Canonical standard 1 MB shard size under GCP-10 / ADR-0011.
    pub const STANDARD_SHARD_SIZE: usize = SHARD_SIZE;

    /// Create a new CauchyReedSolomon codec with specific data and parity shard counts.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return Err(BlobError::InvalidPayloadLength);
        }
        if data_shards + parity_shards > 256 {
            return Err(BlobError::InvalidPayloadLength);
        }

        let parity_matrix = Matrix::cauchy(parity_shards, data_shards);
        Ok(Self {
            data_shards,
            parity_shards,
            parity_matrix,
        })
    }

    /// Total number of shards (k + m).
    #[inline(always)]
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Encode an arbitrary byte slice into `k + m` (14) shards.
    ///
    /// Shard length will be padded to `ceil(payload.len() / k)`.
    /// The returned vector has length `total_shards()` (10 data shards followed by 4 parity shards).
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        if payload.is_empty() {
            return Err(BlobError::EmptyPayload);
        }

        let shard_len = payload.len().div_ceil(self.data_shards);
        self.encode_with_shard_len(payload, shard_len)
    }

    /// Encode with canonical fixed standard shard size (1 MB / 1,048,576 bytes).
    ///
    /// The input payload can be up to `k * STANDARD_SHARD_SIZE` (10 MB).
    pub fn encode_standard(&self, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        if payload.is_empty() {
            return Err(BlobError::EmptyPayload);
        }
        if payload.len() > self.data_shards * Self::STANDARD_SHARD_SIZE {
            return Err(BlobError::InvalidPayloadLength);
        }

        self.encode_with_shard_len(payload, Self::STANDARD_SHARD_SIZE)
    }

    /// Encode with an explicit shard size (must be >= ceil(payload.len() / k)).
    pub fn encode_with_shard_len(&self, payload: &[u8], shard_len: usize) -> Result<Vec<Vec<u8>>> {
        if payload.is_empty() {
            return Err(BlobError::EmptyPayload);
        }
        if shard_len == 0 || shard_len * self.data_shards < payload.len() {
            return Err(BlobError::InvalidPayloadLength);
        }

        let k = self.data_shards;
        let m = self.parity_shards;
        let mut shards = Vec::with_capacity(k + m);

        // Partition payload into k data shards (zero-padded if necessary)
        for i in 0..k {
            let start = i * shard_len;
            let mut shard = vec![0u8; shard_len];
            if start < payload.len() {
                let end = (start + shard_len).min(payload.len());
                shard[..(end - start)].copy_from_slice(&payload[start..end]);
            }
            shards.push(shard);
        }

        // Generate m parity shards using the canonical Cauchy matrix:
        // Parity[p] = sum_{j=0}^{k-1} parity_matrix[p, j] * Data[j]
        for p in 0..m {
            let mut parity_shard = vec![0u8; shard_len];
            for (j, shard) in shards.iter().enumerate().take(k) {
                let coeff = self.parity_matrix.get(p, j);
                mul_slice_add(coeff, shard, &mut parity_shard);
            }
            shards.push(parity_shard);
        }

        Ok(shards)
    }

    /// Reconstruct the original payload from any `k` (10) distinct available shards.
    ///
    /// `shards` is a slice of `(shard_index, shard_data)` tuples, where `shard_index` is in `0..total_shards()`.
    /// `original_len` is the exact byte length of the pre-erasure payload.
    pub fn reconstruct(&self, shards: &[(usize, Vec<u8>)], original_len: usize) -> Result<Vec<u8>> {
        if original_len == 0 {
            return Err(BlobError::EmptyPayload);
        }

        let k = self.data_shards;
        let total = self.total_shards();

        if shards.len() < k {
            return Err(BlobError::InsufficientShards {
                available: shards.len(),
                required: k,
            });
        }

        // Check for invalid indices or duplicates
        let mut seen = vec![false; total];
        let shard_len = shards[0].1.len();
        if shard_len == 0 {
            return Err(BlobError::ShardLengthMismatch);
        }

        let mut selected_shards = Vec::with_capacity(k);

        for (idx, shard_data) in shards {
            if *idx >= total {
                return Err(BlobError::InvalidShardIndex(*idx));
            }
            if seen[*idx] {
                return Err(BlobError::DuplicateShardIndex(*idx));
            }
            seen[*idx] = true;

            if shard_data.len() != shard_len {
                return Err(BlobError::ShardLengthMismatch);
            }

            if selected_shards.len() < k {
                selected_shards.push((*idx, shard_data));
            }
        }

        if original_len > k * shard_len {
            return Err(BlobError::InvalidPayloadLength);
        }

        // Check if all selected shards are already the original data shards 0..k
        let mut all_data = true;
        for (i, &(shard_idx, _)) in selected_shards.iter().enumerate().take(k) {
            if shard_idx != i {
                all_data = false;
                break;
            }
        }

        let reconstructed_data_shards: Vec<Vec<u8>> = if all_data {
            // Fast path: no decoding matrix needed
            selected_shards.iter().map(|(_, s)| (*s).clone()).collect()
        } else {
            // General path:
            // The encoding generator matrix G (total x k) consists of:
            // - Top k rows: Identity(k)
            // - Bottom m rows: Cauchy(m, k)
            //
            // We selected k rows from G, forming submatrix G_sub (k x k).
            // Let D be the original k data shards, and S be the selected k shards.
            // S = G_sub * D  =>  D = (G_sub)^{-1} * S.
            let mut g_sub = Matrix::new(k, k);
            for (row_idx, (shard_idx, _)) in selected_shards.iter().enumerate() {
                if *shard_idx < k {
                    // Row from identity matrix
                    g_sub.set(row_idx, *shard_idx, 1);
                } else {
                    // Row from Cauchy parity matrix
                    let parity_row = *shard_idx - k;
                    for col in 0..k {
                        g_sub.set(row_idx, col, self.parity_matrix.get(parity_row, col));
                    }
                }
            }

            let g_sub_inv = g_sub.invert()?;

            // Multiply g_sub_inv by S to reconstruct all k data shards
            let mut data_shards = vec![vec![0u8; shard_len]; k];
            for (r, row_shard) in data_shards.iter_mut().enumerate().take(k) {
                for (c, &(_, selected_shard_bytes)) in selected_shards.iter().enumerate().take(k) {
                    let coeff = g_sub_inv.get(r, c);
                    mul_slice_add(coeff, selected_shard_bytes, row_shard);
                }
            }

            data_shards
        };

        // Assemble reconstructed data shards and trim to original_len
        let mut recovered = Vec::with_capacity(original_len);
        let mut remaining = original_len;
        for shard in reconstructed_data_shards {
            let take = remaining.min(shard.len());
            recovered.extend_from_slice(&shard[..take]);
            remaining -= take;
            if remaining == 0 {
                break;
            }
        }

        Ok(recovered)
    }
}

impl Default for CauchyReedSolomon {
    fn default() -> Self {
        Self::new(DATA_SHARDS, PARITY_SHARDS).expect("Default 10+4 parameters are valid")
    }
}
