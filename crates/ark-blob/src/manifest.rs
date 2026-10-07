//! Blob manifest and shard status metadata indexing (GCP-10, ADR-0011).
//!
//! A `BlobManifest` indexes:
//! - `blob_cid`: 32-byte canonical BlobCID (Tier 1 Merkle root).
//! - `total_size`: Pre-coding unpadded payload length.
//! - `data_shards`: Number of data shards (canonical: 10).
//! - `parity_shards`: Number of parity shards (canonical: 4).
//! - `shard_hashes`: 14 SHA3-256 content hashes of the 1 MB shards.
//! - `shard_roots`: 14 Tier 2 Merkle roots of the 1 MB shards.
//! - `created_at`: UNIX timestamp.
//!
//! Envelope encapsulation:
//! - Manifests can be serialized into a canonical `ArkEnvelope` with:
//!   - `kind = KIND_BLOB_MANIFEST` (`0x1000_0003`)
//!   - Retention Class 1 (`Class1AppendOnly`)
//!   - Tag `TAG_CONTENT_CID` (`0x0002`) carrying `blob_cid`.

use ark_core::FastHeader;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use serde::{Deserialize, Serialize};

use crate::constants::{KIND_BLOB_MANIFEST, TAG_CONTENT_CID};
use crate::error::{BlobError, Result};

/// Status of an individual shard within a blob custody lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardStatus {
    /// Shard is present and verified on local disk CAS.
    Present,
    /// Shard is pending retrieval or download.
    Pending,
    /// Shard has been evicted or purged (e.g. after Homelab ACK).
    Purged,
}

/// Metadata manifest describing an erasure-coded blob under GCP-10.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobManifest {
    /// 32-byte canonical BlobCID (Tier 1 Merkle root over 64 KB sub-chunks).
    pub blob_cid: [u8; 32],
    /// Original unpadded pre-coding payload size in bytes.
    pub total_size: u64,
    /// Number of Cauchy data shards (canonical: 10).
    pub data_shards: usize,
    /// Number of Cauchy parity shards (canonical: 4).
    pub parity_shards: usize,
    /// Content hashes (SHA3-256) of each 1 MB shard in order (0..14).
    pub shard_hashes: Vec<[u8; 32]>,
    /// Tier 2 Merkle roots of each 1 MB shard in order (0..14).
    pub shard_roots: Vec<[u8; 32]>,
    /// Creation timestamp (seconds since UNIX epoch).
    pub created_at: u64,
}

impl BlobManifest {
    /// Serializes manifest into JSON binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    /// Deserializes manifest from JSON binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    /// Converts this manifest into an `ArkEnvelope` with kind `KIND_BLOB_MANIFEST` (`0x1000_0003`),
    /// classified as Retention Class 1 in `ark-storage`.
    pub fn to_envelope(&self, sender_id: &[u8; 32]) -> Result<ArkEnvelope> {
        let payload = self.to_bytes()?;
        let mut sender_key_id = [0u8; 16];
        sender_key_id.copy_from_slice(&sender_id[..16]);

        let fast_header = FastHeader::new(
            0,
            payload.len() as u32,
            KIND_BLOB_MANIFEST,
            sender_key_id,
            [0u8; 16],
            1,
        );

        let tags = vec![
            BinaryTag::new(TAG_CONTENT_CID, self.blob_cid.to_vec()),
            BinaryTag::new(0, KIND_BLOB_MANIFEST.to_be_bytes().to_vec()),
        ];

        ArkEnvelope::new(
            fast_header.to_bytes(),
            *sender_id,
            [0u8; 32],
            payload,
            vec![],
            0,
            tags,
            self.created_at,
        )
        .map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    /// Reconstructs a `BlobManifest` from a canonical `ArkEnvelope`.
    pub fn from_envelope(envelope: &ArkEnvelope) -> Result<Self> {
        Self::from_bytes(&envelope.payload)
    }
}
