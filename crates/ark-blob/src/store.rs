//! Hybrid persistence engine orchestrating CAS on disk and Fjall LSM metadata indexing.
//!
//! GCP-10 / ADR-0011 architectural requirements:
//! - Shard payloads (1 MB binary) stored content-addressed directly on the filesystem (`.ark/blobs/<shard_hash>`).
//! - Manifests indexed in Fjall LSM via `ark-storage` using `KIND_BLOB_MANIFEST` (`0x1000_0003`)
//!   under Retention Class 1 (`class1_append`) or dedicated `blob_manifests` keyspace.
//! - Shard status pointers indexed in `blob_shards` keyspace: `[blob_cid: 32B] || [shard_index: 4B BE] -> [status byte]`.
//! - Streaming reads and integrity verification without retaining multiple megabytes in memory.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use ark_storage::{Keyspace, StorageEngine};

use crate::cas::CasDiskStore;
use crate::error::{BlobError, Result};
use crate::manifest::{BlobManifest, ShardStatus};

pub const KEYSPACE_BLOB_MANIFESTS: &str = "blob_manifests";
pub const KEYSPACE_BLOB_SHARDS: &str = "blob_shards";

/// Hybrid persistence store coupling CAS filesystem storage with Fjall LSM metadata index.
#[derive(Clone)]
pub struct HybridBlobStore {
    cas: CasDiskStore,
    storage: Arc<StorageEngine>,
    manifests_keyspace: Keyspace,
    shards_keyspace: Keyspace,
}

impl HybridBlobStore {
    /// Opens or creates a HybridBlobStore given a CAS disk root and an `ark-storage` engine.
    pub fn new<P: AsRef<Path>>(cas_root: P, storage: Arc<StorageEngine>) -> Result<Self> {
        let cas = CasDiskStore::new(cas_root)?;
        let manifests_keyspace = storage
            .open_keyspace(KEYSPACE_BLOB_MANIFESTS)
            .map_err(|e| BlobError::Storage(e.to_string()))?;
        let shards_keyspace = storage
            .open_keyspace(KEYSPACE_BLOB_SHARDS)
            .map_err(|e| BlobError::Storage(e.to_string()))?;

        Ok(Self {
            cas,
            storage,
            manifests_keyspace,
            shards_keyspace,
        })
    }

    /// Access reference to underlying `CasDiskStore`.
    pub fn cas(&self) -> &CasDiskStore {
        &self.cas
    }

    /// Access reference to underlying `StorageEngine`.
    pub fn storage(&self) -> &Arc<StorageEngine> {
        &self.storage
    }

    // =========================================================================
    // CAS Shard Operations (Disk Filesystem)
    // =========================================================================

    /// Content-addressed storage for a 1 MB shard payload with atomic write and fsync.
    pub fn put_shard(&self, payload: &[u8]) -> Result<[u8; 32]> {
        self.cas.put_shard(payload)
    }

    /// Reads a shard from disk CAS with cryptographic content verification.
    pub fn read_shard(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        self.cas.read_shard(hash)
    }

    /// Checks if a shard exists in CAS.
    pub fn has_shard(&self, hash: &[u8; 32]) -> bool {
        self.cas.has_shard(hash)
    }

    /// Opens a streaming reader for a shard payload.
    pub fn open_shard_stream(&self, hash: &[u8; 32]) -> Result<BufReader<File>> {
        self.cas.open_shard_stream(hash)
    }

    /// Verifies shard integrity in a streaming fashion.
    pub fn verify_shard_stream(&self, hash: &[u8; 32]) -> Result<bool> {
        self.cas.verify_shard_stream(hash)
    }

    /// Removes a shard from disk CAS.
    pub fn remove_shard(&self, hash: &[u8; 32]) -> Result<bool> {
        self.cas.remove_shard(hash)
    }

    // =========================================================================
    // Manifest & Shard Metadata Operations (Fjall LSM)
    // =========================================================================

    /// Indexes a `BlobManifest` in Fjall LSM:
    /// 1. Stores in dedicated `blob_manifests` keyspace keyed by `blob_cid`.
    /// 2. Also writes canonical `ArkEnvelope` with `KIND_BLOB_MANIFEST` into `StorageEngine`
    ///    enforcing Retention Class 1 (`Class1AppendOnly`).
    pub fn put_manifest(&self, manifest: &BlobManifest) -> Result<()> {
        let manifest_bytes = manifest.to_bytes()?;

        // 1. Point index in blob_manifests keyspace by blob_cid (32 bytes)
        self.manifests_keyspace
            .insert(manifest.blob_cid, &manifest_bytes)
            .map_err(|e| BlobError::Storage(e.to_string()))?;

        // 2. Encapsulate into ArkEnvelope and ingest via StorageEngine (Retention Class 1)
        let sender_id = [0u8; 32];
        let envelope = manifest.to_envelope(&sender_id)?;
        self.storage
            .put_envelope(&envelope)
            .map_err(|e| BlobError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Retrieves a `BlobManifest` by its 32-byte `blob_cid`.
    pub fn get_manifest(&self, blob_cid: &[u8; 32]) -> Result<Option<BlobManifest>> {
        let entry = self
            .manifests_keyspace
            .get(blob_cid)
            .map_err(|e| BlobError::Storage(e.to_string()))?;

        match entry {
            Some(bytes) => {
                let manifest = BlobManifest::from_bytes(&bytes)?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    /// Deletes a manifest from the Fjall index.
    pub fn delete_manifest(&self, blob_cid: &[u8; 32]) -> Result<bool> {
        if self.manifests_keyspace.get(blob_cid).map_err(|e| BlobError::Storage(e.to_string()))?.is_some() {
            self.manifests_keyspace
                .remove(blob_cid)
                .map_err(|e| BlobError::Storage(e.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Key format for shard pointer: `[blob_cid: 32B] || [shard_index: 4B BE]` (36 bytes).
    fn make_shard_key(blob_cid: &[u8; 32], shard_index: u32) -> [u8; 36] {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(blob_cid);
        key[32..36].copy_from_slice(&shard_index.to_be_bytes());
        key
    }

    /// Records or updates the custody status of a shard pointer in Fjall LSM.
    pub fn update_shard_status(
        &self,
        blob_cid: &[u8; 32],
        shard_index: u32,
        status: ShardStatus,
    ) -> Result<()> {
        let key = Self::make_shard_key(blob_cid, shard_index);
        let status_byte = match status {
            ShardStatus::Present => 1u8,
            ShardStatus::Pending => 2u8,
            ShardStatus::Purged => 3u8,
        };

        self.shards_keyspace
            .insert(key, [status_byte])
            .map_err(|e| BlobError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Retrieves the status of a shard pointer from Fjall LSM.
    pub fn get_shard_status(
        &self,
        blob_cid: &[u8; 32],
        shard_index: u32,
    ) -> Result<Option<ShardStatus>> {
        let key = Self::make_shard_key(blob_cid, shard_index);
        let entry = self
            .shards_keyspace
            .get(key)
            .map_err(|e| BlobError::Storage(e.to_string()))?;

        match entry {
            Some(bytes) if !bytes.is_empty() => {
                let status = match bytes[0] {
                    1 => ShardStatus::Present,
                    2 => ShardStatus::Pending,
                    3 => ShardStatus::Purged,
                    _ => return Ok(None),
                };
                Ok(Some(status))
            }
            _ => Ok(None),
        }
    }

    /// Lists shard statuses for all shards of a given blob_cid.
    pub fn list_blob_shard_statuses(&self, blob_cid: &[u8; 32]) -> Result<Vec<(u32, ShardStatus)>> {
        let mut statuses = Vec::new();
        let prefix = blob_cid;

        for guard in self.shards_keyspace.prefix(prefix) {
            let (k, v) = guard.into_inner().map_err(|e| BlobError::Storage(e.to_string()))?;
            if k.len() == 36 && &k[..32] == blob_cid {
                let shard_index = u32::from_be_bytes(k[32..36].try_into().unwrap());
                if !v.is_empty() {
                    let status = match v[0] {
                        1 => ShardStatus::Present,
                        2 => ShardStatus::Pending,
                        3 => ShardStatus::Purged,
                        _ => continue,
                    };
                    statuses.push((shard_index, status));
                }
            }
        }

        statuses.sort_by_key(|&(idx, _)| idx);
        Ok(statuses)
    }
}
