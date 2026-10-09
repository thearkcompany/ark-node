//! Custody state machine and lifecycle engine for ark-blob (GCP-10, ADR-0011).
//!
//! Two-phase custody lifecycle:
//! - Phase 1 (StagedFullCustody): Files < 25 MB enter staged custody where public DePIN
//!   nodes retain all 14 shards (10 data + 4 parity, 140% storage overhead) under a 72-hour transient TTL.
//! - Phase 2 (HomelabConfirmed): Upon receiving authenticated `KIND_HOMELAB_ACK` (0x0000_2011)
//!   envelope signed by the owner's Homelab (FN-DSA-512), public keepers atomically discard
//!   data shards (0..9) on disk CAS, retaining only parity shards (10..13, 40% permanent overhead).
//! - Expired: If 72 hours elapse without Homelab confirmation (or L2 renewal), staged data shards
//!   expire and are pruned by automatic garbage collection.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::constants::{
    KIND_HOMELAB_ACK, STAGED_CUSTODY_TTL_SECS, STAGED_MAX_FILE_SIZE, TAG_CONTENT_CID,
};
use crate::error::{BlobError, Result};
use crate::manifest::{BlobManifest, ShardStatus};
use crate::store::HybridBlobStore;
use ark_core::FastHeader;
use ark_protocol::envelope::ArkEnvelope;

/// The custody state of a blob in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyState {
    /// Phase 1: All 14 shards retained under a transient 72-hour TTL (< 25 MB payloads).
    StagedFullCustody,
    /// Phase 2: Homelab confirmed receipt; data shards 0..9 purged, parity shards 10..13 retained.
    HomelabConfirmed,
    /// Phase 1 TTL expired without confirmation; staged data shards marked for eviction / pruned.
    Expired,
    /// All shards (or unconfirmed shards) have been completely purged from disk and index.
    Purged,
}

impl fmt::Display for CustodyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustodyState::StagedFullCustody => write!(f, "StagedFullCustody"),
            CustodyState::HomelabConfirmed => write!(f, "HomelabConfirmed"),
            CustodyState::Expired => write!(f, "Expired"),
            CustodyState::Purged => write!(f, "Purged"),
        }
    }
}

/// Metadata record tracking custody state and TTL for an indexed blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRecord {
    pub blob_cid: [u8; 32],
    pub state: CustodyState,
    pub created_at: u64,
    pub expires_at: u64,
    pub file_size: u64,
    pub homelab_id: Option<[u8; 32]>,
}

impl CustodyRecord {
    pub fn new(blob_cid: [u8; 32], file_size: u64, created_at: u64) -> Result<Self> {
        if file_size >= STAGED_MAX_FILE_SIZE {
            return Err(BlobError::IneligibleForStagedCustody {
                size: file_size,
                max: STAGED_MAX_FILE_SIZE,
            });
        }
        let expires_at = created_at.saturating_add(STAGED_CUSTODY_TTL_SECS);
        Ok(Self {
            blob_cid,
            state: CustodyState::StagedFullCustody,
            created_at,
            expires_at,
            file_size,
            homelab_id: None,
        })
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        self.state == CustodyState::StagedFullCustody && current_time >= self.expires_at
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BlobError::SerializationError(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BlobError::SerializationError(e.to_string()))
    }
}

/// Custody State Machine orchestrating staging, Homelab acknowledgement, pruning, and GC.
pub struct CustodyStateMachine<'a> {
    store: &'a HybridBlobStore,
}

impl<'a> CustodyStateMachine<'a> {
    pub fn new(store: &'a HybridBlobStore) -> Self {
        Self { store }
    }

    /// Enter Staged Full Custody for a file payload < 25 MB.
    ///
    /// Validates file size constraint, records custody metadata, and initializes
    /// all 14 shard statuses to `ShardStatus::Present`.
    pub fn enter_staged_custody(
        &self,
        manifest: &BlobManifest,
        created_at: u64,
    ) -> Result<CustodyRecord> {
        if manifest.total_size >= STAGED_MAX_FILE_SIZE {
            return Err(BlobError::IneligibleForStagedCustody {
                size: manifest.total_size,
                max: STAGED_MAX_FILE_SIZE,
            });
        }

        // Store manifest
        self.store.put_manifest(manifest)?;

        // Update shard statuses: all 14 shards (0..14) are Present
        for idx in 0..manifest.shard_hashes.len() {
            self.store
                .update_shard_status(&manifest.blob_cid, idx as u32, ShardStatus::Present)?;
        }

        let record = CustodyRecord::new(manifest.blob_cid, manifest.total_size, created_at)?;
        self.save_custody_record(&record)?;

        Ok(record)
    }

    /// Process a received `KIND_HOMELAB_ACK` (`0x0000_2011`) envelope.
    ///
    /// Validates envelope kind, FN-DSA signature against the owner/Homelab public key,
    /// transitions the custody state from `StagedFullCustody` to `HomelabConfirmed`,
    /// and atomically discards data shards (0..9) on disk CAS while retaining parity shards (10..13).
    pub fn handle_homelab_ack(
        &self,
        envelope: &ArkEnvelope,
        expected_homelab_pk: Option<&[u8]>,
    ) -> Result<CustodyRecord> {
        // 1. Verify envelope format and kind
        let kind = get_envelope_kind(envelope)?;
        if kind != KIND_HOMELAB_ACK {
            return Err(BlobError::InvalidEnvelope(format!(
                "Expected KIND_HOMELAB_ACK (0x{:08X}), got 0x{:08X}",
                KIND_HOMELAB_ACK, kind
            )));
        }

        // 2. Extract blob CID from TAG_CONTENT_CID
        let blob_cid = extract_blob_cid_tag(envelope)?;

        // 3. Verify FN-DSA signature
        verify_envelope_fn_dsa_signature(envelope, expected_homelab_pk)?;

        // 4. Load custody record and verify current state
        let mut record = self
            .get_custody_record(&blob_cid)?
            .ok_or_else(|| BlobError::ManifestNotFound(hex::encode(blob_cid)))?;

        match record.state {
            CustodyState::StagedFullCustody => {
                // Valid transition
            }
            CustodyState::HomelabConfirmed => {
                // Idempotent success
                return Ok(record);
            }
            CustodyState::Expired | CustodyState::Purged => {
                return Err(BlobError::InvalidCustodyTransition {
                    from: record.state.to_string(),
                    to: CustodyState::HomelabConfirmed.to_string(),
                });
            }
        }

        // 5. Load manifest to find shard hashes
        let manifest = self
            .store
            .get_manifest(&blob_cid)?
            .ok_or_else(|| BlobError::ManifestNotFound(hex::encode(blob_cid)))?;

        // 6. Discard data shards 0..DATA_SHARDS (0..9) atomically on disk CAS
        // and update Fjall index to ShardStatus::Purged.
        // Parity shards (10..13) are kept as ShardStatus::Present.
        for idx in 0..manifest.data_shards.min(manifest.shard_hashes.len()) {
            let shard_hash = &manifest.shard_hashes[idx];
            // Remove from CAS disk store
            let _ = self.store.remove_shard(shard_hash);
            // Mark purged in Fjall LSM
            self.store
                .update_shard_status(&blob_cid, idx as u32, ShardStatus::Purged)?;
        }

        // Ensure parity shards remain marked Present
        for idx in manifest.data_shards..manifest.shard_hashes.len() {
            self.store
                .update_shard_status(&blob_cid, idx as u32, ShardStatus::Present)?;
        }

        // 7. Update custody record state
        let mut homelab_id = [0u8; 32];
        if envelope.sender_id.len() >= 32 {
            homelab_id.copy_from_slice(&envelope.sender_id[..32]);
        }
        record.state = CustodyState::HomelabConfirmed;
        record.homelab_id = Some(homelab_id);

        self.save_custody_record(&record)?;

        Ok(record)
    }

    /// Garbage collection / pruning of expired staged custody data shards.
    ///
    /// Evaluates all staged blobs against `current_time`.
    /// For any whose TTL (72 hours) has expired without Homelab confirmation:
    /// - Discards data shards (0..9) from CAS disk and marks them `Purged`.
    /// - Transitions custody state to `CustodyState::Expired`.
    ///
    /// Returns the list of expired blob CIDs that were pruned.
    pub fn prune_expired_staged(&self, current_time: u64) -> Result<Vec<[u8; 32]>> {
        let records = self.list_all_custody_records()?;
        let mut pruned = Vec::new();

        for mut record in records {
            if record.is_expired(current_time) {
                let blob_cid = record.blob_cid;
                if let Some(manifest) = self.store.get_manifest(&blob_cid)? {
                    // Discard data shards 0..9 on disk CAS
                    for idx in 0..manifest.data_shards.min(manifest.shard_hashes.len()) {
                        let shard_hash = &manifest.shard_hashes[idx];
                        let _ = self.store.remove_shard(shard_hash);
                        self.store.update_shard_status(
                            &blob_cid,
                            idx as u32,
                            ShardStatus::Purged,
                        )?;
                    }
                }

                record.state = CustodyState::Expired;
                self.save_custody_record(&record)?;
                pruned.push(blob_cid);
            }
        }

        Ok(pruned)
    }

    // --- Persistence helpers for custody records ---

    pub const KEYSPACE_CUSTODY: &'static str = "blob_custody";

    fn save_custody_record(&self, record: &CustodyRecord) -> Result<()> {
        let keyspace = self
            .store
            .storage()
            .open_keyspace(Self::KEYSPACE_CUSTODY)
            .map_err(|e| BlobError::Storage(e.to_string()))?;
        let bytes = record.to_bytes()?;
        keyspace
            .insert(record.blob_cid, bytes)
            .map_err(|e| BlobError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_custody_record(&self, blob_cid: &[u8; 32]) -> Result<Option<CustodyRecord>> {
        let keyspace = self
            .store
            .storage()
            .open_keyspace(Self::KEYSPACE_CUSTODY)
            .map_err(|e| BlobError::Storage(e.to_string()))?;
        match keyspace
            .get(blob_cid)
            .map_err(|e| BlobError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let rec = CustodyRecord::from_bytes(&bytes)?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    pub fn list_all_custody_records(&self) -> Result<Vec<CustodyRecord>> {
        let keyspace = self
            .store
            .storage()
            .open_keyspace(Self::KEYSPACE_CUSTODY)
            .map_err(|e| BlobError::Storage(e.to_string()))?;

        let mut records = Vec::new();
        for guard in keyspace.iter() {
            let (_k, v) = guard
                .into_inner()
                .map_err(|e| BlobError::Storage(e.to_string()))?;
            let rec = CustodyRecord::from_bytes(&v)?;
            records.push(rec);
        }
        Ok(records)
    }
}

/// Helper to extract numeric kind from envelope.
fn get_envelope_kind(envelope: &ArkEnvelope) -> Result<u32> {
    for tag in &envelope.tags {
        if tag.tag_type == 0 {
            if tag.tag_value.len() == 4 {
                return Ok(u32::from_be_bytes(tag.tag_value[..4].try_into().unwrap()));
            } else if tag.tag_value.is_empty() {
                return Ok(0);
            }
        }
    }

    if envelope.fast_header.len() >= 64 {
        if let Ok(bytes) = envelope.fast_header[..64].try_into() {
            if let Ok(hdr) = FastHeader::from_bytes(&bytes) {
                if hdr.fast_tag != 0 {
                    return Ok(hdr.fast_tag);
                }
            }
        }
    }

    Err(BlobError::InvalidEnvelope(
        "Could not determine envelope kind".into(),
    ))
}

/// Helper to extract `TAG_CONTENT_CID` (0x0002) from envelope tags.
fn extract_blob_cid_tag(envelope: &ArkEnvelope) -> Result<[u8; 32]> {
    let tag = envelope
        .tags
        .iter()
        .find(|t| t.tag_type == TAG_CONTENT_CID)
        .ok_or_else(|| {
            BlobError::InvalidEnvelope(format!(
                "Missing TAG_CONTENT_CID (0x{:04X})",
                TAG_CONTENT_CID
            ))
        })?;

    if tag.tag_value.len() != 32 {
        return Err(BlobError::InvalidEnvelope(format!(
            "TAG_CONTENT_CID length is {} bytes, expected 32 bytes",
            tag.tag_value.len()
        )));
    }

    let mut cid = [0u8; 32];
    cid.copy_from_slice(&tag.tag_value);
    Ok(cid)
}

/// Helper to verify FN-DSA signature of an envelope.
fn verify_envelope_fn_dsa_signature(
    envelope: &ArkEnvelope,
    expected_pk: Option<&[u8]>,
) -> Result<()> {
    if envelope.signature.is_empty() {
        return Err(BlobError::InvalidSignature(
            "Envelope signature is missing".into(),
        ));
    }

    // Public key can be supplied explicitly or carried in tag 0x0001 / 0x0002
    let pubkey = if let Some(pk) = expected_pk {
        pk
    } else if let Some(pk_tag) = envelope.tags.iter().find(|t| t.tag_type == 0x0001) {
        &pk_tag.tag_value
    } else {
        return Err(BlobError::InvalidSignature(
            "No public key available to verify signature".into(),
        ));
    };

    // Calculate canonical message digest
    let canonical_id = ark_protocol::hashing::calculate_canonical_id(envelope);

    // Verify FN-DSA-512 signature
    ark_crypto::fn_dsa::verify_fn_dsa_512(pubkey, &canonical_id, &envelope.signature).map_err(|e| {
        BlobError::InvalidSignature(format!("FN-DSA signature verification failed: {}", e))
    })
}
