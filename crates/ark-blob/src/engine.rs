//! Deep module facade BlobEngine aggregating all ark-blob modules (GCP-10, ADR-0011).
//!
//! Orchestrates:
//! - Cauchy Reed-Solomon 10+4 erasure coding (`CauchyReedSolomon`)
//! - Two-Tier Merkle tree integrity proofs (`compute_blob_cid`, `compute_shard_merkle_roots`, `ShardMerkleProof`)
//! - CAS disk filesystem storage (`CasDiskStore`, `.ark/blobs/<shard_hash>`)
//! - Fjall LSM manifest indexing (`HybridBlobStore`, `KIND_BLOB_MANIFEST`)
//! - Custody state machine (`CustodyStateMachine`, `CustodyRecord`, `CustodyState`)
//! - Client Safe-Ghost Locking (`SafeGhostLock`)
//! - DePIN Proof-of-Retrievability (PoR) 4 KB KMAC256 auditing (`DePINChallenge`, `DePINChallengeResponse`)
//! - Pluggable L2 Escrow Verification (`BlobEscrowVerifier`, `TAG_L2_CONTRACT` 0x000F)
//! - QUIC FastHeader shard streaming framing (`ShardStreamFrame`)

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ark_protocol::envelope::ArkEnvelope;
use ark_storage::StorageEngine;

use crate::constants::{
    DATA_SHARDS, PARITY_SHARDS, SHARD_SIZE, STAGED_MAX_FILE_SIZE, TAG_L2_CONTRACT, TOTAL_SHARDS,
};
use crate::custody::{CustodyRecord, CustodyStateMachine};
use crate::error::{BlobError, Result};
use crate::escrow::BlobEscrowVerifier;
use crate::framing::ShardStreamFrame;
use crate::ghost_lock::SafeGhostLock;
use crate::manifest::{BlobManifest, ShardStatus};
use crate::merkle::{compute_blob_cid, compute_shard_merkle_roots};
use crate::por::{DePINChallenge, DePINChallengeResponse};
use crate::store::HybridBlobStore;
use crate::CauchyReedSolomon;

/// Result of storing a newly ingested blob in the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestResult {
    /// 32-byte canonical BlobCID (Tier 1 Merkle root).
    pub blob_cid: [u8; 32],
    /// Total original pre-coding payload bytes.
    pub total_size: u64,
    /// 14 SHA3-256 shard content hashes.
    pub shard_hashes: Vec<[u8; 32]>,
    /// 14 Tier 2 Merkle roots.
    pub shard_roots: Vec<[u8; 32]>,
    /// Initial custody record if staged custody was entered.
    pub custody: Option<CustodyRecord>,
    /// Manifest representing this blob.
    pub manifest: BlobManifest,
}

/// Unified facade for the `ark-blob` storage and erasure coding subsystem.
#[derive(Clone)]
pub struct BlobEngine<V: BlobEscrowVerifier = Arc<dyn BlobEscrowVerifier>> {
    store: HybridBlobStore,
    codec: Arc<CauchyReedSolomon>,
    escrow_verifier: V,
    ghost_lock: SafeGhostLock,
}

impl BlobEngine<Arc<dyn BlobEscrowVerifier>> {
    /// Creates a builder to configure and construct a `BlobEngine`.
    pub fn builder() -> BlobEngineBuilder<Arc<dyn BlobEscrowVerifier>> {
        BlobEngineBuilder::default()
    }
}

impl<V: BlobEscrowVerifier> BlobEngine<V> {
    /// Opens a `BlobEngine` with the given hybrid store and escrow verifier.
    pub fn new(store: HybridBlobStore, escrow_verifier: V) -> Self {
        Self {
            store,
            codec: Arc::new(CauchyReedSolomon::default()),
            escrow_verifier,
            ghost_lock: SafeGhostLock::new(),
        }
    }

    /// Access reference to underlying `HybridBlobStore`.
    pub fn store(&self) -> &HybridBlobStore {
        &self.store
    }

    /// Access reference to `CauchyReedSolomon` codec.
    pub fn codec(&self) -> &CauchyReedSolomon {
        &self.codec
    }

    /// Access reference to `BlobEscrowVerifier`.
    pub fn escrow_verifier(&self) -> &V {
        &self.escrow_verifier
    }

    /// Access reference to client `SafeGhostLock`.
    pub fn ghost_lock(&self) -> &SafeGhostLock {
        &self.ghost_lock
    }

    /// Access custody state machine instance.
    pub fn custody_machine(&self) -> CustodyStateMachine<'_> {
        CustodyStateMachine::new(&self.store)
    }

    // =========================================================================
    // High-Level Ingest & Retrieval API
    // =========================================================================

    /// Encodes a raw payload into 10+4 Cauchy shards, stores all shards in CAS disk storage,
    /// computes Tier 1 & Tier 2 Merkle roots, indexes the manifest in Fjall LSM, and enters
    /// staged custody if eligible (< 25 MB).
    ///
    /// Validates L2 escrow sponsorship contract via `BlobEscrowVerifier` if provided.
    pub fn encode_and_store(
        &self,
        payload: &[u8],
        escrow_contract: Option<&[u8]>,
    ) -> Result<IngestResult> {
        if payload.is_empty() {
            return Err(BlobError::EmptyPayload);
        }

        // 1. Compute canonical Tier 1 BlobCID
        let blob_cid = compute_blob_cid(payload);

        // 2. Validate L2 escrow contract if supplied or required
        if let Some(contract) = escrow_contract {
            let valid = self.escrow_verifier.verify_blob_escrow(contract, &blob_cid)?;
            if !valid {
                return Err(BlobError::EscrowVerificationFailed(format!(
                    "L2 escrow contract 0x{} rejected for blob 0x{}",
                    hex::encode(contract),
                    hex::encode(blob_cid)
                )));
            }
        }

        // 3. Cauchy RS 10+4 standard 1 MB sharding
        let shards = self.codec.encode_with_shard_len(payload, SHARD_SIZE)?;
        if shards.len() != TOTAL_SHARDS {
            return Err(BlobError::InvalidShardCount {
                expected: TOTAL_SHARDS,
                got: shards.len(),
            });
        }

        // 4. Compute Tier 2 Shard Merkle Roots
        let shard_roots = compute_shard_merkle_roots(&shards)?;

        // 5. Store 1 MB shards in CAS disk storage and record statuses
        let mut shard_hashes = Vec::with_capacity(TOTAL_SHARDS);
        for (idx, shard_bytes) in shards.iter().enumerate() {
            let hash = self.store.put_shard(shard_bytes)?;
            shard_hashes.push(hash);
            self.store
                .update_shard_status(&blob_cid, idx as u32, ShardStatus::Present)?;
        }

        let now = current_timestamp();
        let manifest = BlobManifest {
            blob_cid,
            total_size: payload.len() as u64,
            data_shards: DATA_SHARDS,
            parity_shards: PARITY_SHARDS,
            shard_hashes: shard_hashes.clone(),
            shard_roots: shard_roots.clone(),
            created_at: now,
        };

        // 6. Index manifest in Fjall LSM (and StorageEngine Retention Class 1)
        self.store.put_manifest(&manifest)?;

        // 7. If file size < 25 MB, enter Staged Full Custody
        let custody = if (payload.len() as u64) < STAGED_MAX_FILE_SIZE {
            let csm = self.custody_machine();
            Some(csm.enter_staged_custody(&manifest, now)?)
        } else {
            None
        };

        Ok(IngestResult {
            blob_cid,
            total_size: payload.len() as u64,
            shard_hashes,
            shard_roots,
            custody,
            manifest,
        })
    }

    /// Client helper: Stages an upload, acquires Safe-Ghost lock prohibiting local eviction,
    /// and persists local shards.
    pub fn stage_upload(
        &self,
        payload: &[u8],
        escrow_contract: Option<&[u8]>,
    ) -> Result<IngestResult> {
        let result = self.encode_and_store(payload, escrow_contract)?;
        // Physically engage safe-ghost lock to prohibit local cache eviction until confirmation
        self.ghost_lock.lock(result.blob_cid);
        Ok(result)
    }

    /// Reconstructs original payload from any available shards stored on CAS disk or passed in.
    /// Needs at least 10 valid distinct shards.
    pub fn retrieve_and_decode(&self, blob_cid: &[u8; 32]) -> Result<Vec<u8>> {
        let manifest = self
            .store
            .get_manifest(blob_cid)?
            .ok_or_else(|| BlobError::ManifestNotFound(hex::encode(blob_cid)))?;

        let mut available_shards = Vec::new();
        for (idx, hash) in manifest.shard_hashes.iter().enumerate() {
            if self.store.has_shard(hash) {
                if let Ok(data) = self.store.read_shard(hash) {
                    available_shards.push((idx, data));
                    if available_shards.len() >= DATA_SHARDS {
                        break;
                    }
                }
            }
        }

        if available_shards.len() < DATA_SHARDS {
            return Err(BlobError::InsufficientShards {
                available: available_shards.len(),
                required: DATA_SHARDS,
            });
        }

        self.codec
            .reconstruct(&available_shards, manifest.total_size as usize)
    }

    /// Reconstructs payload from an explicit slice of `(shard_index, shard_data)` buffers.
    pub fn decode_shards(
        &self,
        shards: &[(usize, Vec<u8>)],
        original_len: usize,
    ) -> Result<Vec<u8>> {
        self.codec.reconstruct(shards, original_len)
    }

    // =========================================================================
    // Manifest & Escrow Verification API
    // =========================================================================

    /// Ingests and indexes an incoming `BlobManifest` envelope or protobuf message.
    /// Enforces L2 escrow verification if `TAG_L2_CONTRACT` (0x000F) is present or required.
    pub fn ingest_manifest_envelope(
        &self,
        envelope: &ArkEnvelope,
        require_escrow: bool,
    ) -> Result<BlobManifest> {
        let manifest = BlobManifest::from_envelope(envelope)?;

        // Check for TAG_L2_CONTRACT
        let escrow_tag = envelope
            .tags
            .iter()
            .find(|t| t.tag_type == TAG_L2_CONTRACT);

        match escrow_tag {
            Some(tag) => {
                let valid = self
                    .escrow_verifier
                    .verify_blob_escrow(&tag.tag_value, &manifest.blob_cid)?;
                if !valid {
                    return Err(BlobError::EscrowVerificationFailed(format!(
                        "L2 contract 0x{} invalid or unsponsored for blob 0x{}",
                        hex::encode(&tag.tag_value),
                        hex::encode(manifest.blob_cid)
                    )));
                }
            }
            None => {
                if require_escrow {
                    return Err(BlobError::MissingTag(TAG_L2_CONTRACT));
                }
            }
        }

        // Store manifest
        self.store.put_manifest(&manifest)?;
        Ok(manifest)
    }

    // =========================================================================
    // Custody & Safe-Ghost Locking API
    // =========================================================================

    /// Processes a `KIND_HOMELAB_ACK` envelope: transitions custody to `HomelabConfirmed`,
    /// purges data shards 0..9 on CAS disk, and unlocks `SafeGhostLock`.
    pub fn handle_homelab_ack(
        &self,
        ack_envelope: &ArkEnvelope,
        expected_homelab_pk: Option<&[u8]>,
    ) -> Result<CustodyRecord> {
        let csm = self.custody_machine();
        let record = csm.handle_homelab_ack(ack_envelope, expected_homelab_pk)?;

        // Unlock client ghost-lock
        self.ghost_lock.record_homelab_ack(&record.blob_cid);

        Ok(record)
    }

    /// Attempts to evict local cached chunks of a blob, respecting Safe-Ghost Locking rules.
    pub fn evict_cached_blob(&self, blob_cid: &[u8; 32]) -> Result<()> {
        // Enforce safe-ghost lock check first
        self.ghost_lock.check_and_evict(blob_cid)?;

        // If unlocked, remove manifest and shards
        if let Some(manifest) = self.store.get_manifest(blob_cid)? {
            for hash in &manifest.shard_hashes {
                let _ = self.store.remove_shard(hash);
            }
            let _ = self.store.delete_manifest(blob_cid);
        }

        Ok(())
    }

    // =========================================================================
    // DePIN Proof-of-Retrievability (PoR) Engine API
    // =========================================================================

    /// Auditor helper: Generates a new DePIN challenge for a keeper holding a specific shard.
    pub fn create_por_challenge(
        &self,
        blob_cid: [u8; 32],
        shard_index: u32,
        seed: [u8; 32],
        sub_block_index: Option<u32>,
    ) -> DePINChallenge {
        match sub_block_index {
            Some(idx) => DePINChallenge::new(blob_cid, shard_index, idx, seed),
            None => DePINChallenge::new_sampled(blob_cid, shard_index, seed),
        }
    }

    /// Keeper node: Handles an incoming DePIN challenge by retrieving the shard from CAS,
    /// sampling the 4 KB sub-block, computing KMAC256, and building the Merkle proof.
    pub fn handle_depin_challenge(
        &self,
        challenge: &DePINChallenge,
    ) -> Result<DePINChallengeResponse> {
        let manifest = self
            .store
            .get_manifest(&challenge.blob_cid)?
            .ok_or_else(|| BlobError::ManifestNotFound(hex::encode(challenge.blob_cid)))?;

        if challenge.shard_index as usize >= manifest.shard_hashes.len() {
            return Err(BlobError::InvalidShardIndex(challenge.shard_index as usize));
        }

        let shard_hash = &manifest.shard_hashes[challenge.shard_index as usize];
        let shard_bytes = self.store.read_shard(shard_hash)?;

        DePINChallengeResponse::generate(&shard_bytes, challenge)
    }

    /// Auditor node: Verifies a keeper's PoR response against the manifest's shard Merkle root.
    /// If valid and keeper identity is known, records verification towards client SafeGhostLock.
    pub fn verify_depin_response(
        &self,
        response: &DePINChallengeResponse,
        challenge: &DePINChallenge,
        keeper_id: Option<[u8; 32]>,
    ) -> Result<bool> {
        let manifest = self
            .store
            .get_manifest(&challenge.blob_cid)?
            .ok_or_else(|| BlobError::ManifestNotFound(hex::encode(challenge.blob_cid)))?;

        if challenge.shard_index as usize >= manifest.shard_roots.len() {
            return Ok(false);
        }

        let shard_root = &manifest.shard_roots[challenge.shard_index as usize];
        let valid = response.verify(shard_root, challenge);

        if valid {
            if let Some(kid) = keeper_id {
                self.ghost_lock
                    .record_por_challenge_success(&challenge.blob_cid, kid);
            }
        }

        Ok(valid)
    }

    // =========================================================================
    // QUIC FastHeader Shard Streaming API
    // =========================================================================

    /// Frames a stored shard for streaming over a line-rate QUIC connection.
    pub fn frame_shard_stream(
        &self,
        shard_hash: &[u8; 32],
        shard_index: u32,
        sender_prefix: [u8; 16],
        recipient_prefix: [u8; 16],
    ) -> Result<Vec<u8>> {
        let shard_payload = self.store.read_shard(shard_hash)?;
        ShardStreamFrame::encode(
            shard_index,
            &shard_payload,
            sender_prefix,
            recipient_prefix,
        )
    }

    /// Receives and stores a streaming shard frame from a QUIC connection.
    /// Validates the 64-byte FastHeader and writes the shard payload directly into CAS disk store.
    /// Returns `(shard_index, shard_hash)`.
    pub fn ingest_shard_stream_frame(&self, frame_bytes: &[u8]) -> Result<(u32, [u8; 32])> {
        let (_header, shard_index, shard_payload) = ShardStreamFrame::decode(frame_bytes)?;
        let shard_hash = self.store.put_shard(&shard_payload)?;
        Ok((shard_index, shard_hash))
    }
}

/// Builder pattern for `BlobEngine`.
pub struct BlobEngineBuilder<V: BlobEscrowVerifier> {
    cas_dir: Option<std::path::PathBuf>,
    storage: Option<Arc<StorageEngine>>,
    escrow_verifier: Option<V>,
}

impl<V: BlobEscrowVerifier> Default for BlobEngineBuilder<V> {
    fn default() -> Self {
        Self {
            cas_dir: None,
            storage: None,
            escrow_verifier: None,
        }
    }
}

impl<V: BlobEscrowVerifier> BlobEngineBuilder<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cas_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.cas_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn storage(mut self, storage: Arc<StorageEngine>) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn escrow_verifier<NV: BlobEscrowVerifier>(
        self,
        verifier: NV,
    ) -> BlobEngineBuilder<NV> {
        BlobEngineBuilder {
            cas_dir: self.cas_dir,
            storage: self.storage,
            escrow_verifier: Some(verifier),
        }
    }

    pub fn build(self) -> Result<BlobEngine<V>> {
        let cas_dir = self.cas_dir.ok_or_else(|| {
            BlobError::Storage("cas_dir must be configured on BlobEngineBuilder".into())
        })?;
        let storage = self.storage.ok_or_else(|| {
            BlobError::Storage("storage must be configured on BlobEngineBuilder".into())
        })?;
        let escrow_verifier = self.escrow_verifier.ok_or_else(|| {
            BlobError::Storage("escrow_verifier must be configured on BlobEngineBuilder".into())
        })?;

        let store = HybridBlobStore::new(cas_dir, storage)?;
        Ok(BlobEngine::new(store, escrow_verifier))
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
