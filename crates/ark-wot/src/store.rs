//! Fjall LSM Persistent Storage & Lock-Free In-Memory Concurrent Evaluation Cache (ACP-04).

use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;
use ark_core::error::{ArkError, Result};
use ark_crdt::{MstConfig, MstEngine};
use ark_protocol::envelope::ArkEnvelope;
use ark_storage::{Keyspace, StorageEngine};
use crate::crypto::{TrustAttestation, TrustRevocation};
use crate::engine::CRDT_NAMESPACE_WOT;
use crate::graph::{LocalTrustGraph, TrustEvaluation, TrustTier};
use crate::temporal::TemporalValidator;

pub const KEYSPACE_WOT_ATTESTATIONS: &str = "wot_attestations";
pub const KEYSPACE_WOT_REVOCATIONS: &str = "wot_revocations";

/// Durable store orchestrating Fjall LSM keyspaces, internalized MST CRDT, and lock-free DashMap evaluation cache.
pub struct WotStore {
    local_root: [u8; 32],
    storage: Arc<StorageEngine>,
    mst_engine: Arc<MstEngine>,
    attestations_ks: Keyspace,
    revocations_ks: Keyspace,
    validator: TemporalValidator,
    graph: RwLock<LocalTrustGraph>,
    /// Sub-microsecond O(1) concurrent evaluation cache
    cache: DashMap<[u8; 32], TrustEvaluation>,
}

impl WotStore {
    /// Opens or recovers a WotStore using the provided StorageEngine and default MstConfig.
    pub fn open(local_root: [u8; 32], storage: Arc<StorageEngine>) -> Result<Self> {
        let mst_engine = Arc::new(
            MstEngine::open(Arc::clone(&storage), MstConfig::default())
                .map_err(|e| ArkError::Internal(e.to_string()))?,
        );
        Self::with_mst_engine(local_root, storage, mst_engine)
    }

    /// Opens or recovers a WotStore with an injected MstEngine.
    pub fn with_mst_engine(
        local_root: [u8; 32],
        storage: Arc<StorageEngine>,
        mst_engine: Arc<MstEngine>,
    ) -> Result<Self> {
        let attestations_ks = storage
            .open_keyspace(KEYSPACE_WOT_ATTESTATIONS)
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        let revocations_ks = storage
            .open_keyspace(KEYSPACE_WOT_REVOCATIONS)
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        let validator = TemporalValidator::new();
        let graph = RwLock::new(LocalTrustGraph::new(local_root));
        let cache = DashMap::new();

        let store = Self {
            local_root,
            storage,
            mst_engine,
            attestations_ks,
            revocations_ks,
            validator,
            graph,
            cache,
        };

        // Reload existing revocations and attestations from Fjall keyspaces
        store.reload_from_disk()?;

        Ok(store)
    }

    /// Access the internalized MST CRDT engine.
    pub fn mst_engine(&self) -> &Arc<MstEngine> {
        &self.mst_engine
    }

    /// Internal key formatting: [issuer_id: 32B] || [subject_id: 32B]
    pub fn make_relation_key(issuer: &[u8; 32], subject: &[u8; 32]) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(issuer);
        key[32..].copy_from_slice(subject);
        key
    }

    /// Reload persistent state across crashes / engine restarts.
    fn reload_from_disk(&self) -> Result<()> {
        // 1. Reload revocations
        for item in self.revocations_ks.iter() {
            if let Ok(val) = item.value() {
                if let Ok(revocation) = TrustRevocation::from_cbor(&val) {
                    self.validator.record_revocation(revocation);
                }
            }
        }

        // 2. Reload attestations and populate graph
        let mut g = self.graph.write();
        for item in self.attestations_ks.iter() {
            if let Ok(val) = item.value() {
                if let Ok(attestation) = TrustAttestation::from_cbor(&val) {
                    if !self.validator.is_revoked(&attestation.issuer_id, &attestation.subject_id) {
                        g.add_edge(attestation.issuer_id, attestation.subject_id, attestation.score_weight);
                    }
                }
            }
        }

        g.compute_ppr();
        drop(g);

        self.refresh_cache(0);
        Ok(())
    }

    /// Save a verified TrustAttestation to Fjall LSM and update cache.
    pub fn save_attestation(&self, attestation: &TrustAttestation, issuer_pubkey: &[u8]) -> Result<()> {
        attestation.verify_signature(issuer_pubkey)?;

        let key = Self::make_relation_key(&attestation.issuer_id, &attestation.subject_id);
        let bytes = attestation.to_cbor()?;

        self.attestations_ks
            .insert(key, bytes)
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        // Also store canonical ArkEnvelope in ark-storage for retention classes and sync
        let envelope = attestation.to_envelope(issuer_pubkey)?;
        self.storage
            .put_envelope(&envelope)
            .map_err(|e| ArkError::Internal(e.to_string()))?;
        self.mst_engine
            .put(CRDT_NAMESPACE_WOT, &key, &envelope)
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        // Incremental graph update
        if !self.validator.is_revoked(&attestation.issuer_id, &attestation.subject_id) {
            let mut g = self.graph.write();
            g.add_edge(attestation.issuer_id, attestation.subject_id, attestation.score_weight);
            g.compute_ppr();
        }

        self.refresh_cache(attestation.issued_at_pmt);
        Ok(())
    }

    /// Save a verified TrustRevocation to Fjall LSM, index into MST, and immediately update cache.
    pub fn save_revocation(&self, revocation: &TrustRevocation, issuer_pubkey: &[u8]) -> Result<()> {
        revocation.verify_signature(issuer_pubkey)?;

        let key = Self::make_relation_key(&revocation.issuer_id, &revocation.subject_id);
        let bytes = revocation.to_cbor()?;

        self.revocations_ks
            .insert(key, bytes)
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        // Record in validator table
        self.validator.record_revocation(revocation.clone());

        let envelope = revocation.to_envelope(issuer_pubkey)?;
        self.storage
            .put_envelope(&envelope)
            .map_err(|e| ArkError::Internal(e.to_string()))?;
        self.mst_engine
            .put(CRDT_NAMESPACE_WOT, &key, &envelope)
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        // Immediate edge truncation in trust graph
        let mut g = self.graph.write();
        g.remove_edge(&revocation.issuer_id, &revocation.subject_id);
        g.compute_ppr();
        drop(g);

        self.refresh_cache(revocation.revoked_at_pmt);
        Ok(())
    }

    /// Recalculate cache entries.
    pub fn refresh_cache(&self, _current_pmt: u64) {
        let g = self.graph.read();

        // Self is always CorePeer
        self.cache.insert(
            self.local_root,
            TrustEvaluation {
                target: self.local_root,
                score: 1.0,
                distance: 0,
                tier: TrustTier::CorePeer,
            },
        );

        // Re-evaluate distinct subject nodes from graph
        for item in self.attestations_ks.iter() {
            if let Ok(val) = item.value() {
                if let Ok(att) = TrustAttestation::from_cbor(&val) {
                    let subject = att.subject_id;
                    if subject == self.local_root {
                        continue;
                    }
                    let eval = g.evaluate_trust(&subject);
                    self.cache.insert(subject, eval);
                }
            }
        }
    }

    /// Sub-microsecond O(1) concurrent cache evaluation.
    pub fn evaluate_cached(&self, target: &[u8; 32], current_pmt: u64) -> TrustEvaluation {
        if target == &self.local_root {
            return TrustEvaluation {
                target: *target,
                score: 1.0,
                distance: 0,
                tier: TrustTier::CorePeer,
            };
        }

        if current_pmt == 0 {
            if let Some(eval) = self.cache.get(target) {
                return eval.clone();
            }
        }

        // Compute via graph
        let g = self.graph.read();
        let eval = g.evaluate_trust(target);
        self.cache.insert(*target, eval.clone());
        eval
    }

    /// Read all active attestations from persistent storage.
    pub fn get_all_attestations(&self) -> Vec<TrustAttestation> {
        let mut list = Vec::new();
        for item in self.attestations_ks.iter() {
            if let Ok(val) = item.value() {
                if let Ok(att) = TrustAttestation::from_cbor(&val) {
                    list.push(att);
                }
            }
        }
        list
    }

    /// Ingest an inbound anti-entropy CRDT envelope (ADR-0020).
    ///
    /// Cryptographically validates `TAG_WOT_PUBKEY`, checks `issuer_id == SHA3-256(pubkey)`,
    /// verifies the FN-DSA-512 signature against the payload, enforces PMT consensus drift boundaries (±30s),
    /// records the data in the respective Fjall LSM keyspace, indexes into the MST under `CRDT_NAMESPACE_WOT`,
    /// and immediately updates the in-memory trust graph (PPR) and evaluation cache.
    pub fn ingest_crdt_envelope(&self, envelope: &ArkEnvelope, reference_pmt: u64) -> Result<()> {
        use ark_crypto::fn_dsa::FN_DSA_512_PUBKEY_SIZE;
        use sha3::{Digest, Sha3_256};

        let kind = ark_storage::get_envelope_kind(envelope);

        // 1. Extract TAG_WOT_PUBKEY
        let pubkey_tag = envelope
            .tags
            .iter()
            .find(|tag| tag.tag_type == crate::crypto::TAG_WOT_PUBKEY)
            .ok_or_else(|| {
                ArkError::TagError("Envelope missing required TAG_WOT_PUBKEY tag".to_string())
            })?;

        let issuer_pubkey = &pubkey_tag.tag_value;
        if issuer_pubkey.len() != FN_DSA_512_PUBKEY_SIZE {
            return Err(ArkError::CryptoError(format!(
                "Invalid issuer public key size: {} bytes, expected {} bytes",
                issuer_pubkey.len(),
                FN_DSA_512_PUBKEY_SIZE
            )));
        }

        // 2. Validate issuer identity derivation: issuer_id == SHA3-256(pubkey)
        let derived_issuer_id: [u8; 32] = Sha3_256::digest(issuer_pubkey).into();
        if envelope.sender_id.as_slice() != derived_issuer_id.as_slice() {
            return Err(ArkError::CryptoError(
                "Public key does not derive envelope sender_id".to_string(),
            ));
        }

        // 3. Dispatch based on envelope kind
        match kind {
            crate::crypto::KIND_WOT_ATTESTATION => {
                let attestation = TrustAttestation::from_envelope(envelope)?;
                if attestation.issuer_id != derived_issuer_id {
                    return Err(ArkError::CryptoError(
                        "Public key does not match attestation issuer_id".to_string(),
                    ));
                }

                // Consensus drift validation (±30s)
                ark_time::DriftValidator::validate_timestamp(attestation.issued_at_pmt, reference_pmt)?;

                // Cryptographic signature and bound verification
                attestation.verify_signature(issuer_pubkey)?;

                // Save to LSM, storage, MST, trust graph, and refresh cache
                self.save_attestation(&attestation, issuer_pubkey)?;
                Ok(())
            }
            crate::crypto::KIND_WOT_REVOCATION => {
                let revocation = TrustRevocation::from_envelope(envelope)?;
                if revocation.issuer_id != derived_issuer_id {
                    return Err(ArkError::CryptoError(
                        "Public key does not match revocation issuer_id".to_string(),
                    ));
                }

                // Consensus drift validation (±30s)
                ark_time::DriftValidator::validate_timestamp(revocation.revoked_at_pmt, reference_pmt)?;

                // Cryptographic signature verification
                revocation.verify_signature(issuer_pubkey)?;

                // Save to LSM, storage, MST, trust graph, and refresh cache
                self.save_revocation(&revocation, issuer_pubkey)?;
                Ok(())
            }
            other => Err(ArkError::SerializationError(format!(
                "Unsupported WoT envelope kind: 0x{:04x}, expected 0x{:04x} (attestation) or 0x{:04x} (revocation)",
                other,
                crate::crypto::KIND_WOT_ATTESTATION,
                crate::crypto::KIND_WOT_REVOCATION,
            ))),
        }
    }
}

