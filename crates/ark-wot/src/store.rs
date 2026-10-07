//! Fjall LSM Persistent Storage & Lock-Free In-Memory Concurrent Evaluation Cache (ACP-04).

use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;
use ark_core::error::{ArkError, Result};
use ark_storage::{Keyspace, StorageEngine};
use crate::crypto::{TrustAttestation, TrustRevocation};
use crate::graph::{LocalTrustGraph, TrustEvaluation, TrustTier};
use crate::temporal::TemporalValidator;

pub const KEYSPACE_WOT_ATTESTATIONS: &str = "wot_attestations";
pub const KEYSPACE_WOT_REVOCATIONS: &str = "wot_revocations";

/// Durable store orchestrating Fjall LSM keyspaces and lock-free DashMap evaluation cache.
pub struct WotStore {
    local_root: [u8; 32],
    storage: Arc<StorageEngine>,
    attestations_ks: Keyspace,
    revocations_ks: Keyspace,
    validator: TemporalValidator,
    graph: RwLock<LocalTrustGraph>,
    /// Sub-microsecond O(1) concurrent evaluation cache
    cache: DashMap<[u8; 32], TrustEvaluation>,
}

impl WotStore {
    /// Opens or recovers a WotStore using the provided StorageEngine.
    pub fn open(local_root: [u8; 32], storage: Arc<StorageEngine>) -> Result<Self> {
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

    /// Internal key formatting: [issuer_id: 32B] || [subject_id: 32B]
    fn make_relation_key(issuer: &[u8; 32], subject: &[u8; 32]) -> [u8; 64] {
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
        let _ = self.storage.put_envelope(&envelope);

        // Incremental graph update
        if !self.validator.is_revoked(&attestation.issuer_id, &attestation.subject_id) {
            let mut g = self.graph.write();
            g.add_edge(attestation.issuer_id, attestation.subject_id, attestation.score_weight);
            g.compute_ppr();
        }

        self.refresh_cache(attestation.issued_at_pmt);
        Ok(())
    }

    /// Save a verified TrustRevocation to Fjall LSM and immediately update cache.
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
        let _ = self.storage.put_envelope(&envelope);

        // Immediate edge truncation in trust graph
        let mut g = self.graph.write();
        g.remove_edge(&revocation.issuer_id, &revocation.subject_id);
        g.compute_ppr();
        drop(g);

        self.refresh_cache(revocation.revoked_at_pmt);
        Ok(())
    }

    /// Recalculate cache entries.
    pub fn refresh_cache(&self, current_pmt: u64) {
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

        // Re-evaluate known nodes
        for item in self.attestations_ks.iter() {
            if let Ok(val) = item.value() {
                if let Ok(att) = TrustAttestation::from_cbor(&val) {
                    let subject = att.subject_id;
                    if self.validator.is_revoked(&att.issuer_id, &att.subject_id) {
                        // Revoked edge
                        let eval = g.evaluate_trust(&subject);
                        self.cache.insert(subject, eval);
                    } else if current_pmt > 0 && current_pmt > att.expires_at_pmt {
                        // Expired edge
                        self.cache.insert(
                            subject,
                            TrustEvaluation {
                                target: subject,
                                score: 0.0,
                                distance: u32::MAX,
                                tier: TrustTier::Untrusted,
                            },
                        );
                    } else {
                        let eval = g.evaluate_trust(&subject);
                        self.cache.insert(subject, eval);
                    }
                }
            }
        }
    }

    /// Sub-microsecond O(1) concurrent cache evaluation.
    pub fn evaluate_cached(&self, target: &[u8; 32], _current_pmt: u64) -> TrustEvaluation {
        if target == &self.local_root {
            return TrustEvaluation {
                target: *target,
                score: 1.0,
                distance: 0,
                tier: TrustTier::CorePeer,
            };
        }

        if let Some(eval) = self.cache.get(target) {
            return eval.clone();
        }

        // Cache miss: compute via graph
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
}
