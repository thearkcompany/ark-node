//! Unified WotEngine Facade, CRDT MST Anti-Entropy Synchronization & Subsystem Adapters (ACP-04).

use std::sync::Arc;
use ark_core::error::{ArkError, Result};
use ark_crdt::{MstConfig, MstEngine};
use ark_protocol::envelope::ArkEnvelope;
use ark_storage::StorageEngine;
use crate::crypto::{CapabilityScope, TrustAttestation, TrustRevocation};
use crate::graph::{TrustEvaluation, TrustTier};
use crate::store::WotStore;

pub const CRDT_NAMESPACE_WOT: &str = "ark/wot/v1";

/// High-level unified facade for Web-of-Trust Sybil resistance, reputation,
/// anti-entropy CRDT synchronization, and cross-subsystem QoS policy enforcement.
pub struct WotEngine {
    local_root: [u8; 32],
    store: Arc<WotStore>,
    mst_engine: Arc<MstEngine>,
    clock: Arc<dyn ark_time::PmtClock>,
}

impl WotEngine {
    /// Initialises a WotEngine with explicit PmtClock and underlying components.
    pub fn new(
        local_root: [u8; 32],
        store: Arc<WotStore>,
        mst_engine: Arc<MstEngine>,
        clock: Arc<dyn ark_time::PmtClock>,
    ) -> Self {
        Self {
            local_root,
            store,
            mst_engine,
            clock,
        }
    }

    /// Opens or initialises a WotEngine with underlying Fjall LSM storage, MST CRDT, and PmtClock.
    pub fn open(
        local_root: [u8; 32],
        storage: Arc<StorageEngine>,
        clock: Arc<dyn ark_time::PmtClock>,
    ) -> Result<Self> {
        let store = Arc::new(WotStore::open(local_root, Arc::clone(&storage))?);
        let mst_engine = Arc::new(
            MstEngine::open(Arc::clone(&storage), MstConfig::default())
                .map_err(|e| ark_core::error::ArkError::Internal(e.to_string()))?,
        );

        Ok(Self::new(local_root, store, mst_engine, clock))
    }

    pub fn clock(&self) -> &Arc<dyn ark_time::PmtClock> {
        &self.clock
    }

    pub fn local_root(&self) -> &[u8; 32] {
        &self.local_root
    }

    /// Evaluates trust score, topological distance, and TrustTier for a target identity relative to local root,
    /// querying the internal PmtClock for current consensus time.
    pub fn evaluate_trust(&self, target: &[u8; 32]) -> TrustEvaluation {
        let current_pmt = self.clock.now_pmt();
        self.store.evaluate_cached(target, current_pmt)
    }

    /// Evaluates trust score between an issuer and subject against consensus time queried from the internal PmtClock.
    pub fn evaluate_trust_pair(&self, issuer_id: &[u8; 32], subject_id: &[u8; 32]) -> Result<f64> {
        let current_pmt = self.clock.now_pmt();
        // Check if there is an active attestation between issuer and subject
        for att in self.store.get_all_attestations() {
            if &att.issuer_id == issuer_id && &att.subject_id == subject_id {
                let score = crate::temporal::compute_decayed_weight(
                    att.score_weight,
                    att.issued_at_pmt,
                    current_pmt,
                );
                return Ok(score);
            }
        }
        Ok(0.0)
    }

    /// Evaluates trust score with explicit Peer-Median-Time (PMT) timestamp for time-decay.
    pub fn evaluate_trust_at(&self, target: &[u8; 32], pmt_timestamp: u64) -> TrustEvaluation {
        self.store.evaluate_cached(target, pmt_timestamp)
    }

    /// Ingest and store a verified TrustAttestation, updating Fjall LSM, CRDT MST, and cache.
    pub fn record_attestation(&self, attestation: TrustAttestation, issuer_pubkey: &[u8]) -> Result<()> {
        self.store.save_attestation(&attestation, issuer_pubkey)?;

        // CRDT MST ingestion under CRDT_NAMESPACE_WOT
        let envelope = attestation.to_envelope(issuer_pubkey)?;
        self.sync_mst(&attestation.issuer_id, &attestation.subject_id, &envelope);
        Ok(())
    }

    /// Ingest and store a verified TrustRevocation, updating Fjall LSM, CRDT MST, and immediately truncating trust paths.
    pub fn revoke_attestation(&self, revocation: TrustRevocation, issuer_pubkey: &[u8]) -> Result<()> {
        self.store.save_revocation(&revocation, issuer_pubkey)?;

        let envelope = revocation.to_envelope(issuer_pubkey)?;
        self.sync_mst(&revocation.issuer_id, &revocation.subject_id, &envelope);
        Ok(())
    }

    /// Deep WoT envelope ingestion interface (ADR-0017).
    ///
    /// Validates `TAG_WOT_PUBKEY`, checks `issuer_id == SHA3-256(pubkey)`,
    /// verifies post-quantum signature (FN-DSA-512) over canonical payload/attestation/revocation,
    /// persists to `WotStore`, updates the local trust graph and evaluation cache,
    /// and synchronizes `MstEngine` under `CRDT_NAMESPACE_WOT`.
    ///
    /// Rejects malformed or unverified envelopes with descriptive errors without polluting storage.
    pub fn ingest_envelope(&self, envelope: &ArkEnvelope) -> Result<()> {
        use ark_crypto::fn_dsa::FN_DSA_512_PUBKEY_SIZE;
        use sha3::{Digest, Sha3_256};

        let kind = ark_storage::get_envelope_kind(envelope);

        // 1. Extract TAG_WOT_PUBKEY
        let pubkey_tag = envelope
            .tags
            .iter()
            .find(|tag| tag.tag_type == crate::crypto::TAG_WOT_PUBKEY)
            .ok_or_else(|| {
                ArkError::TagError(
                    "Envelope missing required TAG_WOT_PUBKEY tag".to_string(),
                )
            })?;

        let issuer_pubkey = &pubkey_tag.tag_value;
        if issuer_pubkey.len() != FN_DSA_512_PUBKEY_SIZE {
            return Err(ark_core::error::ArkError::CryptoError(format!(
                "Invalid issuer public key size: {} bytes, expected {} bytes",
                issuer_pubkey.len(),
                FN_DSA_512_PUBKEY_SIZE
            )));
        }

        // 2. Validate issuer identity derivation: issuer_id == SHA3-256(pubkey)
        let derived_issuer_id: [u8; 32] = Sha3_256::digest(issuer_pubkey).into();

        if envelope.sender_id.as_slice() != derived_issuer_id.as_slice() {
            return Err(ark_core::error::ArkError::CryptoError(
                "Public key does not derive envelope sender_id".to_string(),
            ));
        }

        // 3. Dispatch based on envelope kind
        match kind {
            crate::crypto::KIND_WOT_ATTESTATION => {
                let attestation = TrustAttestation::from_envelope(envelope)?;
                if attestation.issuer_id != derived_issuer_id {
                    return Err(ark_core::error::ArkError::CryptoError(
                        "Public key does not match attestation issuer_id".to_string(),
                    ));
                }

                // Cryptographic signature and bound verification
                attestation.verify_signature(issuer_pubkey)?;

                // Persist to WotStore (Fjall LSM + trust graph + evaluation cache)
                self.store.save_attestation(&attestation, issuer_pubkey)?;

                // Synchronize MstEngine under CRDT_NAMESPACE_WOT
                self.sync_mst(&attestation.issuer_id, &attestation.subject_id, envelope);

                Ok(())
            }
            crate::crypto::KIND_WOT_REVOCATION => {
                let revocation = TrustRevocation::from_envelope(envelope)?;
                if revocation.issuer_id != derived_issuer_id {
                    return Err(ark_core::error::ArkError::CryptoError(
                        "Public key does not match revocation issuer_id".to_string(),
                    ));
                }

                // Cryptographic signature verification
                revocation.verify_signature(issuer_pubkey)?;

                // Persist to WotStore (Fjall LSM + immediate edge truncation in graph + cache refresh)
                self.store.save_revocation(&revocation, issuer_pubkey)?;

                // Synchronize MstEngine under CRDT_NAMESPACE_WOT
                self.sync_mst(&revocation.issuer_id, &revocation.subject_id, envelope);

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

    /// Synchronizes an envelope into the MST under `CRDT_NAMESPACE_WOT` keyed by issuer_id || subject_id.
    pub fn sync_mst(&self, issuer_id: &[u8; 32], subject_id: &[u8; 32], envelope: &ArkEnvelope) {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(issuer_id);
        key.extend_from_slice(subject_id);
        let _ = self.mst_engine.put(CRDT_NAMESPACE_WOT, &key, envelope);
    }


    /// Anti-entropy subgraph synchronization returning attestations since the specified PMT epoch.
    pub fn sync_subgraph(&self, since_pmt: u64) -> Vec<TrustAttestation> {
        self.store
            .get_all_attestations()
            .into_iter()
            .filter(|a| a.issued_at_pmt >= since_pmt)
            .collect()
    }

    // =========================================================================
    // Cross-Subsystem QoS Policy Adapters (ark-vpn, ark-blob, ark-dns, ark-paas)
    // =========================================================================

    /// ark-vpn: Overlay VPN tunnel admission check.
    ///
    /// Requires CorePeer or Trusted tier, plus RELAY capability scope (if specified).
    pub fn is_vpn_allowed(&self, target: &[u8; 32]) -> bool {
        let eval = self.evaluate_trust(target);
        match eval.tier {
            TrustTier::CorePeer => true,
            TrustTier::Trusted => {
                // Must have RELAY capability in an active attestation
                self.has_capability(target, CapabilityScope::RELAY)
            }
            TrustTier::Probationary | TrustTier::Untrusted => false,
        }
    }

    /// ark-blob: Storage allocation and chunk persistence quota check.
    ///
    /// Requires CorePeer, Trusted, or Probationary with STORAGE capability.
    pub fn is_storage_allowed(&self, target: &[u8; 32]) -> bool {
        let eval = self.evaluate_trust(target);
        match eval.tier {
            TrustTier::CorePeer => true,
            TrustTier::Trusted => self.has_capability(target, CapabilityScope::STORAGE),
            TrustTier::Probationary => self.has_capability(target, CapabilityScope::STORAGE) && eval.score >= 0.25,
            TrustTier::Untrusted => false,
        }
    }

    /// ark-paas: Sovereign compute execution scheduling check.
    ///
    /// Requires CorePeer or Trusted with COMPUTE capability.
    pub fn is_compute_allowed(&self, target: &[u8; 32]) -> bool {
        let eval = self.evaluate_trust(target);
        match eval.tier {
            TrustTier::CorePeer => true,
            TrustTier::Trusted => self.has_capability(target, CapabilityScope::COMPUTE),
            TrustTier::Probationary | TrustTier::Untrusted => false,
        }
    }

    /// Check if target node possesses a specific capability scope in active attestations.
    fn has_capability(&self, target: &[u8; 32], scope: CapabilityScope) -> bool {
        for att in self.store.get_all_attestations() {
            if &att.subject_id == target && att.capability_scopes.contains(scope) {
                return true;
            }
        }
        false
    }
}
