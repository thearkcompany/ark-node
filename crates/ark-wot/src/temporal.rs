//! Temporal Dynamics, Half-Life Decay, and Prioritized Revocation Index (ACP-04).

use crate::crypto::{TrustAttestation, TrustRevocation};
use dashmap::DashMap;
use std::sync::Arc;

/// Standard half-life decay period: 30 days (in seconds).
pub const HALF_LIFE_SECS: u64 = 30 * 86400;

/// Exponential half-life decay function:
/// w(t) = w0 * 2^(-delta_t / tau_1/2)
pub fn compute_decayed_weight(w0: f64, issued_at_pmt: u64, current_pmt: u64) -> f64 {
    if current_pmt <= issued_at_pmt {
        return w0;
    }
    let delta_t = (current_pmt - issued_at_pmt) as f64;
    let exponent = -delta_t / (HALF_LIFE_SECS as f64);
    let decayed = w0 * (2.0f64).powf(exponent);
    decayed.clamp(0.0, 1.0)
}

/// Key identifying an attestation relationship (issuer, subject).
pub type RelationKey = ([u8; 32], [u8; 32]);

/// Thread-safe O(1) Revocation Index tracking active revocations.
#[derive(Debug, Clone, Default)]
pub struct RevocationIndex {
    /// Maps (issuer_id, subject_id) -> TrustRevocation
    revocations: Arc<DashMap<RelationKey, TrustRevocation>>,
}

impl RevocationIndex {
    pub fn new() -> Self {
        Self {
            revocations: Arc::new(DashMap::new()),
        }
    }

    /// Record a revocation. If an existing revocation exists for the same relationship,
    /// preserves the one with the latest revoked_at_pmt timestamp.
    pub fn record(&self, revocation: TrustRevocation) {
        let key = (revocation.issuer_id, revocation.subject_id);
        self.revocations
            .entry(key)
            .and_modify(|existing| {
                if revocation.revoked_at_pmt >= existing.revoked_at_pmt {
                    *existing = revocation.clone();
                }
            })
            .or_insert(revocation);
    }

    /// Check whether an attestation between issuer and subject has been revoked.
    pub fn is_revoked(&self, issuer_id: &[u8; 32], subject_id: &[u8; 32]) -> bool {
        self.revocations.contains_key(&(*issuer_id, *subject_id))
    }

    /// Retrieve the revocation record if present.
    pub fn get_revocation(
        &self,
        issuer_id: &[u8; 32],
        subject_id: &[u8; 32],
    ) -> Option<TrustRevocation> {
        self.revocations
            .get(&(*issuer_id, *subject_id))
            .map(|r| r.clone())
    }

    /// Total active revocations tracked.
    pub fn len(&self) -> usize {
        self.revocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revocations.is_empty()
    }
}

/// Temporal validator coordinating expiration filtering, half-life decay,
/// and absolute revocation precedence.
#[derive(Debug, Clone, Default)]
pub struct TemporalValidator {
    revocation_index: RevocationIndex,
}

impl TemporalValidator {
    pub fn new() -> Self {
        Self {
            revocation_index: RevocationIndex::new(),
        }
    }

    pub fn revocation_index(&self) -> &RevocationIndex {
        &self.revocation_index
    }

    /// Record a revocation into the index.
    pub fn record_revocation(&self, revocation: TrustRevocation) {
        self.revocation_index.record(revocation);
    }

    /// Check O(1) revocation lookup table.
    pub fn is_revoked(&self, issuer_id: &[u8; 32], subject_id: &[u8; 32]) -> bool {
        self.revocation_index.is_revoked(issuer_id, subject_id)
    }

    /// Evaluate an attestation against current PMT timestamp.
    ///
    /// Rules:
    /// 1. If revoked by issuer against subject -> returns None (absolute priority).
    /// 2. If current_pmt > expires_at_pmt -> returns None (expired).
    /// 3. If valid -> returns Some(decayed_weight) calculated via half-life decay.
    pub fn evaluate_attestation(
        &self,
        attestation: &TrustAttestation,
        current_pmt: u64,
    ) -> Option<f64> {
        if self.is_revoked(&attestation.issuer_id, &attestation.subject_id) {
            return None;
        }

        if current_pmt > attestation.expires_at_pmt {
            return None;
        }

        let decayed = compute_decayed_weight(
            attestation.score_weight,
            attestation.issued_at_pmt,
            current_pmt,
        );

        Some(decayed)
    }
}
