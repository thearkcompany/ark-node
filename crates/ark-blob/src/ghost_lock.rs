//! Safe-Ghost Locking for client nodes (GCP-10, ADR-0011).
//!
//! Client daemons (`--role client` or `ark-app`) are physically prohibited from pruning
//! or evicting local cached source chunks/files until receiving cryptographic confirmation:
//! - Either a valid `KIND_HOMELAB_ACK` (0x0000_2011) signed by the owner's Homelab `ArkID`;
//! - Or passing verification of at least 10 remote Proof-of-Retrievability (PoR) challenges
//!   against sponsored DePIN keeper nodes.
//!
//! Any eviction attempt while locked returns `BlobError::SafeGhostLocked`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::constants::REQUIRED_POR_CHALLENGES;
use crate::error::{BlobError, Result};

/// Status tracking the verification state of a locked blob in the client cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostLockEntry {
    pub blob_cid: [u8; 32],
    /// Whether a verified KIND_HOMELAB_ACK envelope has been received for this blob.
    pub homelab_acknowledged: bool,
    /// Set of distinct remote keeper identities that verified a PoR challenge.
    pub verified_por_keepers: HashSet<[u8; 32]>,
}

impl GhostLockEntry {
    pub fn new(blob_cid: [u8; 32]) -> Self {
        Self {
            blob_cid,
            homelab_acknowledged: false,
            verified_por_keepers: HashSet::new(),
        }
    }

    /// Checks if the lock is satisfied and eviction is safely permitted.
    pub fn is_unlocked(&self) -> bool {
        self.homelab_acknowledged || self.verified_por_keepers.len() >= REQUIRED_POR_CHALLENGES
    }

    /// Number of verified remote PoR keeper challenges.
    pub fn por_count(&self) -> usize {
        self.verified_por_keepers.len()
    }
}

/// Client daemon guard physically prohibiting local chunk or source file eviction.
#[derive(Clone, Default)]
pub struct SafeGhostLock {
    locks: Arc<RwLock<HashMap<[u8; 32], GhostLockEntry>>>,
}

impl SafeGhostLock {
    pub fn new() -> Self {
        Self {
            locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Acquire a safe-ghost lock for an uploaded or cached blob.
    pub fn lock(&self, blob_cid: [u8; 32]) {
        let mut locks = self.locks.write().unwrap();
        locks.entry(blob_cid).or_insert_with(|| GhostLockEntry::new(blob_cid));
    }

    /// Check if a blob is currently locked against eviction.
    pub fn is_locked(&self, blob_cid: &[u8; 32]) -> bool {
        let locks = self.locks.read().unwrap();
        match locks.get(blob_cid) {
            Some(entry) => !entry.is_unlocked(),
            None => false, // Not tracked by ghost lock
        }
    }

    /// Record receipt of verified `KIND_HOMELAB_ACK` for a blob.
    pub fn record_homelab_ack(&self, blob_cid: &[u8; 32]) {
        let mut locks = self.locks.write().unwrap();
        let entry = locks.entry(*blob_cid).or_insert_with(|| GhostLockEntry::new(*blob_cid));
        entry.homelab_acknowledged = true;
    }

    /// Record a successfully verified Proof-of-Retrievability challenge against a keeper.
    pub fn record_por_challenge_success(&self, blob_cid: &[u8; 32], keeper_id: [u8; 32]) {
        let mut locks = self.locks.write().unwrap();
        let entry = locks.entry(*blob_cid).or_insert_with(|| GhostLockEntry::new(*blob_cid));
        entry.verified_por_keepers.insert(keeper_id);
    }

    /// Attempt to evict or prune a blob from the local client cache.
    ///
    /// Prohibited with `BlobError::SafeGhostLocked` unless either:
    /// - `homelab_acknowledged == true`, OR
    /// - `verified_por_keepers.len() >= 10`.
    ///
    /// If unlocked, releases the lock entry and returns `Ok(())`.
    pub fn check_and_evict(&self, blob_cid: &[u8; 32]) -> Result<()> {
        let mut locks = self.locks.write().unwrap();
        if let Some(entry) = locks.get(blob_cid) {
            if !entry.is_unlocked() {
                return Err(BlobError::SafeGhostLocked {
                    challenges: entry.por_count(),
                    required: REQUIRED_POR_CHALLENGES,
                });
            }
            // Once unlocked and eviction requested, remove tracking
            locks.remove(blob_cid);
        }
        Ok(())
    }

    /// Get details of lock status for inspection.
    pub fn get_status(&self, blob_cid: &[u8; 32]) -> Option<GhostLockEntry> {
        let locks = self.locks.read().unwrap();
        locks.get(blob_cid).cloned()
    }
}
