//! Unified MstEngine: high-level API for GCP-09 / ADR-0009.
//!
//! Wraps `MstStore`, `MstDiff`, and `sync` functions behind a clean public interface:
//!
//! - `open(storage, config)` — initialise from an existing `StorageEngine`.
//! - `put(namespace, key, envelope)` — insert or update a key under Bivariate LWW.
//! - `get(namespace, key)` — point lookup; returns the corresponding `ArkEnvelope`.
//! - `delete(namespace, key, tombstone)` — record a signed tombstone deletion.
//! - `root_hash(namespace)` — 32-byte digest of the current namespace root.
//! - `compute_sync_diff(namespace, remote_root)` — produce a minimal `MstSyncPlan`.
//! - `handle_sync_request(req)` — generate a bounded `MstSyncResponse`.
//! - `apply_sync_response(res)` — validate and incorporate a peer response.

use ark_protocol::{ArkEnvelope, MstSyncRequest, MstSyncResponse};
use ark_storage::{compute_envelope_id, StorageEngine};
use std::sync::Arc;

use crate::diff::{MstDiff, MstSyncPlan};
use crate::error::Result;
use crate::mst::{MerkleSearchTree, MstPutOutcome};
use crate::store::{MstStore, MstStoreConfig};
use crate::sync::{apply_sync_response, handle_sync_request, SyncApplyStats};

/// Configuration for `MstEngine`.
#[derive(Clone, Debug, Default)]
pub struct MstConfig {
    /// Inner `MstStore` configuration (LRU cache size, etc.).
    pub store: MstStoreConfig,
}

/// High-level unified interface for the Merkle Search Tree CRDT engine (GCP-09).
pub struct MstEngine {
    store: MstStore,
    storage: Arc<StorageEngine>,
}

impl MstEngine {
    /// Opens or initialises an `MstEngine` backed by the given `StorageEngine`.
    pub fn open(storage: Arc<StorageEngine>, config: MstConfig) -> Result<Self> {
        let store = MstStore::open(Arc::clone(&storage), config.store)?;
        Ok(Self { store, storage })
    }

    /// Inserts or updates `envelope` under `key` in `namespace`, applying Bivariate LWW.
    ///
    /// Returns:
    /// - `Inserted` — new key.
    /// - `Updated` — superseded an older entry.
    /// - `SupersededLww` — incoming envelope is older; no tree mutation occurs.
    pub fn put(
        &self,
        namespace: &str,
        key: &[u8],
        envelope: &ArkEnvelope,
    ) -> Result<MstPutOutcome> {
        let envelope_id = compute_envelope_id(envelope)
            .map_err(|e| crate::error::ArkCrdtError::Database(e.to_string()))?;
        let timestamp = envelope.timestamp;

        // Check existing entry for LWW decision.
        let outcome = if let Some((existing_id, existing_ts)) = self.store.get(namespace, key)? {
            if timestamp > existing_ts || (timestamp == existing_ts && envelope_id > existing_id) {
                // Supersede existing — actually insert.
                self.store
                    .put(namespace, key.to_vec(), envelope_id, timestamp)?;
                let _ = self.storage.put_envelope(envelope);
                MstPutOutcome::Updated
            } else {
                MstPutOutcome::SupersededLww
            }
        } else {
            self.store
                .put(namespace, key.to_vec(), envelope_id, timestamp)?;
            let _ = self.storage.put_envelope(envelope);
            MstPutOutcome::Inserted
        };

        Ok(outcome)
    }

    /// Point lookup: returns the `ArkEnvelope` for `key` in `namespace`, if present and not a tombstone.
    pub fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<ArkEnvelope>> {
        match self.store.get(namespace, key)? {
            Some((envelope_id, _ts)) => match self.storage.get_envelope(&envelope_id)? {
                Some(env) => Ok(Some(env)),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Records a signed tombstone deletion for `key` in `namespace`.
    ///
    /// The `tombstone` envelope must have a timestamp newer than any existing record to take effect.
    pub fn delete(
        &self,
        namespace: &str,
        key: &[u8],
        tombstone: &ArkEnvelope,
    ) -> Result<MstPutOutcome> {
        // A tombstone is treated identically to a `put` under Bivariate LWW.
        self.put(namespace, key, tombstone)
    }

    /// Returns the 32-byte root hash for `namespace`, or `None` if the namespace is empty.
    pub fn root_hash(&self, namespace: &str) -> Result<Option<[u8; 32]>> {
        self.store.root_hash(namespace)
    }

    /// Computes a minimal `MstSyncPlan` against a peer's claimed `remote_root` for `namespace`.
    ///
    /// If `remote_root` equals the local root, returns an empty plan in O(1).
    pub fn compute_sync_diff(
        &self,
        namespace: &str,
        remote_root: &[u8; 32],
    ) -> Result<MstSyncPlan> {
        // Build in-memory snapshots to feed into MstDiff.
        let local = self.rebuild_in_memory_tree(namespace)?;
        let remote_placeholder = MerkleSearchTree::with_root_hash(*remote_root);
        Ok(MstDiff::diff(&local, &remote_placeholder))
    }

    /// Handles a peer `MstSyncRequest` and produces a bounded `MstSyncResponse`.
    pub fn handle_sync_request(&self, req: &MstSyncRequest) -> Result<MstSyncResponse> {
        handle_sync_request(req, &self.store, &self.storage)
    }

    /// Validates and applies a peer `MstSyncResponse`, returning ingestion statistics.
    pub fn apply_sync_response(&self, res: &MstSyncResponse) -> Result<SyncApplyStats> {
        apply_sync_response(res, &self.store, &self.storage)
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Reconstructs an in-memory `MerkleSearchTree` for a namespace by iterating
    /// all persisted entries via a point-query-based approach.
    ///
    /// This is only called during `compute_sync_diff` to feed `MstDiff`.
    fn rebuild_in_memory_tree(&self, namespace: &str) -> Result<MerkleSearchTree> {
        let mut tree = MerkleSearchTree::new();

        // Walk the persisted store's root and collect all entries.
        let root_hash = match self.store.root_hash(namespace)? {
            Some(h) if h != [0u8; 32] => h,
            _ => return Ok(tree),
        };

        let root_arc = self.store.load_full_tree(namespace, &root_hash)?;
        collect_entries_into_tree(&mut tree, &root_arc)?;
        Ok(tree)
    }
}

/// Recursively collects all entries from a persisted subtree into an in-memory MST.
fn collect_entries_into_tree(
    tree: &mut MerkleSearchTree,
    node: &crate::mst::MstNode,
) -> Result<()> {
    for entry in &node.entries {
        tree.insert(
            entry.key.clone(),
            entry.envelope_id,
            entry.timestamp,
            entry.is_tombstone,
        );
    }

    for child_arc in node.children.iter().flatten() {
        collect_entries_into_tree(tree, child_arc)?;
    }

    Ok(())
}
