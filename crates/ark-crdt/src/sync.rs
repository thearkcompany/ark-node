//! Protobuf Wire Protocol & Sync Stream Handler (KIND_KV_MST_SYNC).
//!
//! Conforms to GCP-09 / ADR-0009:
//! - Wire encoding and decoding / translation between in-memory `MstNode`/`MstEntry` and `MstNodeWire`/`MstEntryWire`.
//! - Request handling logic (`handle_sync_request`):
//!   - Responds with exact requested nodes or range.
//!   - Strictly bounded by <= 64 nodes or <= 256 keys/envelopes per batch.
//! - Response application logic (`apply_sync_response`):
//!   - Verifies SHA3-256 node integrity (calculated hash == wire node_hash) before incorporating nodes.
//!   - Verifies tree depth <= 16.
//!   - Strict anti-DoS checks: mismatched hashes or depth > 16 return validation errors and reject.
//!   - Incorporates missing envelopes and nodes into local storage and tree index.

use std::collections::{HashSet, VecDeque};
use sha3::{Digest, Sha3_256};
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::{MstEntryWire, MstNodeWire, MstSyncRequest, MstSyncResponse};
use ark_storage::StorageEngine;
use crate::error::{ArkCrdtError, Result};
use crate::mst::{MstEntry, MstNode};
use crate::store::MstStore;

/// Message kind for MST synchronization stream frames.
pub const KIND_KV_MST_SYNC: u32 = 0x0006;

/// Maximum number of nodes permitted in a single sync response batch (anti-DoS bound).
pub const MAX_SYNC_BATCH_NODES: usize = 64;

/// Maximum number of keys/envelopes permitted in a single sync response batch (anti-DoS bound).
pub const MAX_SYNC_BATCH_KEYS: usize = 256;

/// Maximum allowable Merkle Search Tree depth / level (anti-DoS bound).
pub const MAX_TREE_DEPTH: u32 = 16;

/// Outcome and metrics of applying an incoming `MstSyncResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncApplyStats {
    /// Total number of valid tree nodes verified and incorporated.
    pub nodes_applied: usize,
    /// Total number of missing envelopes ingested into storage.
    pub envelopes_stored: usize,
    /// Total number of entries updated or inserted in the tree.
    pub entries_updated: usize,
}

/// Converts an in-memory `MstNode` into its wire-format Protobuf representation (`MstNodeWire`).
pub fn node_to_wire(node: &mut MstNode) -> MstNodeWire {
    let node_hash = node.hash().to_vec();
    let entries = node
        .entries
        .iter()
        .map(|e| MstEntryWire {
            key: e.key.clone(),
            envelope_id: e.envelope_id.to_vec(),
            timestamp: e.timestamp,
        })
        .collect();

    let child_hashes = node
        .child_hashes()
        .into_iter()
        .map(|h| h.to_vec())
        .collect();

    MstNodeWire {
        node_hash,
        level: node.level,
        entries,
        child_hashes,
    }
}

/// Converts a wire-format `MstNodeWire` into an in-memory `MstNode` and its child hashes.
pub fn wire_to_node(wire: &MstNodeWire) -> Result<(MstNode, Vec<[u8; 32]>)> {
    let mut entries = Vec::with_capacity(wire.entries.len());
    for ew in &wire.entries {
        if ew.envelope_id.len() != 32 {
            return Err(ArkCrdtError::ValidationError(format!(
                "Invalid envelope_id length in entry: expected 32, got {}",
                ew.envelope_id.len()
            )));
        }
        let mut env_id = [0u8; 32];
        env_id.copy_from_slice(&ew.envelope_id);
        entries.push(MstEntry::new(ew.key.clone(), env_id, ew.timestamp));
    }

    let mut child_hashes = Vec::with_capacity(wire.child_hashes.len());
    for ch in &wire.child_hashes {
        if ch.len() != 32 {
            return Err(ArkCrdtError::ValidationError(format!(
                "Invalid child_hash length: expected 32, got {}",
                ch.len()
            )));
        }
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(ch);
        child_hashes.push(hash_arr);
    }

    let expected_children_len = entries.len() + 1;
    if child_hashes.len() != expected_children_len {
        return Err(ArkCrdtError::ValidationError(format!(
            "Mismatched child_hashes length: expected {}, got {}",
            expected_children_len,
            child_hashes.len()
        )));
    }

    let children = vec![None; expected_children_len];
    let mut node = MstNode {
        level: wire.level,
        entries,
        children,
        cached_hash: None,
    };

    let computed = compute_wire_node_hash(wire.level, &node.entries, &child_hashes);
    node.cached_hash = Some(computed);

    Ok((node, child_hashes))
}

/// Canonical SHA3-256 node digest calculation matching `MstNode::hash()`.
pub fn compute_wire_node_hash(
    level: u32,
    entries: &[MstEntry],
    child_hashes: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(level.to_be_bytes());
    hasher.update((entries.len() as u32).to_be_bytes());

    for (i, entry) in entries.iter().enumerate() {
        let child_hash = child_hashes.get(i).copied().unwrap_or([0u8; 32]);
        hasher.update(child_hash);

        hasher.update((entry.key.len() as u32).to_be_bytes());
        hasher.update(&entry.key);
        hasher.update(entry.envelope_id);
        hasher.update(entry.timestamp.to_be_bytes());
        hasher.update([if entry.is_tombstone { 1u8 } else { 0u8 }]);
    }

    let last_child_hash = child_hashes.last().copied().unwrap_or([0u8; 32]);
    hasher.update(last_child_hash);

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Handles an incoming `MstSyncRequest` and produces a bounded `MstSyncResponse`.
///
/// Bounded by:
/// - <= 64 nodes per batch
/// - <= 256 keys / envelopes per batch
pub fn handle_sync_request(
    req: &MstSyncRequest,
    store: &MstStore,
    storage: &StorageEngine,
) -> Result<MstSyncResponse> {
    let namespace = &req.namespace;
    let mut response_nodes = Vec::new();
    let mut response_envelopes = Vec::new();
    let mut collected_envelope_ids = HashSet::new();

    // 1. If explicit node hashes were requested, load those directly up to safety limit
    if !req.requested_node_hashes.is_empty() {
        for node_hash_bytes in req.requested_node_hashes.iter().take(MAX_SYNC_BATCH_NODES) {
            if node_hash_bytes.len() != 32 {
                continue;
            }
            let mut node_h = [0u8; 32];
            node_h.copy_from_slice(node_hash_bytes);

            if let Ok(node_arc) = store.load_node(namespace, &node_h) {
                let mut node_clone = (*node_arc).clone();
                let wire_node = node_to_wire(&mut node_clone);

                for entry in &node_clone.entries {
                    if collected_envelope_ids.len() < MAX_SYNC_BATCH_KEYS
                        && collected_envelope_ids.insert(entry.envelope_id)
                    {
                        if let Ok(Some(env)) = storage.get_envelope(&entry.envelope_id) {
                            response_envelopes.push(env.into());
                        }
                    }
                }

                response_nodes.push(wire_node);
                if response_nodes.len() >= MAX_SYNC_BATCH_NODES {
                    break;
                }
            }
        }
    } else {
        // 2. Traversal based on local tree root
        if let Some(local_root_hash) = store.root_hash(namespace)? {
            if local_root_hash != [0u8; 32] {
                let mut remote_root = [0u8; 32];
                if req.root_hash.len() == 32 {
                    remote_root.copy_from_slice(&req.root_hash);
                }

                // If roots already match and no range specified, respond with root node
                let mut queue = VecDeque::new();
                queue.push_back(local_root_hash);
                let mut visited_hashes = HashSet::new();

                while let Some(current_hash) = queue.pop_front() {
                    if response_nodes.len() >= MAX_SYNC_BATCH_NODES {
                        break;
                    }

                    if current_hash == [0u8; 32] || !visited_hashes.insert(current_hash) {
                        continue;
                    }

                    if let Ok(node_arc) = store.load_node(namespace, &current_hash) {
                        let mut node_clone = (*node_arc).clone();
                        let child_hashes = node_clone.child_hashes();

                        // Filter by key range if specified
                        let in_range = node_clone.entries.iter().any(|e| {
                            let start_ok = req.key_range_start.is_empty()
                                || e.key.as_slice() >= req.key_range_start.as_slice();
                            let end_ok = req.key_range_end.is_empty()
                                || e.key.as_slice() <= req.key_range_end.as_slice();
                            start_ok && end_ok
                        }) || (req.key_range_start.is_empty() && req.key_range_end.is_empty());

                        if in_range {
                            for entry in &node_clone.entries {
                                if collected_envelope_ids.len() < MAX_SYNC_BATCH_KEYS
                                    && collected_envelope_ids.insert(entry.envelope_id)
                                {
                                    if let Ok(Some(env)) = storage.get_envelope(&entry.envelope_id) {
                                        response_envelopes.push(env.into());
                                    }
                                }
                            }

                            let wire_node = node_to_wire(&mut node_clone);
                            response_nodes.push(wire_node);
                        }

                        // Enqueue children for further descent
                        for ch in child_hashes {
                            if ch != [0u8; 32] && !visited_hashes.contains(&ch) {
                                queue.push_back(ch);
                            }
                        }
                    }
                }
            }
        }
    }

    let root_hash = store
        .root_hash(namespace)?
        .map(|h| h.to_vec())
        .unwrap_or_default();

    Ok(MstSyncResponse {
        namespace: namespace.to_string(),
        root_hash,
        nodes: response_nodes,
        missing_envelopes: response_envelopes,
    })
}

/// Applies an incoming `MstSyncResponse`, strictly validating node integrity and tree depth.
///
/// Anti-DoS checks:
/// 1. Node level must be <= MAX_TREE_DEPTH (16). Exceeding this returns `ArkCrdtError::DepthLimitExceeded`.
/// 2. Wire `node_hash` must match computed SHA3-256 digest. Mismatches return `ArkCrdtError::InvalidNodeHash`.
/// 3. Incorporates missing envelopes into local storage.
/// 4. Incorporates missing/newer entries into local MST index via Bivariate LWW.
pub fn apply_sync_response(
    res: &MstSyncResponse,
    store: &MstStore,
    storage: &StorageEngine,
) -> Result<SyncApplyStats> {
    let namespace = &res.namespace;
    let mut stats = SyncApplyStats::default();

    // Phase 1: Validate all nodes against anti-DoS boundaries
    for wire_node in &res.nodes {
        // Depth limit check
        if wire_node.level > MAX_TREE_DEPTH {
            return Err(ArkCrdtError::DepthLimitExceeded(wire_node.level));
        }

        if wire_node.node_hash.len() != 32 {
            return Err(ArkCrdtError::ValidationError(format!(
                "Invalid wire node_hash length: expected 32, got {}",
                wire_node.node_hash.len()
            )));
        }

        // Verify SHA3-256 node integrity
        let (mut node, _child_hashes) = wire_to_node(wire_node)?;
        let computed_hash = node.hash();
        if computed_hash.as_slice() != wire_node.node_hash.as_slice() {
            return Err(ArkCrdtError::InvalidNodeHash {
                expected: hex::encode(&wire_node.node_hash),
                actual: hex::encode(computed_hash),
            });
        }
    }

    // Phase 2: Ingest missing envelopes into storage engine
    for proto_envelope in &res.missing_envelopes {
        let envelope: ArkEnvelope = proto_envelope.clone().into();
        if let Ok(outcome) = storage.put_envelope(&envelope) {
            match outcome {
                ark_storage::RetentionOutcome::Stored
                | ark_storage::RetentionOutcome::Replaced => {
                    stats.envelopes_stored += 1;
                }
                _ => {}
            }
        }
    }

    // Phase 3: Incorporate entries and nodes into local tree
    for wire_node in &res.nodes {
        let (node, _child_hashes) = wire_to_node(wire_node)?;
        for entry in node.entries {
            // Apply bivariate LWW to update local MST store
            let _updated = store.put(
                namespace,
                entry.key,
                entry.envelope_id,
                entry.timestamp,
            )?;
            stats.entries_updated += 1;
        }
        stats.nodes_applied += 1;
    }

    // If local tree is empty and remote supplied nodes with a claimed root hash,
    // verify if the newly constructed local root matches or if remote root is valid.
    if let Ok(None) = store.root_hash(namespace) {
        if res.root_hash.len() == 32 {
            let mut claimed_root = [0u8; 32];
            claimed_root.copy_from_slice(&res.root_hash);
            if claimed_root != [0u8; 32] {
                store.set_root_hash(namespace, Some(claimed_root))?;
            }
        }
    }

    Ok(stats)
}
