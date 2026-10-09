//! Merkle Search Tree (MST) diff and delta sync plan computation.
//!
//! Conforms to GCP-09 / ADR-0009:
//! - Bound round-trip complexity to O(Delta log n)
//! - Identical subtree hashes pruned in O(1)
//! - Bivariate LWW conflict resolution: max(timestamp) || max(envelope_id)
//! - Minimal MstSyncPlan computation:
//!   - keys_to_send: local entries that are missing on remote or supersede remote entries
//!   - keys_to_fetch: remote entries that are missing locally or supersede local entries
//!   - divergent_nodes: subtree/node hashes that diverged for wire traversal

use crate::mst::{MerkleSearchTree, MstEntry, MstNode};
use std::sync::Arc;

/// Represents an item in the synchronization plan with its key, envelope identity, and metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstSyncItem {
    pub key: Vec<u8>,
    pub envelope_id: [u8; 32],
    pub timestamp: u64,
    pub is_tombstone: bool,
}

impl From<&MstEntry> for MstSyncItem {
    fn from(entry: &MstEntry) -> Self {
        Self {
            key: entry.key.clone(),
            envelope_id: entry.envelope_id,
            timestamp: entry.timestamp,
            is_tombstone: entry.is_tombstone,
        }
    }
}

/// Computed synchronization plan between a local MST and a remote MST.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MstSyncPlan {
    /// Entries present locally that are missing remotely or supersede remote entries under Bivariate LWW.
    pub keys_to_send: Vec<MstSyncItem>,
    /// Entries present remotely that are missing locally or supersede local entries under Bivariate LWW.
    pub keys_to_fetch: Vec<MstSyncItem>,
    /// List of divergent subtree / node hashes encountered during diff traversal.
    pub divergent_nodes: Vec<[u8; 32]>,
}

impl MstSyncPlan {
    /// Returns true if there are no differences between local and remote trees.
    pub fn is_empty(&self) -> bool {
        self.keys_to_send.is_empty()
            && self.keys_to_fetch.is_empty()
            && self.divergent_nodes.is_empty()
    }
}

/// Diff algorithm for Merkle Search Trees.
pub struct MstDiff;

impl MstDiff {
    /// Computes the delta sync plan between local and remote trees.
    ///
    /// If root hashes match, returns an empty plan immediately in O(1).
    /// Otherwise, recursively descends only through divergent subtrees.
    pub fn diff(local: &MerkleSearchTree, remote: &MerkleSearchTree) -> MstSyncPlan {
        let mut plan = MstSyncPlan::default();

        let local_root = local.root_node();
        let remote_root = remote.root_node();

        let local_hash = local.root_hash();
        let remote_hash = remote.root_hash();

        // O(1) early prune for identical trees (including both empty)
        if local_hash == remote_hash {
            return plan;
        }

        Self::diff_nodes(
            local_root.cloned(),
            remote_root.cloned(),
            local,
            remote,
            &mut plan,
        );

        // Deduplicate and sort keys to maintain deterministic ordering
        plan.keys_to_send.sort_by(|a, b| a.key.cmp(&b.key));
        plan.keys_to_send.dedup_by(|a, b| a.key == b.key);

        plan.keys_to_fetch.sort_by(|a, b| a.key.cmp(&b.key));
        plan.keys_to_fetch.dedup_by(|a, b| a.key == b.key);

        plan
    }

    /// Recursively diff two subtrees.
    pub fn diff_nodes(
        local_opt: Option<Arc<MstNode>>,
        remote_opt: Option<Arc<MstNode>>,
        local_tree: &MerkleSearchTree,
        remote_tree: &MerkleSearchTree,
        plan: &mut MstSyncPlan,
    ) {
        match (local_opt, remote_opt) {
            (None, None) => {}
            (Some(local), None) => {
                // Entire local subtree is missing in this branch on remote.
                // Reconcile each entry in this local subtree against remote_tree.
                Self::reconcile_subtree_against_tree(&local, remote_tree, true, plan);
            }
            (None, Some(remote)) => {
                // Entire remote subtree is missing in this branch locally.
                // Reconcile each entry in this remote subtree against local_tree.
                Self::reconcile_subtree_against_tree(&remote, local_tree, false, plan);
            }
            (Some(local), Some(remote)) => {
                let mut local_node = (*local).clone();
                let mut remote_node = (*remote).clone();

                let h_local = local_node.hash();
                let h_remote = remote_node.hash();

                // If subtree hashes are identical, prune immediately in O(1)!
                if h_local == h_remote {
                    return;
                }

                // Record divergent node hash for wire traversal
                plan.divergent_nodes.push(h_remote);

                if local.level > remote.level {
                    // Local is higher level.
                    // Subtrees of local partition remote by local's keys.
                    Self::diff_higher_lower(local, remote, local_tree, remote_tree, true, plan);
                } else if remote.level > local.level {
                    // Remote is higher level.
                    Self::diff_higher_lower(remote, local, local_tree, remote_tree, false, plan);
                } else {
                    // Same level: compare entries and children within this level
                    Self::diff_same_level(local, remote, local_tree, remote_tree, plan);
                }
            }
        }
    }

    /// Reconcile an entire un-matched subtree against the opposing full tree.
    fn reconcile_subtree_against_tree(
        node: &MstNode,
        opposing_tree: &MerkleSearchTree,
        node_is_local: bool,
        plan: &mut MstSyncPlan,
    ) {
        for (i, entry) in node.entries.iter().enumerate() {
            if let Some(Some(child)) = node.children.get(i) {
                Self::reconcile_subtree_against_tree(child, opposing_tree, node_is_local, plan);
            }

            // Check if opposing tree has this key
            if let Some(opposing_val) = opposing_tree.get(&entry.key) {
                let (local_ts, local_id, local_tomb, remote_ts, remote_id, remote_tomb) =
                    if node_is_local {
                        (
                            entry.timestamp,
                            entry.envelope_id,
                            entry.is_tombstone,
                            opposing_val.timestamp,
                            opposing_val.envelope_id,
                            opposing_val.is_tombstone,
                        )
                    } else {
                        (
                            opposing_val.timestamp,
                            opposing_val.envelope_id,
                            opposing_val.is_tombstone,
                            entry.timestamp,
                            entry.envelope_id,
                            entry.is_tombstone,
                        )
                    };

                match Self::compare_lww(local_ts, &local_id, remote_ts, &remote_id) {
                    std::cmp::Ordering::Greater => {
                        plan.keys_to_send.push(MstSyncItem {
                            key: entry.key.clone(),
                            envelope_id: local_id,
                            timestamp: local_ts,
                            is_tombstone: local_tomb,
                        });
                    }
                    std::cmp::Ordering::Less => {
                        plan.keys_to_fetch.push(MstSyncItem {
                            key: entry.key.clone(),
                            envelope_id: remote_id,
                            timestamp: remote_ts,
                            is_tombstone: remote_tomb,
                        });
                    }
                    std::cmp::Ordering::Equal => {
                        if local_tomb != remote_tomb {
                            if local_tomb {
                                plan.keys_to_send.push(MstSyncItem {
                                    key: entry.key.clone(),
                                    envelope_id: local_id,
                                    timestamp: local_ts,
                                    is_tombstone: local_tomb,
                                });
                            } else {
                                plan.keys_to_fetch.push(MstSyncItem {
                                    key: entry.key.clone(),
                                    envelope_id: remote_id,
                                    timestamp: remote_ts,
                                    is_tombstone: remote_tomb,
                                });
                            }
                        }
                    }
                }
            } else {
                // Key does not exist in opposing tree
                if node_is_local {
                    plan.keys_to_send.push(MstSyncItem::from(entry));
                } else {
                    plan.keys_to_fetch.push(MstSyncItem::from(entry));
                }
            }
        }

        if let Some(Some(last_child)) = node.children.last() {
            Self::reconcile_subtree_against_tree(last_child, opposing_tree, node_is_local, plan);
        }
    }

    /// Compare two entries under Bivariate LWW: max(timestamp) || max(envelope_id).
    fn compare_lww(
        local_ts: u64,
        local_id: &[u8; 32],
        remote_ts: u64,
        remote_id: &[u8; 32],
    ) -> std::cmp::Ordering {
        match local_ts.cmp(&remote_ts) {
            std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Less => std::cmp::Ordering::Less,
            std::cmp::Ordering::Equal => local_id.cmp(remote_id),
        }
    }

    /// Reconciles an entry present in both trees.
    fn reconcile_entry(local_entry: &MstEntry, remote_entry: &MstEntry, plan: &mut MstSyncPlan) {
        match Self::compare_lww(
            local_entry.timestamp,
            &local_entry.envelope_id,
            remote_entry.timestamp,
            &remote_entry.envelope_id,
        ) {
            std::cmp::Ordering::Greater => {
                plan.keys_to_send.push(MstSyncItem::from(local_entry));
            }
            std::cmp::Ordering::Less => {
                plan.keys_to_fetch.push(MstSyncItem::from(remote_entry));
            }
            std::cmp::Ordering::Equal => {
                if local_entry.is_tombstone != remote_entry.is_tombstone {
                    if local_entry.is_tombstone {
                        plan.keys_to_send.push(MstSyncItem::from(local_entry));
                    } else {
                        plan.keys_to_fetch.push(MstSyncItem::from(remote_entry));
                    }
                }
            }
        }
    }

    /// Reconciles a single entry from one tree against the opposing tree.
    fn reconcile_single_entry(
        entry: &MstEntry,
        opposing_tree: &MerkleSearchTree,
        entry_is_local: bool,
        plan: &mut MstSyncPlan,
    ) {
        if let Some(opposing_val) = opposing_tree.get(&entry.key) {
            let (local_ts, local_id, local_tomb, remote_ts, remote_id, remote_tomb) =
                if entry_is_local {
                    (
                        entry.timestamp,
                        entry.envelope_id,
                        entry.is_tombstone,
                        opposing_val.timestamp,
                        opposing_val.envelope_id,
                        opposing_val.is_tombstone,
                    )
                } else {
                    (
                        opposing_val.timestamp,
                        opposing_val.envelope_id,
                        opposing_val.is_tombstone,
                        entry.timestamp,
                        entry.envelope_id,
                        entry.is_tombstone,
                    )
                };

            match Self::compare_lww(local_ts, &local_id, remote_ts, &remote_id) {
                std::cmp::Ordering::Greater => {
                    plan.keys_to_send.push(MstSyncItem {
                        key: entry.key.clone(),
                        envelope_id: local_id,
                        timestamp: local_ts,
                        is_tombstone: local_tomb,
                    });
                }
                std::cmp::Ordering::Less => {
                    plan.keys_to_fetch.push(MstSyncItem {
                        key: entry.key.clone(),
                        envelope_id: remote_id,
                        timestamp: remote_ts,
                        is_tombstone: remote_tomb,
                    });
                }
                std::cmp::Ordering::Equal => {
                    if local_tomb != remote_tomb {
                        if local_tomb {
                            plan.keys_to_send.push(MstSyncItem {
                                key: entry.key.clone(),
                                envelope_id: local_id,
                                timestamp: local_ts,
                                is_tombstone: local_tomb,
                            });
                        } else {
                            plan.keys_to_fetch.push(MstSyncItem {
                                key: entry.key.clone(),
                                envelope_id: remote_id,
                                timestamp: remote_ts,
                                is_tombstone: remote_tomb,
                            });
                        }
                    }
                }
            }
        } else if entry_is_local {
            plan.keys_to_send.push(MstSyncItem::from(entry));
        } else {
            plan.keys_to_fetch.push(MstSyncItem::from(entry));
        }
    }

    /// Diff when one node is at a higher level than the other.
    fn diff_higher_lower(
        higher: Arc<MstNode>,
        mut lower: Arc<MstNode>,
        local_tree: &MerkleSearchTree,
        remote_tree: &MerkleSearchTree,
        higher_is_local: bool,
        plan: &mut MstSyncPlan,
    ) {
        for (i, higher_entry) in higher.entries.iter().enumerate() {
            let (left, right) = MerkleSearchTree::split_child(lower, &higher_entry.key);
            let higher_child = higher.children.get(i).and_then(|c| c.clone());

            if higher_is_local {
                Self::diff_nodes(higher_child, left, local_tree, remote_tree, plan);
                Self::reconcile_single_entry(higher_entry, remote_tree, true, plan);
            } else {
                Self::diff_nodes(left, higher_child, local_tree, remote_tree, plan);
                Self::reconcile_single_entry(higher_entry, local_tree, false, plan);
            }

            match right {
                Some(r) => lower = r,
                None => {
                    for j in (i + 1)..higher.entries.len() {
                        let remaining_entry = &higher.entries[j];
                        let remaining_child = higher.children.get(j).and_then(|c| c.clone());
                        if higher_is_local {
                            Self::diff_nodes(remaining_child, None, local_tree, remote_tree, plan);
                            Self::reconcile_single_entry(remaining_entry, remote_tree, true, plan);
                        } else {
                            Self::diff_nodes(None, remaining_child, local_tree, remote_tree, plan);
                            Self::reconcile_single_entry(remaining_entry, local_tree, false, plan);
                        }
                    }
                    let last_child = higher.children.last().and_then(|c| c.clone());
                    if higher_is_local {
                        Self::diff_nodes(last_child, None, local_tree, remote_tree, plan);
                    } else {
                        Self::diff_nodes(None, last_child, local_tree, remote_tree, plan);
                    }
                    return;
                }
            }
        }

        let last_child = higher.children.last().and_then(|c| c.clone());
        if higher_is_local {
            Self::diff_nodes(last_child, Some(lower), local_tree, remote_tree, plan);
        } else {
            Self::diff_nodes(Some(lower), last_child, local_tree, remote_tree, plan);
        }
    }

    /// Diff two nodes at the exact same level.
    fn diff_same_level(
        local: Arc<MstNode>,
        remote: Arc<MstNode>,
        local_tree: &MerkleSearchTree,
        remote_tree: &MerkleSearchTree,
        plan: &mut MstSyncPlan,
    ) {
        let mut l_idx = 0;
        let mut r_idx = 0;

        while l_idx < local.entries.len() && r_idx < remote.entries.len() {
            let l_entry = &local.entries[l_idx];
            let r_entry = &remote.entries[r_idx];

            match l_entry.key.cmp(&r_entry.key) {
                std::cmp::Ordering::Equal => {
                    let l_child = local.children[l_idx].clone();
                    let r_child = remote.children[r_idx].clone();
                    Self::diff_nodes(l_child, r_child, local_tree, remote_tree, plan);

                    Self::reconcile_entry(l_entry, r_entry, plan);

                    l_idx += 1;
                    r_idx += 1;
                }
                std::cmp::Ordering::Less => {
                    let remote_child = remote.children[r_idx].clone();
                    let (r_left, r_right) = match remote_child {
                        Some(rc) => MerkleSearchTree::split_child(rc, &l_entry.key),
                        None => (None, None),
                    };

                    let l_child = local.children[l_idx].clone();
                    Self::diff_nodes(l_child, r_left, local_tree, remote_tree, plan);

                    Self::reconcile_single_entry(l_entry, remote_tree, true, plan);

                    let mut mut_remote = (*remote).clone();
                    mut_remote.children[r_idx] = r_right;
                    return Self::diff_same_level(
                        Arc::new(MstNode {
                            level: local.level,
                            entries: local.entries[l_idx + 1..].to_vec(),
                            children: local.children[l_idx + 1..].to_vec(),
                            cached_hash: None,
                        }),
                        Arc::new(mut_remote),
                        local_tree,
                        remote_tree,
                        plan,
                    );
                }
                std::cmp::Ordering::Greater => {
                    let local_child = local.children[l_idx].clone();
                    let (l_left, l_right) = match local_child {
                        Some(lc) => MerkleSearchTree::split_child(lc, &r_entry.key),
                        None => (None, None),
                    };

                    let r_child = remote.children[r_idx].clone();
                    Self::diff_nodes(l_left, r_child, local_tree, remote_tree, plan);

                    Self::reconcile_single_entry(r_entry, local_tree, false, plan);

                    let mut mut_local = (*local).clone();
                    mut_local.children[l_idx] = l_right;
                    return Self::diff_same_level(
                        Arc::new(mut_local),
                        Arc::new(MstNode {
                            level: remote.level,
                            entries: remote.entries[r_idx + 1..].to_vec(),
                            children: remote.children[r_idx + 1..].to_vec(),
                            cached_hash: None,
                        }),
                        local_tree,
                        remote_tree,
                        plan,
                    );
                }
            }
        }

        if l_idx < local.entries.len() {
            let l_entry = &local.entries[l_idx];
            let r_child = remote.children.get(r_idx).and_then(|c| c.clone());

            let (r_left, r_right) = match r_child {
                Some(rc) => MerkleSearchTree::split_child(rc, &l_entry.key),
                None => (None, None),
            };

            let l_child = local.children[l_idx].clone();
            Self::diff_nodes(l_child, r_left, local_tree, remote_tree, plan);
            Self::reconcile_single_entry(l_entry, remote_tree, true, plan);

            let mut mut_remote = (*remote).clone();
            if r_idx < mut_remote.children.len() {
                mut_remote.children[r_idx] = r_right;
            }
            return Self::diff_same_level(
                Arc::new(MstNode {
                    level: local.level,
                    entries: local.entries[l_idx + 1..].to_vec(),
                    children: local.children[l_idx + 1..].to_vec(),
                    cached_hash: None,
                }),
                Arc::new(mut_remote),
                local_tree,
                remote_tree,
                plan,
            );
        }

        if r_idx < remote.entries.len() {
            let r_entry = &remote.entries[r_idx];
            let l_child = local.children.get(l_idx).and_then(|c| c.clone());

            let (l_left, l_right) = match l_child {
                Some(lc) => MerkleSearchTree::split_child(lc, &r_entry.key),
                None => (None, None),
            };

            let r_child = remote.children[r_idx].clone();
            Self::diff_nodes(l_left, r_child, local_tree, remote_tree, plan);
            Self::reconcile_single_entry(r_entry, local_tree, false, plan);

            let mut mut_local = (*local).clone();
            if l_idx < mut_local.children.len() {
                mut_local.children[l_idx] = l_right;
            }
            return Self::diff_same_level(
                Arc::new(mut_local),
                Arc::new(MstNode {
                    level: remote.level,
                    entries: remote.entries[r_idx + 1..].to_vec(),
                    children: remote.children[r_idx + 1..].to_vec(),
                    cached_hash: None,
                }),
                local_tree,
                remote_tree,
                plan,
            );
        }

        let l_last = local.children.get(l_idx).and_then(|c| c.clone());
        let r_last = remote.children.get(r_idx).and_then(|c| c.clone());
        Self::diff_nodes(l_last, r_last, local_tree, remote_tree, plan);
    }
}
