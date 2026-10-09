//! Merkle Search Tree (MST) in-memory core engine.
//!
//! Conforms to GCP-09 / ADR-0009:
//! - Deterministic key level derivation: floor(ctz(SHA3-256(key)) / 4)
//! - Fanout b = 16 (4-bit zero nibbles)
//! - Node representation: ordered entries (key, envelope_id, timestamp, is_tombstone) interleaved with child hashes
//! - Canonical node hash calculation using SHA3-256
//! - Order-invariant deterministic root hash
//! - Bivariate LWW conflict resolution: max(timestamp) || max(id)
//! - Tombstone envelope markers and deleted point queries

use sha3::{Digest, Sha3_256};
use std::sync::Arc;

/// Compute the deterministic tree level for a given key.
/// Level = floor(ctz(SHA3-256(key)) / 4).
pub fn compute_key_level(key: &[u8]) -> u32 {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let hash = hasher.finalize();

    let mut trailing_zeros = 0u32;
    for &byte in hash.as_slice() {
        let tz = byte.trailing_zeros();
        trailing_zeros += tz;
        if tz < 8 {
            break;
        }
    }
    trailing_zeros / 4
}

/// Outcome of attempting to insert or update an entry in the MST under Bivariate LWW.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MstPutOutcome {
    /// Entry was inserted as a completely new key.
    Inserted,
    /// Entry superseded an existing entry via Bivariate LWW: newer timestamp or higher envelope ID tie-breaker.
    Updated,
    /// Entry was rejected because an existing entry has a newer timestamp or higher envelope ID tie-breaker.
    /// Tree root hash and entries remain unchanged.
    SupersededLww,
}

/// Point query result returned by MST `get`, containing envelope identity, timestamp, and tombstone state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstValue {
    pub envelope_id: [u8; 32],
    pub timestamp: u64,
    pub is_tombstone: bool,
}

impl MstValue {
    /// Returns true if this entry represents a deletion tombstone.
    pub fn is_deleted(&self) -> bool {
        self.is_tombstone
    }
}

/// An entry stored within an MST node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstEntry {
    pub key: Vec<u8>,
    pub envelope_id: [u8; 32],
    pub timestamp: u64,
    pub is_tombstone: bool,
}

impl MstEntry {
    pub fn new(key: Vec<u8>, envelope_id: [u8; 32], timestamp: u64) -> Self {
        Self {
            key,
            envelope_id,
            timestamp,
            is_tombstone: false,
        }
    }

    pub fn with_tombstone(
        key: Vec<u8>,
        envelope_id: [u8; 32],
        timestamp: u64,
        is_tombstone: bool,
    ) -> Self {
        Self {
            key,
            envelope_id,
            timestamp,
            is_tombstone,
        }
    }
}

/// A node in the Merkle Search Tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstNode {
    pub level: u32,
    pub entries: Vec<MstEntry>,
    pub children: Vec<Option<Arc<MstNode>>>,
    pub cached_hash: Option<[u8; 32]>,
}

impl MstNode {
    /// Creates a new empty node at the specified level.
    pub fn new(level: u32) -> Self {
        Self {
            level,
            entries: Vec::new(),
            children: vec![None], // Initially one child slot (for keys < entries[0])
            cached_hash: None,
        }
    }

    /// Computes or retrieves the SHA3-256 node digest.
    pub fn hash(&mut self) -> [u8; 32] {
        if let Some(h) = self.cached_hash {
            return h;
        }

        let mut hasher = Sha3_256::new();
        hasher.update(self.level.to_be_bytes());
        hasher.update((self.entries.len() as u32).to_be_bytes());

        for (i, entry) in self.entries.iter().enumerate() {
            // Child hash before this entry
            let child_hash = match &self.children[i] {
                Some(child) => child.cached_hash.unwrap_or([0u8; 32]),
                None => [0u8; 32],
            };
            hasher.update(child_hash);

            // Entry data
            hasher.update((entry.key.len() as u32).to_be_bytes());
            hasher.update(&entry.key);
            hasher.update(entry.envelope_id);
            hasher.update(entry.timestamp.to_be_bytes());
            hasher.update([if entry.is_tombstone { 1u8 } else { 0u8 }]);
        }

        // Child hash after the last entry
        let last_child_hash = match self.children.last() {
            Some(Some(child)) => child.cached_hash.unwrap_or([0u8; 32]),
            _ => [0u8; 32],
        };
        hasher.update(last_child_hash);

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        self.cached_hash = Some(out);
        out
    }

    /// Returns the slice/vector of 32-byte hashes for each child slot in this node.
    pub fn child_hashes(&self) -> Vec<[u8; 32]> {
        self.children
            .iter()
            .map(|c| match c {
                Some(child) => child.cached_hash.unwrap_or([0u8; 32]),
                None => [0u8; 32],
            })
            .collect()
    }

    /// Canonical binary serialization of an MstNode.
    /// Format:
    /// [level: 4B BE]
    /// [entries_len: 4B BE]
    /// For each entry i:
    ///   [child_hash_before: 32B]
    ///   [key_len: 4B BE]
    ///   [key: key_len bytes]
    ///   [envelope_id: 32B]
    ///   [timestamp: 8B BE]
    /// [last_child_hash: 32B]
    pub fn serialize(&mut self) -> Vec<u8> {
        let _ = self.hash(); // Ensure hashes are computed
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.level.to_be_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());

        for (i, entry) in self.entries.iter().enumerate() {
            let child_hash = match &self.children[i] {
                Some(child) => child.cached_hash.unwrap_or([0u8; 32]),
                None => [0u8; 32],
            };
            bytes.extend_from_slice(&child_hash);
            bytes.extend_from_slice(&(entry.key.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&entry.key);
            bytes.extend_from_slice(&entry.envelope_id);
            bytes.extend_from_slice(&entry.timestamp.to_be_bytes());
            bytes.push(if entry.is_tombstone { 1u8 } else { 0u8 });
        }

        let last_child_hash = match self.children.last() {
            Some(Some(child)) => child.cached_hash.unwrap_or([0u8; 32]),
            _ => [0u8; 32],
        };
        bytes.extend_from_slice(&last_child_hash);
        bytes
    }

    /// Deserializes binary data into an MstNode skeleton with child slots set to None,
    /// returning the node and its child hashes.
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, Vec<[u8; 32]>), crate::error::ArkCrdtError> {
        if bytes.len() < 8 {
            return Err(crate::error::ArkCrdtError::Serialization(
                "Node serialization too short (missing level and entries_len)".into(),
            ));
        }

        let level = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let entries_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;

        let mut offset = 8;
        let mut entries = Vec::with_capacity(entries_len);
        let mut child_hashes = Vec::with_capacity(entries_len + 1);

        for _ in 0..entries_len {
            if offset + 36 > bytes.len() {
                return Err(crate::error::ArkCrdtError::Serialization(
                    "Unexpected EOF reading child_hash and key_len".into(),
                ));
            }
            let mut child_h = [0u8; 32];
            child_h.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            child_hashes.push(child_h);

            let key_len =
                u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + key_len + 32 + 8 + 1 > bytes.len() {
                return Err(crate::error::ArkCrdtError::Serialization(
                    "Unexpected EOF reading entry content".into(),
                ));
            }

            let key = bytes[offset..offset + key_len].to_vec();
            offset += key_len;

            let mut env_id = [0u8; 32];
            env_id.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;

            let timestamp = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;

            let is_tombstone = bytes[offset] != 0;
            offset += 1;

            entries.push(MstEntry::with_tombstone(
                key,
                env_id,
                timestamp,
                is_tombstone,
            ));
        }

        if offset + 32 > bytes.len() {
            return Err(crate::error::ArkCrdtError::Serialization(
                "Unexpected EOF reading last_child_hash".into(),
            ));
        }
        let mut last_child_h = [0u8; 32];
        last_child_h.copy_from_slice(&bytes[offset..offset + 32]);
        child_hashes.push(last_child_h);

        let children = vec![None; entries_len + 1];

        // Compute the expected hash directly from the serialized bytes
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut computed_hash = [0u8; 32];
        computed_hash.copy_from_slice(&digest);

        let node = MstNode {
            level,
            entries,
            children,
            cached_hash: Some(computed_hash),
        };

        Ok((node, child_hashes))
    }
}

/// Merkle Search Tree data structure.
#[derive(Clone, Debug, Default)]
pub struct MerkleSearchTree {
    root: Option<Arc<MstNode>>,
    len: usize,
}

impl MerkleSearchTree {
    pub fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Creates a placeholder tree with a known root hash but no in-memory nodes.
    /// Used for diff computation against a peer's remote root.
    pub fn with_root_hash(hash: [u8; 32]) -> Self {
        if hash == [0u8; 32] {
            return Self::new();
        }
        let mut node = MstNode::new(0);
        node.cached_hash = Some(hash);
        Self {
            root: Some(Arc::new(node)),
            len: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            Some(root) => root.cached_hash.unwrap_or([0u8; 32]),
            None => [0u8; 32],
        }
    }

    /// Returns the maximum level (height) of the tree, or 0 if empty.
    pub fn height(&self) -> u32 {
        self.root.as_ref().map(|r| r.level + 1).unwrap_or(0)
    }

    /// Returns a reference to the root node if present.
    pub fn root_node(&self) -> Option<&Arc<MstNode>> {
        self.root.as_ref()
    }

    /// Computes a minimal sync plan between this tree and a remote tree.
    pub fn diff(&self, remote: &MerkleSearchTree) -> crate::diff::MstSyncPlan {
        crate::diff::MstDiff::diff(self, remote)
    }

    /// Point query for a key. Returns `Some(MstValue)` if an entry (live or tombstone) is present.
    pub fn get(&self, key: &[u8]) -> Option<MstValue> {
        let mut curr = self.root.as_ref()?;
        loop {
            match curr.entries.binary_search_by(|e| e.key.as_slice().cmp(key)) {
                Ok(idx) => {
                    let entry = &curr.entries[idx];
                    return Some(MstValue {
                        envelope_id: entry.envelope_id,
                        timestamp: entry.timestamp,
                        is_tombstone: entry.is_tombstone,
                    });
                }
                Err(idx) => {
                    curr = curr.children[idx].as_ref()?;
                }
            }
        }
    }

    /// Inserts an entry into the Merkle Search Tree using Bivariate LWW resolution:
    /// `max(timestamp) || max(envelope_id)`.
    ///
    /// - If the key does not exist, it is inserted and `MstPutOutcome::Inserted` is returned.
    /// - If the key exists:
    ///   - If `(new_ts > old_ts) || (new_ts == old_ts && new_id > old_id)`, the entry is updated
    ///     in-place and `MstPutOutcome::Updated` is returned.
    ///   - Otherwise, the write is obsolete; tree is unaltered and `MstPutOutcome::SupersededLww` is returned.
    pub fn insert(
        &mut self,
        key: Vec<u8>,
        envelope_id: [u8; 32],
        timestamp: u64,
        is_tombstone: bool,
    ) -> MstPutOutcome {
        // First check existing entry to apply Bivariate LWW
        if let Some(existing) = self.get(&key) {
            let wins = (timestamp > existing.timestamp)
                || (timestamp == existing.timestamp && envelope_id > existing.envelope_id);
            if !wins {
                return MstPutOutcome::SupersededLww;
            }
        }

        let key_level = compute_key_level(&key);
        let entry = MstEntry::with_tombstone(key, envelope_id, timestamp, is_tombstone);

        let mut replaced = None;
        let new_root = Self::insert_node(self.root.take(), entry, key_level, &mut replaced);
        self.root = Some(new_root);

        if replaced.is_none() {
            self.len += 1;
            MstPutOutcome::Inserted
        } else {
            MstPutOutcome::Updated
        }
    }

    /// Removes a key completely from the tree structure (e.g. for hard compaction/eviction).
    /// For soft deletions that replicate across nodes, use `insert(..., is_tombstone: true)` instead.
    pub fn delete(&mut self, key: &[u8]) -> Option<([u8; 32], u64)> {
        let root = self.root.take()?;
        let mut removed = None;
        let new_root = Self::delete_node(root.clone(), key, &mut removed);
        if removed.is_some() {
            self.root = new_root;
            self.len -= 1;
        } else {
            self.root = Some(root);
        }
        removed
    }

    fn delete_node(
        node_arc: Arc<MstNode>,
        key: &[u8],
        removed: &mut Option<([u8; 32], u64)>,
    ) -> Option<Arc<MstNode>> {
        match node_arc
            .entries
            .binary_search_by(|e| e.key.as_slice().cmp(key))
        {
            Ok(idx) => {
                let mut node = (*node_arc).clone();
                node.cached_hash = None;

                let old = (node.entries[idx].envelope_id, node.entries[idx].timestamp);
                *removed = Some(old);

                let left_child = node.children[idx].take();
                let right_child = node.children.remove(idx + 1);
                let merged_child = Self::merge_children(left_child, right_child);

                node.entries.remove(idx);
                node.children[idx] = merged_child;

                Self::clean_node(node.level, node.entries, node.children)
            }
            Err(idx) => {
                if let Some(child) = &node_arc.children[idx] {
                    let updated_child = Self::delete_node(child.clone(), key, removed);
                    if removed.is_some() {
                        let mut node = (*node_arc).clone();
                        node.cached_hash = None;
                        node.children[idx] = updated_child;
                        Self::clean_node(node.level, node.entries, node.children)
                    } else {
                        Some(node_arc)
                    }
                } else {
                    Some(node_arc)
                }
            }
        }
    }

    /// Merge two adjacent subtrees: left containing keys < K, right containing keys > K.
    fn merge_children(
        left_opt: Option<Arc<MstNode>>,
        right_opt: Option<Arc<MstNode>>,
    ) -> Option<Arc<MstNode>> {
        match (left_opt, right_opt) {
            (None, None) => None,
            (Some(l), None) => Some(l),
            (None, Some(r)) => Some(r),
            (Some(left_arc), Some(right_arc)) => {
                let mut left = (*left_arc).clone();
                let mut right = (*right_arc).clone();

                if left.level > right.level {
                    let last_idx = left.children.len() - 1;
                    let last_child = left.children[last_idx].take();
                    left.children[last_idx] =
                        Self::merge_children(last_child, Some(Arc::new(right)));
                    Self::clean_node(left.level, left.entries, left.children)
                } else if left.level < right.level {
                    let first_child = right.children[0].take();
                    right.children[0] = Self::merge_children(Some(Arc::new(left)), first_child);
                    Self::clean_node(right.level, right.entries, right.children)
                } else {
                    let mid_left = left.children.pop().unwrap_or(None);
                    let mid_right = right.children.remove(0);
                    let merged_mid = Self::merge_children(mid_left, mid_right);

                    let mut combined_entries = left.entries;
                    combined_entries.extend(right.entries);

                    let mut combined_children = left.children;
                    combined_children.push(merged_mid);
                    combined_children.extend(right.children);

                    Self::clean_node(left.level, combined_entries, combined_children)
                }
            }
        }
    }

    fn insert_node(
        node_opt: Option<Arc<MstNode>>,
        entry: MstEntry,
        entry_level: u32,
        replaced: &mut Option<([u8; 32], u64)>,
    ) -> Arc<MstNode> {
        match node_opt {
            None => {
                let mut node = MstNode::new(entry_level);
                node.entries.push(entry);
                node.children.push(None); // [None, None]
                node.hash();
                Arc::new(node)
            }
            Some(node_arc) => {
                let mut node = (*node_arc).clone();
                node.cached_hash = None; // invalidate hash

                if entry_level == node.level {
                    match node
                        .entries
                        .binary_search_by(|e| e.key.as_slice().cmp(&entry.key))
                    {
                        Ok(idx) => {
                            let old = (node.entries[idx].envelope_id, node.entries[idx].timestamp);
                            *replaced = Some(old);
                            node.entries[idx] = entry;
                        }
                        Err(idx) => {
                            let (left_child, right_child) =
                                if let Some(child) = node.children[idx].take() {
                                    Self::split_child(child, &entry.key)
                                } else {
                                    (None, None)
                                };

                            node.entries.insert(idx, entry);
                            node.children[idx] = left_child;
                            node.children.insert(idx + 1, right_child);
                        }
                    }
                    node.hash();
                    Arc::new(node)
                } else if entry_level < node.level {
                    match node
                        .entries
                        .binary_search_by(|e| e.key.as_slice().cmp(&entry.key))
                    {
                        Ok(idx) => {
                            let old = (node.entries[idx].envelope_id, node.entries[idx].timestamp);
                            *replaced = Some(old);
                            node.entries[idx] = entry;
                            node.hash();
                            Arc::new(node)
                        }
                        Err(idx) => {
                            let child = node.children[idx].take();
                            let new_child = Self::insert_node(child, entry, entry_level, replaced);
                            node.children[idx] = Some(new_child);
                            node.hash();
                            Arc::new(node)
                        }
                    }
                } else {
                    let (left_child, right_child) = Self::split_child(Arc::new(node), &entry.key);
                    let mut parent = MstNode::new(entry_level);
                    parent.entries.push(entry);
                    parent.children = vec![left_child, right_child];
                    parent.hash();
                    Arc::new(parent)
                }
            }
        }
    }

    /// Split a subtree `node` into two subtrees:
    /// - left subtree containing all keys < `split_key`
    /// - right subtree containing all keys > `split_key`
    pub(crate) fn split_child(
        node_arc: Arc<MstNode>,
        split_key: &[u8],
    ) -> (Option<Arc<MstNode>>, Option<Arc<MstNode>>) {
        let node = (*node_arc).clone();
        let idx = match node
            .entries
            .binary_search_by(|e| e.key.as_slice().cmp(split_key))
        {
            Ok(i) => i,
            Err(i) => i,
        };

        let mut left_entries = Vec::new();
        let mut left_children = Vec::new();
        for i in 0..idx {
            left_entries.push(node.entries[i].clone());
            left_children.push(node.children[i].clone());
        }

        let (mid_left, mid_right) = if let Some(child_at_idx) = &node.children[idx] {
            Self::split_child(child_at_idx.clone(), split_key)
        } else {
            (None, None)
        };
        left_children.push(mid_left);

        let mut right_entries = Vec::new();
        let mut right_children = Vec::new();
        right_children.push(mid_right);

        let start_right =
            if idx < node.entries.len() && node.entries[idx].key.as_slice() == split_key {
                idx + 1
            } else {
                idx
            };

        for i in start_right..node.entries.len() {
            right_entries.push(node.entries[i].clone());
            right_children.push(node.children[i + 1].clone());
        }

        let left_node = Self::clean_node(node.level, left_entries, left_children);
        let right_node = Self::clean_node(node.level, right_entries, right_children);

        (left_node, right_node)
    }

    fn clean_node(
        level: u32,
        entries: Vec<MstEntry>,
        children: Vec<Option<Arc<MstNode>>>,
    ) -> Option<Arc<MstNode>> {
        if entries.is_empty() {
            if children.iter().any(|c| c.is_some()) {
                return children.into_iter().flatten().next();
            }
            return None;
        }
        let mut node = MstNode {
            level,
            entries,
            children,
            cached_hash: None,
        };
        node.hash();
        Some(Arc::new(node))
    }
}
