use std::sync::{Arc, Mutex};
use ark_storage::{Keyspace, StorageEngine};
use crate::cache::LruNodeCache;
use crate::error::{ArkCrdtError, Result};
use crate::mst::{compute_key_level, MstEntry, MstNode};

/// Configuration for MstStore persistence and LRU node cache.
#[derive(Clone, Debug)]
pub struct MstStoreConfig {
    /// Maximum memory limit in bytes for the in-memory LRU node cache (default: 8 MB).
    pub max_cache_bytes: usize,
}

impl Default for MstStoreConfig {
    fn default() -> Self {
        Self {
            // Strictly bounded to <= 8 MB as specified by GCP-09 / ADR-0009
            max_cache_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Persistent Merkle Search Tree store backed by `ark-storage` and a bounded LRU cache.
///
/// Features:
/// - Isolated namespaces: each collection maintains its own independent root hash.
/// - Dedicated keyspace `mst_nodes` storing serialized nodes by `(namespace, node_hash)`.
/// - Dedicated keyspace `mst_roots` storing `namespace -> root_hash`.
/// - In-memory LRU cache strictly bounded to <= 8 MB.
/// - Restores root hash on startup without scanning all keys.
/// - Loads nodes on-demand from disk when evicted from cache.
pub struct MstStore {
    storage: Arc<StorageEngine>,
    nodes_keyspace: Keyspace,
    roots_keyspace: Keyspace,
    cache: Mutex<LruNodeCache>,
}

impl MstStore {
    /// Opens or initializes an MstStore using the provided StorageEngine instance.
    pub fn open(storage: Arc<StorageEngine>, config: MstStoreConfig) -> Result<Self> {
        let nodes_keyspace = storage.open_keyspace("mst_nodes")?;
        let roots_keyspace = storage.open_keyspace("mst_roots")?;
        let cache = Mutex::new(LruNodeCache::new(config.max_cache_bytes));

        Ok(Self {
            storage,
            nodes_keyspace,
            roots_keyspace,
            cache,
        })
    }

    /// Access the underlying StorageEngine reference.
    pub fn storage(&self) -> &Arc<StorageEngine> {
        &self.storage
    }

    /// Formats the storage key for an MST node: `[namespace_len: 2B BE] || [namespace] || [node_hash: 32B]`
    fn make_node_key(namespace: &str, node_hash: &[u8; 32]) -> Vec<u8> {
        let ns_bytes = namespace.as_bytes();
        let mut key = Vec::with_capacity(2 + ns_bytes.len() + 32);
        key.extend_from_slice(&(ns_bytes.len() as u16).to_be_bytes());
        key.extend_from_slice(ns_bytes);
        key.extend_from_slice(node_hash);
        key
    }

    /// Retrieve the root hash for a given namespace.
    pub fn root_hash(&self, namespace: &str) -> Result<Option<[u8; 32]>> {
        if let Some(bytes) = self
            .roots_keyspace
            .get(namespace.as_bytes())
            .map_err(|e| ArkCrdtError::Database(e.to_string()))?
        {
            if bytes.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                return Ok(Some(hash));
            }
        }
        Ok(None)
    }

    /// Update the root hash for a namespace.
    pub fn set_root_hash(&self, namespace: &str, root_hash: Option<[u8; 32]>) -> Result<()> {
        match root_hash {
            Some(h) => {
                self.roots_keyspace
                    .insert(namespace.as_bytes(), h)
                    .map_err(|e| ArkCrdtError::Database(e.to_string()))?;
            }
            None => {
                self.roots_keyspace
                    .remove(namespace.as_bytes())
                    .map_err(|e| ArkCrdtError::Database(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Fetches a node by hash from cache, or loads from disk if missing/evicted.
    pub fn load_node(&self, namespace: &str, node_hash: &[u8; 32]) -> Result<Arc<MstNode>> {
        // 1. Check in-memory LRU cache
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(node) = cache.get(namespace, node_hash) {
                return Ok(node);
            }
        }

        // 2. Load from disk keyspace `mst_nodes`
        let db_key = Self::make_node_key(namespace, node_hash);
        let raw_bytes = self
            .nodes_keyspace
            .get(&db_key)
            .map_err(|e| ArkCrdtError::Database(e.to_string()))?
            .ok_or_else(|| {
                ArkCrdtError::NodeNotFound(format!(
                    "Node {} in namespace {} not found on disk",
                    hex::encode(node_hash),
                    namespace
                ))
            })?;

        // 3. Deserialize node
        let (mut node, _child_hashes) = MstNode::deserialize(&raw_bytes)?;
        let computed_hash = node.hash();
        if &computed_hash != node_hash {
            return Err(ArkCrdtError::InvalidNodeHash {
                expected: hex::encode(node_hash),
                actual: hex::encode(computed_hash),
            });
        }

        let node_arc = Arc::new(node);

        // 4. Populate cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(namespace, *node_hash, node_arc.clone());
        }

        Ok(node_arc)
    }

    /// Persists a node and caches it in memory.
    pub fn save_node(&self, namespace: &str, node_arc: Arc<MstNode>) -> Result<[u8; 32]> {
        let mut node = (*node_arc).clone();
        let hash = node.hash();
        let serialized = node.serialize();

        let db_key = Self::make_node_key(namespace, &hash);
        self.nodes_keyspace
            .insert(db_key, serialized)
            .map_err(|e| ArkCrdtError::Database(e.to_string()))?;

        // Cache in LRU
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(namespace, hash, node_arc);
        }

        Ok(hash)
    }

    /// Point query: looks up key in the given namespace.
    /// Traverses the tree, loading child nodes on demand from cache or disk.
    pub fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<([u8; 32], u64)>> {
        let root_hash = match self.root_hash(namespace)? {
            Some(h) if h != [0u8; 32] => h,
            _ => return Ok(None),
        };

        let mut curr_node = self.load_node(namespace, &root_hash)?;

        loop {
            match curr_node.entries.binary_search_by(|e| e.key.as_slice().cmp(key)) {
                Ok(idx) => {
                    return Ok(Some((
                        curr_node.entries[idx].envelope_id,
                        curr_node.entries[idx].timestamp,
                    )));
                }
                Err(idx) => {
                    let child_hash = match &curr_node.children[idx] {
                        Some(child) => child.cached_hash.unwrap_or([0u8; 32]),
                        None => [0u8; 32],
                    };

                    if child_hash == [0u8; 32] {
                        return Ok(None);
                    }

                    curr_node = self.load_node(namespace, &child_hash)?;
                }
            }
        }
    }

    /// Inserts or updates an entry in the specified namespace.
    /// Recomputes hashes, persists newly created/updated nodes to disk, and updates namespace root.
    /// Applies Bivariate LWW (max(timestamp) || max(envelope_id)): older entries are rejected without altering the tree.
    pub fn put(
        &self,
        namespace: &str,
        key: Vec<u8>,
        envelope_id: [u8; 32],
        timestamp: u64,
    ) -> Result<Option<([u8; 32], u64)>> {
        // Enforce Bivariate LWW against existing entry
        if let Some((existing_id, existing_ts)) = self.get(namespace, &key)? {
            let wins = (timestamp > existing_ts)
                || (timestamp == existing_ts && envelope_id > existing_id);
            if !wins {
                // Obsolete write: do not mutate the tree or update root
                return Ok(None);
            }
        }

        let key_level = compute_key_level(&key);
        let entry = MstEntry::new(key, envelope_id, timestamp);

        // Load current root if exists
        let root_node = match self.root_hash(namespace)? {
            Some(h) if h != [0u8; 32] => Some(self.load_full_tree(namespace, &h)?),
            _ => None,
        };

        let mut replaced = None;
        let new_root = Self::insert_node(root_node, entry, key_level, &mut replaced);

        // Persist all nodes in the modified tree to disk
        self.persist_subtree(namespace, &new_root)?;

        let new_root_hash = new_root.cached_hash.unwrap_or([0u8; 32]);
        self.set_root_hash(namespace, Some(new_root_hash))?;

        Ok(replaced)
    }

    /// Deletes a key from the specified namespace.
    pub fn delete(&self, namespace: &str, key: &[u8]) -> Result<Option<([u8; 32], u64)>> {
        let root_hash = match self.root_hash(namespace)? {
            Some(h) if h != [0u8; 32] => h,
            _ => return Ok(None),
        };

        let root_node = self.load_full_tree(namespace, &root_hash)?;
        let mut removed = None;
        let new_root = Self::delete_node(root_node, key, &mut removed);

        if removed.is_some() {
            if let Some(ref nr) = new_root {
                self.persist_subtree(namespace, nr)?;
                let new_root_hash = nr.cached_hash.unwrap_or([0u8; 32]);
                self.set_root_hash(namespace, Some(new_root_hash))?;
            } else {
                self.set_root_hash(namespace, None)?;
            }
        }

        Ok(removed)
    }

    /// Recursively loads a full subtree (linking children in memory) for tree transformations.
    pub fn load_full_tree(&self, namespace: &str, node_hash: &[u8; 32]) -> Result<Arc<MstNode>> {
        let node_skeleton = self.load_node(namespace, node_hash)?;
        let child_hashes = node_skeleton.child_hashes();

        let mut full_children = Vec::with_capacity(child_hashes.len());
        let mut any_missing = false;

        for (i, ch) in child_hashes.iter().enumerate() {
            if *ch != [0u8; 32] {
                // If child is not already populated in the Arc
                if node_skeleton.children[i].is_none() {
                    let child_node = self.load_full_tree(namespace, ch)?;
                    full_children.push(Some(child_node));
                    any_missing = true;
                } else {
                    full_children.push(node_skeleton.children[i].clone());
                }
            } else {
                full_children.push(None);
            }
        }

        if any_missing {
            let mut hydrated = (*node_skeleton).clone();
            hydrated.children = full_children;
            hydrated.cached_hash = Some(*node_hash);
            let hydrated_arc = Arc::new(hydrated);
            // Update cache
            let mut cache = self.cache.lock().unwrap();
            cache.put(namespace, *node_hash, hydrated_arc.clone());
            Ok(hydrated_arc)
        } else {
            Ok(node_skeleton)
        }
    }

    /// Recursively persists an entire subtree to `mst_nodes` keyspace and LRU cache.
    fn persist_subtree(&self, namespace: &str, node_arc: &Arc<MstNode>) -> Result<()> {
        for child in node_arc.children.iter().flatten() {
            self.persist_subtree(namespace, child)?;
        }
        self.save_node(namespace, node_arc.clone())?;
        Ok(())
    }

    // --- Pure In-Memory MST Operations (re-used from mst.rs algorithm) ---

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
                node.children.push(None);
                node.hash();
                Arc::new(node)
            }
            Some(node_arc) => {
                let mut node = (*node_arc).clone();
                node.cached_hash = None;

                if entry_level == node.level {
                    match node.entries.binary_search_by(|e| e.key.as_slice().cmp(&entry.key)) {
                        Ok(idx) => {
                            let old = (node.entries[idx].envelope_id, node.entries[idx].timestamp);
                            *replaced = Some(old);
                            node.entries[idx] = entry;
                        }
                        Err(idx) => {
                            let (left_child, right_child) = if let Some(child) = node.children[idx].take() {
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
                    match node.entries.binary_search_by(|e| e.key.as_slice().cmp(&entry.key)) {
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

    fn delete_node(
        node_arc: Arc<MstNode>,
        key: &[u8],
        removed: &mut Option<([u8; 32], u64)>,
    ) -> Option<Arc<MstNode>> {
        match node_arc.entries.binary_search_by(|e| e.key.as_slice().cmp(key)) {
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
                    left.children[last_idx] = Self::merge_children(last_child, Some(Arc::new(right)));
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

    fn split_child(
        node_arc: Arc<MstNode>,
        split_key: &[u8],
    ) -> (Option<Arc<MstNode>>, Option<Arc<MstNode>>) {
        let node = (*node_arc).clone();
        let idx = match node.entries.binary_search_by(|e| e.key.as_slice().cmp(split_key)) {
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

        let start_right = if idx < node.entries.len() && node.entries[idx].key.as_slice() == split_key {
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

    /// Access the LRU node cache (for tests and metrics).
    pub fn cache(&self) -> &Mutex<LruNodeCache> {
        &self.cache
    }
}
