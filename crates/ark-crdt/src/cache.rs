use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use crate::mst::MstNode;

/// Approximate memory usage of an MstNode in bytes.
pub fn estimate_node_size_bytes(node: &MstNode) -> usize {
    // Base struct overhead
    let mut size = std::mem::size_of::<MstNode>();

    // Entries overhead: Vec buffer capacity + heap contents
    size += node.entries.capacity() * std::mem::size_of::<crate::mst::MstEntry>();
    for entry in &node.entries {
        size += entry.key.capacity();
    }

    // Children overhead: Vec buffer capacity
    size += node.children.capacity() * std::mem::size_of::<Option<Arc<MstNode>>>();

    size
}

/// A strictly bounded LRU cache for MST nodes keyed by (namespace, node_hash).
/// Evicts the least recently used nodes when total estimated bytes exceeds capacity_bytes.
pub struct LruNodeCache {
    capacity_bytes: usize,
    current_bytes: usize,
    /// (namespace, node_hash) -> (node, estimated_size)
    map: HashMap<(String, [u8; 32]), (Arc<MstNode>, usize)>,
    /// Access history queue: front is oldest (LRU), back is newest (MRU)
    order: VecDeque<(String, [u8; 32])>,
}

impl LruNodeCache {
    /// Creates a new LRU cache with a maximum capacity in bytes.
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            current_bytes: 0,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Current memory consumption in bytes.
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Maximum capacity in bytes.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    /// Number of cached nodes.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up a node by namespace and node_hash.
    /// Updates the LRU access order if found.
    pub fn get(&mut self, namespace: &str, node_hash: &[u8; 32]) -> Option<Arc<MstNode>> {
        let key = (namespace.to_string(), *node_hash);
        if let Some((node, _size)) = self.map.get(&key) {
            let node_arc = node.clone();
            // Move key to MRU (back of queue)
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
            self.order.push_back(key);
            Some(node_arc)
        } else {
            None
        }
    }

    /// Insert a node into the cache.
    /// Evicts LRU nodes if adding this node exceeds capacity_bytes.
    pub fn put(&mut self, namespace: &str, node_hash: [u8; 32], node: Arc<MstNode>) {
        let key = (namespace.to_string(), node_hash);
        let node_size = estimate_node_size_bytes(&node);

        // If key already exists, deduct old size
        if let Some((_, old_size)) = self.map.remove(&key) {
            self.current_bytes = self.current_bytes.saturating_sub(old_size);
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
        }

        // Evict LRU entries while current_bytes + node_size > capacity_bytes
        while self.current_bytes + node_size > self.capacity_bytes && !self.order.is_empty() {
            if let Some(oldest_key) = self.order.pop_front() {
                if let Some((_, evicted_size)) = self.map.remove(&oldest_key) {
                    self.current_bytes = self.current_bytes.saturating_sub(evicted_size);
                }
            }
        }

        // If a single node is larger than entire cache, do not store it
        if node_size <= self.capacity_bytes {
            self.map.insert(key.clone(), (node, node_size));
            self.order.push_back(key);
            self.current_bytes += node_size;
        }
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
        self.current_bytes = 0;
    }
}
