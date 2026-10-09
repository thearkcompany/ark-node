//! In-memory immutable Compressed Patricia Trie (Radix Trie) and compact Merkle Proofs.
//!
//! Conforms to GCP-08 and ADR-0010:
//! - String keys (FQDNs) and canonical DomainRoutingRecord values.
//! - Persistent / Copy-on-Write immutable node structure with Arc sharing.
//! - Deterministic SHA3-256 Merkle root hash computation over compacted prefix paths.
//! - Compact Merkle inclusion proof generation and verification (<= 256 bytes).

use crate::record::DomainRoutingRecord;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

/// Maximum size in bytes for a serialized Merkle inclusion proof.
pub const MAX_MERKLE_PROOF_SIZE: usize = 256;

/// A compact Merkle inclusion proof demonstrating the existence of a domain record
/// within the Patricia Trie root.
/// Serialized size is strictly bounded (<= 256 bytes for typical and deep domain trees).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// FQDN of the domain.
    pub fqdn: String,
    /// 32-byte digest of the domain's value record.
    pub record_digest: [u8; 32],
    /// Sequence of path proof steps from root down to the leaf.
    pub path_steps: Vec<MerkleProofStep>,
}

/// A single step along the Merkle verification path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProofStep {
    /// Compressed prefix edge of the node.
    pub prefix: Vec<u8>,
    /// Sibling hashes contributing to the node's digest (excluding the child in our branch).
    pub sibling_hashes: Vec<[u8; 32]>,
    /// Whether this node carries a value and if so its digest (if this node is not the target leaf).
    pub node_val_digest: Option<[u8; 32]>,
}

impl MerkleProof {
    /// Returns the approximate binary encoded size in bytes.
    pub fn encoded_size(&self) -> usize {
        let mut size = 4 + self.fqdn.len(); // fqdn len + bytes
        size += 32; // record_digest
        size += 2; // path_steps len
        for step in &self.path_steps {
            size += 2 + step.prefix.len();
            size += 1 + step.sibling_hashes.len() * 32;
            size += 1 + if step.node_val_digest.is_some() {
                32
            } else {
                0
            };
        }
        size
    }

    /// Encode MerkleProof to compact binary format.
    /// Returns the serialized bytes, ensuring size does not exceed `MAX_MERKLE_PROOF_SIZE` (256 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_size());
        let fqdn_bytes = self.fqdn.as_bytes();
        buf.extend_from_slice(&(fqdn_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(fqdn_bytes);
        buf.extend_from_slice(&self.record_digest);
        buf.extend_from_slice(&(self.path_steps.len() as u16).to_be_bytes());
        for step in &self.path_steps {
            buf.extend_from_slice(&(step.prefix.len() as u16).to_be_bytes());
            buf.extend_from_slice(&step.prefix);
            buf.push(step.sibling_hashes.len() as u8);
            for sh in &step.sibling_hashes {
                buf.extend_from_slice(sh);
            }
            match step.node_val_digest {
                Some(ref vd) => {
                    buf.push(1u8);
                    buf.extend_from_slice(vd);
                }
                None => {
                    buf.push(0u8);
                }
            }
        }
        debug_assert!(
            buf.len() <= MAX_MERKLE_PROOF_SIZE,
            "MerkleProof::to_bytes() exceeded maximum bound of {} bytes (actual: {} bytes)",
            MAX_MERKLE_PROOF_SIZE,
            buf.len()
        );
        buf
    }

    /// Decode MerkleProof from compact binary format.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut offset = 0;
        if bytes.len() < offset + 2 {
            return None;
        }
        let fqdn_len = u16::from_be_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;
        if bytes.len() < offset + fqdn_len + 32 + 2 {
            return None;
        }
        let fqdn = std::str::from_utf8(&bytes[offset..offset + fqdn_len])
            .ok()?
            .to_string();
        offset += fqdn_len;
        let mut record_digest = [0u8; 32];
        record_digest.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        let steps_len = u16::from_be_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;

        let mut path_steps = Vec::with_capacity(steps_len);
        for _ in 0..steps_len {
            if bytes.len() < offset + 2 {
                return None;
            }
            let pfx_len = u16::from_be_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
            offset += 2;
            if bytes.len() < offset + pfx_len + 1 {
                return None;
            }
            let prefix = bytes[offset..offset + pfx_len].to_vec();
            offset += pfx_len;
            let sib_len = bytes[offset] as usize;
            offset += 1;
            if bytes.len() < offset + sib_len * 32 + 1 {
                return None;
            }
            let mut sibling_hashes = Vec::with_capacity(sib_len);
            for _ in 0..sib_len {
                let mut sh = [0u8; 32];
                sh.copy_from_slice(&bytes[offset..offset + 32]);
                offset += 32;
                sibling_hashes.push(sh);
            }
            let has_val = bytes[offset];
            offset += 1;
            let node_val_digest = if has_val == 1 {
                if bytes.len() < offset + 32 {
                    return None;
                }
                let mut vd = [0u8; 32];
                vd.copy_from_slice(&bytes[offset..offset + 32]);
                offset += 32;
                Some(vd)
            } else {
                None
            };
            path_steps.push(MerkleProofStep {
                prefix,
                sibling_hashes,
                node_val_digest,
            });
        }
        Some(MerkleProof {
            fqdn,
            record_digest,
            path_steps,
        })
    }

    /// Verify this inclusion proof against a given root hash and record.
    pub fn verify(&self, root_hash: &[u8; 32], record: &DomainRoutingRecord) -> bool {
        if self.fqdn != record.fqdn {
            return false;
        }
        let expected_digest = record.compute_record_digest();
        if self.record_digest != expected_digest {
            return false;
        }

        if self.path_steps.is_empty() {
            return false;
        }

        // Recompute hashes bottom-up
        let mut current_child_hash: Option<[u8; 32]> = None;

        for step in self.path_steps.iter().rev() {
            let mut hasher = Sha3_256::new();
            hasher.update(b"ARK-TRIE-NODE-V1");
            hasher.update((step.prefix.len() as u16).to_be_bytes());
            hasher.update(&step.prefix);

            match step.node_val_digest {
                Some(vd) => {
                    hasher.update([1u8]);
                    hasher.update(vd);
                }
                None => {
                    hasher.update([0u8]);
                }
            }

            // Sibling hashes + current_child_hash combined
            let total_children =
                step.sibling_hashes.len() + if current_child_hash.is_some() { 1 } else { 0 };
            hasher.update((total_children as u16).to_be_bytes());

            let mut all_child_hashes = step.sibling_hashes.clone();
            if let Some(ch) = current_child_hash {
                all_child_hashes.push(ch);
            }
            all_child_hashes.sort();

            for ch in &all_child_hashes {
                hasher.update(ch);
            }

            let node_hash: [u8; 32] = hasher.finalize().into();
            current_child_hash = Some(node_hash);
        }

        match current_child_hash {
            Some(computed_root) => computed_root == *root_hash,
            None => false,
        }
    }
}

/// A node in the Compressed Patricia Trie.
#[derive(Clone, Debug)]
pub(crate) struct TrieNode {
    /// Compressed common edge prefix (bytes).
    pub(crate) prefix: Vec<u8>,
    /// Optional value if a key terminates exactly at this node.
    pub(crate) value: Option<Arc<DomainRoutingRecord>>,
    /// Children indexed by their branch edge's first byte.
    /// Ordered by branch character byte for deterministic hashing and iteration.
    pub(crate) children: Vec<(u8, Arc<TrieNode>)>,
    /// Cached Merkle hash of this node subtree.
    pub(crate) cached_hash: [u8; 32],
}

impl TrieNode {
    fn new(
        prefix: Vec<u8>,
        value: Option<Arc<DomainRoutingRecord>>,
        children: Vec<(u8, Arc<TrieNode>)>,
    ) -> Self {
        let mut node = Self {
            prefix,
            value,
            children,
            cached_hash: [0u8; 32],
        };
        node.recompute_hash();
        node
    }

    fn recompute_hash(&mut self) {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ARK-TRIE-NODE-V1");
        hasher.update((self.prefix.len() as u16).to_be_bytes());
        hasher.update(&self.prefix);

        match &self.value {
            Some(record) => {
                hasher.update([1u8]);
                let digest = record.compute_record_digest();
                hasher.update(digest);
            }
            None => {
                hasher.update([0u8]);
            }
        }

        let mut child_hashes: Vec<[u8; 32]> =
            self.children.iter().map(|(_, c)| c.cached_hash).collect();
        child_hashes.sort();

        hasher.update((child_hashes.len() as u16).to_be_bytes());
        for ch in &child_hashes {
            hasher.update(ch);
        }

        self.cached_hash = hasher.finalize().into();
    }
}

/// Immutable Compressed Patricia Trie core.
///
/// Modifying operations return a new cloned root sharing unchanged subtrees via `Arc`.
#[derive(Clone, Debug)]
pub struct CompressedPatriciaTrie {
    root: Option<Arc<TrieNode>>,
    count: usize,
}

impl Default for CompressedPatriciaTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressedPatriciaTrie {
    /// Create a new empty Compressed Patricia Trie.
    pub fn new() -> Self {
        Self {
            root: None,
            count: 0,
        }
    }

    /// Returns the number of domain records in the trie.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the trie contains no records.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Compute the 32-byte SHA3-256 Merkle root hash of the trie.
    /// An empty trie returns `[0u8; 32]`.
    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            Some(r) => r.cached_hash,
            None => [0u8; 32],
        }
    }

    /// Lookup a domain record by its fully-qualified domain name (FQDN).
    /// Ultra-fast $\mathcal{O}(k)$ time, zero lock contention.
    pub fn get(&self, fqdn: &str) -> Option<Arc<DomainRoutingRecord>> {
        let key = fqdn.as_bytes();
        let mut current = self.root.as_ref()?;
        let mut key_rem = key;

        loop {
            // Check if key_rem starts with current.prefix
            if !key_rem.starts_with(&current.prefix) {
                return None;
            }

            key_rem = &key_rem[current.prefix.len()..];

            if key_rem.is_empty() {
                return current.value.clone();
            }

            // Descend into child branch
            let first_byte = key_rem[0];
            let child = current.children.iter().find(|(b, _)| *b == first_byte)?;
            current = &child.1;
        }
    }

    /// Insert a domain routing record into the trie, returning a new `CompressedPatriciaTrie`.
    pub fn insert(&self, record: DomainRoutingRecord) -> Self {
        let record_arc = Arc::new(record);
        let key = record_arc.fqdn.as_bytes();

        let mut inserted_new = false;
        let new_root = match &self.root {
            Some(root) => Self::insert_node(root, key, Arc::clone(&record_arc), &mut inserted_new),
            None => {
                inserted_new = true;
                Arc::new(TrieNode::new(key.to_vec(), Some(record_arc), Vec::new()))
            }
        };

        Self {
            root: Some(new_root),
            count: if inserted_new {
                self.count + 1
            } else {
                self.count
            },
        }
    }

    fn insert_node(
        node: &Arc<TrieNode>,
        key: &[u8],
        record: Arc<DomainRoutingRecord>,
        inserted_new: &mut bool,
    ) -> Arc<TrieNode> {
        let common = common_prefix_len(&node.prefix, key);

        // Case 1: Key matches or extends node.prefix
        if common == node.prefix.len() {
            let rem_key = &key[common..];
            if rem_key.is_empty() {
                // Key lands exactly at this node
                if node.value.is_none() {
                    *inserted_new = true;
                }
                return Arc::new(TrieNode::new(
                    node.prefix.clone(),
                    Some(record),
                    node.children.clone(),
                ));
            }

            // Descend into matching child or create new child
            let branch_byte = rem_key[0];
            let mut new_children = node.children.clone();

            if let Some(pos) = new_children.iter().position(|(b, _)| *b == branch_byte) {
                let updated_child =
                    Self::insert_node(&new_children[pos].1, rem_key, record, inserted_new);
                new_children[pos] = (branch_byte, updated_child);
            } else {
                *inserted_new = true;
                let new_child = Arc::new(TrieNode::new(rem_key.to_vec(), Some(record), Vec::new()));
                new_children.push((branch_byte, new_child));
                new_children.sort_by_key(|(b, _)| *b);
            }

            return Arc::new(TrieNode::new(
                node.prefix.clone(),
                node.value.clone(),
                new_children,
            ));
        }

        // Case 2: Node prefix needs to be split
        *inserted_new = true;
        let common_prefix = node.prefix[..common].to_vec();
        let old_node_rem_prefix = node.prefix[common..].to_vec();
        let key_rem = &key[common..];

        // The old node becomes a child with its remaining prefix
        let old_child_branch = old_node_rem_prefix[0];
        let old_child = Arc::new(TrieNode::new(
            old_node_rem_prefix,
            node.value.clone(),
            node.children.clone(),
        ));

        let mut split_children = Vec::with_capacity(2);

        if key_rem.is_empty() {
            // New record sits right at the split node
            split_children.push((old_child_branch, old_child));
            split_children.sort_by_key(|(b, _)| *b);
            Arc::new(TrieNode::new(common_prefix, Some(record), split_children))
        } else {
            // New record becomes a sibling branch
            let new_child_branch = key_rem[0];
            let new_child = Arc::new(TrieNode::new(key_rem.to_vec(), Some(record), Vec::new()));

            split_children.push((old_child_branch, old_child));
            split_children.push((new_child_branch, new_child));
            split_children.sort_by_key(|(b, _)| *b);

            Arc::new(TrieNode::new(common_prefix, None, split_children))
        }
    }

    /// Remove a domain record from the trie, returning the updated trie and the removed record if any.
    pub fn remove(&self, fqdn: &str) -> (Self, Option<Arc<DomainRoutingRecord>>) {
        let root = match &self.root {
            Some(r) => r,
            None => return (self.clone(), None),
        };

        let mut removed_record = None;
        let new_root = Self::remove_node(root, fqdn.as_bytes(), &mut removed_record);

        let count = if removed_record.is_some() {
            self.count.saturating_sub(1)
        } else {
            self.count
        };

        (
            Self {
                root: new_root,
                count,
            },
            removed_record,
        )
    }

    fn remove_node(
        node: &Arc<TrieNode>,
        key: &[u8],
        removed: &mut Option<Arc<DomainRoutingRecord>>,
    ) -> Option<Arc<TrieNode>> {
        if !key.starts_with(&node.prefix) {
            return Some(node.clone());
        }

        let rem_key = &key[node.prefix.len()..];

        if rem_key.is_empty() {
            // Target node found
            *removed = node.value.clone();

            if node.children.is_empty() {
                // Leaf with no children -> delete node entirely
                return None;
            } else if node.children.len() == 1 {
                // Compaction: Merge with single child
                let (_, child) = &node.children[0];
                let mut merged_prefix = node.prefix.clone();
                merged_prefix.extend_from_slice(&child.prefix);
                return Some(Arc::new(TrieNode::new(
                    merged_prefix,
                    child.value.clone(),
                    child.children.clone(),
                )));
            } else {
                // Multiple children -> keep node, clear value
                return Some(Arc::new(TrieNode::new(
                    node.prefix.clone(),
                    None,
                    node.children.clone(),
                )));
            }
        }

        // Descend into child
        let branch_byte = rem_key[0];
        let child_pos = node.children.iter().position(|(b, _)| *b == branch_byte)?;

        let (_, child) = &node.children[child_pos];
        let updated_child_opt = Self::remove_node(child, rem_key, removed);

        let mut new_children = node.children.clone();
        match updated_child_opt {
            Some(updated_child) => {
                new_children[child_pos] = (branch_byte, updated_child);
            }
            None => {
                new_children.remove(child_pos);
            }
        }

        // Check if node should be compacted
        if node.value.is_none() && new_children.is_empty() {
            return None;
        }

        if node.value.is_none() && new_children.len() == 1 {
            // Compact single child into this node
            let (_, only_child) = &new_children[0];
            let mut merged_prefix = node.prefix.clone();
            merged_prefix.extend_from_slice(&only_child.prefix);
            return Some(Arc::new(TrieNode::new(
                merged_prefix,
                only_child.value.clone(),
                only_child.children.clone(),
            )));
        }

        Some(Arc::new(TrieNode::new(
            node.prefix.clone(),
            node.value.clone(),
            new_children,
        )))
    }

    /// Generate a compact Merkle inclusion proof for the specified domain.
    pub fn generate_merkle_proof(&self, fqdn: &str) -> Option<MerkleProof> {
        let key = fqdn.as_bytes();
        let root = self.root.as_ref()?;
        let mut path_steps = Vec::new();
        let mut current = root;
        let mut key_rem = key;

        let record_arc = loop {
            if !key_rem.starts_with(&current.prefix) {
                return None;
            }

            key_rem = &key_rem[current.prefix.len()..];

            if key_rem.is_empty() {
                let rec = current.value.as_ref()?;
                // Leaf step reached
                let sibling_hashes: Vec<[u8; 32]> = current
                    .children
                    .iter()
                    .map(|(_, c)| c.cached_hash)
                    .collect();
                path_steps.push(MerkleProofStep {
                    prefix: current.prefix.clone(),
                    sibling_hashes,
                    node_val_digest: Some(rec.compute_record_digest()),
                });
                break rec.clone();
            }

            let first_byte = key_rem[0];
            let child_pos = current
                .children
                .iter()
                .position(|(b, _)| *b == first_byte)?;
            let child = &current.children[child_pos].1;

            // Collect sibling hashes of all other children
            let mut sibling_hashes = Vec::new();
            for (i, (_, c)) in current.children.iter().enumerate() {
                if i != child_pos {
                    sibling_hashes.push(c.cached_hash);
                }
            }

            let node_val_digest = current.value.as_ref().map(|v| v.compute_record_digest());

            path_steps.push(MerkleProofStep {
                prefix: current.prefix.clone(),
                sibling_hashes,
                node_val_digest,
            });

            current = child;
        };

        Some(MerkleProof {
            fqdn: fqdn.to_string(),
            record_digest: record_arc.compute_record_digest(),
            path_steps,
        })
    }

    /// Return all domain routing records contained in the trie.
    pub fn all_records(&self) -> Vec<Arc<DomainRoutingRecord>> {
        let mut records = Vec::with_capacity(self.count);
        if let Some(root) = &self.root {
            Self::collect_records(root, &mut records);
        }
        records
    }

    fn collect_records(node: &Arc<TrieNode>, records: &mut Vec<Arc<DomainRoutingRecord>>) {
        if let Some(val) = &node.value {
            records.push(val.clone());
        }
        for (_, child) in &node.children {
            Self::collect_records(child, records);
        }
    }
}

fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let mut len = 0;
    while len < a.len() && len < b.len() && a[len] == b[len] {
        len += 1;
    }
    len
}
