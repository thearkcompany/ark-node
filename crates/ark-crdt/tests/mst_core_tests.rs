use ark_crdt::mst::{compute_key_level, MerkleSearchTree};
use sha3::Digest;

#[test]
fn test_key_level_computation_deterministic() {
    // Test that compute_key_level produces floor(ctz(SHA3-256(key)) / 4)
    let key1 = b"test/domain/a";
    let level1 = compute_key_level(key1);
    let level1_repeat = compute_key_level(key1);
    assert_eq!(level1, level1_repeat);

    // Also verify mathematical property:
    // Compute SHA3-256 of key, count trailing zeros (ctz) of hash bytes (in little-endian or bit order), / 4
    let mut hasher = sha3::Sha3_256::default();
    use sha3::Digest;
    hasher.update(key1);
    let hash: [u8; 32] = hasher.finalize().into();
    let ctz = {
        let mut count = 0u32;
        for &byte in &hash {
            let tz = byte.trailing_zeros();
            count += tz;
            if tz < 8 {
                break;
            }
        }
        count
    };
    assert_eq!(level1, ctz / 4);
}

#[test]
fn test_empty_tree_root_hash() {
    let tree = MerkleSearchTree::new();
    assert!(tree.is_empty());
    assert_eq!(tree.len(), 0);
    assert_eq!(tree.root_hash(), [0u8; 32]);
}

#[test]
fn test_insert_and_get() {
    let mut tree = MerkleSearchTree::new();
    let key = b"ark.alice.id".to_vec();
    let env_id = [42u8; 32];
    let timestamp = 1700000000;

    assert!(tree.get(&key).is_none());

    let old = tree.insert(key.clone(), env_id, timestamp);
    assert!(old.is_none());
    assert_eq!(tree.len(), 1);

    let found = tree.get(&key);
    assert_eq!(found, Some((env_id, timestamp)));

    // Re-insert with new timestamp and envelope_id
    let new_env_id = [99u8; 32];
    let new_timestamp = 1700000500;
    let replaced = tree.insert(key.clone(), new_env_id, new_timestamp);
    assert_eq!(replaced, Some((env_id, timestamp)));
    assert_eq!(tree.len(), 1);
    assert_eq!(tree.get(&key), Some((new_env_id, new_timestamp)));
}

#[test]
fn test_order_invariance_deterministic_root() {
    let mut pairs = Vec::new();
    for i in 0..50 {
        let key = format!("ark.domain.node.{}", i).into_bytes();
        let env_id = [(i as u8); 32];
        let timestamp = 1000 + i as u64;
        pairs.push((key, env_id, timestamp));
    }

    let mut tree1 = MerkleSearchTree::new();
    for (k, e, t) in &pairs {
        tree1.insert(k.clone(), *e, *t);
    }

    // Insert in reverse order
    let mut tree2 = MerkleSearchTree::new();
    for (k, e, t) in pairs.iter().rev() {
        tree2.insert(k.clone(), *e, *t);
    }

    // Insert in permuted / pseudo-random order
    let mut permuted = pairs.clone();
    // deterministic permutation
    permuted.sort_by(|a, b| {
        let ha = sha3::Sha3_256::digest(&a.0);
        let hb = sha3::Sha3_256::digest(&b.0);
        ha.cmp(&hb)
    });

    let mut tree3 = MerkleSearchTree::new();
    for (k, e, t) in &permuted {
        tree3.insert(k.clone(), *e, *t);
    }

    assert_ne!(tree1.root_hash(), [0u8; 32]);
    assert_eq!(tree1.root_hash(), tree2.root_hash(), "Reverse insertion order produced different root hash!");
    assert_eq!(tree1.root_hash(), tree3.root_hash(), "Permuted insertion order produced different root hash!");
}

#[test]
fn test_delete_updates_tree_and_matches_uninserted_tree() {
    let mut pairs = Vec::new();
    for i in 0..30 {
        let key = format!("ark.record.{}", i).into_bytes();
        let env_id = [(i as u8); 32];
        let timestamp = 5000 + i as u64;
        pairs.push((key, env_id, timestamp));
    }

    // Tree with all 30 items
    let mut tree_with_all = MerkleSearchTree::new();
    for (k, e, t) in &pairs {
        tree_with_all.insert(k.clone(), *e, *t);
    }

    // Delete item 10, item 0, item 29
    let keys_to_delete = vec![
        pairs[10].0.clone(),
        pairs[0].0.clone(),
        pairs[29].0.clone(),
    ];

    for k in &keys_to_delete {
        let removed = tree_with_all.delete(k);
        assert!(removed.is_some(), "Key should be deleted");
        assert!(tree_with_all.get(k).is_none(), "Key should not exist after deletion");
    }
    assert_eq!(tree_with_all.len(), 27);

    // Build another tree that never inserted those 3 keys
    let mut tree_without_deleted = MerkleSearchTree::new();
    for (k, e, t) in &pairs {
        if !keys_to_delete.contains(k) {
            tree_without_deleted.insert(k.clone(), *e, *t);
        }
    }
    assert_eq!(tree_without_deleted.len(), 27);

    // Assert their root hashes are identical!
    assert_eq!(
        tree_with_all.root_hash(),
        tree_without_deleted.root_hash(),
        "Tree after deletions must have identical root hash to tree constructed without those keys"
    );

    // Non-existent deletion should return None and not change root hash
    let root_before = tree_with_all.root_hash();
    assert!(tree_with_all.delete(b"non.existent.key").is_none());
    assert_eq!(tree_with_all.root_hash(), root_before);
}

#[test]
fn test_tree_balance_and_height_under_randomized_keys() {
    let mut tree = MerkleSearchTree::new();
    let num_keys = 2000;

    for i in 0..num_keys {
        let key = format!("sovereign/peer/record/{:08x}", i * 1337 + 7).into_bytes();
        let env_id = [(i as u8); 32];
        let timestamp = 1700000000 + i as u64;
        tree.insert(key, env_id, timestamp);
    }

    assert_eq!(tree.len(), num_keys);

    // Height verification:
    // With branching factor b = 16, for N = 2000 keys, expected height is around log_16(2000) ~ 2.7,
    // so max level is typically 2, 3 or 4 (height = level + 1 <= 8).
    // ADR-0009 and Issue #20 specify maximum tree depth ceiling of 16.
    let height = tree.height();
    assert!(height > 0 && height <= 8, "Tree height {} should be well balanced (<= 8) for 2000 keys", height);

    // Verify search tree balance and invariant properties:
    // 1. All keys in left child of entry E must be strictly less than E.key.
    // 2. All keys in right child of entry E must be strictly greater than E.key.
    // 3. Child levels must be strictly less than parent level.
    fn verify_node_invariants(node: &std::sync::Arc<ark_crdt::mst::MstNode>, min_bound: Option<&[u8]>, max_bound: Option<&[u8]>) {
        assert!(!node.entries.is_empty(), "Node must have entries");

        for i in 0..node.entries.len() {
            let k = &node.entries[i].key;
            if let Some(min) = min_bound {
                assert!(k.as_slice() > min, "Entry key must be > min_bound");
            }
            if let Some(max) = max_bound {
                assert!(k.as_slice() < max, "Entry key must be < max_bound");
            }
            if i > 0 {
                assert!(node.entries[i - 1].key < node.entries[i].key, "Entries within node must be sorted");
            }
        }

        assert_eq!(node.children.len(), node.entries.len() + 1);

        for (i, child_opt) in node.children.iter().enumerate() {
            if let Some(child) = child_opt {
                assert!(child.level < node.level, "Child level {} must be < parent level {}", child.level, node.level);

                let child_min = if i == 0 { min_bound } else { Some(node.entries[i - 1].key.as_slice()) };
                let child_max = if i < node.entries.len() { Some(node.entries[i].key.as_slice()) } else { max_bound };

                verify_node_invariants(child, child_min, child_max);
            }
        }
    }

    if let Some(root) = tree.root_node() {
        verify_node_invariants(root, None, None);
    }
}
