use ark_crdt::MerkleSearchTree;

#[test]
fn test_identical_trees_empty_diff() {
    let mut tree_a = MerkleSearchTree::new();
    let mut tree_b = MerkleSearchTree::new();

    for i in 0..50 {
        let key = format!("node/key/{}", i).into_bytes();
        let env_id = [i as u8; 32];
        let ts = 1000 + i as u64;
        tree_a.insert(key.clone(), env_id, ts, false);
        tree_b.insert(key, env_id, ts, false);
    }

    assert_eq!(tree_a.root_hash(), tree_b.root_hash());

    let plan = tree_a.diff(&tree_b);
    assert!(
        plan.is_empty(),
        "Identical trees must produce empty sync plan"
    );
    assert_eq!(plan.keys_to_fetch.len(), 0);
    assert_eq!(plan.keys_to_send.len(), 0);
    assert_eq!(plan.divergent_nodes.len(), 0);
}

#[test]
fn test_empty_trees_diff() {
    let tree_a = MerkleSearchTree::new();
    let tree_b = MerkleSearchTree::new();

    let plan = tree_a.diff(&tree_b);
    assert!(plan.is_empty());
}

#[test]
fn test_local_empty_remote_non_empty() {
    let local = MerkleSearchTree::new();
    let mut remote = MerkleSearchTree::new();

    remote.insert(b"alpha".to_vec(), [1u8; 32], 100, false);
    remote.insert(b"beta".to_vec(), [2u8; 32], 200, false);

    let plan = local.diff(&remote);
    assert_eq!(plan.keys_to_send.len(), 0);
    assert_eq!(plan.keys_to_fetch.len(), 2);
    assert_eq!(plan.keys_to_fetch[0].key, b"alpha");
    assert_eq!(plan.keys_to_fetch[1].key, b"beta");
}

#[test]
fn test_local_non_empty_remote_empty() {
    let mut local = MerkleSearchTree::new();
    let remote = MerkleSearchTree::new();

    local.insert(b"alpha".to_vec(), [1u8; 32], 100, false);
    local.insert(b"beta".to_vec(), [2u8; 32], 200, false);

    let plan = local.diff(&remote);
    assert_eq!(plan.keys_to_send.len(), 2);
    assert_eq!(plan.keys_to_fetch.len(), 0);
    assert_eq!(plan.keys_to_send[0].key, b"alpha");
    assert_eq!(plan.keys_to_send[1].key, b"beta");
}

#[test]
fn test_bivariate_lww_conflict_resolution_in_diff() {
    let mut local = MerkleSearchTree::new();
    let mut remote = MerkleSearchTree::new();

    // Key 1: local has newer timestamp -> local supersedes remote -> keys_to_send
    local.insert(b"key1".to_vec(), [1u8; 32], 200, false);
    remote.insert(b"key1".to_vec(), [1u8; 32], 100, false);

    // Key 2: remote has newer timestamp -> remote supersedes local -> keys_to_fetch
    local.insert(b"key2".to_vec(), [2u8; 32], 100, false);
    remote.insert(b"key2".to_vec(), [2u8; 32], 200, false);

    // Key 3: identical timestamps, local has higher envelope_id -> local wins -> keys_to_send
    local.insert(b"key3".to_vec(), [20u8; 32], 150, false);
    remote.insert(b"key3".to_vec(), [10u8; 32], 150, false);

    // Key 4: identical timestamps, remote has higher envelope_id -> remote wins -> keys_to_fetch
    local.insert(b"key4".to_vec(), [10u8; 32], 150, false);
    remote.insert(b"key4".to_vec(), [20u8; 32], 150, false);

    // Key 5: completely identical -> neither send nor fetch
    local.insert(b"key5".to_vec(), [5u8; 32], 500, false);
    remote.insert(b"key5".to_vec(), [5u8; 32], 500, false);

    let plan = local.diff(&remote);
    assert_eq!(plan.keys_to_send.len(), 2);
    assert_eq!(plan.keys_to_fetch.len(), 2);

    let send_keys: Vec<&[u8]> = plan.keys_to_send.iter().map(|e| e.key.as_slice()).collect();
    let fetch_keys: Vec<&[u8]> = plan
        .keys_to_fetch
        .iter()
        .map(|e| e.key.as_slice())
        .collect();

    assert!(send_keys.contains(&b"key1".as_slice()));
    assert!(send_keys.contains(&b"key3".as_slice()));
    assert!(fetch_keys.contains(&b"key2".as_slice()));
    assert!(fetch_keys.contains(&b"key4".as_slice()));
}

#[test]
fn test_tombstone_lww_diff() {
    let mut local = MerkleSearchTree::new();
    let mut remote = MerkleSearchTree::new();

    // Local deleted a key with timestamp 250 (tombstone)
    local.insert(b"user:deleted".to_vec(), [99u8; 32], 250, true);
    // Remote still has older live key with timestamp 200
    remote.insert(b"user:deleted".to_vec(), [99u8; 32], 200, false);

    let plan = local.diff(&remote);
    // Local tombstone supersedes remote live key -> send tombstone to remote
    assert_eq!(plan.keys_to_send.len(), 1);
    assert_eq!(plan.keys_to_send[0].key, b"user:deleted");
    assert!(plan.keys_to_send[0].is_tombstone);
    assert_eq!(plan.keys_to_fetch.len(), 0);

    // Reverse: remote diff local
    let reverse_plan = remote.diff(&local);
    assert_eq!(reverse_plan.keys_to_fetch.len(), 1);
    assert_eq!(reverse_plan.keys_to_fetch[0].key, b"user:deleted");
    assert!(reverse_plan.keys_to_fetch[0].is_tombstone);
    assert_eq!(reverse_plan.keys_to_send.len(), 0);
}

#[test]
fn test_disjoint_trees_diff() {
    let mut tree_a = MerkleSearchTree::new();
    let mut tree_b = MerkleSearchTree::new();

    for i in 0..10 {
        tree_a.insert(format!("a-{}", i).into_bytes(), [1u8; 32], 100 + i, false);
        tree_b.insert(format!("b-{}", i).into_bytes(), [2u8; 32], 200 + i, false);
    }

    let plan = tree_a.diff(&tree_b);
    assert_eq!(plan.keys_to_send.len(), 10);
    assert_eq!(plan.keys_to_fetch.len(), 10);
}

#[test]
fn test_deep_divergence_and_subtrees() {
    let mut local = MerkleSearchTree::new();
    let mut remote = MerkleSearchTree::new();

    // Insert 200 identical keys
    for i in 0..200 {
        let key = format!("common/record/{:04}", i).into_bytes();
        let env_id = [i as u8; 32];
        local.insert(key.clone(), env_id, 1000 + i as u64, false);
        remote.insert(key, env_id, 1000 + i as u64, false);
    }

    // Insert 2 divergent keys
    local.insert(b"local_only_special".to_vec(), [77u8; 32], 5000, false);
    remote.insert(b"remote_only_special".to_vec(), [88u8; 32], 5000, false);

    let plan = local.diff(&remote);
    assert_eq!(plan.keys_to_send.len(), 1);
    assert_eq!(plan.keys_to_send[0].key, b"local_only_special");
    assert_eq!(plan.keys_to_fetch.len(), 1);
    assert_eq!(plan.keys_to_fetch[0].key, b"remote_only_special");
}
