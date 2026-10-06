use ark_crdt::mst::{MerkleSearchTree, MstPutOutcome, MstValue};

#[test]
fn test_newer_timestamp_supersedes_existing_entry() {
    let mut tree = MerkleSearchTree::new();
    let key = b"user/profile/alice".to_vec();
    let env_id_1 = [1u8; 32];
    let ts_1 = 1000;

    // First insert
    let outcome1 = tree.insert(key.clone(), env_id_1, ts_1, false);
    assert_eq!(outcome1, MstPutOutcome::Inserted);
    assert_eq!(tree.len(), 1);
    assert_eq!(
        tree.get(&key),
        Some(MstValue {
            envelope_id: env_id_1,
            timestamp: ts_1,
            is_tombstone: false,
        })
    );

    let root_1 = tree.root_hash();
    assert_ne!(root_1, [0u8; 32]);

    // Newer insert
    let env_id_2 = [2u8; 32];
    let ts_2 = 2000;
    let outcome2 = tree.insert(key.clone(), env_id_2, ts_2, false);
    assert_eq!(outcome2, MstPutOutcome::Updated);
    assert_eq!(tree.len(), 1);
    assert_eq!(
        tree.get(&key),
        Some(MstValue {
            envelope_id: env_id_2,
            timestamp: ts_2,
            is_tombstone: false,
        })
    );

    let root_2 = tree.root_hash();
    assert_ne!(root_1, root_2);
}

#[test]
fn test_older_timestamp_is_discarded_as_superseded_lww() {
    let mut tree = MerkleSearchTree::new();
    let key = b"dns/record/example.ark".to_vec();
    let env_id_recent = [10u8; 32];
    let ts_recent = 5000;

    let outcome1 = tree.insert(key.clone(), env_id_recent, ts_recent, false);
    assert_eq!(outcome1, MstPutOutcome::Inserted);
    let root_before = tree.root_hash();

    // Older insert attempt
    let env_id_older = [99u8; 32]; // even with higher id, older timestamp must lose
    let ts_older = 4000;
    let outcome2 = tree.insert(key.clone(), env_id_older, ts_older, false);
    assert_eq!(outcome2, MstPutOutcome::SupersededLww);

    // Assert tree length, point query, and root hash remain unchanged
    assert_eq!(tree.len(), 1);
    assert_eq!(
        tree.get(&key),
        Some(MstValue {
            envelope_id: env_id_recent,
            timestamp: ts_recent,
            is_tombstone: false,
        })
    );
    assert_eq!(tree.root_hash(), root_before);
}

#[test]
fn test_identical_timestamps_tie_break_deterministically_via_envelope_id() {
    let mut tree = MerkleSearchTree::new();
    let key = b"config/cluster/node-1".to_vec();
    let ts = 3000;

    let id_low = [0x10u8; 32];
    let id_high = [0x20u8; 32];
    assert!(id_high > id_low);

    // Case A: Insert low first, then high -> should update
    let outcome_a1 = tree.insert(key.clone(), id_low, ts, false);
    assert_eq!(outcome_a1, MstPutOutcome::Inserted);
    let root_low = tree.root_hash();

    let outcome_a2 = tree.insert(key.clone(), id_high, ts, false);
    assert_eq!(outcome_a2, MstPutOutcome::Updated);
    assert_eq!(
        tree.get(&key),
        Some(MstValue {
            envelope_id: id_high,
            timestamp: ts,
            is_tombstone: false,
        })
    );
    let root_high = tree.root_hash();
    assert_ne!(root_low, root_high);

    // Case B: In a new tree, insert high first, then attempt low -> low should be SupersededLww
    let mut tree2 = MerkleSearchTree::new();
    let outcome_b1 = tree2.insert(key.clone(), id_high, ts, false);
    assert_eq!(outcome_b1, MstPutOutcome::Inserted);
    assert_eq!(tree2.root_hash(), root_high);

    let outcome_b2 = tree2.insert(key.clone(), id_low, ts, false);
    assert_eq!(outcome_b2, MstPutOutcome::SupersededLww);
    assert_eq!(tree2.root_hash(), root_high);
    assert_eq!(
        tree2.get(&key),
        Some(MstValue {
            envelope_id: id_high,
            timestamp: ts,
            is_tombstone: false,
        })
    );

    // Case C: Exact identical envelope_id and timestamp -> SupersededLww (or idempotent, no tree change)
    let outcome_b3 = tree2.insert(key.clone(), id_high, ts, false);
    assert_eq!(outcome_b3, MstPutOutcome::SupersededLww);
    assert_eq!(tree2.root_hash(), root_high);
}

#[test]
fn test_tombstone_envelopes_supersede_older_data_and_signal_deleted() {
    let mut tree = MerkleSearchTree::new();
    let key = b"ephemeral/session/abc".to_vec();
    let env_id_data = [5u8; 32];
    let ts_data = 1000;

    // 1. Insert live data
    assert_eq!(
        tree.insert(key.clone(), env_id_data, ts_data, false),
        MstPutOutcome::Inserted
    );
    assert_eq!(
        tree.get(&key),
        Some(MstValue {
            envelope_id: env_id_data,
            timestamp: ts_data,
            is_tombstone: false,
        })
    );
    let root_before_tombstone = tree.root_hash();

    // 2. Tombstone with newer timestamp
    let env_id_tomb = [6u8; 32];
    let ts_tomb = 2000;
    let outcome_tomb = tree.insert(key.clone(), env_id_tomb, ts_tomb, true);
    assert_eq!(outcome_tomb, MstPutOutcome::Updated);
    assert_ne!(tree.root_hash(), root_before_tombstone);

    // Point query get: returns active entry signaling deleted / tombstone status
    let res = tree.get(&key);
    assert!(res.is_some());
    let val = res.unwrap();
    assert_eq!(val.envelope_id, env_id_tomb);
    assert_eq!(val.timestamp, ts_tomb);
    assert!(val.is_tombstone);
    assert!(val.is_deleted());

    // 3. Obsolete data write at t=1500 (older than tombstone at t=2000)
    let env_id_late = [7u8; 32];
    let ts_late = 1500;
    let outcome_late = tree.insert(key.clone(), env_id_late, ts_late, false);
    assert_eq!(outcome_late, MstPutOutcome::SupersededLww);
    // Tombstone still in effect
    assert_eq!(tree.get(&key).unwrap().is_tombstone, true);

    // 4. Fresh write at t=3000 supersedes tombstone
    let env_id_resurrect = [8u8; 32];
    let ts_resurrect = 3000;
    let outcome_resurrect = tree.insert(key.clone(), env_id_resurrect, ts_resurrect, false);
    assert_eq!(outcome_resurrect, MstPutOutcome::Updated);
    let val_resurrect = tree.get(&key).unwrap();
    assert_eq!(val_resurrect.envelope_id, env_id_resurrect);
    assert!(!val_resurrect.is_tombstone);
}

#[test]
fn test_tombstone_insertion_as_new_key() {
    let mut tree = MerkleSearchTree::new();
    let key = b"preemptively/deleted/key".to_vec();
    let env_id_tomb = [0x55u8; 32];
    let ts_tomb = 1500;

    let outcome = tree.insert(key.clone(), env_id_tomb, ts_tomb, true);
    assert_eq!(outcome, MstPutOutcome::Inserted);
    assert_eq!(tree.len(), 1);

    let val = tree.get(&key).expect("entry must exist");
    assert_eq!(val.envelope_id, env_id_tomb);
    assert_eq!(val.timestamp, ts_tomb);
    assert!(val.is_tombstone);
}

#[test]
fn test_order_invariance_with_mixed_updates_and_tombstones() {
    // Operations on keys k1, k2, k3 with different timestamps
    let mut tree_seq = MerkleSearchTree::new();

    // Sequence 1:
    // k1 v1(ts=100) -> k1 v2(ts=200)
    // k2 v1(ts=150) -> k2 tombstone(ts=250)
    // k3 v1(ts=300)
    tree_seq.insert(b"k1".to_vec(), [1u8; 32], 100, false);
    tree_seq.insert(b"k1".to_vec(), [2u8; 32], 200, false);
    tree_seq.insert(b"k2".to_vec(), [3u8; 32], 150, false);
    tree_seq.insert(b"k2".to_vec(), [4u8; 32], 250, true);
    tree_seq.insert(b"k3".to_vec(), [5u8; 32], 300, false);

    // Sequence 2: applied in different order, including obsolete writes
    let mut tree_alt = MerkleSearchTree::new();
    tree_alt.insert(b"k3".to_vec(), [5u8; 32], 300, false);
    tree_alt.insert(b"k2".to_vec(), [4u8; 32], 250, true);
    tree_alt.insert(b"k2".to_vec(), [3u8; 32], 150, false); // should be SupersededLww
    tree_alt.insert(b"k1".to_vec(), [2u8; 32], 200, false);
    tree_alt.insert(b"k1".to_vec(), [1u8; 32], 100, false); // should be SupersededLww

    assert_eq!(tree_seq.root_hash(), tree_alt.root_hash());
    assert_eq!(tree_seq.len(), tree_alt.len());
    assert_eq!(tree_seq.get(b"k1"), tree_alt.get(b"k1"));
    assert_eq!(tree_seq.get(b"k2"), tree_alt.get(b"k2"));
    assert_eq!(tree_seq.get(b"k3"), tree_alt.get(b"k3"));
}
