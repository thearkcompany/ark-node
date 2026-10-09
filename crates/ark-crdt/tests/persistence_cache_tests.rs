use ark_crdt::error::Result;
use ark_crdt::store::{MstStore, MstStoreConfig};
use ark_storage::{StorageConfig, StorageEngine};
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_node_persistence_across_engine_reopen() -> Result<()> {
    let dir = tempdir().expect("tempdir");
    let expected_root;

    // Phase 1: Open storage engine and MST store, insert entries, commit/flush
    {
        let storage = Arc::new(
            StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"),
        );
        let store = MstStore::open(storage, MstStoreConfig::default()).expect("open mst store");

        let ns = "test-dns";
        store.put(ns, b"ark.alice.id".to_vec(), [1u8; 32], 1000)?;
        store.put(ns, b"ark.bob.id".to_vec(), [2u8; 32], 1001)?;
        store.put(ns, b"ark.charlie.id".to_vec(), [3u8; 32], 1002)?;

        let root_opt = store.root_hash(ns)?;
        assert!(root_opt.is_some(), "root hash must exist");
        expected_root = root_opt.unwrap();
        assert_ne!(expected_root, [0u8; 32]);
    }

    // Phase 2: Close and Reopen from disk
    {
        let storage = Arc::new(
            StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("reopen storage"),
        );
        let store = MstStore::open(storage, MstStoreConfig::default()).expect("reopen mst store");

        let ns = "test-dns";
        let reopened_root = store.root_hash(ns)?.expect("reopened root must exist");
        assert_eq!(
            reopened_root, expected_root,
            "root hash must persist across reopen"
        );

        // Verify point queries after reopen
        let alice = store.get(ns, b"ark.alice.id")?.expect("alice entry");
        assert_eq!(alice, ([1u8; 32], 1000));

        let bob = store.get(ns, b"ark.bob.id")?.expect("bob entry");
        assert_eq!(bob, ([2u8; 32], 1001));

        let charlie = store.get(ns, b"ark.charlie.id")?.expect("charlie entry");
        assert_eq!(charlie, ([3u8; 32], 1002));

        // Non-existent key
        assert!(store.get(ns, b"ark.nonexistent.id")?.is_none());
    }

    Ok(())
}

#[test]
fn test_multiple_namespaces_complete_isolation() -> Result<()> {
    let dir = tempdir().expect("tempdir");
    let storage =
        Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));
    let store = MstStore::open(storage, MstStoreConfig::default()).expect("open mst store");

    let ns_dns = "domain.ark";
    let ns_apps = "apps.kv";
    let ns_meta = "worker.meta";

    // Insert disjoint and overlapping keys across different namespaces
    store.put(ns_dns, b"alice".to_vec(), [10u8; 32], 100)?;
    store.put(ns_apps, b"alice".to_vec(), [20u8; 32], 200)?;
    store.put(ns_meta, b"alice".to_vec(), [30u8; 32], 300)?;

    store.put(ns_dns, b"bob".to_vec(), [11u8; 32], 101)?;
    store.put(ns_apps, b"charlie".to_vec(), [21u8; 32], 201)?;

    let root_dns = store.root_hash(ns_dns)?.expect("dns root");
    let root_apps = store.root_hash(ns_apps)?.expect("apps root");
    let root_meta = store.root_hash(ns_meta)?.expect("meta root");

    // All roots must be completely distinct
    assert_ne!(root_dns, root_apps);
    assert_ne!(root_dns, root_meta);
    assert_ne!(root_apps, root_meta);

    // Verify key values are isolated per namespace
    assert_eq!(store.get(ns_dns, b"alice")?, Some(([10u8; 32], 100)));
    assert_eq!(store.get(ns_apps, b"alice")?, Some(([20u8; 32], 200)));
    assert_eq!(store.get(ns_meta, b"alice")?, Some(([30u8; 32], 300)));

    // Keys in one namespace must not bleed into another
    assert_eq!(store.get(ns_dns, b"charlie")?, None);
    assert_eq!(store.get(ns_apps, b"bob")?, None);
    assert_eq!(store.get(ns_meta, b"bob")?, None);

    // Deleting from one namespace does not affect the others
    store.delete(ns_dns, b"alice")?;
    assert_eq!(store.get(ns_dns, b"alice")?, None);
    assert_eq!(store.get(ns_apps, b"alice")?, Some(([20u8; 32], 200)));
    assert_eq!(store.get(ns_meta, b"alice")?, Some(([30u8; 32], 300)));

    Ok(())
}

#[test]
fn test_lru_cache_memory_bound_and_eviction() -> Result<()> {
    let dir = tempdir().expect("tempdir");
    let storage =
        Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));

    // Set a tiny LRU cache budget of 16 KB (16 * 1024 bytes) to test eviction under pressure
    let cache_limit = 16 * 1024;
    let store = MstStore::open(
        storage,
        MstStoreConfig {
            max_cache_bytes: cache_limit,
        },
    )?;

    let ns = "bounded.cache";

    // Insert 500 keys into the tree
    for i in 0..500 {
        let key = format!("cache.pressure.key.{:06}", i).into_bytes();
        let env_id = [(i % 256) as u8; 32];
        store.put(ns, key, env_id, 2000 + i as u64)?;

        // Ensure memory usage in LRU cache NEVER exceeds the configured limit
        let cache_lock = store.cache().lock().unwrap();
        assert!(
            cache_lock.current_bytes() <= cache_limit,
            "Cache memory {} bytes exceeded strict limit {} bytes at iteration {}",
            cache_lock.current_bytes(),
            cache_limit,
            i
        );
    }

    // Now test point queries and on-demand disk reloading:
    // With 500 keys and only a 16 KB cache limit, earlier nodes were certainly evicted.
    // Reading early keys must succeed by transparently reloading them from disk!
    for i in (0..500).step_by(25) {
        let key = format!("cache.pressure.key.{:06}", i).into_bytes();
        let expected_env_id = [(i % 256) as u8; 32];
        let val = store
            .get(ns, &key)?
            .expect("evicted node reloaded from disk");
        assert_eq!(val, (expected_env_id, 2000 + i as u64));

        // And verify cache is STILL strictly bounded
        let cache_lock = store.cache().lock().unwrap();
        assert!(
            cache_lock.current_bytes() <= cache_limit,
            "Cache memory {} bytes exceeded limit during read reload",
            cache_lock.current_bytes()
        );
    }

    Ok(())
}

#[test]
fn test_default_8mb_cache_limit() {
    let default_config = MstStoreConfig::default();
    assert_eq!(
        default_config.max_cache_bytes,
        8 * 1024 * 1024,
        "Default cache limit must be strictly <= 8 MB (8,388,608 bytes)"
    );
}
