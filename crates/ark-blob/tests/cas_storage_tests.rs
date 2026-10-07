use std::io::Read;
use std::sync::Arc;
use tempfile::tempdir;

use ark_blob::cas::{CasDiskStore, StoragePaths};
use ark_blob::constants::{DATA_SHARDS, PARITY_SHARDS, SHARD_SIZE, TOTAL_SHARDS};
use ark_blob::error::BlobError;
use ark_blob::manifest::{BlobManifest, ShardStatus};
use ark_blob::store::HybridBlobStore;
use ark_blob::CauchyReedSolomon;
use ark_storage::{RetentionClass, StorageConfig, StorageEngine};
use sha3::{Digest, Sha3_256};

#[test]
fn test_cas_disk_store_atomic_write_and_read() {
    let dir = tempdir().expect("create tempdir");
    let cas = CasDiskStore::new(dir.path()).expect("create cas store");

    let payload = vec![0x42u8; SHARD_SIZE];
    let mut hasher = Sha3_256::new();
    hasher.update(&payload);
    let hash: [u8; 32] = hasher.finalize().into();

    // 1. Write shard
    let written_hash = cas.put_shard(&payload).expect("put shard");
    assert_eq!(written_hash, hash);

    // 2. Check exists
    assert!(cas.has_shard(&hash));

    // 3. Read back full shard
    let read_back = cas.read_shard(&hash).expect("read shard");
    assert_eq!(read_back, payload);

    // 4. Check file path format .ark/blobs/<hex_shard_hash>
    let hex_hash = hex::encode(hash);
    let expected_path = dir.path().join(StoragePaths::BLOBS_DIR).join(&hex_hash);
    assert!(expected_path.exists());
    assert_eq!(std::fs::metadata(&expected_path).unwrap().len(), SHARD_SIZE as u64);
}

#[test]
fn test_cas_disk_store_deduplication() {
    let dir = tempdir().expect("create tempdir");
    let cas = CasDiskStore::new(dir.path()).expect("create cas store");

    let payload = vec![0xA5u8; SHARD_SIZE];
    let mut hasher = Sha3_256::new();
    hasher.update(&payload);
    let hash: [u8; 32] = hasher.finalize().into();

    let hash1 = cas.put_shard(&payload).expect("first put");
    let hash2 = cas.put_shard(&payload).expect("second put (deduplicated)");
    assert_eq!(hash1, hash2);
    assert_eq!(hash1, hash);

    // Temp file should not remain
    let temp_dir = dir.path().join(StoragePaths::TEMP_DIR);
    if temp_dir.exists() {
        let entries = std::fs::read_dir(temp_dir).unwrap().count();
        assert_eq!(entries, 0, "No temporary files should be left behind");
    }
}

#[test]
fn test_cas_disk_store_streaming_read_bounded_memory() {
    let dir = tempdir().expect("create tempdir");
    let cas = CasDiskStore::new(dir.path()).expect("create cas store");

    let payload = vec![0x7Eu8; SHARD_SIZE];
    let hash = cas.put_shard(&payload).expect("put shard");

    // Open stream
    let mut reader = cas.open_shard_stream(&hash).expect("open stream");
    let mut buffer = [0u8; 64 * 1024]; // 64 KB read buffer
    let mut total_bytes = 0;

    let mut stream_hasher = Sha3_256::new();
    loop {
        let n = reader.read(&mut buffer).expect("stream read");
        if n == 0 {
            break;
        }
        stream_hasher.update(&buffer[..n]);
        total_bytes += n;
    }

    assert_eq!(total_bytes, SHARD_SIZE);
    let computed_hash: [u8; 32] = stream_hasher.finalize().into();
    assert_eq!(computed_hash, hash);

    // Verify stream integrity check
    assert!(cas.verify_shard_stream(&hash).expect("verify shard integrity"));
}

#[test]
fn test_cas_integrity_verification_detects_corruption() {
    let dir = tempdir().expect("create tempdir");
    let cas = CasDiskStore::new(dir.path()).expect("create cas store");

    let payload = vec![0x11u8; SHARD_SIZE];
    let hash = cas.put_shard(&payload).expect("put shard");

    // Corrupt shard file directly on disk
    let hex_hash = hex::encode(hash);
    let file_path = dir.path().join(StoragePaths::BLOBS_DIR).join(&hex_hash);
    let mut corrupted = payload.clone();
    corrupted[42] ^= 0xFF;
    std::fs::write(&file_path, &corrupted).expect("write corrupted file");

    // Reading should return corruption error
    let read_res = cas.read_shard(&hash);
    assert!(matches!(read_res, Err(BlobError::CorruptedShard { .. })));

    // Stream verification should report false
    assert!(!cas.verify_shard_stream(&hash).expect("stream verification"));
}

#[test]
fn test_manifest_indexing_in_fjall_lsm() {
    let dir = tempdir().expect("create tempdir");
    let storage_engine = Arc::new(
        StorageEngine::open(dir.path().join("lsm"), StorageConfig::frugal())
            .expect("open storage engine"),
    );

    let hybrid_store = HybridBlobStore::new(dir.path().join("cas"), storage_engine.clone())
        .expect("create hybrid store");

    let blob_cid = [0x55u8; 32];
    let shard_hashes = (0..TOTAL_SHARDS)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h
        })
        .collect::<Vec<_>>();

    let manifest = BlobManifest {
        blob_cid,
        total_size: 10 * 1024 * 1024,
        data_shards: DATA_SHARDS,
        parity_shards: PARITY_SHARDS,
        shard_hashes: shard_hashes.clone(),
        shard_roots: shard_hashes.clone(),
        created_at: 1_700_000_000,
    };

    // Store manifest
    hybrid_store
        .put_manifest(&manifest)
        .expect("index manifest in Fjall");

    // Retrieve manifest by blob_cid
    let retrieved = hybrid_store
        .get_manifest(&blob_cid)
        .expect("get manifest")
        .expect("manifest found");

    assert_eq!(retrieved.blob_cid, blob_cid);
    assert_eq!(retrieved.total_size, 10 * 1024 * 1024);
    assert_eq!(retrieved.shard_hashes.len(), TOTAL_SHARDS);

    // Verify envelope indexing in ark-storage satisfies Retention Class 1
    let manifest_env = retrieved
        .to_envelope(&[1u8; 32])
        .expect("convert manifest to envelope");
    assert_eq!(
        ark_storage::classify_retention(&manifest_env),
        RetentionClass::Class1AppendOnly
    );

    // Update and query shard status pointers in Fjall
    hybrid_store
        .update_shard_status(&blob_cid, 0, ShardStatus::Present)
        .expect("update shard status");
    let status_0 = hybrid_store
        .get_shard_status(&blob_cid, 0)
        .expect("get shard status");
    assert_eq!(status_0, Some(ShardStatus::Present));

    let status_1 = hybrid_store
        .get_shard_status(&blob_cid, 1)
        .expect("get shard status");
    assert_eq!(status_1, None);
}

#[test]
fn test_end_to_end_store_and_stream_reconstruct() {
    let dir = tempdir().expect("create tempdir");
    let storage_engine = Arc::new(
        StorageEngine::open(dir.path().join("lsm"), StorageConfig::frugal())
            .expect("open storage engine"),
    );
    let hybrid_store = HybridBlobStore::new(dir.path().join("cas"), storage_engine)
        .expect("create hybrid store");

    // 5 MB dummy payload
    let payload = vec![0x33u8; 5 * 1024 * 1024];
    let rs = CauchyReedSolomon::default();
    let shards = rs.encode_standard(&payload).expect("encode shards");

    let blob_cid = ark_blob::compute_blob_cid(&payload);
    let shard_roots = ark_blob::compute_shard_merkle_roots(&shards).expect("compute shard roots");

    let mut shard_hashes = Vec::with_capacity(TOTAL_SHARDS);
    for (i, shard) in shards.iter().enumerate() {
        let hash = hybrid_store.put_shard(shard).expect("put shard to cas");
        shard_hashes.push(hash);
        hybrid_store
            .update_shard_status(&blob_cid, i as u32, ShardStatus::Present)
            .expect("update status");
    }

    let manifest = BlobManifest {
        blob_cid,
        total_size: payload.len() as u64,
        data_shards: DATA_SHARDS,
        parity_shards: PARITY_SHARDS,
        shard_hashes,
        shard_roots,
        created_at: 1_700_000_100,
    };
    hybrid_store.put_manifest(&manifest).expect("put manifest");

    // Stream shards directly from CAS to reconstruct payload
    let mut available_shards = Vec::new();
    // Pick any 10 shards (e.g., 0..5 and 9..14)
    let selected_indices = [0, 1, 2, 3, 4, 9, 10, 11, 12, 13];
    for &idx in &selected_indices {
        let hash = &manifest.shard_hashes[idx];
        let shard_bytes = hybrid_store.read_shard(hash).expect("read shard");
        available_shards.push((idx, shard_bytes));
    }

    let reconstructed = rs
        .reconstruct(&available_shards, payload.len())
        .expect("reconstruct payload");
    assert_eq!(reconstructed, payload);
}

#[test]
fn test_concurrent_writes_and_cleanup() {
    let dir = tempdir().expect("create tempdir");
    let cas = Arc::new(CasDiskStore::new(dir.path()).expect("create cas store"));

    let handles: Vec<_> = (0..16)
        .map(|thread_id| {
            let cas_clone = cas.clone();
            std::thread::spawn(move || {
                let payload = vec![thread_id as u8; SHARD_SIZE];
                let hash = cas_clone.put_shard(&payload).expect("put shard in thread");
                let read = cas_clone.read_shard(&hash).expect("read shard in thread");
                assert_eq!(read, payload);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread finished cleanly");
    }

    // Verify temp dir is completely clean
    let temp_dir = dir.path().join(StoragePaths::TEMP_DIR);
    if temp_dir.exists() {
        let count = std::fs::read_dir(temp_dir).unwrap().count();
        assert_eq!(count, 0, "No leftover temp files after concurrent writes");
    }
}
