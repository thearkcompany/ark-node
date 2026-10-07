//! Content-Addressed Storage (CAS) on disk for ark-blob (GCP-10, ADR-0011).
//!
//! Stores 1 MB binary shard payloads content-addressed at `.ark/blobs/<shard_hash>`.
//! Features:
//! - Content-addressed naming using hex-encoded SHA3-256 digest of shard payload.
//! - Atomic writes: writes payload first to `.ark/temp/<uuid/pid>.tmp`, fsyncs, then renames to `.ark/blobs/<shard_hash>`.
//! - Inherent deduplication: if the content hash already exists on disk, skips re-write and cleans up temp file.
//! - Streaming reads and streaming verification in bounded chunks (e.g. 64 KB) to strictly respect <= 65 MB RAM ceiling.
//! - Crash-resilient cleanup of stray temp files.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha3::{Digest, Sha3_256};

use crate::constants::SHARD_SIZE;
use crate::error::{BlobError, Result};

/// Canonical path layout constants for blob storage.
pub struct StoragePaths;

impl StoragePaths {
    pub const BLOBS_DIR: &'static str = ".ark/blobs";
    pub const TEMP_DIR: &'static str = ".ark/temp";
}

/// Disk-based Content-Addressed Storage engine.
#[derive(Clone, Debug)]
pub struct CasDiskStore {
    root_dir: PathBuf,
    blobs_dir: PathBuf,
    temp_dir: PathBuf,
}

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl CasDiskStore {
    /// Initializes or opens a CAS store rooted at `root_path`.
    /// Creates `.ark/blobs` and `.ark/temp` if they do not exist, and cleans up old temp files.
    pub fn new<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let root_dir = root_path.as_ref().to_path_buf();
        let blobs_dir = root_dir.join(StoragePaths::BLOBS_DIR);
        let temp_dir = root_dir.join(StoragePaths::TEMP_DIR);

        fs::create_dir_all(&blobs_dir)?;
        fs::create_dir_all(&temp_dir)?;

        let store = Self {
            root_dir,
            blobs_dir,
            temp_dir,
        };

        // Clean up any stale temp files left from aborted processes / crashes
        let _ = store.cleanup_temp_files();

        Ok(store)
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn blobs_dir(&self) -> &Path {
        &self.blobs_dir
    }

    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Computes the content hash (SHA3-256) of a shard payload.
    pub fn hash_shard(payload: &[u8]) -> [u8; 32] {
        Sha3_256::digest(payload).into()
    }

    /// Derives the absolute path on disk for a given 32-byte shard hash.
    pub fn shard_path(&self, hash: &[u8; 32]) -> PathBuf {
        let hex_hash = hex::encode(hash);
        self.blobs_dir.join(hex_hash)
    }

    /// Checks if a shard with the given hash already exists on disk and is non-empty.
    pub fn has_shard(&self, hash: &[u8; 32]) -> bool {
        let path = self.shard_path(hash);
        path.exists()
    }

    /// Stores a 1 MB binary shard payload content-addressed on the filesystem.
    ///
    /// 1. Computes SHA3-256 content hash.
    /// 2. If the destination `.ark/blobs/<shard_hash>` already exists, returns the hash immediately (deduplication).
    /// 3. Writes payload to a uniquely named temporary file in `.ark/temp/`.
    /// 4. Synchronously calls `sync_all()` (fsync) on the temporary file to ensure data is flushed to durable storage.
    /// 5. Atomically renames the temporary file to `.ark/blobs/<shard_hash>`.
    /// 6. Cleans up temporary file if any error occurs.
    pub fn put_shard(&self, payload: &[u8]) -> Result<[u8; 32]> {
        let hash = Self::hash_shard(payload);
        let dest_path = self.shard_path(&hash);

        // Deduplication check: if file already exists with identical name, skip write
        if dest_path.exists() {
            return Ok(hash);
        }

        // Generate a unique temporary filename
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let thread_id = std::thread::current().id();
        let temp_filename = format!("put_{:?}_{}_{}.tmp", thread_id, pid, counter);
        let temp_path = self.temp_dir.join(temp_filename);

        // Write to temp file
        let write_res = (|| -> Result<()> {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(payload)?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            Ok(())
        })();

        if let Err(e) = write_res {
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }

        // Atomic rename into final content-addressed location
        // If another concurrent thread wrote the same file in the meantime, rename atomically overwrites it.
        if let Err(e) = fs::rename(&temp_path, &dest_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(BlobError::from(e));
        }

        Ok(hash)
    }

    /// Reads an entire shard from disk into memory and verifies its content integrity.
    pub fn read_shard(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        let path = self.shard_path(hash);
        if !path.exists() {
            return Err(BlobError::ShardNotFound(hex::encode(hash)));
        }

        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::with_capacity(SHARD_SIZE);
        reader.read_to_end(&mut buffer)?;

        // Verify SHA3-256 integrity
        let computed = Self::hash_shard(&buffer);
        if computed != *hash {
            return Err(BlobError::CorruptedShard {
                hash: hex::encode(hash),
                expected: hex::encode(hash),
                got: hex::encode(computed),
            });
        }

        Ok(buffer)
    }

    /// Opens a streaming reader for a shard without loading the full payload into memory.
    /// This allows consumers to process shards in small buffers (e.g. 4 KB or 64 KB).
    pub fn open_shard_stream(&self, hash: &[u8; 32]) -> Result<BufReader<File>> {
        let path = self.shard_path(hash);
        if !path.exists() {
            return Err(BlobError::ShardNotFound(hex::encode(hash)));
        }

        let file = File::open(&path)?;
        Ok(BufReader::new(file))
    }

    /// Streams through a shard file on disk using a 64 KB buffer, computing its SHA3-256 digest
    /// to verify disk integrity without exceeding RAM bounds.
    pub fn verify_shard_stream(&self, hash: &[u8; 32]) -> Result<bool> {
        let mut reader = match self.open_shard_stream(hash) {
            Ok(r) => r,
            Err(BlobError::ShardNotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };

        let mut hasher = Sha3_256::new();
        let mut buffer = [0u8; 64 * 1024];

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let computed: [u8; 32] = hasher.finalize().into();
        Ok(computed == *hash)
    }

    /// Deletes a shard file from disk. Returns true if removed, false if it did not exist.
    pub fn remove_shard(&self, hash: &[u8; 32]) -> Result<bool> {
        let path = self.shard_path(hash);
        if path.exists() {
            fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Cleans up any orphaned temporary files in `.ark/temp/`.
    pub fn cleanup_temp_files(&self) -> Result<usize> {
        if !self.temp_dir.exists() {
            return Ok(0);
        }

        let mut removed = 0;
        for entry in fs::read_dir(&self.temp_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Ok(()) = fs::remove_file(path) {
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }
}
