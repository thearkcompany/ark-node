use std::path::{Path, PathBuf};
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use ark_protocol::envelope::ArkEnvelope;
use sha3::{Digest, Sha3_256};

use crate::config::StorageConfig;
use crate::error::{ArkStorageError, Result};
use crate::retention::{
    classify_retention, get_envelope_expiration, get_envelope_kind, get_envelope_param_d,
    RetentionClass, RetentionOutcome,
};

pub struct StorageEngine {
    db: Database,
    pub(crate) path: PathBuf,
    pub(crate) class1_append: Keyspace,
    pub(crate) class2_replaceable: Keyspace,
    pub(crate) class3_param_d: Keyspace,
    pub(crate) class4_ttl: Keyspace,
    pub(crate) class4_index: Keyspace,
    pub(crate) class5_worm: Keyspace,
}

impl StorageEngine {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn open<P: AsRef<Path>>(path: P, config: StorageConfig) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path_buf)?;

        let cache_size_bytes = (config.block_cache_mb as u64) * 1024 * 1024;
        // Bound memtable size per keyspace so total RAM across 6 active keyspaces
        // strictly remains <= config.write_buffer_mb (e.g. 16 MB / 6 ≈ 2.66 MB)
        let memtable_max_bytes = std::cmp::max(
            512 * 1024,
            ((config.write_buffer_mb as u64) * 1024 * 1024) / 6,
        );

        let db = Database::builder(&path_buf)
            .cache_size(cache_size_bytes)
            .open()
            .map_err(|e| ArkStorageError::Database(e.to_string()))?;

        let make_opts = move || {
            KeyspaceCreateOptions::default().max_memtable_size(memtable_max_bytes)
        };

        let class1_append = db
            .keyspace("class1_append", make_opts)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?;

        let class2_replaceable = db
            .keyspace("class2_replaceable", make_opts)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?;

        let class3_param_d = db
            .keyspace("class3_param_d", make_opts)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?;

        let class4_ttl = db
            .keyspace("class4_ttl", make_opts)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?;

        let class4_index = db
            .keyspace("class4_index", make_opts)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?;

        let class5_worm = db
            .keyspace("class5_worm", make_opts)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?;

        Ok(Self {
            db,
            path: path_buf,
            class1_append,
            class2_replaceable,
            class3_param_d,
            class4_ttl,
            class4_index,
            class5_worm,
        })
    }

    /// Primary ingest API routing incoming envelopes according to GCP-06 retention classes.
    pub fn put_envelope(&self, envelope: &ArkEnvelope) -> Result<RetentionOutcome> {
        let class = classify_retention(envelope);

        match class {
            RetentionClass::Class0Ephemeral => {
                // Class 0: Ephemeral / RAM-only events bypass disk write completely.
                Ok(RetentionOutcome::EphemeralPassed)
            }
            RetentionClass::Class1AppendOnly => {
                let id = compute_envelope_id(envelope)?;
                let bytes = envelope
                    .encode_to_vec()
                    .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
                self.class1_append
                    .insert(id, bytes)
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?;
                Ok(RetentionOutcome::Stored)
            }
            RetentionClass::Class2Replaceable => {
                let sender_key_id = extract_sender_key_id(envelope);
                let kind = get_envelope_kind(envelope);
                let key = make_class2_key(&sender_key_id, kind);
                self.apply_bivariate_lww(&self.class2_replaceable, key, envelope)
            }
            RetentionClass::Class3ParamReplaceable => {
                let sender_key_id = extract_sender_key_id(envelope);
                let kind = get_envelope_kind(envelope);
                let param_d = get_envelope_param_d(envelope).unwrap_or_default();
                let key = make_class3_key(&sender_key_id, kind, &param_d);
                self.apply_bivariate_lww(&self.class3_param_d, key, envelope)
            }
            RetentionClass::Class4BoundedTtl => {
                let id = compute_envelope_id(envelope)?;
                let expiration = get_envelope_expiration(envelope).unwrap_or(0);
                let bytes = envelope
                    .encode_to_vec()
                    .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;

                // Store in class4_ttl indexed by id
                self.class4_ttl
                    .insert(id, bytes)
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?;

                // Store in class4_index: [expiration_ts: 8B BE] || [id: 32B] -> empty
                let index_key = make_class4_index_key(expiration, &id);
                self.class4_index
                    .insert(index_key, &[])
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?;

                Ok(RetentionOutcome::Stored)
            }
            RetentionClass::Class5StrictWorm => {
                let id = compute_envelope_id(envelope)?;
                let new_bytes = envelope
                    .encode_to_vec()
                    .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;

                // Check if already exists in WORM storage
                if let Some(existing_bytes) = self
                    .class5_worm
                    .get(&id)
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?
                {
                    if existing_bytes.as_ref() == new_bytes.as_slice() {
                        return Ok(RetentionOutcome::IdempotentDuplicate);
                    } else {
                        return Err(ArkStorageError::WormViolation(format!(
                            "Divergent payload write rejected for WORM id {:x?}",
                            &id[..8]
                        )));
                    }
                }

                // Insert into WORM keyspace
                self.class5_worm
                    .insert(id, new_bytes)
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?;

                // Class 5 forces immediate synchronous fsync to protect equivocation proofs
                self.db
                    .persist(PersistMode::SyncAll)
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?;

                Ok(RetentionOutcome::Stored)
            }
        }
    }

    fn apply_bivariate_lww(
        &self,
        keyspace: &Keyspace,
        key: Vec<u8>,
        envelope: &ArkEnvelope,
    ) -> Result<RetentionOutcome> {
        let new_id = compute_envelope_id(envelope)?;
        let new_ts = envelope.timestamp;

        if let Some(existing_bytes) = keyspace
            .get(&key)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let existing_env = ArkEnvelope::decode_from_slice(&existing_bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            let existing_id = compute_envelope_id(&existing_env)?;
            let existing_ts = existing_env.timestamp;

            // Deterministic Bivariate LWW: max(timestamp) || max(id)
            if (new_ts > existing_ts) || (new_ts == existing_ts && new_id > existing_id) {
                let new_bytes = envelope
                    .encode_to_vec()
                    .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
                keyspace
                    .insert(key, new_bytes)
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?;
                Ok(RetentionOutcome::Replaced)
            } else {
                Ok(RetentionOutcome::SupersededLww)
            }
        } else {
            let new_bytes = envelope
                .encode_to_vec()
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            keyspace
                .insert(key, new_bytes)
                .map_err(|e| ArkStorageError::Database(e.to_string()))?;
            Ok(RetentionOutcome::Stored)
        }
    }

    /// Retrieve an envelope by its canonical 32-byte SHA3-256 id.
    pub fn get_envelope(&self, id: &[u8; 32]) -> Result<Option<ArkEnvelope>> {
        // Check Class 1
        if let Some(bytes) = self
            .class1_append
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            return Ok(Some(env));
        }

        // Check Class 4: TTL with lazy expiration on read
        if let Some(bytes) = self
            .class4_ttl
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;

            if let Some(expiration) = get_envelope_expiration(&env) {
                let current_time_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                let current_time_sec = current_time_ms / 1000;

                // Support expiration in either seconds or milliseconds:
                // if expiration < 10_000_000_000, treat as seconds, otherwise ms
                let is_expired = if expiration < 10_000_000_000 {
                    current_time_sec >= expiration
                } else {
                    current_time_ms >= expiration
                };

                if is_expired {
                    return Ok(None);
                }
            }

            return Ok(Some(env));
        }

        // Check Class 5
        if let Some(bytes) = self
            .class5_worm
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            return Ok(Some(env));
        }

        // Check Class 2: Replaceable
        for item in self.class2_replaceable.iter() {
            let val = item.value().map_err(|e| ArkStorageError::Database(e.to_string()))?;
            let env = ArkEnvelope::decode_from_slice(&val)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            if let Ok(env_id) = compute_envelope_id(&env) {
                if &env_id == id {
                    return Ok(Some(env));
                }
            }
        }

        // Check Class 3: Parameterized Replaceable
        for item in self.class3_param_d.iter() {
            let val = item.value().map_err(|e| ArkStorageError::Database(e.to_string()))?;
            let env = ArkEnvelope::decode_from_slice(&val)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            if let Ok(env_id) = compute_envelope_id(&env) {
                if &env_id == id {
                    return Ok(Some(env));
                }
            }
        }

        Ok(None)
    }

    /// Retrieve Class 4 envelope with explicit current_time reference for lazy expiration testing.
    pub fn get_envelope_at_time(
        &self,
        id: &[u8; 32],
        current_time: u64,
    ) -> Result<Option<ArkEnvelope>> {
        if let Some(bytes) = self
            .class4_ttl
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;

            if let Some(expiration) = get_envelope_expiration(&env) {
                if current_time >= expiration {
                    return Ok(None);
                }
            }

            return Ok(Some(env));
        }

        self.get_envelope(id)
    }

    /// Point lookup for Class 2 Simple Replaceable record by sender_key_id and kind.
    pub fn get_replaceable(
        &self,
        sender_key_id: &[u8; 16],
        kind: u32,
    ) -> Result<Option<ArkEnvelope>> {
        let key = make_class2_key(sender_key_id, kind);
        if let Some(bytes) = self
            .class2_replaceable
            .get(&key)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            return Ok(Some(env));
        }
        Ok(None)
    }

    /// Point lookup for Class 3 Parameterized Replaceable record by sender_key_id, kind, and param_d.
    pub fn get_param_d(
        &self,
        sender_key_id: &[u8; 16],
        kind: u32,
        param_d: &[u8],
    ) -> Result<Option<ArkEnvelope>> {
        let key = make_class3_key(sender_key_id, kind, param_d);
        if let Some(bytes) = self
            .class3_param_d
            .get(&key)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            return Ok(Some(env));
        }
        Ok(None)
    }

    /// Prune expired Class 4 records whose expiration timestamp <= current_time.
    /// Returns the number of reclaimed records.
    pub fn sweep_expired(&self, current_time: u64) -> Result<usize> {
        let mut expired_keys = Vec::new();
        let mut expired_ids = Vec::new();

        for guard in self.class4_index.iter() {
            let key = guard.key().map_err(|e| ArkStorageError::Database(e.to_string()))?;
            if key.len() == 40 {
                let exp_ts = u64::from_be_bytes(key[..8].try_into().unwrap());
                if exp_ts <= current_time {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&key[8..40]);
                    expired_keys.push(key.to_vec());
                    expired_ids.push(id);
                } else {
                    // Since index is lexicographically ordered by expiration_ts (big-endian),
                    // once exp_ts > current_time, all subsequent entries are in the future!
                    break;
                }
            }
        }

        let reclaimed_count = expired_ids.len();

        for (key, id) in expired_keys.into_iter().zip(expired_ids) {
            self.class4_index
                .remove(key)
                .map_err(|e| ArkStorageError::Database(e.to_string()))?;
            self.class4_ttl
                .remove(id)
                .map_err(|e| ArkStorageError::Database(e.to_string()))?;
        }

        Ok(reclaimed_count)
    }

    /// Delete an envelope by id. Fails with WormViolation if envelope is Class 5 WORM.
    pub fn delete_envelope(&self, id: &[u8; 32]) -> Result<bool> {
        // Check Class 5 first: deletion strictly prohibited
        if self
            .class5_worm
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
            .is_some()
        {
            return Err(ArkStorageError::WormViolation(format!(
                "Attempted deletion of immutable WORM record {:x?}",
                &id[..8]
            )));
        }

        // Check Class 1
        if self
            .class1_append
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
            .is_some()
        {
            self.class1_append
                .remove(id)
                .map_err(|e| ArkStorageError::Database(e.to_string()))?;
            return Ok(true);
        }

        // Check Class 4
        if let Some(bytes) = self
            .class4_ttl
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            let exp = get_envelope_expiration(&env).unwrap_or(0);
            let idx_key = make_class4_index_key(exp, id);

            self.class4_ttl
                .remove(id)
                .map_err(|e| ArkStorageError::Database(e.to_string()))?;
            self.class4_index
                .remove(idx_key)
                .map_err(|e| ArkStorageError::Database(e.to_string()))?;
            return Ok(true);
        }

        // Check Class 2
        for item in self.class2_replaceable.iter() {
            let (key, val) = item.into_inner().map_err(|e| ArkStorageError::Database(e.to_string()))?;
            let env = ArkEnvelope::decode_from_slice(&val)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            if let Ok(env_id) = compute_envelope_id(&env) {
                if &env_id == id {
                    self.class2_replaceable
                        .remove(key)
                        .map_err(|e| ArkStorageError::Database(e.to_string()))?;
                    return Ok(true);
                }
            }
        }

        // Check Class 3
        for item in self.class3_param_d.iter() {
            let (key, val) = item.into_inner().map_err(|e| ArkStorageError::Database(e.to_string()))?;
            let env = ArkEnvelope::decode_from_slice(&val)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            if let Ok(env_id) = compute_envelope_id(&env) {
                if &env_id == id {
                    self.class3_param_d
                        .remove(key)
                        .map_err(|e| ArkStorageError::Database(e.to_string()))?;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub fn keyspace_count(&self) -> usize {
        self.db.keyspace_count()
    }

    /// Spawns a background worker thread that periodically invokes `sweep_expired`.
    pub fn spawn_background_sweeper(
        engine: std::sync::Arc<Self>,
        interval: std::time::Duration,
    ) -> BackgroundSweeperHandle {
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        let thread = std::thread::Builder::new()
            .name("ark-storage-sweeper".to_string())
            .spawn(move || {
                let mut last_sweep = std::time::Instant::now();
                while !shutdown_clone.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    if last_sweep.elapsed() >= interval {
                        let current_time_sec = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let _ = engine.sweep_expired(current_time_sec);
                        last_sweep = std::time::Instant::now();
                    }
                }
            })
            .expect("failed to spawn background sweeper thread");

        BackgroundSweeperHandle {
            shutdown,
            handle: Some(thread),
        }
    }
}

/// Handle to an active background sweeper task.
pub struct BackgroundSweeperHandle {
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl BackgroundSweeperHandle {
    /// Signals the background sweeper to stop and waits for the thread to exit.
    pub fn stop(mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for BackgroundSweeperHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

pub fn extract_sender_key_id(envelope: &ArkEnvelope) -> [u8; 16] {
    if envelope.fast_header.len() >= 64 {
        if let Ok(bytes) = envelope.fast_header[..64].try_into() {
            if let Ok(hdr) = ark_core::FastHeader::from_bytes(bytes) {
                return hdr.sender_key_id;
            }
        }
    }
    if envelope.sender_id.len() >= 16 {
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&envelope.sender_id[..16]);
        return key_id;
    }
    [0u8; 16]
}

pub fn make_class2_key(sender_key_id: &[u8; 16], kind: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(20);
    key.extend_from_slice(sender_key_id);
    key.extend_from_slice(&kind.to_be_bytes());
    key
}

pub fn make_class3_key(sender_key_id: &[u8; 16], kind: u32, param_d: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(20 + param_d.len());
    key.extend_from_slice(sender_key_id);
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(param_d);
    key
}

pub fn make_class4_index_key(expiration: u64, id: &[u8; 32]) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&expiration.to_be_bytes());
    key[8..40].copy_from_slice(id);
    key
}

pub fn compute_envelope_id(envelope: &ArkEnvelope) -> Result<[u8; 32]> {
    let bytes = envelope
        .encode_to_vec()
        .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
    let mut hasher = Sha3_256::new();
    hasher.update(&bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}
