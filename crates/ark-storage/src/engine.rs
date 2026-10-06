use std::path::{Path, PathBuf};
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use ark_protocol::envelope::ArkEnvelope;
use sha3::{Digest, Sha3_256};

use crate::config::StorageConfig;
use crate::error::{ArkStorageError, Result};
use crate::retention::{
    classify_retention, get_envelope_kind, get_envelope_param_d, RetentionClass, RetentionOutcome,
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
    pub fn open<P: AsRef<Path>>(path: P, config: StorageConfig) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path_buf)?;

        let cache_size_bytes = (config.block_cache_mb as u64) * 1024 * 1024;
        let memtable_max_bytes = (config.write_buffer_mb as u64) * 1024 * 1024;

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
                let new_id = compute_envelope_id(envelope)?;
                let new_ts = envelope.timestamp;

                // Check existing record under (sender_key_id, kind)
                if let Some(existing_bytes) = self
                    .class2_replaceable
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
                        self.class2_replaceable
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
                    self.class2_replaceable
                        .insert(key, new_bytes)
                        .map_err(|e| ArkStorageError::Database(e.to_string()))?;
                    Ok(RetentionOutcome::Stored)
                }
            }
            RetentionClass::Class3ParamReplaceable => {
                let sender_key_id = extract_sender_key_id(envelope);
                let kind = get_envelope_kind(envelope);
                let param_d = get_envelope_param_d(envelope).unwrap_or_default();
                let key = make_class3_key(&sender_key_id, kind, &param_d);
                let new_id = compute_envelope_id(envelope)?;
                let new_ts = envelope.timestamp;

                // Check existing record under (sender_key_id, kind, param_d)
                if let Some(existing_bytes) = self
                    .class3_param_d
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
                        self.class3_param_d
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
                    self.class3_param_d
                        .insert(key, new_bytes)
                        .map_err(|e| ArkStorageError::Database(e.to_string()))?;
                    Ok(RetentionOutcome::Stored)
                }
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
            RetentionClass::Class4BoundedTtl => {
                let id = compute_envelope_id(envelope)?;
                let bytes = envelope
                    .encode_to_vec()
                    .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
                self.class1_append
                    .insert(id, bytes)
                    .map_err(|e| ArkStorageError::Database(e.to_string()))?;
                Ok(RetentionOutcome::Stored)
            }
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

        Ok(None)
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

        Ok(false)
    }

    pub fn keyspace_count(&self) -> usize {
        self.db.keyspace_count()
    }
}

pub fn extract_sender_key_id(envelope: &ArkEnvelope) -> [u8; 16] {
    if envelope.fast_header.len() >= 32 {
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&envelope.fast_header[16..32]);
        return key_id;
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
