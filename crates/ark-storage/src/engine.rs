use std::path::{Path, PathBuf};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use ark_protocol::envelope::ArkEnvelope;
use sha3::{Digest, Sha3_256};

use crate::config::StorageConfig;
use crate::error::{ArkStorageError, Result};
use crate::retention::{classify_retention, RetentionClass, RetentionOutcome};

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
            RetentionClass::Class2Replaceable
            | RetentionClass::Class3ParamReplaceable
            | RetentionClass::Class4BoundedTtl
            | RetentionClass::Class5StrictWorm => {
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
        if let Some(bytes) = self
            .class1_append
            .get(id)
            .map_err(|e| ArkStorageError::Database(e.to_string()))?
        {
            let env = ArkEnvelope::decode_from_slice(&bytes)
                .map_err(|e| ArkStorageError::Serialization(e.to_string()))?;
            return Ok(Some(env));
        }
        Ok(None)
    }

    pub fn keyspace_count(&self) -> usize {
        self.db.keyspace_count()
    }
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
