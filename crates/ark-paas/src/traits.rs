//! Mockable backend traits and in-memory test doubles for Ark Host-ABI.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::error::Result;

/// Trait for Key-Value storage capability.
pub trait KvStoreBackend: Send + Sync {
    /// Retrieve value by key. Returns Ok(None) if key doesn't exist.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    /// Set key to value.
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()>;
}

/// Trait for Blob retrieval capability.
pub trait BlobReaderBackend: Send + Sync {
    /// Read chunk of blob at `offset` with maximum `max_len` bytes.
    /// Returns Ok(None) if blob with `cid` does not exist.
    fn read(&self, cid: &[u8], offset: u64, max_len: usize) -> Result<Option<Vec<u8>>>;
}

/// Trait for emitting/dispatching envelopes.
pub trait EnvelopeEmitterBackend: Send + Sync {
    /// Emit an encoded ArkEnvelope.
    fn emit(&self, envelope_bytes: &[u8]) -> Result<()>;
}

/// Trait for querying Peer-Median-Time (PMT) consensus timestamp.
pub trait PmtClockBackend: Send + Sync {
    /// Current PMT timestamp in seconds (or unix seconds).
    fn now_pmt(&self) -> u64;
}

/// In-memory mock implementation of `KvStoreBackend`.
#[derive(Default, Clone)]
pub struct InMemoryKvStore {
    store: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl InMemoryKvStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_initial(data: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            store: Arc::new(Mutex::new(data)),
        }
    }
}

impl KvStoreBackend for InMemoryKvStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let store = self.store.lock().unwrap();
        Ok(store.get(key).cloned())
    }

    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

/// In-memory mock implementation of `BlobReaderBackend`.
#[derive(Default, Clone)]
pub struct InMemoryBlobReader {
    blobs: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl InMemoryBlobReader {
    pub fn new() -> Self {
        Self {
            blobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, cid: Vec<u8>, data: Vec<u8>) {
        self.blobs.lock().unwrap().insert(cid, data);
    }
}

impl BlobReaderBackend for InMemoryBlobReader {
    fn read(&self, cid: &[u8], offset: u64, max_len: usize) -> Result<Option<Vec<u8>>> {
        let blobs = self.blobs.lock().unwrap();
        match blobs.get(cid) {
            Some(data) => {
                let offset = offset as usize;
                if offset >= data.len() {
                    Ok(Some(Vec::new()))
                } else {
                    let end = std::cmp::min(offset + max_len, data.len());
                    Ok(Some(data[offset..end].to_vec()))
                }
            }
            None => Ok(None),
        }
    }
}

/// In-memory mock implementation of `EnvelopeEmitterBackend`.
#[derive(Default, Clone)]
pub struct InMemoryEnvelopeEmitter {
    emitted: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl InMemoryEnvelopeEmitter {
    pub fn new() -> Self {
        Self {
            emitted: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_emitted(&self) -> Vec<Vec<u8>> {
        self.emitted.lock().unwrap().clone()
    }
}

impl EnvelopeEmitterBackend for InMemoryEnvelopeEmitter {
    fn emit(&self, envelope_bytes: &[u8]) -> Result<()> {
        self.emitted.lock().unwrap().push(envelope_bytes.to_vec());
        Ok(())
    }
}

/// In-memory mock implementation of `PmtClockBackend`.
#[derive(Clone)]
pub struct InMemoryPmtClock {
    time: Arc<Mutex<u64>>,
}

impl InMemoryPmtClock {
    pub fn new(initial_time: u64) -> Self {
        Self {
            time: Arc::new(Mutex::new(initial_time)),
        }
    }

    pub fn set_time(&self, new_time: u64) {
        *self.time.lock().unwrap() = new_time;
    }
}

impl Default for InMemoryPmtClock {
    fn default() -> Self {
        Self::new(1700000000)
    }
}

impl PmtClockBackend for InMemoryPmtClock {
    fn now_pmt(&self) -> u64 {
        *self.time.lock().unwrap()
    }
}

impl crate::cron::PmtClock for InMemoryPmtClock {
    fn now_pmt(&self) -> u64 {
        *self.time.lock().unwrap()
    }
}

impl PmtClockBackend for crate::cron::MockPmtClock {
    fn now_pmt(&self) -> u64 {
        crate::cron::PmtClock::now_pmt(self)
    }
}

