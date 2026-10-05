//! Anti-Replay with Dual Cuckoo Filter in RAM (<24 MB footprint).
//! Rotates current and previous generation filters every epoch to prune expired records without locking stalls.

use ark_core::error::{ArkError, Result};
use ark_core::traits::AntiReplayFilter;
use cuckoofilter::CuckooFilter;
use parking_lot::RwLock;
use std::collections::hash_map::DefaultHasher;

const DEFAULT_CAPACITY: usize = 1_000_000;

pub struct DualCuckooAntiReplay {
    current: RwLock<CuckooFilter<DefaultHasher>>,
    previous: RwLock<CuckooFilter<DefaultHasher>>,
}

impl DualCuckooAntiReplay {
    pub fn new() -> Self {
        Self {
            current: RwLock::new(CuckooFilter::with_capacity(DEFAULT_CAPACITY)),
            previous: RwLock::new(CuckooFilter::with_capacity(DEFAULT_CAPACITY)),
        }
    }

    /// Rotate generations: current becomes previous, and a fresh current is initialized.
    pub fn rotate_generation(&self) {
        let mut cur_guard = self.current.write();
        let mut prev_guard = self.previous.write();
        
        *prev_guard = std::mem::replace(&mut *cur_guard, CuckooFilter::with_capacity(DEFAULT_CAPACITY));
    }
}

impl Default for DualCuckooAntiReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayFilter for DualCuckooAntiReplay {
    /// Returns Ok(true) if the item is fresh and inserted.
    /// Returns Err(ArkError::ReplayDetected) if present in current or previous filter.
    fn check_and_insert(&self, item: &[u8]) -> Result<bool> {
        // Read locks to check existence
        {
            let cur = self.current.read();
            if cur.contains(item) {
                return Err(ArkError::ReplayDetected);
            }
        }
        {
            let prev = self.previous.read();
            if prev.contains(item) {
                return Err(ArkError::ReplayDetected);
            }
        }

        // Insert into current filter
        let mut cur = self.current.write();
        if cur.contains(item) {
            return Err(ArkError::ReplayDetected);
        }

        cur.add(item)
            .map_err(|_| ArkError::Internal("Cuckoo filter capacity exceeded".into()))?;

        Ok(true)
    }
}
