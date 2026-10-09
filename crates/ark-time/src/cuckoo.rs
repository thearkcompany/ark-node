//! Anti-Replay with Dual Cuckoo Filter in RAM (<24 MB footprint).
//! Rotates current and previous generation filters every epoch to prune expired records without locking stalls.

use ark_core::error::{ArkError, Result};
use ark_core::traits::AntiReplayFilter;
use cuckoofilter::CuckooFilter;
use parking_lot::RwLock;
use std::collections::hash_map::DefaultHasher;

pub const DEFAULT_CAPACITY: usize = 2_097_152; // 2^21 buckets = 8 MB per filter => 16 MB total <= 24 MB ceiling

pub struct DualCuckooAntiReplay {
    capacity: usize,
    current: RwLock<CuckooFilter<DefaultHasher>>,
    previous: RwLock<CuckooFilter<DefaultHasher>>,
}

impl DualCuckooAntiReplay {
    /// Initialize with the default capacity ensuring <= 24 MB total memory allocation.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Initialize with a custom capacity (number of items), capped strictly to <= 24 MB total RAM.
    pub fn with_capacity(capacity: usize) -> Self {
        let bucket_count = std::cmp::max(1, capacity.next_power_of_two() / 4);
        let total_bytes = bucket_count * 4 * 2;
        assert!(
            total_bytes <= 24 * 1024 * 1024,
            "DualCuckooAntiReplay capacity exceeds 24 MB ceiling (estimated: {} bytes)",
            total_bytes
        );

        Self {
            capacity,
            current: RwLock::new(CuckooFilter::with_capacity(capacity)),
            previous: RwLock::new(CuckooFilter::with_capacity(capacity)),
        }
    }

    /// Estimated memory allocated in bytes across both generational filters.
    /// In cuckoofilter-0.5, each bucket contains 4 single-byte fingerprints (4 bytes per bucket).
    /// Number of buckets per filter is `max(1, capacity.next_power_of_two() / 4)`.
    pub fn estimated_memory_bytes(&self) -> usize {
        let bucket_count = std::cmp::max(1, self.capacity.next_power_of_two() / 4);
        let per_filter_bytes = bucket_count * 4;
        per_filter_bytes * 2
    }

    /// Rotate generations: current becomes previous, and a fresh current is initialized.
    pub fn rotate_generation(&self) {
        let mut cur_guard = self.current.write();
        let mut prev_guard = self.previous.write();

        *prev_guard =
            std::mem::replace(&mut *cur_guard, CuckooFilter::with_capacity(self.capacity));
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
    /// Returns Err(ArkError::ReplayFilterFull) when the filter is saturated (ADR-0003).
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

        cur.add(item).map_err(|_| ArkError::ReplayFilterFull)?;

        Ok(true)
    }
}
