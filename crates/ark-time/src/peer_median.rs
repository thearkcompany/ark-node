//! Peer-Median-Time (PMT) consensus in user-space without reliance on centralized NTP.

use parking_lot::RwLock;
use std::collections::HashMap;

pub struct PeerMedianTime {
    peer_samples: RwLock<HashMap<[u8; 16], i64>>,
}

impl PeerMedianTime {
    pub fn new() -> Self {
        Self {
            peer_samples: RwLock::new(HashMap::new()),
        }
    }

    /// Record a time offset sample from a trusted or connected peer
    pub fn record_peer_offset(&self, peer_id: [u8; 16], offset_secs: i64) {
        let mut map = self.peer_samples.write();
        map.insert(peer_id, offset_secs);
    }

    /// Calculate the median offset among active peer samples
    pub fn calculate_median_offset(&self) -> i64 {
        let map = self.peer_samples.read();
        if map.is_empty() {
            return 0;
        }

        let mut offsets: Vec<i64> = map.values().copied().collect();
        offsets.sort_unstable();

        let mid = offsets.len() / 2;
        if offsets.len().is_multiple_of(2) {
            (offsets[mid - 1] + offsets[mid]) / 2
        } else {
            offsets[mid]
        }
    }

    /// Get current network-adjusted consensus time (local seconds + median offset)
    pub fn network_time_secs(&self, local_secs: u64) -> u64 {
        let median = self.calculate_median_offset();
        (local_secs as i64 + median).max(0) as u64
    }
}

impl Default for PeerMedianTime {
    fn default() -> Self {
        Self::new()
    }
}
