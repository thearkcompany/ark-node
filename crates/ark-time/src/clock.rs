//! Canonical Peer-Median-Time (PMT) Clock Capability and Adapters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::peer_median::PeerMedianTime;

/// Canonical capability trait for querying network consensus time (Peer-Median-Time).
pub trait PmtClock: Send + Sync {
    /// Returns current Peer-Median-Time in Unix seconds.
    fn now_pmt(&self) -> u64;
}

/// Production PMT clock combining host system clock with PeerMedianTime network offset.
pub struct SystemPmtClock {
    peer_median: Arc<PeerMedianTime>,
}

impl SystemPmtClock {
    /// Create a new SystemPmtClock backed by the given PeerMedianTime instance.
    pub fn new(peer_median: Arc<PeerMedianTime>) -> Self {
        Self { peer_median }
    }

    /// Access the underlying PeerMedianTime instance.
    pub fn peer_median(&self) -> &Arc<PeerMedianTime> {
        &self.peer_median
    }
}

impl PmtClock for SystemPmtClock {
    fn now_pmt(&self) -> u64 {
        let local_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.peer_median.network_time_secs(local_secs)
    }
}

/// Deterministic atomic mock clock providing zero-sleep time simulation.
#[derive(Debug, Default)]
pub struct MockPmtClock {
    current_time: AtomicU64,
}

impl MockPmtClock {
    /// Create a new MockPmtClock with an initial timestamp in seconds.
    pub fn new(initial_secs: u64) -> Self {
        Self {
            current_time: AtomicU64::new(initial_secs),
        }
    }

    /// Set PMT to an exact Unix timestamp in seconds.
    pub fn set_time(&self, secs: u64) {
        self.current_time.store(secs, Ordering::SeqCst);
    }

    /// Advance PMT forward by delta seconds and return new timestamp.
    pub fn advance(&self, delta_secs: u64) -> u64 {
        self.current_time.fetch_add(delta_secs, Ordering::SeqCst) + delta_secs
    }
}

impl PmtClock for MockPmtClock {
    fn now_pmt(&self) -> u64 {
        self.current_time.load(Ordering::SeqCst)
    }
}
