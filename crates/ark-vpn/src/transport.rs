//! Transport seam abstractions and adapters for VpnEngine.
//!
//! Provides `VpnTransportSink` capability trait and `ChannelTransportSink` bounded in-memory adapter.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::engine::OutboundPacket;
use crate::error::{Result, VpnError};

/// Abstract capability trait at the outbound network seam of VpnEngine.
///
/// Dispatches encapsulated `OutboundPacket` messages across the physical network.
#[async_trait]
pub trait VpnTransportSink: Send + Sync {
    /// Send an outbound encapsulated packet across the network transport.
    async fn send_packet(&self, packet: OutboundPacket) -> Result<()>;
}

/// Bounded in-memory channel adapter satisfying `VpnTransportSink`.
///
/// Used for deterministic CI testing, sandboxes, and loopback verification.
pub struct ChannelTransportSink {
    tx: mpsc::Sender<OutboundPacket>,
    rx: tokio::sync::Mutex<Option<mpsc::Receiver<OutboundPacket>>>,
}

impl ChannelTransportSink {
    /// Default bounded channel capacity (1,024 packets).
    pub const DEFAULT_CAPACITY: usize = 1024;

    /// Create a new `ChannelTransportSink` with specified bounded capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx: tokio::sync::Mutex::new(Some(rx)),
        }
    }

    /// Take the receiving half of the channel (callable once).
    pub fn take_receiver(&self) -> Option<mpsc::Receiver<OutboundPacket>> {
        let mut guard = self.rx.try_lock().ok()?;
        guard.take()
    }
}

impl Default for ChannelTransportSink {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

#[async_trait]
impl VpnTransportSink for ChannelTransportSink {
    async fn send_packet(&self, packet: OutboundPacket) -> Result<()> {
        self.tx
            .send(packet)
            .await
            .map_err(|_| VpnError::InterfaceClosed)
    }
}
