pub mod error;
pub mod ipam;
pub mod tun;

pub use error::{Result, VpnError};
pub use ipam::{DeterministicIpam, DualStackAddress};
pub use tun::{MockTunAdapter, NativeTunAdapter, PacketDirection, VirtualTunAdapter, DEFAULT_SAFE_MTU, TCP_MSS_FLOOR};

/// [Preparação para v1.0] Malha overlay Zero-Trust em user-space.
pub struct ZeroTrustOverlayMesh {
    // Overlay mesh routing state
}

impl ZeroTrustOverlayMesh {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ZeroTrustOverlayMesh {
    fn default() -> Self {
        Self::new()
    }
}
