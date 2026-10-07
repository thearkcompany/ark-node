pub mod error;
pub mod framing;
pub mod ipam;
pub mod pqmt;
pub mod tun;

pub use error::{Result, VpnError};
pub use framing::{
    deframe_fast_packet, deframe_micro_packet, frame_fast_packet, frame_micro_packet,
    MicroHeader, KIND_VPN_DATA, KIND_VPN_HANDSHAKE, MICRO_HEADER_SIZE,
};
pub use ipam::{DeterministicIpam, DualStackAddress};
pub use pqmt::{HandshakeInit, HandshakeResp, PqmtEngine, VpnSession};
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
