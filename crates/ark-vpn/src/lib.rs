pub mod acl;
pub mod engine;
pub mod error;
pub mod framing;
pub mod ipam;
pub mod pqmt;
pub mod relay;
pub mod roaming;
pub mod tun;

pub use acl::{
    AclEngine, AclVerdict, IpProtocol, VpnAction, VpnAclStats, VpnPeerInfo, VpnSecurityPolicy,
};
pub use engine::{
    RouteMode, VpnEngine, VpnEngineConfig, VpnEngineMetrics, VpnEngineStatus,
};
pub use error::{Result, VpnError};
pub use framing::{
    deframe_fast_packet, deframe_micro_packet, frame_fast_packet, frame_micro_packet,
    MicroHeader, KIND_VPN_DATA, KIND_VPN_HANDSHAKE, MICRO_HEADER_SIZE,
};
pub use ipam::{DeterministicIpam, DualStackAddress};
pub use pqmt::{HandshakeInit, HandshakeResp, PqmtEngine, VpnSession};
pub use relay::{
    BlindRelayNode, ForwardedPacket, RelayConfig, RelayEnvelope, RelayForwarder, RelayProfile,
    RelayStats,
};
pub use roaming::{PeerSessionEntry, RoamingTable, DEFAULT_SESSION_IDLE_TIMEOUT};
pub use tun::{
    MockTunAdapter, NativeTunAdapter, PacketDirection, VirtualTunAdapter, DEFAULT_SAFE_MTU,
    TCP_MSS_FLOOR,
};

use std::sync::Arc;
use ark_crypto::identity::PersistentIdentity;

/// [Preparação para v1.0] Malha overlay Zero-Trust em user-space.
/// Fachada de alto nível sobre a `VpnEngine`.
pub struct ZeroTrustOverlayMesh {
    engine: Option<VpnEngine>,
}

impl ZeroTrustOverlayMesh {
    pub fn new() -> Self {
        Self { engine: None }
    }

    /// Cria uma nova malha overlay com adaptador TUN virtual e identidade soberana.
    pub fn with_tun(identity: PersistentIdentity, tun: Arc<dyn VirtualTunAdapter>) -> Self {
        let config = VpnEngineConfig::default();
        let engine = VpnEngine::new(identity, tun, config);
        Self {
            engine: Some(engine),
        }
    }

    /// Cria uma nova malha overlay com configuração personalizada.
    pub fn with_config(
        identity: PersistentIdentity,
        tun: Arc<dyn VirtualTunAdapter>,
        config: VpnEngineConfig,
    ) -> Self {
        let engine = VpnEngine::new(identity, tun, config);
        Self {
            engine: Some(engine),
        }
    }

    /// Inicia a malha overlay.
    pub async fn start(&mut self) -> Result<()> {
        if let Some(ref engine) = self.engine {
            engine.start().await?;
        }
        Ok(())
    }

    /// Para a malha overlay.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(ref engine) = self.engine {
            engine.stop().await?;
        }
        Ok(())
    }

    /// Retorna se o overlay mesh está ativo.
    pub fn is_running(&self) -> bool {
        self.engine
            .as_ref()
            .map(|e| e.status() == VpnEngineStatus::Running)
            .unwrap_or(false)
    }

    /// Acesso direto à VpnEngine subjacente.
    pub fn engine(&self) -> Option<&VpnEngine> {
        self.engine.as_ref()
    }
}

impl Default for ZeroTrustOverlayMesh {
    fn default() -> Self {
        Self::new()
    }
}

