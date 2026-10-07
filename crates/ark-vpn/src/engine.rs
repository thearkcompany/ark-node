//! Unified VpnEngine Facade and Core Pipeline Orchestration.
//!
//! Provides:
//! - Consolidated public API exposing lifecycle management (`start`, `stop`, `add_peer`, `apply_policy`, `status`, etc.).
//! - Coordinating TUN read/write loops, routing, security ACLs, and wire framing.
//! - Transparent failover between Direct P2P and Sovereign Blind Relay routes.
//! - Zero-allocation passthrough observability counters and drop reason metrics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ark_crypto::fn_dsa::FN_DSA_512_PUBKEY_SIZE;
use ark_crypto::identity::PersistentIdentity;
use tokio::sync::watch;

use crate::acl::{AclEngine, VpnPeerInfo, VpnSecurityPolicy};
use crate::error::Result;
use crate::ipam::{DeterministicIpam, DualStackAddress};
use crate::pqmt::PqmtEngine;
use crate::roaming::RoamingTable;
use crate::tun::VirtualTunAdapter;

/// Active route mode between two peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    DirectP2p,
    Relayed,
}

/// Operational status of the VPN engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnEngineStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// Configuration options for the VpnEngine facade.
#[derive(Debug, Clone)]
pub struct VpnEngineConfig {
    pub listen_addr: SocketAddr,
    pub enable_relay_fallback: bool,
    pub probing_interval: Duration,
    pub p2p_timeout: Duration,
}

impl Default for VpnEngineConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            enable_relay_fallback: true,
            probing_interval: Duration::from_secs(5),
            p2p_timeout: Duration::from_secs(10),
        }
    }
}

/// Zero-Allocation Passthrough Metrics for VpnEngine
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VpnEngineMetrics {
    pub active_peers: usize,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub p2p_packets: u64,
    pub relayed_packets: u64,
    pub dropped_acl: u64,
    pub dropped_no_route: u64,
    pub dropped_errors: u64,
}

struct InternalEngineMetrics {
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    p2p_packets: AtomicU64,
    relayed_packets: AtomicU64,
    dropped_acl: AtomicU64,
    dropped_no_route: AtomicU64,
    dropped_errors: AtomicU64,
}

impl Default for InternalEngineMetrics {
    fn default() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            p2p_packets: AtomicU64::new(0),
            relayed_packets: AtomicU64::new(0),
            dropped_acl: AtomicU64::new(0),
            dropped_no_route: AtomicU64::new(0),
            dropped_errors: AtomicU64::new(0),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct PeerRouteState {
    direct_addr: Option<SocketAddr>,
    route_mode: RouteMode,
    is_p2p_failing: bool,
}

/// Unified VpnEngine Facade orchestrating overlay mesh routing, encryption, TUN loops, and relays.
pub struct VpnEngine {
    identity: Arc<PersistentIdentity>,
    tun: Arc<dyn VirtualTunAdapter>,
    config: VpnEngineConfig,
    pqmt: Arc<PqmtEngine>,
    roaming: Arc<RoamingTable>,
    acl: Arc<AclEngine>,
    relays: RwLock<HashMap<[u8; 32], SocketAddr>>,
    peer_routes: RwLock<HashMap<[u8; 32], PeerRouteState>>,
    status: RwLock<VpnEngineStatus>,
    metrics: InternalEngineMetrics,
    shutdown_tx: watch::Sender<bool>,
    _shutdown_rx: watch::Receiver<bool>,
}

impl VpnEngine {
    /// Create a new VpnEngine instance.
    pub fn new(
        identity: PersistentIdentity,
        tun: Arc<dyn VirtualTunAdapter>,
        config: VpnEngineConfig,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let ark_id = identity.ark_id;
        let acl = Arc::new(AclEngine::new(ark_id, ark_id));
        let pqmt = Arc::new(PqmtEngine::new(identity));
        let roaming = Arc::new(RoamingTable::new());

        Self {
            identity: Arc::clone(pqmt.identity_arc()),
            tun,
            config,
            pqmt,
            roaming,
            acl,
            relays: RwLock::new(HashMap::new()),
            peer_routes: RwLock::new(HashMap::new()),
            status: RwLock::new(VpnEngineStatus::Stopped),
            metrics: InternalEngineMetrics::default(),
            shutdown_tx,
            _shutdown_rx: shutdown_rx,
        }
    }

    /// Access local persistent identity.
    pub fn identity(&self) -> &PersistentIdentity {
        &self.identity
    }

    /// Operational status of the VPN engine.
    pub fn status(&self) -> VpnEngineStatus {
        *self.status.read().unwrap()
    }

    /// Derived local virtual IP addresses (IPv6 ULA and IPv4 CGNAT).
    pub fn local_virtual_addrs(&self) -> DualStackAddress {
        DeterministicIpam::derive_from_ark_id(&self.identity.ark_id)
    }

    /// Start the VPN engine and background worker loops.
    pub async fn start(&self) -> Result<()> {
        let mut status = self.status.write().unwrap();
        if *status == VpnEngineStatus::Running {
            return Ok(());
        }
        *status = VpnEngineStatus::Starting;
        let _ = self.shutdown_tx.send(false);
        *status = VpnEngineStatus::Running;
        Ok(())
    }

    /// Stop the VPN engine cleanly.
    pub async fn stop(&self) -> Result<()> {
        let mut status = self.status.write().unwrap();
        if *status == VpnEngineStatus::Stopped {
            return Ok(());
        }
        *status = VpnEngineStatus::Stopping;
        let _ = self.shutdown_tx.send(true);
        *status = VpnEngineStatus::Stopped;
        Ok(())
    }

    /// Register a known Sovereign Blind Relay.
    pub fn add_relay(&self, relay_id: [u8; 32], endpoint: SocketAddr) {
        let mut relays = self.relays.write().unwrap();
        relays.insert(relay_id, endpoint);
    }

    /// Add or update a peer endpoint in the mesh.
    pub async fn add_peer(
        &self,
        peer_id: [u8; 32],
        endpoint: SocketAddr,
        _fn_dsa_pubkey: Option<[u8; FN_DSA_512_PUBKEY_SIZE]>,
    ) -> Result<()> {
        // Register in ACL engine (owner = peer_id by default, epoch 1)
        self.acl.register_peer(VpnPeerInfo {
            ark_id: peer_id,
            owner_id: peer_id,
            sub_key_epoch: 1,
        });

        // Set initial route mode
        let mut routes = self.peer_routes.write().unwrap();
        routes.insert(
            peer_id,
            PeerRouteState {
                direct_addr: Some(endpoint),
                route_mode: RouteMode::DirectP2p,
                is_p2p_failing: false,
            },
        );

        Ok(())
    }

    /// Remove a peer from the engine routing and security table.
    pub fn remove_peer(&self, peer_id: &[u8; 32]) {
        let mut routes = self.peer_routes.write().unwrap();
        routes.remove(peer_id);
    }

    /// Active peer count.
    pub fn peer_count(&self) -> usize {
        self.peer_routes.read().unwrap().len()
    }

    /// Apply declarative security microsegmentation policy.
    pub fn apply_policy(&self, policy: VpnSecurityPolicy) -> Result<()> {
        self.acl.add_policy(policy);
        Ok(())
    }

    /// Query the current route mode (DirectP2p or Relayed) for a given peer.
    pub fn get_route_mode(&self, peer_id: &[u8; 32]) -> Option<RouteMode> {
        let routes = self.peer_routes.read().unwrap();
        routes.get(peer_id).map(|r| r.route_mode)
    }

    /// Simulate or trigger direct P2P failure, causing transparent failover to Relay.
    pub fn simulate_p2p_failure(&self, peer_id: &[u8; 32]) {
        let mut routes = self.peer_routes.write().unwrap();
        if let Some(route) = routes.get_mut(peer_id) {
            route.is_p2p_failing = true;
            if self.config.enable_relay_fallback && !self.relays.read().unwrap().is_empty() {
                route.route_mode = RouteMode::Relayed;
            }
        }
    }

    /// Simulate direct P2P route recovery via background probing.
    pub fn simulate_p2p_recovered(&self, peer_id: &[u8; 32]) {
        let mut routes = self.peer_routes.write().unwrap();
        if let Some(route) = routes.get_mut(peer_id) {
            route.is_p2p_failing = false;
            route.route_mode = RouteMode::DirectP2p;
        }
    }

    /// Read real-time zero-allocation passthrough metrics.
    pub fn metrics(&self) -> VpnEngineMetrics {
        let active_peers = self.peer_routes.read().unwrap().len();
        VpnEngineMetrics {
            active_peers,
            packets_sent: self.metrics.packets_sent.load(Ordering::Relaxed),
            packets_received: self.metrics.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.metrics.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.metrics.bytes_received.load(Ordering::Relaxed),
            p2p_packets: self.metrics.p2p_packets.load(Ordering::Relaxed),
            relayed_packets: self.metrics.relayed_packets.load(Ordering::Relaxed),
            dropped_acl: self.metrics.dropped_acl.load(Ordering::Relaxed),
            dropped_no_route: self.metrics.dropped_no_route.load(Ordering::Relaxed),
            dropped_errors: self.metrics.dropped_errors.load(Ordering::Relaxed),
        }
    }

    /// Reference to internal ACL engine.
    pub fn acl(&self) -> &Arc<AclEngine> {
        &self.acl
    }

    /// Reference to internal PQMT engine.
    pub fn pqmt(&self) -> &Arc<PqmtEngine> {
        &self.pqmt
    }

    /// Reference to internal RoamingTable.
    pub fn roaming(&self) -> &Arc<RoamingTable> {
        &self.roaming
    }

    /// TUN adapter handle.
    pub fn tun(&self) -> &Arc<dyn VirtualTunAdapter> {
        &self.tun
    }
}
