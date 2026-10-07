use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use rand_chacha::rand_core::SeedableRng;
use ark_crypto::identity::PersistentIdentity;
use ark_vpn::acl::{IpProtocol, VpnAction, VpnSecurityPolicy};
use ark_vpn::engine::{RouteMode, VpnEngine, VpnEngineConfig, VpnEngineStatus};
use ark_vpn::relay::{BlindRelayNode, RelayConfig, RelayProfile};
use ark_vpn::tun::MockTunAdapter;

#[tokio::test]
async fn test_vpn_engine_lifecycle_and_peer_management() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xAAAA);
    let identity = PersistentIdentity::generate(&mut rng);
    let tun = Arc::new(MockTunAdapter::new("mock0", 1200));

    let config = VpnEngineConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        enable_relay_fallback: true,
        probing_interval: Duration::from_millis(50),
        p2p_timeout: Duration::from_millis(100),
    };

    let engine = VpnEngine::new(identity, tun.clone(), config);
    assert_eq!(engine.status(), VpnEngineStatus::Stopped);

    engine.start().await.expect("Engine should start");
    assert_eq!(engine.status(), VpnEngineStatus::Running);

    let peer_identity = PersistentIdentity::generate(&mut rng);
    let peer_addr: SocketAddr = "127.0.0.1:9099".parse().unwrap();

    engine.add_peer(peer_identity.ark_id, peer_addr, None).await.expect("Add peer");
    assert_eq!(engine.peer_count(), 1);

    // Apply security policy
    let policy = VpnSecurityPolicy {
        source_ark_id: Some(peer_identity.ark_id),
        destination_port: Some(8080),
        protocol: IpProtocol::Tcp,
        action: VpnAction::Allow,
    };
    engine.apply_policy(policy).expect("Apply policy");

    // Metrics check
    let metrics = engine.metrics();
    assert_eq!(metrics.active_peers, 1);
    assert_eq!(metrics.packets_sent, 0);

    engine.stop().await.expect("Engine should stop");
    assert_eq!(engine.status(), VpnEngineStatus::Stopped);
}

#[tokio::test]
async fn test_vpn_engine_failover_transparent_p2p_relay_and_probing() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xBBBB);
    // 1. Create Mock Relay Node
    let relay_identity = PersistentIdentity::generate(&mut rng);
    let relay_ark_id = relay_identity.ark_id;
    let relay = Arc::new(BlindRelayNode::new(
        relay_identity,
        RelayConfig {
            profile: RelayProfile::Homelab,
            max_active_peers: 10,
            rate_limit_per_peer_pps: 1000,
        },
    ));
    let relay_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();

    // 2. Setup Node A and Node B engines with MockTunAdapters
    let id_a = PersistentIdentity::generate(&mut rng);
    let id_a_ark = id_a.ark_id;
    let tun_a = Arc::new(MockTunAdapter::new("tunA", 1200));
    let mut config_a = VpnEngineConfig::default();
    config_a.p2p_timeout = Duration::from_millis(100);
    config_a.probing_interval = Duration::from_millis(50);
    config_a.enable_relay_fallback = true;

    let engine_a = VpnEngine::new(id_a, tun_a.clone(), config_a);

    let id_b = PersistentIdentity::generate(&mut rng);
    let id_b_ark = id_b.ark_id;
    let tun_b = Arc::new(MockTunAdapter::new("tunB", 1200));
    let mut config_b = VpnEngineConfig::default();
    config_b.p2p_timeout = Duration::from_millis(100);
    config_b.probing_interval = Duration::from_millis(50);
    config_b.enable_relay_fallback = true;

    let engine_b = VpnEngine::new(id_b, tun_b.clone(), config_b);

    // Register relay in both engines
    engine_a.add_relay(relay_ark_id, relay_addr);
    engine_b.add_relay(relay_ark_id, relay_addr);

    // Register clients on relay
    relay.register_client(id_a_ark, "127.0.0.1:8001".parse().unwrap());
    relay.register_client(id_b_ark, "127.0.0.1:8002".parse().unwrap());

    // Connect Node A and Node B directly initially
    let direct_addr_b: SocketAddr = "127.0.0.1:8002".parse().unwrap();
    engine_a.add_peer(id_b_ark, direct_addr_b, None).await.unwrap();

    // Route should initially be Direct P2P
    assert_eq!(engine_a.get_route_mode(&id_b_ark), Some(RouteMode::DirectP2p));

    // Simulate direct P2P failure / degradation
    engine_a.simulate_p2p_failure(&id_b_ark);

    // Failover to Relay
    assert_eq!(engine_a.get_route_mode(&id_b_ark), Some(RouteMode::Relayed));

    // Probing restores P2P when direct path recovers
    engine_a.simulate_p2p_recovered(&id_b_ark);
    assert_eq!(engine_a.get_route_mode(&id_b_ark), Some(RouteMode::DirectP2p));
}

#[tokio::test]
async fn test_vpn_engine_zero_trust_overlay_mesh_facade() {
    use ark_vpn::ZeroTrustOverlayMesh;

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xCCCC);
    let identity = PersistentIdentity::generate(&mut rng);
    let tun = Arc::new(MockTunAdapter::new("mesh0", 1200));

    let mut mesh = ZeroTrustOverlayMesh::with_tun(identity, tun);
    assert_eq!(mesh.is_running(), false);
    mesh.start().await.expect("Mesh should start");
    assert_eq!(mesh.is_running(), true);
    mesh.stop().await.expect("Mesh should stop");
    assert_eq!(mesh.is_running(), false);
}
