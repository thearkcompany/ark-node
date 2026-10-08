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
async fn test_vpn_engine_dual_node_mesh_pipeline_roaming_and_failover() {
    use ark_vpn::pqmt::VpnSession;
    use ark_vpn::DeterministicIpam;

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xDDDD);

    // 1. Initialize Node A and Node B identities
    let id_a = PersistentIdentity::generate(&mut rng);
    let id_a_ark = id_a.ark_id;
    let tun_a = Arc::new(MockTunAdapter::new("tunA", 1200));
    let engine_a = Arc::new(VpnEngine::new(id_a, tun_a.clone(), VpnEngineConfig::default()));

    let id_b = PersistentIdentity::generate(&mut rng);
    let id_b_ark = id_b.ark_id;
    let tun_b = Arc::new(MockTunAdapter::new("tunB", 1200));
    let engine_b = Arc::new(VpnEngine::new(id_b, tun_b.clone(), VpnEngineConfig::default()));

    let addrs_a = DeterministicIpam::derive_from_ark_id(&id_a_ark);
    let addrs_b = DeterministicIpam::derive_from_ark_id(&id_b_ark);

    // Initial physical endpoints
    let initial_endpoint_a: SocketAddr = "192.168.1.10:51820".parse().unwrap();
    let initial_endpoint_b: SocketAddr = "192.168.1.20:51820".parse().unwrap();

    // Register peers in engines
    engine_a.add_peer(id_b_ark, initial_endpoint_b, None).await.unwrap();
    engine_b.add_peer(id_a_ark, initial_endpoint_a, None).await.unwrap();

    // Allow mutual mesh traffic across Node A and Node B
    use ark_vpn::acl::{IpProtocol, VpnAction, VpnSecurityPolicy};
    engine_a.apply_policy(VpnSecurityPolicy {
        source_ark_id: None,
        destination_port: None,
        protocol: IpProtocol::Any,
        action: VpnAction::Allow,
    }).unwrap();
    engine_b.apply_policy(VpnSecurityPolicy {
        source_ark_id: None,
        destination_port: None,
        protocol: IpProtocol::Any,
        action: VpnAction::Allow,
    }).unwrap();

    // Start both engines
    engine_a.start().await.unwrap();
    engine_b.start().await.unwrap();

    // 2. Establish PQMT session between Node A and Node B
    let session_id = 42u32;
    let key_a_to_b = [0x11u8; 32];
    let key_b_to_a = [0x22u8; 32];

    let session_on_a = VpnSession {
        session_id,
        peer_ark_id: id_b_ark,
        send_key: key_a_to_b,
        recv_key: key_b_to_a,
        send_seq: 1,
        recv_seq: 0,
    };
    engine_a.pqmt().insert_session(session_on_a.clone());
    engine_a.roaming().insert_session(session_on_a, initial_endpoint_b, None, 1000);

    let session_on_b = VpnSession {
        session_id,
        peer_ark_id: id_a_ark,
        send_key: key_b_to_a,
        recv_key: key_a_to_b,
        send_seq: 1,
        recv_seq: 0,
    };
    engine_b.pqmt().insert_session(session_on_b.clone());
    engine_b.roaming().insert_session(session_on_b, initial_endpoint_a, None, 1000);

    // 3. Exchange IPv6 Packet from Node A to Node B
    let mut ipv6_pkt = Vec::new();
    ipv6_pkt.push(0x60); // IPv6 version
    ipv6_pkt.extend_from_slice(&[0, 0, 0]); // Traffic class & Flow label
    let payload_data = b"Hello from Node A IPv6";
    let payload_len = (payload_data.len() + 8) as u16; // UDP header (8) + payload
    ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes());
    ipv6_pkt.push(17); // UDP
    ipv6_pkt.push(64); // Hop limit
    ipv6_pkt.extend_from_slice(&addrs_a.ipv6.octets());
    ipv6_pkt.extend_from_slice(&addrs_b.ipv6.octets());
    // UDP header (src_port: 7000, dst_port: 8000)
    ipv6_pkt.extend_from_slice(&7000u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&8000u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes());
    ipv6_pkt.extend_from_slice(&[0, 0]); // UDP checksum placeholder
    ipv6_pkt.extend_from_slice(payload_data);

    // Node A processes outbound packet from TUN
    let outbound_a = engine_a.process_outbound_packet(&ipv6_pkt).expect("Process outbound on A");
    let out_a = outbound_a.expect("Outbound packet should be generated");
    assert_eq!(out_a.recipient_id, id_b_ark);
    assert_eq!(out_a.target_endpoint, initial_endpoint_b);
    assert_eq!(out_a.route_mode, RouteMode::DirectP2p);

    // Node B receives inbound packet from Node A
    engine_b
        .process_inbound_packet(&out_a.payload, initial_endpoint_a, 1000, 1000)
        .await
        .expect("Process inbound on B");

    // Verify TUN on Node B received plaintext IPv6 packet
    let b_tun_received = tun_b.read_outbound().await.expect("Read packet from TUN B");
    assert_eq!(b_tun_received, ipv6_pkt);

    // 4. Exchange IPv4 CGNAT Packet from Node B to Node A with Endpoint Roaming
    // Node B switches IP to a cellular endpoint (203.0.113.50:60000)
    let roamed_endpoint_b: SocketAddr = "203.0.113.50:60000".parse().unwrap();

    let mut ipv4_pkt = Vec::new();
    ipv4_pkt.push(0x45); // IPv4, IHL = 5
    ipv4_pkt.push(0x00);
    let v4_payload_data = b"Hello from Node B IPv4 CGNAT";
    let v4_total_len = (20 + 8 + v4_payload_data.len()) as u16;
    ipv4_pkt.extend_from_slice(&v4_total_len.to_be_bytes());
    ipv4_pkt.extend_from_slice(&[0, 0, 0, 0]);
    ipv4_pkt.push(64); // TTL
    ipv4_pkt.push(17); // UDP
    ipv4_pkt.extend_from_slice(&[0, 0]); // Header checksum
    ipv4_pkt.extend_from_slice(&addrs_b.ipv4.octets());
    ipv4_pkt.extend_from_slice(&addrs_a.ipv4.octets());
    // UDP header (src_port: 8000, dst_port: 7000)
    ipv4_pkt.extend_from_slice(&8000u16.to_be_bytes());
    ipv4_pkt.extend_from_slice(&7000u16.to_be_bytes());
    let v4_udp_len = (8 + v4_payload_data.len()) as u16;
    ipv4_pkt.extend_from_slice(&v4_udp_len.to_be_bytes());
    ipv4_pkt.extend_from_slice(&[0, 0]);
    ipv4_pkt.extend_from_slice(v4_payload_data);

    let outbound_b = engine_b.process_outbound_packet(&ipv4_pkt).expect("Process outbound on B");
    let out_b = outbound_b.expect("Outbound packet from B");

    // Node A receives from Node B's ROAMED cellular endpoint
    engine_a
        .process_inbound_packet(&out_b.payload, roamed_endpoint_b, 1005, 1005)
        .await
        .expect("Process inbound on A with roaming endpoint");

    // Verify TUN on Node A received plaintext IPv4 packet
    let a_tun_received = tun_a.read_outbound().await.expect("Read packet from TUN A");
    assert_eq!(a_tun_received, ipv4_pkt);

    // Verify Node A's RoamingTable dynamically updated Node B's physical endpoint!
    let b_roaming_entry_on_a = engine_a.roaming().get_by_ark_id(&id_b_ark).expect("Node B in RoamingTable");
    assert_eq!(b_roaming_entry_on_a.physical_endpoint, roamed_endpoint_b);

    // 5. Test Relay Failover on Direct P2P Degradation
    let relay_addr: SocketAddr = "10.10.10.1:7777".parse().unwrap();
    let relay_id = [0xEEu8; 32];
    engine_a.add_relay(relay_id, relay_addr);

    // Trigger P2P failure for peer B on engine A
    engine_a.simulate_p2p_failure(&id_b_ark);
    assert_eq!(engine_a.get_route_mode(&id_b_ark), Some(RouteMode::Relayed));

    // Next outbound packet from A targeting B now routes to Relay!
    let outbound_relayed = engine_a.process_outbound_packet(&ipv6_pkt).expect("Process outbound on A");
    let out_relayed = outbound_relayed.expect("Outbound packet relayed");
    assert_eq!(out_relayed.route_mode, RouteMode::Relayed);
    assert_eq!(out_relayed.target_endpoint, relay_addr);

    // P2P recovered via probing
    engine_a.simulate_p2p_recovered(&id_b_ark);
    assert_eq!(engine_a.get_route_mode(&id_b_ark), Some(RouteMode::DirectP2p));

    let outbound_p2p_again = engine_a.process_outbound_packet(&ipv6_pkt).expect("Process outbound on A");
    let out_p2p_again = outbound_p2p_again.expect("Outbound packet restored to P2P");
    assert_eq!(out_p2p_again.route_mode, RouteMode::DirectP2p);
    assert_eq!(out_p2p_again.target_endpoint, roamed_endpoint_b);

    // Clean shutdown
    engine_a.stop().await.unwrap();
    engine_b.stop().await.unwrap();
}
