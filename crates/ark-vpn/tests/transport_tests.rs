use std::sync::Arc;
use tokio::time::Duration;
use ark_vpn::engine::{OutboundPacket, RouteMode};
use ark_vpn::transport::{ChannelTransportSink, VpnTransportSink};
use ark_vpn::error::VpnError;

#[tokio::test]
async fn test_channel_transport_sink_send_and_receive() {
    let sink = ChannelTransportSink::new(10);
    let mut rx = sink.take_receiver().expect("take_receiver should return Some on first call");

    let packet = OutboundPacket {
        recipient_id: [1u8; 32],
        target_endpoint: "127.0.0.1:8000".parse().unwrap(),
        route_mode: RouteMode::DirectP2p,
        payload: vec![1, 2, 3, 4],
    };

    sink.send_packet(packet.clone()).await.expect("send should succeed");

    let received = tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .expect("did not timeout")
        .expect("received packet");

    assert_eq!(received, packet);
}

#[tokio::test]
async fn test_channel_transport_sink_take_receiver_once() {
    let sink = ChannelTransportSink::new(10);
    assert!(sink.take_receiver().is_some());
    assert!(sink.take_receiver().is_none());
}

#[tokio::test]
async fn test_channel_transport_sink_closed_channel_returns_error() {
    let sink = ChannelTransportSink::new(1);
    let rx = sink.take_receiver().unwrap();
    drop(rx); // Drop receiver so channel is closed

    let packet = OutboundPacket {
        recipient_id: [2u8; 32],
        target_endpoint: "127.0.0.1:8001".parse().unwrap(),
        route_mode: RouteMode::Relayed,
        payload: vec![5, 6, 7],
    };

    let result = sink.send_packet(packet).await;
    assert!(matches!(result, Err(VpnError::InterfaceClosed)));
}

#[tokio::test]
async fn test_channel_transport_sink_trait_object() {
    let sink: Arc<dyn VpnTransportSink> = Arc::new(ChannelTransportSink::default());
    let packet = OutboundPacket {
        recipient_id: [3u8; 32],
        target_endpoint: "127.0.0.1:8002".parse().unwrap(),
        route_mode: RouteMode::DirectP2p,
        payload: vec![9, 9, 9],
    };

    sink.send_packet(packet).await.expect("send via trait object");
}

#[tokio::test]
async fn test_pipeline_outbound_transmission_and_drop_metrics() {
    use ark_crypto::identity::PersistentIdentity;
    use ark_vpn::engine::{VpnEngine, VpnEngineConfig};
    use ark_vpn::tun::MockTunAdapter;
    use ark_vpn::acl::{IpProtocol, VpnAction, VpnSecurityPolicy};
    use ark_vpn::pqmt::VpnSession;
    use ark_vpn::DeterministicIpam;
    use rand_chacha::rand_core::SeedableRng;

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x1234);
    let identity = PersistentIdentity::generate(&mut rng);
    let my_ark_id = identity.ark_id;
    let peer_identity = PersistentIdentity::generate(&mut rng);
    let peer_ark_id = peer_identity.ark_id;

    let my_addrs = DeterministicIpam::derive_from_ark_id(&my_ark_id);
    let peer_addrs = DeterministicIpam::derive_from_ark_id(&peer_ark_id);

    let tun = Arc::new(MockTunAdapter::new("tun0", 1200));
    let transport_sink = Arc::new(ChannelTransportSink::new(10));
    let mut rx = transport_sink.take_receiver().unwrap();

    let engine = VpnEngine::new(identity, tun.clone(), VpnEngineConfig::default());
    engine.set_transport_sink(transport_sink.clone());
    let engine = Arc::new(engine);

    // Register peer and session
    let peer_endpoint = "192.168.1.100:51820".parse().unwrap();
    engine.add_peer(peer_ark_id, peer_endpoint, None).await.unwrap();

    let session = VpnSession {
        session_id: 101,
        peer_ark_id,
        send_key: [0x33u8; 32],
        recv_key: [0x44u8; 32],
        send_seq: 1,
        recv_seq: 0,
    };
    engine.pqmt().insert_session(session.clone());
    engine.roaming().insert_session(session, peer_endpoint, None, 1000);

    // Allow ACL
    engine.apply_policy(VpnSecurityPolicy {
        source_ark_id: None,
        destination_port: None,
        protocol: IpProtocol::Any,
        action: VpnAction::Allow,
    }).unwrap();

    // Start engine and spawn pipeline
    engine.start().await.unwrap();
    let handle = engine.spawn_packet_pipeline();

    // Create an IPv6 packet from me to peer
    let mut ipv6_pkt = Vec::new();
    ipv6_pkt.push(0x60);
    ipv6_pkt.extend_from_slice(&[0, 0, 0]);
    let payload = b"Test packet through pipeline";
    let payload_len = (payload.len() + 8) as u16;
    ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes());
    ipv6_pkt.push(17); // UDP
    ipv6_pkt.push(64);
    ipv6_pkt.extend_from_slice(&my_addrs.ipv6.octets());
    ipv6_pkt.extend_from_slice(&peer_addrs.ipv6.octets());
    ipv6_pkt.extend_from_slice(&9000u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&9001u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes());
    ipv6_pkt.extend_from_slice(&[0, 0]);
    ipv6_pkt.extend_from_slice(payload);

    // Inject packet into TUN adapter
    tun.inject_packet(ipv6_pkt.clone()).await.unwrap();

    // Receive transmitted OutboundPacket from transport sink
    let transmitted = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("should not timeout")
        .expect("should receive outbound packet");

    assert_eq!(transmitted.recipient_id, peer_ark_id);
    assert_eq!(transmitted.target_endpoint, peer_endpoint);
    assert_eq!(transmitted.route_mode, RouteMode::DirectP2p);
    assert!(!transmitted.payload.is_empty());

    // Stop engine
    engine.stop().await.unwrap();
    let _ = handle.await;
}

#[tokio::test]
async fn test_pipeline_outbound_relay_routing_and_sink_drop_metrics() {
    use ark_crypto::identity::PersistentIdentity;
    use ark_vpn::engine::{VpnEngine, VpnEngineConfig};
    use ark_vpn::tun::MockTunAdapter;
    use ark_vpn::acl::{IpProtocol, VpnAction, VpnSecurityPolicy};
    use ark_vpn::pqmt::VpnSession;
    use ark_vpn::DeterministicIpam;
    use rand_chacha::rand_core::SeedableRng;

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x5678);
    let identity = PersistentIdentity::generate(&mut rng);
    let my_ark_id = identity.ark_id;
    let peer_identity = PersistentIdentity::generate(&mut rng);
    let peer_ark_id = peer_identity.ark_id;

    let my_addrs = DeterministicIpam::derive_from_ark_id(&my_ark_id);
    let peer_addrs = DeterministicIpam::derive_from_ark_id(&peer_ark_id);

    let tun = Arc::new(MockTunAdapter::new("tun0", 1200));
    let transport_sink = Arc::new(ChannelTransportSink::new(10));
    let mut rx = transport_sink.take_receiver().unwrap();

    let engine = Arc::new(
        VpnEngine::new(identity, tun.clone(), VpnEngineConfig::default())
            .with_transport_sink(transport_sink.clone()),
    );

    let peer_endpoint = "192.168.1.100:51820".parse().unwrap();
    let relay_endpoint = "10.0.0.1:7777".parse().unwrap();
    let relay_id = [0x55u8; 32];
    engine.add_relay(relay_id, relay_endpoint);
    engine.add_peer(peer_ark_id, peer_endpoint, None).await.unwrap();

    // Trigger relay failover
    engine.simulate_p2p_failure(&peer_ark_id);
    assert_eq!(engine.get_route_mode(&peer_ark_id), Some(RouteMode::Relayed));

    let session = VpnSession {
        session_id: 102,
        peer_ark_id,
        send_key: [0x55u8; 32],
        recv_key: [0x66u8; 32],
        send_seq: 1,
        recv_seq: 0,
    };
    engine.pqmt().insert_session(session.clone());
    engine.roaming().insert_session(session, peer_endpoint, None, 1000);

    engine.apply_policy(VpnSecurityPolicy {
        source_ark_id: None,
        destination_port: None,
        protocol: IpProtocol::Any,
        action: VpnAction::Allow,
    }).unwrap();

    engine.start().await.unwrap();
    let handle = engine.spawn_packet_pipeline();

    // Send packet
    let mut ipv6_pkt = Vec::new();
    ipv6_pkt.push(0x60);
    ipv6_pkt.extend_from_slice(&[0, 0, 0]);
    let payload = b"Relayed packet";
    let payload_len = (payload.len() + 8) as u16;
    ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes());
    ipv6_pkt.push(17);
    ipv6_pkt.push(64);
    ipv6_pkt.extend_from_slice(&my_addrs.ipv6.octets());
    ipv6_pkt.extend_from_slice(&peer_addrs.ipv6.octets());
    ipv6_pkt.extend_from_slice(&9000u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&9001u16.to_be_bytes());
    ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes());
    ipv6_pkt.extend_from_slice(&[0, 0]);
    ipv6_pkt.extend_from_slice(payload);

    tun.inject_packet(ipv6_pkt.clone()).await.unwrap();

    let transmitted = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("should not timeout")
        .expect("should receive outbound packet");

    assert_eq!(transmitted.recipient_id, peer_ark_id);
    assert_eq!(transmitted.target_endpoint, relay_endpoint);
    assert_eq!(transmitted.route_mode, RouteMode::Relayed);

    // Test sink drop errors increment dropped_errors without breaking worker loop
    drop(rx); // Drop receiver so sink.send_packet will fail
    tun.inject_packet(ipv6_pkt.clone()).await.unwrap();

    // Allow worker loop to process and record drop error
    tokio::time::sleep(Duration::from_millis(50)).await;
    let metrics = engine.metrics();
    assert!(metrics.dropped_errors >= 1);

    engine.stop().await.unwrap();
    let _ = handle.await;
}
