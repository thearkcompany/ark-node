use ark_vpn::acl::{
    AclEngine, AclVerdict, IpProtocol, VpnAction, VpnPeerInfo, VpnSecurityPolicy,
};
use ark_vpn::tun::{MockTunAdapter, VirtualTunAdapter};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    let ihl = 5u8;
    let version_ihl = (4 << 4) | ihl;
    pkt.push(version_ihl);
    pkt.push(0); // DSCP/ECN
    let total_len = 20 + if protocol == 6 || protocol == 17 { 20 } else { 8 } + payload.len();
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ID
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Flags/Fragment
    pkt.push(64); // TTL
    pkt.push(protocol);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Header Checksum placeholder
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());

    // Protocol header
    if protocol == 6 {
        // TCP
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes()); // Seq
        pkt.extend_from_slice(&0u32.to_be_bytes()); // Ack
        pkt.push(5 << 4); // Data offset 5 words
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&65535u16.to_be_bytes()); // Window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Urgent pointer
    } else if protocol == 17 {
        // UDP
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum
    } else {
        // ICMP (protocol 1)
        pkt.push(8); // Echo Request
        pkt.push(0); // Code
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        pkt.extend_from_slice(&0u32.to_be_bytes()); // Rest of header
    }

    pkt.extend_from_slice(payload);
    pkt
}

#[test]
fn test_acl_declarative_microsegmentation_rules() {
    let local_owner = [1u8; 32];
    let local_id = [2u8; 32];
    let acl = AclEngine::new(local_id, local_owner);

    let friend_ark_id = [10u8; 32];
    let stranger_ark_id = [20u8; 32];

    // Register stranger peer with different owner (external node)
    acl.register_peer(VpnPeerInfo {
        ark_id: stranger_ark_id,
        owner_id: [99u8; 32], // different owner
        sub_key_epoch: 1,
    });

    // 1. By default, stranger is Default Deny quarantined
    let tcp_80_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 2),
        Ipv4Addr::new(100, 64, 0, 1),
        6,
        12345,
        80,
        b"GET / HTTP/1.1\r\n\r\n",
    );
    let verdict = acl.evaluate_ingress(&stranger_ark_id, 1, &tcp_80_pkt);
    assert_eq!(verdict, AclVerdict::Deny);

    // 2. Add rule allowing TCP port 80 from stranger
    acl.add_policy(VpnSecurityPolicy {
        source_ark_id: Some(stranger_ark_id),
        destination_port: Some(80),
        protocol: IpProtocol::Tcp,
        action: VpnAction::Allow,
    });

    let verdict_allowed = acl.evaluate_ingress(&stranger_ark_id, 1, &tcp_80_pkt);
    assert_eq!(verdict_allowed, AclVerdict::Allow);

    // 3. But stranger trying to access port 22 is still Denied
    let tcp_22_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 2),
        Ipv4Addr::new(100, 64, 0, 1),
        6,
        12345,
        22,
        b"SSH-2.0",
    );
    assert_eq!(acl.evaluate_ingress(&stranger_ark_id, 1, &tcp_22_pkt), AclVerdict::Deny);

    // 4. Test explicit Deny rule takes priority over wildcard
    acl.add_policy(VpnSecurityPolicy {
        source_ark_id: Some(friend_ark_id),
        destination_port: Some(443),
        protocol: IpProtocol::Tcp,
        action: VpnAction::Deny,
    });

    // Register friend with same owner
    acl.register_peer(VpnPeerInfo {
        ark_id: friend_ark_id,
        owner_id: local_owner, // same owner!
        sub_key_epoch: 1,
    });

    let tcp_443_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 3),
        Ipv4Addr::new(100, 64, 0, 1),
        6,
        12345,
        443,
        b"TLS handshake",
    );
    let tcp_8080_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 3),
        Ipv4Addr::new(100, 64, 0, 1),
        6,
        12345,
        8080,
        b"HTTP test",
    );

    // 443 has explicit Deny rule -> Denied even though friend has same owner
    assert_eq!(acl.evaluate_ingress(&friend_ark_id, 1, &tcp_443_pkt), AclVerdict::Deny);
    // Other ports for same owner peer are Allowed under intra-namespace trust
    assert_eq!(acl.evaluate_ingress(&friend_ark_id, 1, &tcp_8080_pkt), AclVerdict::Allow);
}

#[test]
fn test_acl_namespace_isolation_and_quarantine() {
    let owner_a = [0xAA; 32];
    let owner_b = [0xBB; 32];
    let local_id = [0x01; 32];

    let acl = AclEngine::new(local_id, owner_a);

    let cluster_peer_id = [0x02; 32];
    let external_peer_id = [0x03; 32];

    acl.register_peer(VpnPeerInfo {
        ark_id: cluster_peer_id,
        owner_id: owner_a, // Same owner
        sub_key_epoch: 1,
    });

    acl.register_peer(VpnPeerInfo {
        ark_id: external_peer_id,
        owner_id: owner_b, // External
        sub_key_epoch: 1,
    });

    let pkt_udp = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 2),
        Ipv4Addr::new(100, 64, 0, 1),
        17,
        5000,
        5000,
        b"mesh-gossip",
    );

    // Intra-namespace: Allowed
    assert_eq!(acl.evaluate_ingress(&cluster_peer_id, 1, &pkt_udp), AclVerdict::Allow);

    // External peer without rule: Quarantine / Default Deny
    assert_eq!(acl.evaluate_ingress(&external_peer_id, 1, &pkt_udp), AclVerdict::Deny);

    // Unregistered node: Absolute Default Deny
    let unknown_node = [0xFF; 32];
    assert_eq!(acl.evaluate_ingress(&unknown_node, 1, &pkt_udp), AclVerdict::Deny);
}

#[test]
fn test_acl_instantaneous_sub_key_epoch_revocation() {
    let owner = [1u8; 32];
    let local_id = [2u8; 32];
    let peer_id = [3u8; 32];

    let acl = AclEngine::new(local_id, owner);

    acl.register_peer(VpnPeerInfo {
        ark_id: peer_id,
        owner_id: owner,
        sub_key_epoch: 1,
    });

    let pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 3),
        Ipv4Addr::new(100, 64, 0, 1),
        17,
        4000,
        4000,
        b"data",
    );

    // Packet with epoch 1 is accepted
    assert_eq!(acl.evaluate_ingress(&peer_id, 1, &pkt), AclVerdict::Allow);

    // Monotonically increment sub_key_epoch to revoke epoch 1
    acl.update_peer_epoch(&peer_id, 2);

    // Measure revocation lookup latency (< 15 microseconds acceptance criteria)
    let start = Instant::now();
    let verdict = acl.evaluate_ingress(&peer_id, 1, &pkt);
    let elapsed = start.elapsed();

    assert_eq!(verdict, AclVerdict::Deny);
    println!("Instantaneous revocation evaluated in {:?}", elapsed);
    assert!(
        elapsed.as_micros() < 15,
        "Revocation check took {:?}, expected < 15µs",
        elapsed
    );

    // Packet with active epoch 2 is accepted
    assert_eq!(acl.evaluate_ingress(&peer_id, 2, &pkt), AclVerdict::Allow);
}

#[test]
fn test_acl_atomic_metrics_and_drop_counters() {
    let owner = [1u8; 32];
    let local_id = [2u8; 32];
    let peer_id = [3u8; 32];

    let acl = AclEngine::new(local_id, owner);
    // Unregistered peer
    let pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 3),
        Ipv4Addr::new(100, 64, 0, 1),
        6,
        1000,
        80,
        b"payload",
    );

    let stats_before = acl.stats();
    assert_eq!(stats_before.denied_packets, 0);
    assert_eq!(stats_before.allowed_packets, 0);

    for _ in 0..100 {
        let _ = acl.evaluate_ingress(&peer_id, 1, &pkt);
    }

    let stats_after = acl.stats();
    assert_eq!(stats_after.denied_packets, 100);
    assert_eq!(stats_after.allowed_packets, 0);
    assert_eq!(stats_after.quarantine_drops, 100);
}

#[tokio::test]
async fn test_ingress_and_egress_filtering_integration() {
    let owner = [1u8; 32];
    let local_id = [2u8; 32];
    let remote_id = [3u8; 32];

    let acl = Arc::new(AclEngine::new(local_id, owner));

    // Register remote node as external
    acl.register_peer(VpnPeerInfo {
        ark_id: remote_id,
        owner_id: [99u8; 32],
        sub_key_epoch: 1,
    });

    let tun = Arc::new(MockTunAdapter::new("mock0", 1200));

    let allowed_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 3),
        Ipv4Addr::new(100, 64, 0, 2),
        6,
        54321,
        80,
        b"HTTP request",
    );
    let blocked_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 3),
        Ipv4Addr::new(100, 64, 0, 2),
        6,
        54321,
        22,
        b"SSH probe",
    );

    // Rule: Allow ingress port 80 only
    acl.add_policy(VpnSecurityPolicy {
        source_ark_id: Some(remote_id),
        destination_port: Some(80),
        protocol: IpProtocol::Tcp,
        action: VpnAction::Allow,
    });

    // Ingress pipeline:
    // When incoming packet arrives from wire, evaluate_ingress before tun.write_packet
    let verdict_blocked = acl.evaluate_ingress(&remote_id, 1, &blocked_pkt);
    assert_eq!(verdict_blocked, AclVerdict::Deny);
    if verdict_blocked == AclVerdict::Allow {
        tun.write_packet(&blocked_pkt).await.unwrap();
    }

    let verdict_allowed = acl.evaluate_ingress(&remote_id, 1, &allowed_pkt);
    assert_eq!(verdict_allowed, AclVerdict::Allow);
    if verdict_allowed == AclVerdict::Allow {
        tun.write_packet(&allowed_pkt).await.unwrap();
    }

    // Check TUN adapter received ONLY the allowed packet
    let received = tun.read_outbound().await.expect("Read written packet");
    assert_eq!(received, allowed_pkt);

    // Egress pipeline:
    // When TUN generates packet, evaluate_egress before wire transmission
    let egress_verdict = acl.evaluate_egress(&remote_id, &allowed_pkt);
    // Peer is external and no egress rule configured -> Default Deny
    assert_eq!(egress_verdict, AclVerdict::Deny);

    // Add egress permissive rule for peer
    acl.add_policy(VpnSecurityPolicy {
        source_ark_id: Some(local_id),
        destination_port: Some(80),
        protocol: IpProtocol::Tcp,
        action: VpnAction::Allow,
    });

    let egress_verdict_allowed = acl.evaluate_egress(&remote_id, &allowed_pkt);
    assert_eq!(egress_verdict_allowed, AclVerdict::Allow);
}
