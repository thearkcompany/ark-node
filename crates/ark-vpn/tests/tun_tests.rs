use ark_vpn::error::VpnError;
use ark_vpn::tun::{
    clamp_tcp_mss, MockTunAdapter, NativeTunAdapter, VirtualTunAdapter, DEFAULT_SAFE_MTU,
    TCP_MSS_FLOOR,
};

#[tokio::test]
async fn test_mock_tun_adapter_read_write() {
    let tun = MockTunAdapter::new("mock0", DEFAULT_SAFE_MTU);
    assert_eq!(tun.name(), "mock0");
    assert_eq!(tun.mtu(), DEFAULT_SAFE_MTU);

    let test_packet = vec![
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
    ];

    // Inject packet from userspace into TUN interface (as if incoming from OS)
    tun.inject_packet(test_packet.clone()).await.unwrap();

    // Read packet out of the TUN interface (as read by the VPN engine)
    let read = tun.read_packet().await.unwrap();
    assert_eq!(read, test_packet);

    // Write packet into TUN interface (as written by the VPN engine to the OS)
    tun.write_packet(&test_packet).await.unwrap();

    // Verify injected outbound packet was emitted
    let outbound = tun.read_outbound().await.unwrap();
    assert_eq!(outbound, test_packet);
}

#[tokio::test]
async fn test_mock_tun_adapter_mtu_enforcement() {
    let tun = MockTunAdapter::new("mock0", 1200);

    // 1200 bytes is acceptable
    let valid_packet = vec![0u8; 1200];
    assert!(tun.write_packet(&valid_packet).await.is_ok());

    // 1201 bytes exceeds MTU ceiling
    let oversize_packet = vec![0u8; 1201];
    let err = tun.write_packet(&oversize_packet).await.unwrap_err();
    assert_eq!(
        err,
        VpnError::MtuExceeded {
            size: 1201,
            limit: 1200
        }
    );

    // Injection of oversize packet is also rejected
    let inject_err = tun.inject_packet(oversize_packet).await.unwrap_err();
    assert_eq!(
        inject_err,
        VpnError::MtuExceeded {
            size: 1201,
            limit: 1200
        }
    );
}

#[tokio::test]
async fn test_tcp_mss_clamping_ipv4() {
    let tun = MockTunAdapter::new("mock0", 1200);

    // Construct an IPv4 TCP SYN packet with MSS option = 1460 (0x05b4)
    let packet = vec![
        0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x02, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
    ];

    // Clamping on write or processing:
    tun.write_packet(&packet).await.unwrap();
    let outbound = tun.read_outbound().await.unwrap();

    // Verify MSS option was clamped to <= 1160 (0x0488)
    assert_eq!(outbound[40], 0x02);
    assert_eq!(outbound[41], 0x04);
    let clamped_mss = u16::from_be_bytes([outbound[42], outbound[43]]);
    assert_eq!(clamped_mss, TCP_MSS_FLOOR); // 1160

    // Verify TCP checksum recalculated and non-zero
    let tcp_csum = u16::from_be_bytes([outbound[36], outbound[37]]);
    assert_ne!(tcp_csum, 0);
}

#[tokio::test]
async fn test_tcp_mss_clamping_ipv6() {
    let tun = MockTunAdapter::new("mock0", 1200);

    let mut packet = vec![0u8; 64];
    packet[0] = 0x60; // IPv6
    packet[4] = 0x00;
    packet[5] = 0x18; // 24 bytes payload
    packet[6] = 0x06; // Next header = TCP
    packet[7] = 64; // Hop limit
    packet[8] = 0xfd; // Src ULA
    packet[24] = 0xfd; // Dst ULA
    packet[40] = 0x1f;
    packet[41] = 0x90; // Port 8080
    packet[42] = 0x00;
    packet[43] = 0x50; // Port 80
    packet[52] = 0x60; // Data offset = 6 (24 bytes)
    packet[53] = 0x02; // SYN
                       // MSS Option
    packet[60] = 0x02;
    packet[61] = 0x04;
    packet[62] = 0x05;
    packet[63] = 0xa0; // 1440

    tun.write_packet(&packet).await.unwrap();
    let outbound = tun.read_outbound().await.unwrap();

    let clamped_mss = u16::from_be_bytes([outbound[62], outbound[63]]);
    // For IPv6, MTU 1200 - 60 = 1140 (clamped to <= TCP_MSS_IPV6_FLOOR)
    assert_eq!(clamped_mss, ark_vpn::tun::TCP_MSS_IPV6_FLOOR);

    // Verify TCP checksum recalculated and non-zero
    let tcp_csum = u16::from_be_bytes([outbound[56], outbound[57]]);
    assert_ne!(tcp_csum, 0);
}

#[tokio::test]
async fn test_tcp_mss_clamping_non_syn_ignored() {
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x10, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x05,
        0xb4, // ACK flag, not SYN
    ];

    let original = packet.clone();
    clamp_tcp_mss(&mut packet, 1200).unwrap();
    assert_eq!(packet, original);
}

#[test]
fn test_native_tun_adapter_creation_unprivileged() {
    // In unprivileged test environment (non-root), creating NativeTunAdapter should return error or succeed if root
    let res = NativeTunAdapter::create("ark0", 1200);
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        assert!(res.is_err());
        let err = res.err().unwrap();
        match err {
            VpnError::InterfaceError(msg) => {
                assert!(msg.contains("requires root or CAP_NET_ADMIN"));
            }
            _ => panic!("Expected InterfaceError, got {:?}", err),
        }
    } else {
        assert!(res.is_ok());
    }
}
