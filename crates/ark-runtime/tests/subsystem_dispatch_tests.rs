
use ark_core::FastHeader;
use ark_crypto::PersistentIdentity;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_protocol::wire::WireFrame;
use ark_transport::ArkQuicEndpoint;
use ark_runtime::{NodeRuntimeBuilder, Role};
use rand::rngs::OsRng;
use tempfile::tempdir;

#[tokio::test]
async fn test_subsystem_dispatch_routing_and_fault_isolation() {
    let tmp = tempdir().unwrap();
    let mut rng = OsRng;
    let identity = PersistentIdentity::generate(&mut rng);

    let handle = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp.path())
        .role(Role::Server)
        .identity(identity)
        .spawn()
        .await
        .expect("Failed to spawn NodeRuntime");

    let bound_addr = handle.local_addr();

    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Failed to create client endpoint");

    let connecting = client_endpoint
        .endpoint
        .connect(bound_addr, "localhost")
        .expect("Failed to connect");
    let conn = connecting.await.expect("Client handshake failed");

    // 1. Send DNS claim envelope (KIND_DNS_CLAIM_PUBLIC = 0x3000_0002)
    let fast_header_dns = FastHeader::new(0, 100, 0x3000_0002, [1u8; 16], [2u8; 16], 1);
    let env_dns = ArkEnvelope::new(
        fast_header_dns.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"sovereign.ark".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x3000_0002u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).unwrap();
    let wire_dns = WireFrame::encode(&fast_header_dns, &env_dns).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_dns).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "DNS dispatch should return ACK 1");

    // 2. Send WoT attestation envelope (KIND_WOT_ATTESTATION = 0x000A)
    let fast_header_wot = FastHeader::new(0, 100, 0x000A, [1u8; 16], [2u8; 16], 2);
    let env_wot = ArkEnvelope::new(
        fast_header_wot.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"wot-attestation-payload".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x000Au32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).unwrap();
    let wire_wot = WireFrame::encode(&fast_header_wot, &env_wot).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_wot).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "WoT dispatch should return ACK 1");

    // 3. Send DePIN challenge envelope (KIND_DEPIN_CHALLENGE = 0x4000_0002)
    let fast_header_blob = FastHeader::new(0, 100, 0x4000_0002, [1u8; 16], [2u8; 16], 3);
    let env_blob = ArkEnvelope::new(
        fast_header_blob.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"depin-challenge-payload".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x4000_0002u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).unwrap();
    let wire_blob = WireFrame::encode(&fast_header_blob, &env_blob).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_blob).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "Blob challenge dispatch should return ACK 1");

    // 4. Fault isolation test: Send corrupt/malformed payload under PaaS kind
    // Daemon and QUIC connection should remain fully alive
    let fast_header_bad = FastHeader::new(0, 100, 0x5000_0001, [1u8; 16], [2u8; 16], 4);
    let env_bad = ArkEnvelope::new(
        fast_header_bad.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"corrupt-paas-worker-trap".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x5000_0001u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).unwrap();
    let wire_bad = WireFrame::encode(&fast_header_bad, &env_bad).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_bad).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "Fault should be isolated and envelope handled gracefully");

    // Check daemon status is still Running
    assert_eq!(handle.status(), ark_runtime::NodeRuntimeStatus::Running);

    handle.shutdown().await.unwrap();
}
