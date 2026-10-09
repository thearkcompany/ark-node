use ark_core::FastHeader;
use ark_crypto::PersistentIdentity;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_protocol::wire::WireFrame;
use ark_storage::compute_envelope_id;
use ark_transport::ArkQuicEndpoint;
use ark_runtime::{NodeRuntimeBuilder, Role};
use rand::rngs::OsRng;
use tempfile::tempdir;

#[tokio::test]
async fn test_wire_demux_and_storage_envelope_ingest() {
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

    // Create client endpoint
    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Failed to create client endpoint");

    let connecting = client_endpoint
        .endpoint
        .connect(bound_addr, "localhost")
        .expect("Failed to connect");
    let conn = connecting.await.expect("Client handshake failed");

    // Construct a Class 1 Append-Only envelope
    let fast_header = FastHeader::new(
        0,
        200,
        0x1000_0001,
        [1u8; 16],
        [2u8; 16],
        1,
    );

    let envelope = ArkEnvelope::new(
        fast_header.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"hello storage from wire".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x1000_0001u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).expect("Failed to build envelope");

    let envelope_id = compute_envelope_id(&envelope).expect("Failed to compute id");

    // Frame with WireFrame: 64B FastHeader + Protobuf ArkEnvelope
    let wire_bytes = WireFrame::encode(&fast_header, &envelope).expect("Failed to encode wireframe");

    // Send over QUIC bi-stream
    let (mut send, mut recv) = conn.open_bi().await.expect("Failed to open stream");
    send.write_all(&wire_bytes).await.expect("Failed to write wire bytes");
    send.finish().expect("Failed to finish stream");

    // Read 1-byte ACK from node
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Failed to receive ack from node");
    assert_eq!(ack[0], 1);

    // Verify envelope is persisted in storage
    let stored = handle.storage().get_envelope(&envelope_id).expect("Storage query failed");
    assert!(stored.is_some(), "Envelope was not persisted in storage");
    let stored_env = stored.unwrap();
    assert_eq!(stored_env.payload, b"hello storage from wire");

    handle.shutdown().await.expect("Shutdown failed");
}

#[tokio::test]
async fn test_wire_demux_vpn_ephemeral_and_remote_socket_propagation() {
    let tmp = tempdir().unwrap();
    let mut rng = OsRng;
    let identity = PersistentIdentity::generate(&mut rng);

    let handle = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp.path())
        .role(Role::Server)
        .identity(identity)
        .enable_vpn(true)
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

    // 1. Send VPN data packet (KIND_VPN_DATA = 0x0008)
    let fast_header_vpn = FastHeader::new(
        0,
        100,
        0x0008, // KIND_VPN_DATA
        [1u8; 16],
        [2u8; 16],
        10,
    );

    let env_vpn = ArkEnvelope::new(
        fast_header_vpn.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"vpn-encrypted-payload-data".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x0008u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).expect("Failed to build VPN envelope");

    let vpn_envelope_id = compute_envelope_id(&env_vpn).expect("Failed to compute id");
    let wire_vpn = WireFrame::encode(&fast_header_vpn, &env_vpn).expect("Encode wire");

    let (mut send, mut recv) = conn.open_bi().await.expect("Open bi stream");
    send.write_all(&wire_vpn).await.expect("Send wire");
    send.finish().expect("Finish send");

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Receive ack");
    assert_eq!(ack[0], 1, "VPN packet should receive ACK 1");

    // VPN packets MUST bypass StorageEngine disk writes (Ephemeral Retention Class 0)
    let stored = handle.storage().get_envelope(&vpn_envelope_id).expect("Storage query");
    assert!(stored.is_none(), "VPN traffic must bypass StorageEngine writes");

    // 2. Also send VPN Handshake packet (KIND_VPN_HANDSHAKE = 0x0009)
    let fast_header_hs = FastHeader::new(
        0,
        100,
        0x0009, // KIND_VPN_HANDSHAKE
        [1u8; 16],
        [2u8; 16],
        11,
    );

    let env_hs = ArkEnvelope::new(
        fast_header_hs.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"vpn-handshake-init".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x0009u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).expect("Failed to build VPN handshake envelope");

    let hs_envelope_id = compute_envelope_id(&env_hs).expect("Failed to compute id");
    let wire_hs = WireFrame::encode(&fast_header_hs, &env_hs).expect("Encode wire");

    let (mut send, mut recv) = conn.open_bi().await.expect("Open bi stream");
    send.write_all(&wire_hs).await.expect("Send wire");
    send.finish().expect("Finish send");

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Receive ack");
    assert_eq!(ack[0], 1, "VPN handshake packet should receive ACK 1");

    let stored_hs = handle.storage().get_envelope(&hs_envelope_id).expect("Storage query");
    assert!(stored_hs.is_none(), "VPN handshake traffic must bypass StorageEngine writes");

    handle.shutdown().await.expect("Shutdown failed");
}

#[tokio::test]
async fn test_wire_demux_vpn_disabled_or_unconfigured() {
    let tmp = tempdir().unwrap();
    let mut rng = OsRng;
    let identity = PersistentIdentity::generate(&mut rng);

    // Node spawned with VPN disabled
    let handle = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp.path())
        .role(Role::Server)
        .identity(identity)
        .enable_vpn(false)
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

    let fast_header_vpn = FastHeader::new(
        0,
        100,
        0x0008,
        [1u8; 16],
        [2u8; 16],
        20,
    );

    let env_vpn = ArkEnvelope::new(
        fast_header_vpn.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"vpn-packet-disabled".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x0008u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).expect("Build envelope");

    let wire_vpn = WireFrame::encode(&fast_header_vpn, &env_vpn).expect("Encode wire");

    let (mut send, mut recv) = conn.open_bi().await.expect("Open bi stream");
    send.write_all(&wire_vpn).await.expect("Send wire");
    send.finish().expect("Finish send");

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Receive ack");
    // Should be discarded cleanly without error (ACK 1 returned, not crashing or NACK)
    assert_eq!(ack[0], 1, "VPN packet should be discarded cleanly without error");

    handle.shutdown().await.expect("Shutdown failed");
}

