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
async fn test_multi_node_daemon_e2e_interaction() {
    let tmp_a = tempdir().unwrap();
    let tmp_b = tempdir().unwrap();
    let mut rng = OsRng;

    let identity_a = PersistentIdentity::generate(&mut rng);
    let identity_b = PersistentIdentity::generate(&mut rng);

    let sender_key_id_a = identity_a.sender_key_id;
    let ark_id_a = identity_a.ark_id;
    let sender_key_id_b = identity_b.sender_key_id;
    let ark_id_b = identity_b.ark_id;

    // Spawn Node A (Server)
    let handle_a = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp_a.path())
        .role(Role::Server)
        .identity(identity_a)
        .spawn()
        .await
        .expect("Failed to spawn Node A");

    // Spawn Node B (Server)
    let handle_b = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp_b.path())
        .role(Role::Server)
        .identity(identity_b)
        .spawn()
        .await
        .expect("Failed to spawn Node B");

    let addr_a = handle_a.local_addr();
    let addr_b = handle_b.local_addr();
    assert_ne!(addr_a.port(), 0);
    assert_ne!(addr_b.port(), 0);
    assert_ne!(addr_a.port(), addr_b.port());

    // Connect from client to Node A and send a state update (Retention Class 1)
    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Failed to create client endpoint");

    let connecting_a = client_endpoint
        .endpoint
        .connect(addr_a, "localhost")
        .expect("Failed to connect to Node A");
    let conn_a = connecting_a.await.expect("Client handshake with Node A failed");

    let fast_header = FastHeader::new(
        0,
        150,
        0x1000_0001,
        sender_key_id_a,
        sender_key_id_b,
        100,
    );

    let envelope = ArkEnvelope::new(
        fast_header.to_bytes(),
        ark_id_a,
        ark_id_b,
        b"multi-node sync payload".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x1000_0001u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).expect("Failed to create envelope");

    let wire_bytes = WireFrame::encode(&fast_header, &envelope).expect("Failed to encode wireframe");

    let (mut send_a, mut recv_a) = conn_a.open_bi().await.expect("Failed to open stream to Node A");
    send_a.write_all(&wire_bytes).await.expect("Failed to send wire bytes to Node A");
    send_a.finish().expect("Failed to finish stream");

    let mut ack = [0u8; 1];
    recv_a.read_exact(&mut ack).await.expect("Failed to read ack from Node A");
    assert_eq!(ack[0], 1, "Node A must acknowledge valid envelope ingest");

    // Connect to Node B and verify Node B is also listening and responsive
    let connecting_b = client_endpoint
        .endpoint
        .connect(addr_b, "localhost")
        .expect("Failed to connect to Node B");
    let conn_b = connecting_b.await.expect("Client handshake with Node B failed");

    let (mut send_b, mut recv_b) = conn_b.open_bi().await.expect("Failed to open stream to Node B");
    send_b.write_all(b"ping").await.expect("Failed to send ping to Node B");
    send_b.finish().expect("Failed to finish stream to Node B");

    let mut buf = [0u8; 4];
    recv_b.read_exact(&mut buf).await.expect("Failed to read echo from Node B");
    assert_eq!(&buf, b"ping");

    // Clean shutdown of both nodes
    handle_a.shutdown().await.expect("Node A shutdown failed");
    handle_b.shutdown().await.expect("Node B shutdown failed");
}
