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
