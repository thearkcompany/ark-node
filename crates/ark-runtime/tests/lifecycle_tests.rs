use ark_crypto::PersistentIdentity;
use ark_runtime::{NodeRuntimeBuilder, NodeRuntimeStatus, Role};
use ark_transport::ArkQuicEndpoint;
use rand::rngs::OsRng;
use tempfile::tempdir;

#[tokio::test]
async fn test_runtime_spawn_connect_and_graceful_shutdown() {
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
    assert_ne!(bound_addr.port(), 0);
    assert_eq!(handle.status(), NodeRuntimeStatus::Running);

    // Connect with external QUIC client using strict ALPN
    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Failed to create client endpoint");

    let connecting = client_endpoint
        .endpoint
        .connect(bound_addr, "localhost")
        .expect("Failed to initiate QUIC connection");

    let conn = connecting.await.expect("Client handshake failed");
    let (mut send, _recv) = conn.open_bi().await.expect("Failed to open stream");
    send.write_all(b"ping")
        .await
        .expect("Failed to write to stream");
    send.finish().expect("Failed to finish stream");

    // Close client connection cleanly
    conn.close(0u32.into(), b"done");

    // Graceful shutdown of runtime
    handle.shutdown().await.expect("Graceful shutdown failed");
}
