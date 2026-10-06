use ark_cli::ping::ping_peer;
use ark_transport::ArkQuicEndpoint;
use std::net::SocketAddr;

#[tokio::test]
async fn test_ping_peer_success() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = ArkQuicEndpoint::new_server_self_signed(server_addr).expect("Failed to start server");
    let bound_addr = server.endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let mut buf = [0u8; 4];
                    if recv.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                        let _ = send.write_all(b"pong").await;
                        let _ = send.finish();
                    }
                }
                let _ = conn.closed().await;
            }
        }
    });

    let rtt = ping_peer(bound_addr.to_string().as_str()).await.expect("Ping failed");
    assert!(rtt.as_millis() < 5000);

    let _ = server_handle.await;
}

#[tokio::test]
async fn test_ping_peer_connection_failure() {
    // Unbound port should fail ping
    let res = ping_peer("127.0.0.1:54321").await;
    assert!(res.is_err());
}
