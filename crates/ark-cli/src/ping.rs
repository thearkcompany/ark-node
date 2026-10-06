//! Handshake ping probe using ALPN "ark-pqc/v1".

use ark_transport::ArkQuicEndpoint;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Pings a target peer via QUIC endpoint locked strictly to ALPN "ark-pqc/v1"
pub async fn ping_peer(target: &str) -> anyhow::Result<Duration> {
    let target_formatted = if !target.contains(':') {
        format!("{}:8443", target)
    } else {
        target.to_string()
    };

    let target_addr: SocketAddr = if let Ok(addr) = target_formatted.parse::<SocketAddr>() {
        addr
    } else {
        tokio::net::lookup_host(&target_formatted)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve target: {}", target_formatted))?
    };

    let sni_hostname = if let Ok(addr) = target.parse::<SocketAddr>() {
        addr.ip().to_string()
    } else if let Some((host, _)) = target.split_once(':') {
        host.to_string()
    } else {
        target.to_string()
    };

    let bind_addr: SocketAddr = if target_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let client = ArkQuicEndpoint::new_client(bind_addr)
        .map_err(|e| anyhow::anyhow!("Failed to initialize QUIC client: {}", e))?;

    let start = Instant::now();

    let connecting = client.endpoint.connect(target_addr, &sni_hostname)
        .map_err(|e| anyhow::anyhow!("Failed to initiate connect to {}: {}", target_addr, e))?;

    let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout to {}", target_addr))?
        .map_err(|e| anyhow::anyhow!("QUIC handshake failed with {}: {}", target_addr, e))?;

    let (mut send, mut recv) = conn.open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open bidirectional stream: {}", e))?;

    send.write_all(b"ping")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send ping payload: {}", e))?;
    send.finish()
        .map_err(|e| anyhow::anyhow!("Failed to finish stream: {}", e))?;

    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("Timeout awaiting pong from {}", target_addr))?
        .map_err(|e| anyhow::anyhow!("Failed to read pong response: {}", e))?;

    if &buf != b"pong" {
        return Err(anyhow::anyhow!("Unexpected response from peer: {:?}", buf));
    }

    let elapsed = start.elapsed();
    conn.close(0u32.into(), b"done");

    Ok(elapsed)
}
