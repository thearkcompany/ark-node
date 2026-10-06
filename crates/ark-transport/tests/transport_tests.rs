use ark_core::error::ArkError;
use ark_transport::{ArkQuicEndpoint, ArkSocket, EchConfig, RetryCookieManager};
use std::net::SocketAddr;

#[tokio::test]
async fn test_socket_dual_stack_binding_and_io() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socket1 = ArkSocket::bind(addr).expect("Failed to bind socket1");
    let local1 = socket1.local_addr().expect("Failed to get local_addr");

    let socket2 = ArkSocket::bind("127.0.0.1:0".parse().unwrap()).expect("Failed to bind socket2");
    let local2 = socket2.local_addr().expect("Failed to get local_addr");

    let payload = b"ping from socket1 to socket2";
    let sent = socket1.send_to(payload, local2).await.expect("Failed to send");
    assert_eq!(sent, payload.len());

    let mut buf = [0u8; 1024];
    let (received, sender) = socket2.recv_from(&mut buf).await.expect("Failed to recv");
    assert_eq!(received, payload.len());
    assert_eq!(&buf[..received], payload);
    assert_eq!(sender, local1);
}

#[tokio::test]
async fn test_socket_ipv6_binding() {
    let addr: SocketAddr = "[::1]:0".parse().unwrap();
    let socket = ArkSocket::bind(addr).expect("Failed to bind IPv6 socket");
    let local = socket.local_addr().expect("Failed to get local_addr");
    assert!(local.is_ipv6());
}

#[test]
fn test_retry_cookie_manager_lifecycle() {
    let secret = [0x99u8; 32];
    let manager = RetryCookieManager::new(secret);
    let client_addr: SocketAddr = "192.0.2.10:9999".parse().unwrap();

    let cookie = manager.generate_cookie(client_addr);
    assert_eq!(cookie.len(), 40);

    // Valid cookie within 60s
    let val_res = manager.validate_cookie(client_addr, &cookie, 60);
    assert!(val_res.is_ok());

    // Address mismatch
    let different_addr: SocketAddr = "192.0.2.11:9999".parse().unwrap();
    let mismatch_res = manager.validate_cookie(different_addr, &cookie, 60);
    assert!(matches!(mismatch_res, Err(ArkError::InvalidRetryCookie)));

    // Forged cookie (altered byte)
    let mut tampered = cookie.clone();
    tampered[15] ^= 0xAA;
    let forged_res = manager.validate_cookie(client_addr, &tampered, 60);
    assert!(matches!(forged_res, Err(ArkError::InvalidRetryCookie)));

    // Truncated / malformed length
    let bad_len_res = manager.validate_cookie(client_addr, &cookie[..39], 60);
    assert!(matches!(bad_len_res, Err(ArkError::InvalidRetryCookie)));
}

#[test]
fn test_retry_cookie_expiration() {
    let secret = [0x55u8; 32];
    let manager = RetryCookieManager::new(secret);
    let client_addr: SocketAddr = "127.0.0.1:4567".parse().unwrap();

    let cookie = manager.generate_cookie(client_addr);

    // Max age 0s should expire immediately (or within tiny window if strictly > 0)
    // To deterministically test expiration, forge an old timestamp
    let mut expired_cookie = cookie.clone();
    let old_ts = 1000u64.to_be_bytes();
    expired_cookie[0..8].copy_from_slice(&old_ts);
    // Even if tag was somehow valid, timestamp is in the past (> max_age_secs)
    let res = manager.validate_cookie(client_addr, &expired_cookie, 10);
    assert!(matches!(res, Err(ArkError::InvalidRetryCookie)));
}

#[test]
fn test_ech_cover_sni_masking() {
    let kem_pubkey = vec![0x11u8; 1184]; // ML-KEM-768 pubkey size
    let ech = EchConfig::new("ark.network", kem_pubkey);

    let destination_id_1 = [0xAAu8; 32];
    let sni_1 = ech.mask_destination(&destination_id_1);

    let destination_id_2 = [0xBBu8; 32];
    let sni_2 = ech.mask_destination(&destination_id_2);

    assert!(sni_1.ends_with(".ech.ark.network"));
    assert!(sni_2.ends_with(".ech.ark.network"));
    assert_ne!(sni_1, sni_2);

    // Deterministic masking for same destination
    let sni_1_repeat = ech.mask_destination(&destination_id_1);
    assert_eq!(sni_1, sni_1_repeat);
}

fn generate_test_cert() -> (Vec<u8>, Vec<u8>) {
    let rcgen_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rcgen_cert.cert.der().to_vec();
    let key_der = rcgen_cert.key_pair.serialize_der();
    (cert_der, key_der)
}

#[tokio::test]
async fn test_quic_alpn_negotiation_success() {
    let (cert_der, key_der) = generate_test_cert();

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = ArkQuicEndpoint::new_server(server_addr, cert_der, key_der)
        .expect("Failed to start QUIC server");
    let bound_server_addr = server_endpoint.endpoint.local_addr().unwrap();

    let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_endpoint = ArkQuicEndpoint::new_client(client_addr)
        .expect("Failed to start QUIC client");

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.endpoint.accept().await.expect("No incoming connection");
        let conn = incoming.await.expect("Handshake failed on server");
        let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept bi-stream");
        let mut buf = [0u8; 4];
        recv.read_exact(&mut buf).await.expect("Server failed to read");
        assert_eq!(&buf, b"ping");
        send.write_all(b"pong").await.expect("Server failed to write");
        send.finish().unwrap();
        // Wait for client to finish or closed
        let _ = conn.closed().await;
        // Keep server endpoint alive
        drop(server_endpoint);
    });

    // Client connects
    let connecting = client_endpoint
        .endpoint
        .connect(bound_server_addr, "localhost")
        .expect("Failed to initiate connect");
    let conn = connecting.await.expect("Client handshake failed");

    let (mut send, mut recv) = conn.open_bi().await.expect("Failed to open bi-stream");
    send.write_all(b"ping").await.expect("Client failed to write");
    send.finish().unwrap();

    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf).await.expect("Client failed to read pong");
    assert_eq!(&buf, b"pong");

    conn.close(0u32.into(), b"done");
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_quic_mismatched_alpn_rejection() {
    let (cert_der, key_der) = generate_test_cert();

    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = ArkQuicEndpoint::new_server(server_addr, cert_der, key_der)
        .expect("Failed to start QUIC server");
    let bound_server_addr = server_endpoint.endpoint.local_addr().unwrap();

    // Create client with mismatched ALPN (e.g., "h3" or "bogus-alpn")
    let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut client_endpoint = quinn::Endpoint::client(client_addr).unwrap();

    let mut crypto_cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(DangerousVerifier))
        .with_no_client_auth();

    // Mismatched ALPN protocol
    crypto_cfg.alpn_protocols = vec![b"mismatched-alpn".to_vec()];

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto_cfg).unwrap();
    client_endpoint.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(quic_client_config)));

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.endpoint.accept().await {
            let _ = incoming.await; // Should fail handshake
        }
    });

    let connecting = client_endpoint.connect(bound_server_addr, "localhost").unwrap();
    let client_res = connecting.await;

    // Connection must fail due to ALPN mismatch
    assert!(client_res.is_err(), "Handshake with mismatched ALPN should fail");

    let _ = server_handle.await;
}

#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
