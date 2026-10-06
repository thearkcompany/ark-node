//! End-to-End Integration Test Suite (Full Protocol Verification)
//!
//! Tests the full protocol stack:
//! [x] Integration test spins up an in-process server listening on local UDP/QUIC and a client connects over ALPN "ark-pqc/v1".
//! [x] Server validates the 64-byte raw FastHeader directly before Protobuf decoding.
//! [x] Server verifies client's FN-DSA-512 signature on the envelope.
//! [x] Server inserts envelope nonce into DualCuckooAntiReplay and rejects simulated duplicate packet replay.
//! [x] Server validates envelope timestamp within +-30s window using DriftValidator.
//! [x] Test harness asserts rejection when client attempts connection with mismatched ALPN (e.g. "ark-pqc/v0").
//! [x] Test suite runs cleanly in `cargo test --test e2e_node`.

use ark_core::constants::{FAST_HEADER_SIZE, MAGIC_VALUE};
use ark_core::error::ArkError;
use ark_core::fast_header::FastHeader;
use ark_core::traits::AntiReplayFilter;
use ark_crypto::fn_dsa::verify_fn_dsa_512;
use ark_crypto::identity::PersistentIdentity;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::hashing::calculate_canonical_id;
use ark_protocol::tags::{BinaryTag, TagMask, TAG_MASK_SIGNED};
use ark_protocol::wire::WireFrame;
use ark_time::cuckoo::DualCuckooAntiReplay;
use ark_time::drift::DriftValidator;
use ark_transport::ArkQuicEndpoint;
use prost::Message;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Helper to generate self-signed certificate DER pair for QUIC server
fn generate_server_cert() -> (Vec<u8>, Vec<u8>) {
    let rcgen_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rcgen_cert.cert.der().to_vec();
    let key_der = rcgen_cert.key_pair.serialize_der();
    (cert_der, key_der)
}

#[tokio::test]
async fn test_e2e_full_protocol_stack_verification() {
    let mut rng = OsRng;

    // 1. Generate post-quantum identities for client and server
    let server_identity = PersistentIdentity::generate(&mut rng);
    let client_identity = PersistentIdentity::generate(&mut rng);

    // 2. Set up server state: anti-replay filter
    let anti_replay = Arc::new(DualCuckooAntiReplay::new());

    // 3. Spin up QUIC server listening on local UDP with ALPN ark-pqc/v1
    let (cert_der, key_der) = generate_server_cert();
    let server_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = ArkQuicEndpoint::new_server(server_bind_addr, cert_der, key_der)
        .expect("Failed to start QUIC server");
    let bound_server_addr = server_endpoint.endpoint.local_addr().unwrap();

    // 4. Server worker task handling incoming connection and protocol verification
    let server_anti_replay = anti_replay.clone();
    let client_pubkey_expected = client_identity.fn_dsa_keypair.public_key;
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint
            .endpoint
            .accept()
            .await
            .expect("Server failed to accept connection");
        let conn = incoming.await.expect("QUIC handshake failed on server");

        let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept bi-stream");

        // Read framed packet from stream
        // Read 4 bytes length prefix first or read wire frame until finished
        let wire_bytes = recv
            .read_to_end(128 * 1024)
            .await
            .expect("Server failed to read wire bytes");

        // [Criteria 2] Server validates the 64-byte raw FastHeader directly before Protobuf decoding
        assert!(wire_bytes.len() >= FAST_HEADER_SIZE, "Frame shorter than 64-byte FastHeader");
        let raw_header = WireFrame::inspect_header(&wire_bytes)
            .expect("Direct 64-byte FastHeader inspection failed");
        raw_header.validate().expect("FastHeader validation failed");
        assert_eq!(raw_header.magic, MAGIC_VALUE);
        assert_eq!(raw_header.version, 1);
        assert_eq!(raw_header.sender_key_id, client_identity.sender_key_id);
        assert_eq!(raw_header.recipient_key_id, server_identity.sender_key_id);

        // Now decode full frame
        let (decoded_header, decoded_envelope) =
            WireFrame::decode(&wire_bytes).expect("Failed to decode wire frame");
        assert_eq!(decoded_header, raw_header);

        // [Criteria 5] Server validates envelope timestamp within +-30s window using DriftValidator
        DriftValidator::validate_now(decoded_envelope.timestamp)
            .expect("Envelope timestamp exceeds drift bounds");

        // [Criteria 3] Server verifies client's FN-DSA-512 signature on the envelope
        let canonical_id = calculate_canonical_id(&decoded_envelope);
        verify_fn_dsa_512(
            &client_pubkey_expected,
            &canonical_id,
            &decoded_envelope.signature,
        )
        .expect("FN-DSA-512 signature verification failed on server");

        // [Criteria 4] Server inserts envelope nonce into DualCuckooAntiReplay and rejects duplicate
        let nonce_bytes = raw_header.sequence_nonce.to_be_bytes();
        let fresh = server_anti_replay
            .check_and_insert(&nonce_bytes)
            .expect("Failed to insert nonce into DualCuckooAntiReplay");
        assert!(fresh, "Expected nonce to be fresh on first receipt");

        // Simulated duplicate packet replay rejection
        let replay_res = server_anti_replay.check_and_insert(&nonce_bytes);
        match replay_res {
            Err(ArkError::ReplayDetected) => (),
            other => panic!("Expected ReplayDetected on duplicate nonce, got {:?}", other),
        }

        // Respond with acknowledgment
        send.write_all(b"ARK_ACK").await.expect("Server failed to write ACK");
        send.finish().expect("Server failed to finish stream");

        let _ = conn.closed().await;
    });

    // 5. Client spins up endpoint and connects over ALPN ark-pqc/v1
    let client_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_endpoint = ArkQuicEndpoint::new_client(client_bind_addr)
        .expect("Failed to start QUIC client");

    let connecting = client_endpoint
        .endpoint
        .connect(bound_server_addr, "localhost")
        .expect("Failed to initiate connect");
    let conn = connecting.await.expect("Client handshake failed");

    // 6. Build valid client envelope and wire frame
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let sequence_nonce: u64 = 424242;

    let payload = b"E2E Sovereign Message: Secure PQC Transmission".to_vec();
    let mut mask = 0u64;
    TagMask::set_flag(&mut mask, TAG_MASK_SIGNED);
    let tags = vec![BinaryTag::new(1, vec![0x10, 0x20])];

    let mut partial_header = FastHeader::new(
        0x01,
        0, // placeholder before envelope calculation
        0xDEADBEEF,
        client_identity.sender_key_id,
        server_identity.sender_key_id,
        sequence_nonce,
    );

    // Construct envelope without signature first to calculate canonical ID
    let mut envelope = ArkEnvelope::new(
        partial_header.to_bytes(),
        client_identity.ark_id,
        server_identity.ark_id,
        payload.clone(),
        vec![], // signature placeholder
        mask,
        tags,
        now,
    )
    .expect("Failed to build envelope template");

    // Compute canonical ID and sign with client FN-DSA-512 private key
    let canonical_id = calculate_canonical_id(&envelope);
    let signature = client_identity
        .fn_dsa_keypair
        .sign(&canonical_id)
        .expect("Client failed to sign canonical ID");
    envelope.signature = signature;

    // Update header with actual envelope length
    partial_header.envelope_len = envelope.encoded_len() as u32;

    // Encode to wire format: [64B FastHeader] || [Protobuf Envelope]
    let wire_bytes = WireFrame::encode(&partial_header, &envelope)
        .expect("Failed to encode wire frame");

    // Send over QUIC bidirectional stream
    let (mut send, mut recv) = conn.open_bi().await.expect("Failed to open bi-stream");
    send.write_all(&wire_bytes).await.expect("Client failed to write wire frame");
    send.finish().expect("Client failed to finish write");

    let mut ack_buf = [0u8; 7];
    recv.read_exact(&mut ack_buf).await.expect("Client failed to read ACK");
    assert_eq!(&ack_buf, b"ARK_ACK");

    conn.close(0u32.into(), b"done");
    server_handle.await.expect("Server task encountered an error");
}

#[tokio::test]
async fn test_e2e_rejection_on_mismatched_alpn() {
    let (cert_der, key_der) = generate_server_cert();
    let server_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = ArkQuicEndpoint::new_server(server_bind_addr, cert_der, key_der)
        .expect("Failed to start QUIC server");
    let bound_server_addr = server_endpoint.endpoint.local_addr().unwrap();

    // Client connects with mismatched ALPN (e.g. "ark-pqc/v0")
    let client_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut client_endpoint = quinn::Endpoint::client(client_bind_addr)
        .expect("Failed to create quinn client endpoint");

    let mut crypto_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
    .with_no_client_auth();

    // Mismatched ALPN protocol
    crypto_cfg.alpn_protocols = vec![b"ark-pqc/v0".to_vec()];

    let quic_client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_cfg).unwrap();
    client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quic_client_config,
    )));

    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.endpoint.accept().await {
            let _ = incoming.await; // Handshake fails
        }
    });

    let connecting = client_endpoint.connect(bound_server_addr, "localhost").unwrap();
    let client_res = connecting.await;

    assert!(
        client_res.is_err(),
        "QUIC connection must be rejected when client requests mismatched ALPN 'ark-pqc/v0'"
    );

    let _ = server_handle.await;
}

#[tokio::test]
async fn test_e2e_rejection_on_excessive_clock_drift() {
    // Assert DriftValidator rejects timestamps outside the +-30s window
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Valid: within +-30s
    assert!(DriftValidator::validate_now(now).is_ok());
    assert!(DriftValidator::validate_now(now + 15).is_ok());
    assert!(DriftValidator::validate_now(now - 15).is_ok());

    // Invalid: past 30s in the future
    let future_res = DriftValidator::validate_now(now + 31);
    assert!(matches!(future_res, Err(ArkError::ClockDriftExceeded(_, 30))));

    // Invalid: past 30s in the past
    let past_res = DriftValidator::validate_now(now - 31);
    assert!(matches!(past_res, Err(ArkError::ClockDriftExceeded(_, 30))));
}
