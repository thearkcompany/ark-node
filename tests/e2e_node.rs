//! End-to-End Integration Test Suite (Full Protocol & Storage Engine Verification)
//!
//! Tests the full protocol stack:
//! [x] Server manages active `StorageEngine` instance in addition to anti-replay and drift validation.
//! [x] Integration test spins up an in-process server listening on local UDP/QUIC and a client connects over ALPN "ark-pqc/v1".
//! [x] Server validates the 64-byte raw FastHeader directly before Protobuf decoding.
//! [x] Server verifies client's FN-DSA-512 signature on the envelope.
//! [x] Server inserts envelope nonce into DualCuckooAntiReplay and rejects simulated duplicate packet replay.
//! [x] Server validates envelope timestamp within +-30s window using DriftValidator.
//! [x] Server ingests valid signed Class 1 and Class 2 envelopes into `StorageEngine` and persists them.
//! [x] Server processes Class 0 ephemeral events in-memory without leaving disk records.
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
use ark_protocol::tags::{BinaryTag, TagMask, TAG_MASK_ROUTING, TAG_MASK_SIGNED};
use ark_protocol::wire::WireFrame;
use ark_storage::{compute_envelope_id, RetentionOutcome, StorageConfig, StorageEngine};
use ark_time::cuckoo::DualCuckooAntiReplay;
use ark_time::drift::DriftValidator;
use ark_transport::ArkQuicEndpoint;
use prost::Message;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

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

/// Helper to construct, sign, and wire-encode an ArkEnvelope
fn create_wire_packet(
    sender: &PersistentIdentity,
    recipient: &PersistentIdentity,
    sequence_nonce: u64,
    timestamp: u64,
    kind: u32,
    routing_mask: bool,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut mask = 0u64;
    TagMask::set_flag(&mut mask, TAG_MASK_SIGNED);
    if routing_mask {
        TagMask::set_flag(&mut mask, TAG_MASK_ROUTING);
    }

    let tags = vec![
        BinaryTag::new(0, kind.to_be_bytes().to_vec()),
        BinaryTag::new(1, vec![0x10, 0x20]),
    ];

    let mut partial_header = FastHeader::new(
        0x01,
        0, // placeholder before envelope calculation
        kind,
        sender.sender_key_id,
        recipient.sender_key_id,
        sequence_nonce,
    );

    let mut envelope = ArkEnvelope::new(
        partial_header.to_bytes(),
        sender.ark_id,
        recipient.ark_id,
        payload,
        vec![], // signature placeholder
        mask,
        tags,
        timestamp,
    )
    .expect("Failed to build envelope template");

    let canonical_id = calculate_canonical_id(&envelope);
    let signature = sender
        .fn_dsa_keypair
        .sign(&canonical_id)
        .expect("Failed to sign canonical ID");
    envelope.signature = signature;

    partial_header.envelope_len = envelope.encoded_len() as u32;

    WireFrame::encode(&partial_header, &envelope).expect("Failed to encode wire frame")
}

#[tokio::test]
async fn test_e2e_full_protocol_stack_verification() {
    let mut rng = OsRng;

    // 1. Generate post-quantum identities for client and server
    let server_identity = PersistentIdentity::generate(&mut rng);
    let client_identity = PersistentIdentity::generate(&mut rng);

    // 2. Set up server state: anti-replay filter and storage engine
    let storage_dir = tempdir().expect("create storage dir");
    let storage = Arc::new(
        StorageEngine::open(storage_dir.path(), StorageConfig::frugal())
            .expect("open storage engine"),
    );
    let anti_replay = Arc::new(DualCuckooAntiReplay::new());

    // 3. Spin up QUIC server listening on local UDP with ALPN ark-pqc/v1
    let (cert_der, key_der) = generate_server_cert();
    let server_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = ArkQuicEndpoint::new_server(server_bind_addr, cert_der, key_der)
        .expect("Failed to start QUIC server");
    let bound_server_addr = server_endpoint.endpoint.local_addr().unwrap();

    let server_anti_replay = Arc::clone(&anti_replay);
    let server_storage = Arc::clone(&storage);
    let client_pubkey_expected = client_identity.fn_dsa_keypair.public_key;

    // 4. Server task: accepts connections and verifies frames + retention outcomes
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint
            .endpoint
            .accept()
            .await
            .expect("Server failed to accept connection");
        let conn = incoming.await.expect("QUIC handshake failed on server");

        // Process first transmission: Class 1 (Append-Only)
        {
            let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept bi-stream 1");
            let wire_bytes = recv
                .read_to_end(128 * 1024)
                .await
                .expect("Server failed to read wire bytes 1");

            // Server validates the 64-byte raw FastHeader directly before Protobuf decoding
            assert!(wire_bytes.len() >= FAST_HEADER_SIZE, "Frame shorter than 64-byte FastHeader");
            let raw_header = WireFrame::inspect_header(&wire_bytes)
                .expect("Direct 64-byte FastHeader inspection failed");
            raw_header.validate().expect("FastHeader validation failed");
            assert_eq!(raw_header.magic, MAGIC_VALUE);
            assert_eq!(raw_header.version, 1);
            assert_eq!(raw_header.sender_key_id, client_identity.sender_key_id);
            assert_eq!(raw_header.recipient_key_id, server_identity.sender_key_id);

            // Decode full frame
            let (decoded_header, decoded_envelope) =
                WireFrame::decode(&wire_bytes).expect("Failed to decode wire frame");
            assert_eq!(decoded_header, raw_header);

            // Server validates envelope timestamp within +-30s window using DriftValidator
            DriftValidator::validate_now(decoded_envelope.timestamp)
                .expect("Envelope timestamp exceeds drift bounds");

            // Server verifies client's FN-DSA-512 signature on the envelope
            let canonical_id = calculate_canonical_id(&decoded_envelope);
            verify_fn_dsa_512(
                &client_pubkey_expected,
                &canonical_id,
                &decoded_envelope.signature,
            )
            .expect("FN-DSA-512 signature verification failed on server");

            // Server inserts envelope nonce into DualCuckooAntiReplay
            let nonce_bytes = raw_header.sequence_nonce.to_be_bytes();
            let fresh = server_anti_replay
                .check_and_insert(&nonce_bytes)
                .expect("Failed to insert nonce into DualCuckooAntiReplay");
            assert!(fresh, "Expected nonce to be fresh on first receipt");

            // Ingest into StorageEngine -> Class 1 Stored
            let outcome = server_storage
                .put_envelope(&decoded_envelope)
                .expect("store class 1 envelope");
            assert_eq!(outcome, RetentionOutcome::Stored);

            send.write_all(b"OK").await.expect("Server failed to write OK");
            send.finish().expect("Server failed to finish stream");
        }

        // Process second transmission over QUIC: simulated duplicate packet replay
        {
            let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept bi-stream 2");
            let replayed_bytes = recv
                .read_to_end(128 * 1024)
                .await
                .expect("Server failed to read replayed wire bytes");

            let raw_header = WireFrame::inspect_header(&replayed_bytes)
                .expect("Header inspection on replayed packet");
            let nonce_bytes = raw_header.sequence_nonce.to_be_bytes();

            let replay_res = server_anti_replay.check_and_insert(&nonce_bytes);
            match replay_res {
                Err(ArkError::ReplayDetected) => {
                    send.write_all(b"ERR_REPLAY").await.expect("Write replay rejection");
                    send.finish().expect("Finish replay stream");
                }
                other => panic!("Expected ReplayDetected on duplicate nonce over wire, got {:?}", other),
            }
        }

        // Process third transmission over QUIC: simulated excessive clock drift
        {
            let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept bi-stream 3");
            let drifted_bytes = recv
                .read_to_end(128 * 1024)
                .await
                .expect("Server failed to read drifted wire bytes");

            let (_, decoded_envelope) =
                WireFrame::decode(&drifted_bytes).expect("Decode drifted wire frame");

            let drift_res = DriftValidator::validate_now(decoded_envelope.timestamp);
            match drift_res {
                Err(ArkError::ClockDriftExceeded(_, 30)) => {
                    send.write_all(b"ERR_DRIFT").await.expect("Write drift rejection");
                    send.finish().expect("Finish drift stream");
                }
                other => panic!("Expected ClockDriftExceeded on drifted envelope over wire, got {:?}", other),
            }
        }

        // Process fourth transmission: Class 0 Ephemeral RAM-only message
        {
            let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept bi-stream 4");
            let eph_bytes = recv
                .read_to_end(128 * 1024)
                .await
                .expect("Server failed to read ephemeral wire bytes");

            let (header, decoded_envelope) =
                WireFrame::decode(&eph_bytes).expect("Decode ephemeral wire frame");

            let nonce_bytes = header.sequence_nonce.to_be_bytes();
            server_anti_replay
                .check_and_insert(&nonce_bytes)
                .expect("Insert nonce");

            let outcome = server_storage
                .put_envelope(&decoded_envelope)
                .expect("handle ephemeral envelope");
            assert_eq!(outcome, RetentionOutcome::EphemeralPassed);

            let eph_id = compute_envelope_id(&decoded_envelope).unwrap();
            assert!(
                server_storage.get_envelope(&eph_id).unwrap().is_none(),
                "Ephemeral event must leave zero disk traces"
            );

            send.write_all(b"OK_EPHEMERAL").await.expect("Write ok ephemeral");
            send.finish().expect("Finish stream");
        }

        // Process fifth transmission: Class 2 Replaceable record
        {
            let (mut send, mut recv) = conn.accept_bi().await.expect("Failed to accept bi-stream 5");
            let repl_bytes = recv
                .read_to_end(128 * 1024)
                .await
                .expect("Server failed to read replaceable wire bytes");

            let (header, decoded_envelope) =
                WireFrame::decode(&repl_bytes).expect("Decode replaceable wire frame");

            let nonce_bytes = header.sequence_nonce.to_be_bytes();
            server_anti_replay
                .check_and_insert(&nonce_bytes)
                .expect("Insert nonce");

            let outcome = server_storage
                .put_envelope(&decoded_envelope)
                .expect("store class 2 envelope");
            assert_eq!(outcome, RetentionOutcome::Stored);

            let repl_retrieved = server_storage
                .get_replaceable(&client_identity.sender_key_id, 10005)
                .unwrap()
                .expect("Class 2 record retrievable from storage");
            assert_eq!(repl_retrieved.payload, b"User profile version 1");

            send.write_all(b"OK_REPLACEABLE").await.expect("Write ok repl");
            send.finish().expect("Finish stream");
        }

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

    // 6. Send fresh valid Class 1 envelope
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let sequence_nonce: u64 = 424242;
    let payload = b"E2E Sovereign Message: Secure PQC Transmission".to_vec();

    let wire_bytes = create_wire_packet(
        &client_identity,
        &server_identity,
        sequence_nonce,
        now,
        1001,
        false,
        payload,
    );

    let (mut send1, mut recv1) = conn.open_bi().await.expect("Failed to open bi-stream 1");
    send1.write_all(&wire_bytes).await.expect("Client write wire bytes 1");
    send1.finish().expect("Client finish stream 1");

    let mut ok_buf = [0u8; 2];
    recv1.read_exact(&mut ok_buf).await.expect("Client read OK");
    assert_eq!(&ok_buf, b"OK");

    // 7. Transmit simulated duplicate packet replay over QUIC network stream
    let (mut send2, mut recv2) = conn.open_bi().await.expect("Failed to open bi-stream 2");
    send2.write_all(&wire_bytes).await.expect("Client send replayed wire bytes");
    send2.finish().expect("Client finish stream 2");

    let mut replay_buf = [0u8; 10];
    recv2.read_exact(&mut replay_buf).await.expect("Client read replay error");
    assert_eq!(&replay_buf, b"ERR_REPLAY");

    // 8. Transmit simulated excessive clock drift (+45s) over QUIC network stream
    let drifted_wire_bytes = create_wire_packet(
        &client_identity,
        &server_identity,
        sequence_nonce + 1,
        now + 45, // outside +-30s window
        1001,
        false,
        b"Clock drifted envelope".to_vec(),
    );

    let (mut send3, mut recv3) = conn.open_bi().await.expect("Failed to open bi-stream 3");
    send3.write_all(&drifted_wire_bytes).await.expect("Client send drifted wire bytes");
    send3.finish().expect("Client finish stream 3");

    let mut drift_buf = [0u8; 9];
    recv3.read_exact(&mut drift_buf).await.expect("Client read drift error");
    assert_eq!(&drift_buf, b"ERR_DRIFT");

    // 9. Transmit Class 0 Ephemeral packet (kind 25000)
    let eph_wire_bytes = create_wire_packet(
        &client_identity,
        &server_identity,
        sequence_nonce + 2,
        now,
        25000,
        true,
        b"Ephemeral ping beacon".to_vec(),
    );

    let (mut send4, mut recv4) = conn.open_bi().await.expect("Failed to open bi-stream 4");
    send4.write_all(&eph_wire_bytes).await.expect("Client send eph bytes");
    send4.finish().expect("Client finish stream 4");

    let mut eph_buf = [0u8; 12];
    recv4.read_exact(&mut eph_buf).await.expect("Client read eph ok");
    assert_eq!(&eph_buf, b"OK_EPHEMERAL");

    // 10. Transmit Class 2 Replaceable packet (kind 10005)
    let repl_wire_bytes = create_wire_packet(
        &client_identity,
        &server_identity,
        sequence_nonce + 3,
        now,
        10005,
        false,
        b"User profile version 1".to_vec(),
    );

    let (mut send5, mut recv5) = conn.open_bi().await.expect("Failed to open bi-stream 5");
    send5.write_all(&repl_wire_bytes).await.expect("Client send repl bytes");
    send5.finish().expect("Client finish stream 5");

    let mut repl_buf = [0u8; 14];
    recv5.read_exact(&mut repl_buf).await.expect("Client read repl ok");
    assert_eq!(&repl_buf, b"OK_REPLACEABLE");

    conn.close(0u32.into(), b"done");
    server_handle.await.expect("Server task encountered an error");

    // Verify stored envelopes directly from the server storage engine
    let (_header, decoded) = WireFrame::decode(&wire_bytes).unwrap();
    let id_class1 = compute_envelope_id(&decoded).unwrap();
    let fetched1 = storage.get_envelope(&id_class1).unwrap().expect("found class 1");
    assert_eq!(fetched1.payload, b"E2E Sovereign Message: Secure PQC Transmission");

    let fetched2 = storage
        .get_replaceable(&client_identity.sender_key_id, 10005)
        .unwrap()
        .expect("found class 2");
    assert_eq!(fetched2.payload, b"User profile version 1");
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
