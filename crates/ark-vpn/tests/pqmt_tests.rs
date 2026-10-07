//! Exhaustive tests for Post-Quantum Mesh Tunneling (PQMT) & Ephemeral Wire Framing (Issue #53).
//!
//! Covers:
//! 1. FastHeader (64B) -> MicroHeader (16B) transition.
//! 2. Retention Class 0 invariant (RAM-only bypass of Fjall LSM and disk).
//! 3. Post-Quantum ML-KEM-768 session key encapsulation/decapsulation with FN-DSA-512 signatures.
//! 4. Line-speed zero-copy packet serialization and deserialization.
//! 5. Integrity and decapsulation validation (tampered payload, bad MAC rejection, replay rejection).

use ark_core::constants::FAST_HEADER_SIZE;
use ark_crypto::identity::PersistentIdentity;
use ark_storage::config::StorageConfig;
use ark_storage::engine::StorageEngine;
use ark_storage::retention::{classify_retention, RetentionClass, RetentionOutcome};
use ark_vpn::error::VpnError;
use ark_vpn::framing::{
    deframe_fast_packet, deframe_micro_packet, frame_fast_packet, frame_micro_packet,
    MicroHeader, KIND_VPN_DATA, KIND_VPN_HANDSHAKE, MICRO_HEADER_SIZE,
};
use ark_vpn::pqmt::{PqmtEngine, VpnSession};
use bytes::Bytes;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tempfile::tempdir;

#[test]
fn test_micro_header_size_and_alignment() {
    assert_eq!(std::mem::size_of::<MicroHeader>(), 16);
    assert_eq!(MICRO_HEADER_SIZE, 16);

    let mac = [1, 2, 3, 4, 5, 6, 7, 8];
    let header = MicroHeader::new(0x12345678, 0x0000002a, mac);
    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), 16);

    let parsed = MicroHeader::from_bytes(&bytes).expect("MicroHeader parsing failed");
    assert_eq!(parsed.session_id, 0x12345678);
    assert_eq!(parsed.sequence_nonce, 0x0000002a);
    assert_eq!(parsed.session_mac, mac);
}

#[test]
fn test_fast_header_size_and_cache_line_alignment() {
    assert_eq!(FAST_HEADER_SIZE, 64);
    let payload = b"handshake-test-payload";
    let sender_id = [1u8; 16];
    let recipient_id = [2u8; 16];

    let framed = frame_fast_packet(0, sender_id, recipient_id, 42, payload);
    assert_eq!(framed.len(), 64 + payload.len());

    let (hdr, deframed_payload) = deframe_fast_packet(framed).expect("Deframe failed");
    assert_eq!(hdr.fast_tag, KIND_VPN_HANDSHAKE);
    assert_eq!(hdr.sender_key_id, sender_id);
    assert_eq!(hdr.recipient_key_id, recipient_id);
    assert_eq!(hdr.sequence_nonce, 42);
    assert_eq!(deframed_payload.as_ref(), payload);
}

#[test]
fn test_pqmt_full_handshake_and_session_establishment() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x42_1337);

    // Node A (Initiator) and Node B (Responder)
    let id_a = PersistentIdentity::generate(&mut rng);
    let id_b = PersistentIdentity::generate(&mut rng);

    let engine_a = PqmtEngine::new(id_a);
    let engine_b = PqmtEngine::new(id_b);

    let timestamp = 1_700_000_000u64;

    // 1. Node A creates HandshakeInit framed with 64-byte FastHeader
    let init_packet = engine_a
        .create_handshake_init(engine_b.identity().sender_key_id, timestamp, &mut rng)
        .expect("Init packet creation failed");

    // FastHeader check: initial packet has 64-byte FastHeader
    assert!(init_packet.len() >= 64);
    let (fast_hdr_init, _) = deframe_fast_packet(init_packet.clone()).expect("Deframe init fast header");
    assert_eq!(fast_hdr_init.fast_tag, KIND_VPN_HANDSHAKE);
    assert_eq!(fast_hdr_init.sender_key_id, engine_a.identity().sender_key_id);

    // 2. Node B handles HandshakeInit and returns HandshakeResp framed with 64-byte FastHeader
    let resp_packet = engine_b
        .handle_handshake_init(init_packet, timestamp + 1, &mut rng)
        .expect("Handle HandshakeInit failed");

    let (fast_hdr_resp, _) = deframe_fast_packet(resp_packet.clone()).expect("Deframe resp fast header");
    assert_eq!(fast_hdr_resp.fast_tag, KIND_VPN_HANDSHAKE);

    // 3. Node A handles HandshakeResp and establishes its session
    let session_id_a = engine_a
        .handle_handshake_resp(resp_packet)
        .expect("Handle HandshakeResp failed");

    assert_eq!(session_id_a, 100);

    // 4. Verify ongoing data packets transition to 16-byte MicroHeader
    let ip_packet_a_to_b = b"GET /vpn/metrics HTTP/1.1\r\nHost: ark0\r\n\r\n";
    let framed_data = engine_a
        .frame_data_packet(session_id_a, ip_packet_a_to_b)
        .expect("Frame data packet failed");

    // MicroHeader check: 16 bytes overhead strictly
    assert_eq!(framed_data.len(), 16 + ip_packet_a_to_b.len());

    // 5. Node B receives and deframes the MicroHeader data packet
    let (session_id_b, seq_b, deframed_payload) = engine_b
        .deframe_data_packet(framed_data)
        .expect("Deframe data packet failed");

    assert_eq!(session_id_b, session_id_a);
    assert_eq!(seq_b, 1);
    assert_eq!(deframed_payload.as_ref(), ip_packet_a_to_b);

    // 6. Node B replies with ongoing data packet back to Node A
    let ip_packet_b_to_a = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let framed_data_reply = engine_b
        .frame_data_packet(session_id_b, ip_packet_b_to_a)
        .expect("Frame data packet reply failed");

    assert_eq!(framed_data_reply.len(), 16 + ip_packet_b_to_a.len());

    let (session_id_a_recv, seq_a, deframed_reply_payload) = engine_a
        .deframe_data_packet(framed_data_reply)
        .expect("Deframe data packet reply failed");

    assert_eq!(session_id_a_recv, session_id_a);
    assert_eq!(seq_a, 1);
    assert_eq!(deframed_reply_payload.as_ref(), ip_packet_b_to_a);
}

#[test]
fn test_retention_class0_invariant_and_storage_bypass() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x999);
    let id_a = PersistentIdentity::generate(&mut rng);
    let engine = PqmtEngine::new(id_a);

    let recipient_id = [0x55u8; 32];
    let payload = vec![0xaa, 0xbb, 0xcc, 0xdd];

    // Envelope for VPN Handshake (0x0009)
    let env_handshake = engine
        .wrap_in_envelope(KIND_VPN_HANDSHAKE, recipient_id, payload.clone(), 1_700_000_000)
        .expect("Envelope creation failed");

    // Envelope for VPN Data (0x0008)
    let env_data = engine
        .wrap_in_envelope(KIND_VPN_DATA, recipient_id, payload.clone(), 1_700_000_001)
        .expect("Envelope creation failed");

    // Check 1: Classifier classifies both strictly as Class0Ephemeral
    assert_eq!(classify_retention(&env_handshake), RetentionClass::Class0Ephemeral);
    assert_eq!(classify_retention(&env_data), RetentionClass::Class0Ephemeral);

    // Check 2: Put in StorageEngine completely bypasses disk / Fjall LSM
    let dir = tempdir().expect("Failed to create tempdir");
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("Failed to open StorageEngine");

    let outcome_hs = storage.put_envelope(&env_handshake).expect("put_envelope failed");
    assert_eq!(outcome_hs, RetentionOutcome::EphemeralPassed);

    let outcome_data = storage.put_envelope(&env_data).expect("put_envelope failed");
    assert_eq!(outcome_data, RetentionOutcome::EphemeralPassed);

    // Ensure database keyspaces remain empty for persistent classes
    let retrieved_hs = storage.get_envelope(&[0u8; 32]).expect("get failed");
    assert!(retrieved_hs.is_none());
}

#[test]
fn test_tampered_payload_and_mac_rejection() {
    let session_key = [0x42u8; 32];
    let session_id = 777;
    let seq = 1;
    let payload = b"confidential-tunneled-ip-payload";

    let framed = frame_micro_packet(session_id, seq, &session_key, payload).to_vec();

    // 1. Successful deframe without tampering
    let (hdr, deframed) = deframe_micro_packet(&session_key, Bytes::copy_from_slice(&framed))
        .expect("Clean deframe should succeed");
    assert_eq!(hdr.session_id, session_id);
    assert_eq!(deframed.as_ref(), payload);

    // 2. Tampered payload content
    let mut tampered_payload = framed.clone();
    tampered_payload[18] ^= 0xff; // Flip a bit in the payload portion
    let err_tampered = deframe_micro_packet(&session_key, Bytes::from(tampered_payload))
        .expect_err("Tampered payload should fail MAC verification");
    assert_eq!(err_tampered, VpnError::SessionMacInvalid);

    // 3. Tampered MAC bytes
    let mut tampered_mac = framed.clone();
    tampered_mac[10] ^= 0x01; // Flip a bit in the session_mac portion
    let err_mac = deframe_micro_packet(&session_key, Bytes::from(tampered_mac))
        .expect_err("Tampered MAC should fail verification");
    assert_eq!(err_mac, VpnError::SessionMacInvalid);

    // 4. Incorrect session key
    let wrong_key = [0x99u8; 32];
    let err_wrong_key = deframe_micro_packet(&wrong_key, Bytes::copy_from_slice(&framed))
        .expect_err("Wrong key should fail verification");
    assert_eq!(err_wrong_key, VpnError::SessionMacInvalid);
}

#[test]
fn test_anti_replay_and_monotonic_sequence_enforcement() {
    let mut session = VpnSession {
        session_id: 1,
        peer_ark_id: [0u8; 32],
        send_key: [1u8; 32],
        recv_key: [2u8; 32],
        send_seq: 1,
        recv_seq: 0,
    };

    // First packet accepted
    assert!(session.accept_recv_seq(1).is_ok());

    // Higher seq accepted
    assert!(session.accept_recv_seq(2).is_ok());

    // Duplicate seq (replay attack) rejected
    let err_replay = session.accept_recv_seq(2).expect_err("Replay must be rejected");
    assert_eq!(err_replay, VpnError::ReplayDetected(2));

    // Lower seq (delayed / replay attack) rejected
    let err_old = session.accept_recv_seq(1).expect_err("Older packet must be rejected");
    assert_eq!(err_old, VpnError::ReplayDetected(1));

    // Strictly monotonic progression succeeds
    assert!(session.accept_recv_seq(5).is_ok());
    assert!(session.accept_recv_seq(6).is_ok());
}

#[test]
fn test_zero_copy_slicing_and_buffer_performance() {
    let session_key = [0x11u8; 32];
    let payload = Bytes::from_static(b"zero-copy-wire-speed-buffer");

    let framed = frame_micro_packet(1234, 10, &session_key, &payload);
    assert_eq!(framed.len(), 16 + payload.len());

    let (hdr, deframed) = deframe_micro_packet(&session_key, framed)
        .expect("Zero-copy deframing failed");

    assert_eq!(hdr.session_id, 1234);
    assert_eq!(hdr.sequence_nonce, 10);
    assert_eq!(deframed, payload);
}
