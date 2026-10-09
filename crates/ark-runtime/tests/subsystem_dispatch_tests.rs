
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
async fn test_subsystem_dispatch_routing_and_fault_isolation() {
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

    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Failed to create client endpoint");

    let connecting = client_endpoint
        .endpoint
        .connect(bound_addr, "localhost")
        .expect("Failed to connect");
    let conn = connecting.await.expect("Client handshake failed");

    // 1. Send DNS claim envelope (KIND_DNS_CLAIM_PUBLIC = 0x3000_0002)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let fast_header_dns = FastHeader::new(0, 128, 0x3000_0002, [1u8; 16], [2u8; 16], 1);
    let mut env_dns = ArkEnvelope {
        magic: ark_core::constants::MAGIC_BYTES.to_vec(),
        fast_header: fast_header_dns.to_bytes().to_vec(),
        sender_id: vec![1u8; 16],
        recipient_id: vec![0u8; 32],
        payload: b"127.0.0.1:8080".to_vec(),
        signature: vec![1u8; 64],
        core_tag_mask: 0,
        tags: vec![
            BinaryTag::new(0, 0x3000_0002u32.to_be_bytes().to_vec()),
            BinaryTag::new(ark_dns::anti_sybil::TAG_PARAM_D, b"sovereign.ark".to_vec()),
            BinaryTag::new(ark_dns::anti_sybil::TAG_DNS_LEASE_EPOCH, (now + 30 * 86_400).to_be_bytes().to_vec()),
            BinaryTag::new(ark_dns::anti_sybil::TAG_L2_CONTRACT, b"mock-contract".to_vec()),
            BinaryTag::new(ark_dns::anti_sybil::TAG_NONCE, 0u64.to_be_bytes().to_vec()),
        ],
        timestamp: now,
    };
    for nonce in 0u64..1_000_000 {
        for tag in &mut env_dns.tags {
            if tag.tag_type == ark_dns::anti_sybil::TAG_NONCE {
                tag.tag_value = nonce.to_be_bytes().to_vec();
                break;
            }
        }
        let id = ark_storage::compute_envelope_id(&env_dns).unwrap();
        if id[0] == 0 && id[1] == 0 {
            break;
        }
    }
    let wire_dns = WireFrame::encode(&fast_header_dns, &env_dns).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_dns).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "DNS dispatch should return ACK 1");

    // 2. Send WoT attestation envelope (KIND_WOT_ATTESTATION = 0x000A)
    let wot_issuer_key = ark_crypto::fn_dsa::FnDsaKeyPair::generate(&mut rng);
    let wot_issuer_id = ark_crypto::identity::Identity::from_public_key(&wot_issuer_key.public_key).ark_id;
    let wot_subject_id = [2u8; 32];
    let mut wot_scopes = ark_wot::crypto::CapabilityScopes::empty();
    wot_scopes.insert(ark_wot::crypto::CapabilityScope::RELAY);
    let att = ark_wot::crypto::TrustAttestation::create_and_sign(
        wot_issuer_id,
        wot_subject_id,
        0.8,
        wot_scopes,
        now,
        now + 30 * 86400,
        2,
        &wot_issuer_key,
    ).unwrap();
    let env_wot = att.to_envelope(&wot_issuer_key.public_key).unwrap();
    let fast_header_wot = FastHeader::from_bytes(&env_wot.fast_header[..64].try_into().unwrap()).unwrap();
    let wire_wot = WireFrame::encode(&fast_header_wot, &env_wot).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_wot).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "WoT dispatch should return ACK 1");

    // 3. Send DePIN challenge envelope (KIND_DEPIN_CHALLENGE = 0x4000_0002)
    let fast_header_blob = FastHeader::new(0, 100, 0x4000_0002, [1u8; 16], [2u8; 16], 3);
    let env_blob = ArkEnvelope::new(
        fast_header_blob.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"depin-challenge-payload".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x4000_0002u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).unwrap();
    let wire_blob = WireFrame::encode(&fast_header_blob, &env_blob).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_blob).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "Blob challenge dispatch should return ACK 1");

    // 4. Fault isolation test: Send corrupt/malformed payload under PaaS kind
    // Daemon and QUIC connection should remain fully alive
    let fast_header_bad = FastHeader::new(0, 100, 0x5000_0001, [1u8; 16], [2u8; 16], 4);
    let env_bad = ArkEnvelope::new(
        fast_header_bad.to_bytes(),
        [1u8; 32],
        [2u8; 32],
        b"corrupt-paas-worker-trap".to_vec(),
        vec![0u8; 64],
        0,
        vec![BinaryTag::new(0, 0x5000_0001u32.to_be_bytes().to_vec())],
        1_700_000_000,
    ).unwrap();
    let wire_bad = WireFrame::encode(&fast_header_bad, &env_bad).unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&wire_bad).await.unwrap();
    send.finish().unwrap();
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 1, "Fault should be isolated and envelope handled gracefully");

    // Check daemon status is still Running
    assert_eq!(handle.status(), ark_runtime::NodeRuntimeStatus::Running);

    handle.shutdown().await.unwrap();
}
