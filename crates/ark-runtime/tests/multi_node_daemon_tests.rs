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

    // Clean shutdown of initial interaction
    handle_a.shutdown().await.expect("Node A shutdown failed");
    handle_b.shutdown().await.expect("Node B shutdown failed");
}

fn create_test_dns_claim_envelope(
    fqdn: &str,
    lease_epoch: u64,
    contract_id: &[u8],
    owner_key_id: [u8; 16],
) -> ArkEnvelope {
    use ark_dns::anti_sybil::{TAG_DNS_LEASE_EPOCH, TAG_L2_CONTRACT, TAG_NONCE, TAG_PARAM_D};

    let fast_header = FastHeader::new(
        0,
        128,
        ark_runtime::dispatcher::KIND_DNS_CLAIM_PUBLIC,
        owner_key_id,
        [0u8; 16],
        1,
    );

    let mut envelope = ArkEnvelope {
        magic: ark_core::constants::MAGIC_BYTES.to_vec(),
        fast_header: fast_header.to_bytes().to_vec(),
        sender_id: owner_key_id.to_vec(),
        recipient_id: vec![0u8; 32],
        payload: b"127.0.0.1:8080".to_vec(),
        signature: vec![1u8; 64],
        core_tag_mask: 0,
        tags: vec![
            BinaryTag::new(TAG_PARAM_D, fqdn.as_bytes().to_vec()),
            BinaryTag::new(TAG_DNS_LEASE_EPOCH, lease_epoch.to_be_bytes().to_vec()),
            BinaryTag::new(TAG_L2_CONTRACT, contract_id.to_vec()),
            BinaryTag::new(TAG_NONCE, 0u64.to_be_bytes().to_vec()),
        ],
        timestamp: 1_700_000_000,
    };

    // Mine 16-bit PoW (leading 2 zero bytes)
    for nonce in 0u64..1_000_000 {
        for tag in &mut envelope.tags {
            if tag.tag_type == TAG_NONCE {
                tag.tag_value = nonce.to_be_bytes().to_vec();
                break;
            }
        }
        let id = ark_storage::compute_envelope_id(&envelope).unwrap();
        if id[0] == 0 && id[1] == 0 {
            return envelope;
        }
    }
    panic!("Failed to mine 16-bit PoW in test helper");
}

#[tokio::test]
async fn test_multi_node_dns_claim_and_merkle_resolution() {
    let tmp = tempdir().unwrap();
    let mut rng = OsRng;
    let identity = PersistentIdentity::generate(&mut rng);

    // Spawn sovereign node daemon with DNS enabled
    let handle = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp.path())
        .role(Role::Server)
        .identity(identity)
        .enable_dns(true)
        .spawn()
        .await
        .expect("Failed to spawn node runtime");

    let addr = handle.local_addr();

    // Client connects over live QUIC
    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Failed to create client endpoint");
    let conn = client_endpoint
        .endpoint
        .connect(addr, "localhost")
        .expect("Failed to connect")
        .await
        .expect("Client QUIC handshake failed");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let owner_key_id = [42u8; 16];
    let contract_id = b"l2-escrow-pqc-001";
    let lease_epoch = now + 30 * 86_400;
    let domain = "peer-sovereign.ark";

    let env = create_test_dns_claim_envelope(domain, lease_epoch, contract_id, owner_key_id);
    let envelope_id = ark_storage::compute_envelope_id(&env).expect("Compute ID");
    let fast_header = FastHeader::from_bytes(&env.fast_header[..64].try_into().unwrap()).unwrap();
    let wire_bytes = WireFrame::encode(&fast_header, &env).expect("Encode wire frame");

    let (mut send, mut recv) = conn.open_bi().await.expect("Open bi stream");
    send.write_all(&wire_bytes).await.expect("Send wire bytes");
    send.finish().expect("Finish send");

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Receive ack");
    assert_eq!(ack[0], 1, "DNS claim frame over live QUIC must yield ACK 1");

    // Peer node storage check
    let stored = handle.storage().get_envelope(&envelope_id).expect("Storage query");
    assert!(stored.is_some(), "Registered DNS claim envelope must be persisted in StorageEngine");

    // Peer node DNS resolution and Merkle inclusion proof check
    let dns_engine = handle.dispatcher().dns_engine().expect("DNS engine must be present");
    let resolve_res = dns_engine.resolve(domain, None).expect("Domain must resolve on peer node");
    assert_eq!(resolve_res.owner_key_id, owner_key_id.to_vec());
    assert!(!resolve_res.merkle_inclusion_proof.is_empty(), "Resolved domain must have valid Merkle inclusion proof");

    handle.shutdown().await.expect("Node shutdown failed");
}

#[tokio::test]
async fn test_multi_node_wot_attestation_updates_cache_and_trust_tiers() {
    let tmp = tempdir().unwrap();
    let mut rng = OsRng;

    // Spawn sovereign node daemon with WoT enabled using a generated PersistentIdentity
    let node_identity = PersistentIdentity::generate(&mut rng);
    let root_id = node_identity.ark_id;
    let root_key = node_identity.fn_dsa_keypair.clone();

    let handle = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp.path())
        .role(Role::Server)
        .identity(node_identity)
        .enable_wot(true)
        .spawn()
        .await
        .expect("Failed to spawn node runtime");

    let addr = handle.local_addr();

    // Verify initial trust evaluation: subject is unknown (Untrusted)
    let wot_engine = handle.dispatcher().wot_engine().expect("WoT engine must be present");
    let subject_key = ark_crypto::fn_dsa::FnDsaKeyPair::generate(&mut rng);
    let subject_id = ark_crypto::identity::Identity::from_public_key(&subject_key.public_key).ark_id;

    let initial_eval = wot_engine.evaluate_trust(&subject_id);
    assert_eq!(initial_eval.tier, ark_wot::graph::TrustTier::Untrusted);
    assert!(!wot_engine.is_vpn_allowed(&subject_id));

    // The node root issues a high-confidence attestation certifying the subject
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut scopes = ark_wot::crypto::CapabilityScopes::empty();
    scopes.insert(ark_wot::crypto::CapabilityScope::RELAY);
    scopes.insert(ark_wot::crypto::CapabilityScope::STORAGE);

    // Create attestation from root_id -> subject_id
    let att = ark_wot::crypto::TrustAttestation::create_and_sign(
        root_id,
        subject_id,
        0.95,
        scopes,
        now,
        now + 30 * 86_400,
        1,
        &root_key,
    ).expect("Sign attestation");

    let env_att = att.to_envelope(&root_key.public_key).expect("To envelope");
    let envelope_id = ark_storage::compute_envelope_id(&env_att).expect("Compute ID");

    let fast_header = FastHeader::from_bytes(&env_att.fast_header[..64].try_into().unwrap()).unwrap();
    let wire_bytes = WireFrame::encode(&fast_header, &env_att).expect("Encode wire frame");

    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Client endpoint");
    let conn = client_endpoint
        .endpoint
        .connect(addr, "localhost")
        .expect("Connect")
        .await
        .expect("Handshake");

    let (mut send, mut recv) = conn.open_bi().await.expect("Open bi");
    send.write_all(&wire_bytes).await.expect("Write wire bytes");
    send.finish().expect("Finish send");

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Read ack");
    assert_eq!(ack[0], 1, "WoT attestation frame must yield ACK 1");

    // Verify storage persistence
    let stored = handle.storage().get_envelope(&envelope_id).expect("Storage query");
    assert!(stored.is_some(), "WoT attestation must be persisted in storage");

    // Verify recipient's evaluation cache and trust tiers are updated
    let updated_eval = wot_engine.evaluate_trust(&subject_id);
    assert_eq!(updated_eval.tier, ark_wot::graph::TrustTier::Trusted, "Trust tier must be upgraded to Trusted");
    assert!(updated_eval.score >= 0.5, "Trust score must reflect attestation weight (score: {})", updated_eval.score);
    assert!(wot_engine.is_vpn_allowed(&subject_id), "VPN admission check must now succeed");
    assert!(wot_engine.is_storage_allowed(&subject_id), "Storage admission check must now succeed");

    handle.shutdown().await.expect("Shutdown root handle");
}

#[tokio::test]
async fn test_adversarial_rejection_and_zero_storage_entries() {
    let tmp = tempdir().unwrap();
    let mut rng = OsRng;
    let identity = PersistentIdentity::generate(&mut rng);

    let handle = NodeRuntimeBuilder::new()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .data_dir(tmp.path())
        .role(Role::Server)
        .identity(identity)
        .enable_dns(true)
        .enable_wot(true)
        .spawn()
        .await
        .expect("Failed to spawn node runtime");

    let addr = handle.local_addr();

    let client_endpoint = ArkQuicEndpoint::new_client("127.0.0.1:0".parse().unwrap())
        .expect("Client endpoint");
    let conn = client_endpoint
        .endpoint
        .connect(addr, "localhost")
        .expect("Connect")
        .await
        .expect("Handshake");

    // 1. Adversarial: DNS claim with missing/invalid PoW
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut bad_dns_env = create_test_dns_claim_envelope("adversarial.ark", now + 86400, b"contract-adv", [99u8; 16]);
    // Corrupt PoW by deliberately breaking the nonce
    for tag in &mut bad_dns_env.tags {
        if tag.tag_type == ark_dns::anti_sybil::TAG_NONCE {
            tag.tag_value = 0xDEADBEEF_u64.to_be_bytes().to_vec();
            break;
        }
    }
    let bad_dns_id = ark_storage::compute_envelope_id(&bad_dns_env).expect("Compute ID");
    assert!(bad_dns_id[0] != 0 || bad_dns_id[1] != 0, "Tampered envelope must fail PoW");

    let bad_dns_header = FastHeader::from_bytes(&bad_dns_env.fast_header[..64].try_into().unwrap()).unwrap();
    let wire_bad_dns = WireFrame::encode(&bad_dns_header, &bad_dns_env).expect("Encode");

    let (mut send, mut recv) = conn.open_bi().await.expect("Open bi");
    send.write_all(&wire_bad_dns).await.expect("Write bad dns wire");
    send.finish().expect("Finish");

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Read ack");
    assert_eq!(ack[0], 0, "Missing PoW must produce NACK 0");

    let stored_bad_dns = handle.storage().get_envelope(&bad_dns_id).expect("Query storage");
    assert!(stored_bad_dns.is_none(), "Adversarial envelope with missing PoW must leave zero entries in StorageEngine");

    // 2. Adversarial: WoT attestation with corrupted signature
    let issuer_key = ark_crypto::fn_dsa::FnDsaKeyPair::generate(&mut rng);
    let issuer_id = ark_crypto::identity::Identity::from_public_key(&issuer_key.public_key).ark_id;
    let subject_id = [77u8; 32];
    let scopes = ark_wot::crypto::CapabilityScopes::empty();

    let att = ark_wot::crypto::TrustAttestation::create_and_sign(
        issuer_id,
        subject_id,
        0.5,
        scopes,
        now,
        now + 86400,
        1,
        &issuer_key,
    ).expect("Sign att");

    let mut bad_wot_env = att.to_envelope(&issuer_key.public_key).expect("To envelope");
    // Corrupt the signature inside CBOR payload
    let mut tampered_att = att.clone();
    tampered_att.signature[0] ^= 0xFF;
    bad_wot_env.payload = tampered_att.to_cbor().unwrap();
    let bad_wot_id = ark_storage::compute_envelope_id(&bad_wot_env).expect("Compute ID");

    let bad_wot_header = FastHeader::from_bytes(&bad_wot_env.fast_header[..64].try_into().unwrap()).unwrap();
    let wire_bad_wot = WireFrame::encode(&bad_wot_header, &bad_wot_env).expect("Encode");

    let (mut send, mut recv) = conn.open_bi().await.expect("Open bi");
    send.write_all(&wire_bad_wot).await.expect("Write bad wot wire");
    send.finish().expect("Finish");

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await.expect("Read ack");
    assert_eq!(ack[0], 0, "Corrupted signature must produce NACK 0");

    let stored_bad_wot = handle.storage().get_envelope(&bad_wot_id).expect("Query storage");
    assert!(stored_bad_wot.is_none(), "Adversarial envelope with corrupted signature must leave zero entries in StorageEngine");

    handle.shutdown().await.expect("Shutdown failed");
}
