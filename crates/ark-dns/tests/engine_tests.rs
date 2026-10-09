use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tempfile::tempdir;

use ark_core::FastHeader;
use ark_dns::anti_sybil::{
    L2ContractVerifier, KIND_DNS_CLAIM_PUBLIC, TAG_DNS_LEASE_EPOCH,
    TAG_L2_CONTRACT, TAG_NONCE, TAG_PARAM_D,
};
use ark_dns::crypto_name::format_cryptographic_name_from_hash;
use ark_dns::engine::{DnsPacketHandler, SovereignDnsEngine};
use ark_dns::error::DnsError;
use ark_dns::lifecycle::{MockPmtClock, PmtClock};
use ark_dns::overlay::OverlayRecord;


use ark_dns::record::DomainRoutingRecord;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::proto::DomainResolveResponse;
use ark_protocol::tags::BinaryTag;
use ark_storage::{compute_envelope_id, StorageConfig, StorageEngine};
use prost::Message;

struct TestL2Verifier {
    valid_contracts: Vec<(Vec<u8>, Vec<u8>)>,
}

impl TestL2Verifier {
    fn new() -> Self {
        Self { valid_contracts: Vec::new() }
    }

    fn allow(mut self, contract_id: &[u8], owner_key_id: &[u8]) -> Self {
        self.valid_contracts.push((contract_id.to_vec(), owner_key_id.to_vec()));
        self
    }
}

impl L2ContractVerifier for TestL2Verifier {
    fn verify_escrow_contract(&self, contract_id: &[u8], owner_key_id: &[u8]) -> Result<bool, DnsError> {
        Ok(self.valid_contracts.iter().any(|(c, o)| c.as_slice() == contract_id && o.as_slice() == owner_key_id))
    }
}

fn create_valid_claim_envelope(
    fqdn: &str,
    lease_epoch: u64,
    contract_id: &[u8],
    owner_key_id: [u8; 16],
    target_peer_id: [u8; 32],
    routing_addrs: &[String],
    ech_pubkey: &[u8],
) -> ArkEnvelope {
    let fast_header = FastHeader::new(
        0,
        128,
        KIND_DNS_CLAIM_PUBLIC,
        owner_key_id,
        [0u8; 16],
        1,
    );

    // Payload can carry target_peer_id, routing_addrs, etc.
    let mut payload = Vec::new();
    payload.extend_from_slice(&target_peer_id);
    let addrs_json = serde_json::to_vec(routing_addrs).unwrap();
    payload.extend_from_slice(&(addrs_json.len() as u32).to_be_bytes());
    payload.extend_from_slice(&addrs_json);
    payload.extend_from_slice(ech_pubkey);

    let mut envelope = ArkEnvelope {
        magic: b"ARK1".to_vec(),
        fast_header: fast_header.to_bytes().to_vec(),
        sender_id: owner_key_id.to_vec(),
        recipient_id: vec![0u8; 32],
        payload,
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

    // Mine 16-bit PoW
    for nonce in 0u64..1_000_000 {
        for tag in &mut envelope.tags {
            if tag.tag_type == TAG_NONCE {
                tag.tag_value = nonce.to_be_bytes().to_vec();
                break;
            }
        }
        let id = compute_envelope_id(&envelope).unwrap();
        if id[0] == 0 && id[1] == 0 {
            return envelope;
        }
    }
    panic!("PoW mining failed in test");
}

#[test]
fn test_tier1_cryptographic_name_resolution() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let verifier = Arc::new(TestL2Verifier::new());

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let identity_hash = [0x42u8; 32];
    let crypto_fqdn = format_cryptographic_name_from_hash(&identity_hash).unwrap();

    let response = engine.resolve(&crypto_fqdn, None).expect("Tier 1 resolution should succeed");
    assert_eq!(response.target_peer_id, identity_hash.to_vec());
    assert_eq!(response.owner_key_id, identity_hash[..16].to_vec());
    assert_eq!(response.expires_at, u64::MAX);
    assert!(!response.in_grace_period);
    assert!(response.merkle_inclusion_proof.is_empty());
}

#[test]
fn test_tier2_private_overlay_resolution() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let verifier = Arc::new(TestL2Verifier::new());

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let caller_ark_id = [0x11u8; 32];
    let other_caller = [0x22u8; 32];

    let overlay = OverlayRecord {
        domain: "nas.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        target_peer_id: Some("homelab-nas".to_string()),
        txt_records: vec!["service=storage".to_string()],
        created_at: 1_000_000,
    };

    engine.register_private_overlay(&caller_ark_id, &overlay).unwrap();

    // Query with matching caller ArkID
    let res = engine.resolve("nas.ark", Some(&caller_ark_id)).expect("overlay should resolve");
    assert_eq!(res.routing_addrs, vec!["192.168.1.100".to_string()]);
    assert_eq!(res.owner_key_id, caller_ark_id[..16].to_vec());
    assert_eq!(res.target_peer_id, "homelab-nas".as_bytes().to_vec());
    assert_eq!(res.expires_at, u64::MAX);
    assert!(!res.in_grace_period);

    // Query with different caller ArkID -> Should not see caller A's private overlay
    let res_other = engine.resolve("nas.ark", Some(&other_caller));
    assert!(matches!(res_other, Err(DnsError::NotFound(_))));

    // Query without caller ArkID -> Should not see private overlay
    let res_none = engine.resolve("nas.ark", None);
    assert!(matches!(res_none, Err(DnsError::NotFound(_))));
}

#[test]
fn test_tier3_public_patricia_trie_resolution_and_merkle_proof() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let owner_a = [0x55u8; 16];
    let contract = b"escrow-bond-001";
    let verifier = Arc::new(TestL2Verifier::new().allow(contract, &owner_a));

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock.clone())
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let target_peer = [0x77u8; 32];
    let routing_addrs = vec!["/ip4/127.0.0.1/udp/4433/quic-v1".to_string()];
    let ech_key = vec![0xca, 0xfe];
    let lease_epoch = 1_000_000 + 86400 * 30; // 30 days

    let envelope = create_valid_claim_envelope(
        "alice.ark",
        lease_epoch,
        contract,
        owner_a,
        target_peer,
        &routing_addrs,
        &ech_key,
    );

    // Dynamic registration
    engine.register_public_domain(&envelope).expect("registration must succeed");

    // Resolve Tier 3
    let res = engine.resolve("alice.ark", None).expect("public resolution succeeds");
    assert_eq!(res.owner_key_id, owner_a.to_vec());
    assert_eq!(res.target_peer_id, target_peer.to_vec());
    assert_eq!(res.routing_addrs, routing_addrs);
    assert_eq!(res.expires_at, lease_epoch);
    assert!(!res.in_grace_period);
    assert_eq!(res.ech_public_key, ech_key);
    assert!(!res.merkle_inclusion_proof.is_empty());
    assert!(
        res.merkle_inclusion_proof.len() <= ark_dns::trie::MAX_MERKLE_PROOF_SIZE,
        "Merkle proof size in engine was {} (> {})",
        res.merkle_inclusion_proof.len(),
        ark_dns::trie::MAX_MERKLE_PROOF_SIZE
    );

    // Verify Merkle inclusion proof
    let proof = ark_dns::trie::MerkleProof::from_bytes(&res.merkle_inclusion_proof).expect("proof decode");
    assert_eq!(proof.fqdn, "alice.ark");
    let root = engine.root_hash();
    let record = engine.trie().get("alice.ark").unwrap();
    assert!(proof.verify(&root, &record));
}

#[test]
fn test_tier_precedence_overlay_over_public() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let owner_a = [0x55u8; 16];
    let contract = b"escrow-bond-002";
    let verifier = Arc::new(TestL2Verifier::new().allow(contract, &owner_a));

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let caller_ark_id = [0x99u8; 32];

    // 1. Register public domain "shop.ark"
    let envelope = create_valid_claim_envelope(
        "shop.ark",
        1_000_000 + 86400 * 30,
        contract,
        owner_a,
        [0x11u8; 32],
        &["/ip4/1.1.1.1/udp/4433/quic-v1".to_string()],
        &[],
    );
    engine.register_public_domain(&envelope).unwrap();

    // 2. Register private overlay "shop.ark" for caller_ark_id
    let overlay = OverlayRecord {
        domain: "shop.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        target_peer_id: Some("local-shop".to_string()),
        txt_records: vec![],
        created_at: 1_000_000,
    };
    engine.register_private_overlay(&caller_ark_id, &overlay).unwrap();

    // Precedence: caller_ark_id gets private overlay (Tier 2 takes precedence over Tier 3)
    let res_overlay = engine.resolve("shop.ark", Some(&caller_ark_id)).unwrap();
    assert_eq!(res_overlay.routing_addrs, vec!["10.0.0.1".to_string()]);
    assert_eq!(res_overlay.target_peer_id, "local-shop".as_bytes().to_vec());

    // Other caller gets public record (Tier 3)
    let res_public = engine.resolve("shop.ark", None).unwrap();
    assert_eq!(res_public.routing_addrs, vec!["/ip4/1.1.1.1/udp/4433/quic-v1".to_string()]);
    assert_eq!(res_public.target_peer_id, vec![0x11u8; 32]);
}

#[test]
fn test_grace_period_and_renewal_workflow() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let owner_a = [0x12u8; 16];
    let owner_b = [0x34u8; 16];
    let contract_a = b"contract-a";
    let contract_b = b"contract-b";
    let verifier = Arc::new(
        TestL2Verifier::new()
            .allow(contract_a, &owner_a)
            .allow(contract_b, &owner_b),
    );

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock.clone())
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let lease_epoch = 1_000_000 + 86400 * 10;
    let env_a = create_valid_claim_envelope(
        "renewme.ark",
        lease_epoch,
        contract_a,
        owner_a,
        [1u8; 32],
        &["/ip4/127.0.0.1/tcp/80".to_string()],
        &[],
    );
    engine.register_public_domain(&env_a).unwrap();

    // Advance clock into 14-day grace period
    clock.set_time(lease_epoch + 100);

    // Resolve returns in_grace_period = true
    let res_grace = engine.resolve("renewme.ark", None).unwrap();
    assert!(res_grace.in_grace_period);

    // Unauthorized renewal attempt by Owner B during grace period
    let env_b = create_valid_claim_envelope(
        "renewme.ark",
        clock.now_pmt() + 86400 * 30,
        contract_b,
        owner_b,
        [2u8; 32],
        &["/ip4/127.0.0.1/tcp/80".to_string()],
        &[],
    );
    let err = engine.renew_public_domain(&env_b).unwrap_err();
    assert!(matches!(err, DnsError::GracePeriodRenewalUnauthorized { .. }));

    // Authorized renewal by Owner A
    let env_renew_a = create_valid_claim_envelope(
        "renewme.ark",
        clock.now_pmt() + 86400 * 30,
        contract_a,
        owner_a,
        [1u8; 32],
        &["/ip4/127.0.0.1/tcp/80".to_string()],
        &[],
    );
    engine.renew_public_domain(&env_renew_a).expect("Owner renewal succeeds");

    // Back to active
    let res_renewed = engine.resolve("renewme.ark", None).unwrap();
    assert!(!res_renewed.in_grace_period);
}

#[test]
fn test_eviction_and_reregistration() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let owner_a = [0x12u8; 16];
    let owner_b = [0x34u8; 16];
    let contract_a = b"contract-a";
    let contract_b = b"contract-b";
    let verifier = Arc::new(
        TestL2Verifier::new()
            .allow(contract_a, &owner_a)
            .allow(contract_b, &owner_b),
    );

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock.clone())
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let lease_epoch = 1_000_000 + 86400 * 5;
    let env_a = create_valid_claim_envelope(
        "expireme.ark",
        lease_epoch,
        contract_a,
        owner_a,
        [1u8; 32],
        &[],
        &[],
    );
    engine.register_public_domain(&env_a).unwrap();

    // Advance clock past 14 days grace period
    clock.set_time(lease_epoch + 14 * 86400 + 10);

    // Eviction sweep
    let evicted = engine.evict_expired();
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0].fqdn, "expireme.ark");

    // Resolve returns NotFound
    assert!(matches!(engine.resolve("expireme.ark", None), Err(DnsError::NotFound(_))));

    // Owner B can now register fresh claim
    let env_b = create_valid_claim_envelope(
        "expireme.ark",
        clock.now_pmt() + 86400 * 30,
        contract_b,
        owner_b,
        [2u8; 32],
        &[],
        &[],
    );
    engine.register_public_domain(&env_b).expect("Fresh registration by new owner succeeds");

    let res_b = engine.resolve("expireme.ark", None).unwrap();
    assert_eq!(res_b.owner_key_id, owner_b.to_vec());
}

#[test]
fn test_protobuf_wire_serialization_and_packet_handler() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let verifier = Arc::new(TestL2Verifier::new());

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let identity_hash = [0x33u8; 32];
    let crypto_fqdn = format_cryptographic_name_from_hash(&identity_hash).unwrap();

    // Using DnsPacketHandler trait
    let wire_bytes = engine.handle_dns_query_packet(&crypto_fqdn, None).expect("packet handler succeeds");
    assert!(!wire_bytes.is_empty());

    // Decode DomainResolveResponse from protobuf wire bytes
    let decoded = DomainResolveResponse::decode(&wire_bytes[..]).expect("protobuf decode succeeds");
    assert_eq!(decoded.target_peer_id, identity_hash.to_vec());
}

#[test]
fn test_concurrent_three_tier_resolution_workflows() {
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::Duration;

    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let verifier = Arc::new(TestL2Verifier::new());

    let caller_ark_id = [0x77u8; 32];
    let engine = Arc::new(
        SovereignDnsEngine::builder()
            .storage(storage)
            .time_provider(clock)
            .l2_verifier(verifier)
            .default_caller_ark_id(caller_ark_id)
            .build()
            .unwrap(),
    );

    // Setup Tier 1
    let crypto_hash = [0x88u8; 32];
    let crypto_fqdn = format_cryptographic_name_from_hash(&crypto_hash).unwrap();

    // Setup Tier 2
    let overlay = OverlayRecord {
        domain: "cluster-gw.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)),
        target_peer_id: Some("gw-01".to_string()),
        txt_records: vec![],
        created_at: 1_000_000,
    };
    engine.register_private_overlay(&caller_ark_id, &overlay).unwrap();

    // Setup Tier 3
    let public_record = DomainRoutingRecord {
        fqdn: "public-service.ark".to_string(),
        owner_key_id: [0x33u8; 16],
        target_peer_id: [0x44u8; 32],
        routing_addrs: vec!["/ip4/10.0.0.1/udp/4433/quic-v1".to_string()],
        expires_at: 1_000_000 + 86400 * 30,
        in_grace_period: false,
        epoch_timestamp: 1_000_000,
        ech_public_key: vec![1, 2, 3],
    };
    engine.lifecycle_engine().register(public_record).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = vec![];

    // Spawn 8 reader threads resolving concurrently across all three tiers
    for _worker_id in 0..8 {
        let eng = engine.clone();
        let st = stop.clone();
        let c_fqdn = crypto_fqdn.clone();
        handles.push(thread::spawn(move || {
            let mut iterations = 0;
            while !st.load(std::sync::atomic::Ordering::Relaxed) && iterations < 500 {
                // Tier 1
                let res1 = eng.resolve(&c_fqdn, None).unwrap();
                assert_eq!(res1.target_peer_id, vec![0x88u8; 32]);

                // Tier 2
                let res2 = eng.resolve("cluster-gw.ark", None).unwrap();
                assert_eq!(res2.routing_addrs, vec!["192.168.50.1".to_string()]);

                // Tier 3
                let res3 = eng.resolve("public-service.ark", None).unwrap();
                assert_eq!(res3.target_peer_id, vec![0x44u8; 32]);

                iterations += 1;
            }
            iterations
        }));
    }

    // Spawn 1 writer thread mutating public trie
    let eng_writer = engine.clone();
    let st_writer = stop.clone();
    let writer_handle = thread::spawn(move || {
        let mut count = 0;
        while !st_writer.load(std::sync::atomic::Ordering::Relaxed) && count < 200 {
            let rec = DomainRoutingRecord {
                fqdn: format!("dyn{}.ark", count),
                owner_key_id: [count as u8; 16],
                target_peer_id: [count as u8; 32],
                routing_addrs: vec![],
                expires_at: 1_000_000 + 86400 * 30,
                in_grace_period: false,
                epoch_timestamp: 1_000_000,
                ech_public_key: vec![],
            };
            eng_writer.lifecycle_engine().register(rec).unwrap();
            count += 1;
            thread::sleep(Duration::from_micros(50));
        }
        count
    });

    for h in handles {
        let iters = h.join().expect("reader thread should not panic");
        assert!(iters > 0);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let writes = writer_handle.join().expect("writer thread should not panic");
    assert!(writes > 0);
}

#[test]
fn test_private_overlay_crud_facade() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockPmtClock::new(1_000_000));
    let verifier = Arc::new(TestL2Verifier::new());

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let owner = [0x55u8; 32];
    let overlay1 = OverlayRecord {
        domain: "app1.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        target_peer_id: None,
        txt_records: vec![],
        created_at: 100,
    };
    let overlay2 = OverlayRecord {
        domain: "app2.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
        target_peer_id: None,
        txt_records: vec![],
        created_at: 200,
    };

    engine.register_private_overlay(&owner, &overlay1).unwrap();
    engine.register_private_overlay(&owner, &overlay2).unwrap();

    // Get
    let fetched = engine.get_private_overlay(&owner, "app1.ark").unwrap().unwrap();
    assert_eq!(fetched.target_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));

    // List
    let list = engine.list_private_overlays(&owner).unwrap();
    assert_eq!(list.len(), 2);

    // Remove
    assert!(engine.remove_private_overlay(&owner, "app1.ark").unwrap());
    assert!(engine.get_private_overlay(&owner, "app1.ark").unwrap().is_none());
    assert!(!engine.remove_private_overlay(&owner, "app1.ark").unwrap());
}

#[test]
fn test_builder_defaults_and_validation() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path().join("s1"), StorageConfig::frugal()).unwrap();
    let verifier = Arc::new(TestL2Verifier::new());

    // Omitting clock uses default SystemPmtClock
    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .l2_verifier(verifier)
        .build()
        .expect("builder should supply SystemPmtClock by default");

    assert!(engine.lifecycle_engine().clock().now_pmt() > 0);

    // Missing l2_verifier returns Err(DnsError::InvalidRecord)
    let storage2 = StorageEngine::open(dir.path().join("s2"), StorageConfig::frugal()).unwrap();
    let res = SovereignDnsEngine::builder()
        .storage(storage2)
        .build();

    let err = match res {
        Ok(_) => panic!("builder must fail when l2_verifier is omitted"),
        Err(e) => e,
    };

    match err {
        DnsError::InvalidRecord(msg) => {
            assert!(msg.contains("L2ContractVerifier must be provided"));
        }
        other => panic!("expected InvalidRecord, got {:?}", other),
    }
}


