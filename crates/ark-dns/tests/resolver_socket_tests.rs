use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::UdpSocket;

use ark_dns::anti_sybil::L2ContractVerifier;
use ark_dns::engine::SovereignDnsEngine;
use ark_dns::error::DnsError;
use ark_dns::lifecycle::MockTimeProvider;
use ark_dns::overlay::OverlayRecord;
use ark_dns::resolver::{StubResolver, StubResolverConfig};
use ark_dns::wire::{DnsClass, DnsMessage, DnsQuestion, DnsRcode, DnsRecordData, DnsRecordType};
use ark_storage::{StorageConfig, StorageEngine};

struct DummyL2Verifier;
impl L2ContractVerifier for DummyL2Verifier {
    fn verify_escrow_contract(
        &self,
        _contract_id: &[u8],
        _owner_key_id: &[u8],
    ) -> Result<bool, DnsError> {
        Ok(true)
    }
}

#[tokio::test]
async fn test_resolver_loopback_private_overlay_query() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockTimeProvider::new(1_000_000));
    let verifier = Arc::new(DummyL2Verifier);
    let owner_ark_id = [42u8; 32];

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .default_caller_ark_id(owner_ark_id)
        .build()
        .unwrap();

    // Register overlay
    let overlay = OverlayRecord {
        domain: "nas.ark".to_string(),
        target_ip: "192.168.1.100".parse().unwrap(),
        target_peer_id: None,
        txt_records: Vec::new(),
        created_at: 1000,
    };
    engine
        .register_private_overlay(&owner_ark_id, &overlay)
        .unwrap();

    // Bind stub resolver to dynamic port 127.0.0.1:0
    let config = StubResolverConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_dns: None,
        default_ttl: 60,
    };
    let resolver = StubResolver::new(Arc::new(engine), config).await.unwrap();
    let server_addr = resolver.local_addr().unwrap();

    // Start server in background task
    let server_handle = tokio::spawn(async move {
        let _ = resolver.run().await;
    });

    // Send UDP query from client
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut query = DnsMessage::new_response(0x1234, DnsRcode::NoError);
    query.header.is_response = false;
    query.header.recursion_desired = true;
    query.questions.push(DnsQuestion {
        qname: "nas.ark".to_string(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query_wire = query.to_wire().unwrap();

    client_sock.send_to(&query_wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
    let resp = DnsMessage::from_wire(&buf[..n]).unwrap();

    assert_eq!(resp.header.id, 0x1234);
    assert!(resp.header.is_response);
    assert_eq!(resp.header.rcode, DnsRcode::NoError);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0].rdata,
        DnsRecordData::A("192.168.1.100".parse().unwrap())
    );

    server_handle.abort();
}

#[tokio::test]
async fn test_resolver_non_ark_without_upstream_refused() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockTimeProvider::new(1_000_000));
    let verifier = Arc::new(DummyL2Verifier);

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let config = StubResolverConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_dns: None, // No upstream
        default_ttl: 60,
    };
    let resolver = StubResolver::new(Arc::new(engine), config).await.unwrap();
    let server_addr = resolver.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = resolver.run().await;
    });

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut query = DnsMessage::new_response(0x4321, DnsRcode::NoError);
    query.header.is_response = false;
    query.questions.push(DnsQuestion {
        qname: "google.com".to_string(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query_wire = query.to_wire().unwrap();

    client_sock.send_to(&query_wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
    let resp = DnsMessage::from_wire(&buf[..n]).unwrap();

    assert_eq!(resp.header.id, 0x4321);
    assert!(resp.header.is_response);
    assert_eq!(resp.header.rcode, DnsRcode::Refused);

    server_handle.abort();
}

#[tokio::test]
async fn test_resolver_non_ark_with_upstream_forwarding() {
    // Spin up a mock upstream DNS server on UDP
    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();

    let upstream_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        let (n, client) = upstream_sock.recv_from(&mut buf).await.unwrap();
        let query = DnsMessage::from_wire(&buf[..n]).unwrap();
        let mut resp = DnsMessage::new_response(query.header.id, DnsRcode::NoError);
        resp.questions = query.questions.clone();
        resp.answers.push(ark_dns::wire::DnsRecord {
            name: "example.org".to_string(),
            rtype: DnsRecordType::A,
            rclass: DnsClass::IN,
            ttl: 300,
            rdata: DnsRecordData::A("93.184.216.34".parse().unwrap()),
        });
        upstream_sock
            .send_to(&resp.to_wire().unwrap(), client)
            .await
            .unwrap();
    });

    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockTimeProvider::new(1_000_000));
    let verifier = Arc::new(DummyL2Verifier);

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let config = StubResolverConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_dns: Some(upstream_addr),
        default_ttl: 60,
    };
    let resolver = StubResolver::new(Arc::new(engine), config).await.unwrap();
    let server_addr = resolver.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = resolver.run().await;
    });

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut query = DnsMessage::new_response(0x9999, DnsRcode::NoError);
    query.header.is_response = false;
    query.questions.push(DnsQuestion {
        qname: "example.org".to_string(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query_wire = query.to_wire().unwrap();

    client_sock.send_to(&query_wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
    let resp = DnsMessage::from_wire(&buf[..n]).unwrap();

    assert_eq!(resp.header.id, 0x9999);
    assert_eq!(resp.header.rcode, DnsRcode::NoError);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0].rdata,
        DnsRecordData::A("93.184.216.34".parse().unwrap())
    );

    server_handle.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn test_resolver_nxdomain_for_unregistered_ark() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockTimeProvider::new(1_000_000));
    let verifier = Arc::new(DummyL2Verifier);

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let config = StubResolverConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_dns: None,
        default_ttl: 60,
    };
    let resolver = StubResolver::new(Arc::new(engine), config).await.unwrap();
    let server_addr = resolver.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = resolver.run().await;
    });

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut query = DnsMessage::new_response(0x7777, DnsRcode::NoError);
    query.header.is_response = false;
    query.questions.push(DnsQuestion {
        qname: "nonexistent.ark".to_string(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let query_wire = query.to_wire().unwrap();

    client_sock.send_to(&query_wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
    let resp = DnsMessage::from_wire(&buf[..n]).unwrap();

    assert_eq!(resp.header.id, 0x7777);
    assert_eq!(resp.header.rcode, DnsRcode::NameError); // NXDOMAIN

    server_handle.abort();
}

#[tokio::test]
async fn test_resolver_cryptographic_name_query() {
    let dummy_hash = [0x5au8; 32];
    let domain = ark_dns::crypto_name::format_cryptographic_name_from_hash(&dummy_hash).unwrap();

    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockTimeProvider::new(1_000_000));
    let verifier = Arc::new(DummyL2Verifier);

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock)
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let config = StubResolverConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_dns: None,
        default_ttl: 60,
    };
    let resolver = StubResolver::new(Arc::new(engine), config).await.unwrap();
    let server_addr = resolver.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = resolver.run().await;
    });

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Query TXT for cryptographic name
    let mut query = DnsMessage::new_response(0x3333, DnsRcode::NoError);
    query.header.is_response = false;
    query.questions.push(DnsQuestion {
        qname: domain.clone(),
        qtype: DnsRecordType::TXT,
        qclass: DnsClass::IN,
    });
    let query_wire = query.to_wire().unwrap();

    client_sock.send_to(&query_wire, server_addr).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
    let resp = DnsMessage::from_wire(&buf[..n]).unwrap();

    assert_eq!(resp.header.id, 0x3333);
    assert_eq!(resp.header.rcode, DnsRcode::NoError);
    assert_eq!(resp.answers.len(), 1);

    match &resp.answers[0].rdata {
        DnsRecordData::TXT(txts) => {
            assert!(txts
                .iter()
                .any(|s| s.contains("peer=") && s.contains(&hex::encode(dummy_hash))));
        }
        other => panic!("expected TXT, got {:?}", other),
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_resolver_grace_period_returns_nxdomain() {
    let dir = tempdir().unwrap();
    let storage = StorageEngine::open(dir.path(), StorageConfig::frugal()).unwrap();
    let clock = Arc::new(MockTimeProvider::new(1_000_000));
    let verifier = Arc::new(DummyL2Verifier);
    let owner_key = [0x77u8; 16];

    let engine = SovereignDnsEngine::builder()
        .storage(storage)
        .time_provider(clock.clone())
        .l2_verifier(verifier)
        .build()
        .unwrap();

    let lease_epoch = 1_000_000 + 1000;
    // Register public domain
    let claim = ark_dns::anti_sybil::ValidatedDnsClaim {
        fqdn: "quarantined.ark".to_string(),
        lease_epoch,
        contract_id: b"escrow-contract-001".to_vec(),
        owner_key_id: owner_key,
        envelope_id: [0u8; 32],
    };
    engine
        .lifecycle_engine()
        .register_claim(&claim, [0u8; 32], vec!["192.168.1.50".to_string()], vec![])
        .unwrap();

    // Bind resolver
    let config = StubResolverConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        upstream_dns: None,
        default_ttl: 60,
    };
    let resolver = StubResolver::new(Arc::new(engine), config).await.unwrap();
    let server_addr = resolver.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = resolver.run().await;
    });

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. While Active: resolves normally to NoError with A record
    let mut query = DnsMessage::new_response(0x5555, DnsRcode::NoError);
    query.header.is_response = false;
    query.questions.push(DnsQuestion {
        qname: "quarantined.ark".to_string(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    client_sock
        .send_to(&query.to_wire().unwrap(), server_addr)
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let (n, _) = client_sock.recv_from(&mut buf).await.unwrap();
    let resp = DnsMessage::from_wire(&buf[..n]).unwrap();
    assert_eq!(resp.header.rcode, DnsRcode::NoError);
    assert_eq!(resp.answers.len(), 1);

    // 2. Advance clock into 14-day Grace Period: external resolution suspended -> NXDOMAIN
    clock.set_time(lease_epoch + 100);

    let mut query2 = DnsMessage::new_response(0x6666, DnsRcode::NoError);
    query2.header.is_response = false;
    query2.questions.push(DnsQuestion {
        qname: "quarantined.ark".to_string(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    client_sock
        .send_to(&query2.to_wire().unwrap(), server_addr)
        .await
        .unwrap();

    let (n2, _) = client_sock.recv_from(&mut buf).await.unwrap();
    let resp2 = DnsMessage::from_wire(&buf[..n2]).unwrap();
    assert_eq!(resp2.header.rcode, DnsRcode::NameError); // NXDOMAIN
    assert!(resp2.answers.is_empty());

    server_handle.abort();
}
