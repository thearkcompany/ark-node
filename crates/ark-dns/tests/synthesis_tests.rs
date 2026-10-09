use ark_dns::synthesis::synthesize_dns_answers;
use ark_dns::wire::{DnsRecordData, DnsRecordType};
use ark_protocol::proto::DomainResolveResponse;
use std::net::Ipv4Addr;

#[test]
fn test_synthesize_a_records_from_ips_and_multiaddrs() {
    let response = DomainResolveResponse {
        owner_key_id: vec![1, 2, 3, 4],
        target_peer_id: vec![5, 6, 7, 8],
        routing_addrs: vec![
            "192.168.1.50".to_string(),
            "/ip4/10.0.0.1/tcp/443".to_string(),
            "/ip6/2001:db8::1/udp/1234/quic-v1".to_string(),
            "2001:db8::2".to_string(),
        ],
        expires_at: 1_800_000_000,
        in_grace_period: false,
        merkle_inclusion_proof: Vec::new(),
        epoch_timestamp: 1_700_000_000,
        ech_public_key: Vec::new(),
    };

    let a_records = synthesize_dns_answers("alice.ark", DnsRecordType::A, &response, 60);
    assert_eq!(a_records.len(), 2);
    assert_eq!(
        a_records[0].rdata,
        DnsRecordData::A(Ipv4Addr::new(192, 168, 1, 50))
    );
    assert_eq!(
        a_records[1].rdata,
        DnsRecordData::A(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(a_records[0].ttl, 60);

    let aaaa_records = synthesize_dns_answers("alice.ark", DnsRecordType::AAAA, &response, 60);
    assert_eq!(aaaa_records.len(), 2);
    assert_eq!(
        aaaa_records[0].rdata,
        DnsRecordData::AAAA("2001:db8::1".parse().unwrap())
    );
    assert_eq!(
        aaaa_records[1].rdata,
        DnsRecordData::AAAA("2001:db8::2".parse().unwrap())
    );
}

#[test]
fn test_synthesize_txt_records() {
    let response = DomainResolveResponse {
        owner_key_id: vec![0xaa, 0xbb],
        target_peer_id: vec![0x11, 0x22, 0x33],
        routing_addrs: vec![],
        expires_at: 1_800_000_000,
        in_grace_period: false,
        merkle_inclusion_proof: Vec::new(),
        epoch_timestamp: 1_700_000_000,
        ech_public_key: vec![0x09, 0x08],
    };

    let txt_records = synthesize_dns_answers("alice.ark", DnsRecordType::TXT, &response, 120);
    assert!(!txt_records.is_empty());
    // Should contain target_peer_id, owner_key_id, etc.
    let rdata_strings: Vec<String> = txt_records
        .into_iter()
        .filter_map(|r| match r.rdata {
            DnsRecordData::TXT(chunks) => Some(chunks.join(" ")),
            _ => None,
        })
        .collect();

    assert!(rdata_strings
        .iter()
        .any(|s| s.contains("peer=") || s.contains("target_peer_id=")));
    assert!(rdata_strings
        .iter()
        .any(|s| s.contains("owner=") || s.contains("owner_key_id=")));
}
