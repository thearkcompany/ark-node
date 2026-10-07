use std::net::{Ipv4Addr, Ipv6Addr};
use ark_dns::wire::{
    DnsMessage, DnsQuestion, DnsRecord, DnsRecordData,
    DnsOpcode, DnsRcode, DnsRecordType, DnsClass,
};

#[test]
fn test_parse_simple_a_query() {
    // Standard query for alice.ark, type A, class IN
    // ID: 0x1234, Flags: 0x0100 (standard query, RD=1)
    // QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0
    let mut packet = Vec::new();
    // Header (12 bytes)
    packet.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question: alice.ark
    packet.push(5);
    packet.extend_from_slice(b"alice");
    packet.push(3);
    packet.extend_from_slice(b"ark");
    packet.push(0); // root label
    packet.extend_from_slice(&1u16.to_be_bytes()); // Type A (1)
    packet.extend_from_slice(&1u16.to_be_bytes()); // Class IN (1)

    let msg = DnsMessage::from_wire(&packet).expect("parse query");
    assert_eq!(msg.header.id, 0x1234);
    assert_eq!(msg.header.opcode, DnsOpcode::Query);
    assert!(!msg.header.is_response);
    assert!(msg.header.recursion_desired);
    assert_eq!(msg.questions.len(), 1);
    assert_eq!(msg.questions[0].qname, "alice.ark");
    assert_eq!(msg.questions[0].qtype, DnsRecordType::A);
    assert_eq!(msg.questions[0].qclass, DnsClass::IN);
}

#[test]
fn test_serialize_and_parse_response_with_a_aaaa_txt() {
    let mut resp = DnsMessage::new_response(0xABCD, DnsRcode::NoError);
    resp.questions.push(DnsQuestion {
        qname: "test.ark".to_string(),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    resp.answers.push(DnsRecord {
        name: "test.ark".to_string(),
        rtype: DnsRecordType::A,
        rclass: DnsClass::IN,
        ttl: 300,
        rdata: DnsRecordData::A(Ipv4Addr::new(192, 168, 1, 10)),
    });
    resp.answers.push(DnsRecord {
        name: "test.ark".to_string(),
        rtype: DnsRecordType::AAAA,
        rclass: DnsClass::IN,
        ttl: 300,
        rdata: DnsRecordData::AAAA(Ipv6Addr::LOCALHOST),
    });
    resp.answers.push(DnsRecord {
        name: "test.ark".to_string(),
        rtype: DnsRecordType::TXT,
        rclass: DnsClass::IN,
        ttl: 300,
        rdata: DnsRecordData::TXT(vec!["owner=abc".to_string()]),
    });

    let wire_bytes = resp.to_wire().expect("serialize response");
    let parsed = DnsMessage::from_wire(&wire_bytes).expect("parse back");

    assert_eq!(parsed.header.id, 0xABCD);
    assert!(parsed.header.is_response);
    assert_eq!(parsed.header.rcode, DnsRcode::NoError);
    assert_eq!(parsed.answers.len(), 3);

    match &parsed.answers[0].rdata {
        DnsRecordData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 10)),
        other => panic!("expected A record, got {:?}", other),
    }

    match &parsed.answers[1].rdata {
        DnsRecordData::AAAA(ip) => assert_eq!(*ip, Ipv6Addr::LOCALHOST),
        other => panic!("expected AAAA record, got {:?}", other),
    }

    match &parsed.answers[2].rdata {
        DnsRecordData::TXT(txts) => assert_eq!(txts, &["owner=abc".to_string()]),
        other => panic!("expected TXT record, got {:?}", other),
    }
}

#[test]
fn test_name_compression_pointer() {
    // Build a packet where a record points back to query name
    // Header (12 bytes)
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x5678u16.to_be_bytes());
    packet.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    packet.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    // Question name at offset 12: "node.ark"
    packet.push(4);
    packet.extend_from_slice(b"node");
    packet.push(3);
    packet.extend_from_slice(b"ark");
    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes()); // Type A
    packet.extend_from_slice(&1u16.to_be_bytes()); // Class IN

    // Answer name: pointer to offset 12 -> 0xC00C
    packet.extend_from_slice(&0xC00Cu16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // Type A
    packet.extend_from_slice(&1u16.to_be_bytes()); // Class IN
    packet.extend_from_slice(&60u32.to_be_bytes()); // TTL 60
    packet.extend_from_slice(&4u16.to_be_bytes()); // RDLength 4
    packet.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1

    let msg = DnsMessage::from_wire(&packet).expect("parse compressed packet");
    assert_eq!(msg.questions[0].qname, "node.ark");
    assert_eq!(msg.answers[0].name, "node.ark");
    assert_eq!(msg.answers[0].rdata, DnsRecordData::A(Ipv4Addr::new(127, 0, 0, 1)));
}

#[test]
fn test_malformed_packet_handling() {
    // Truncated packet
    assert!(DnsMessage::from_wire(&[0, 1, 2]).is_err());

    // Loop compression pointer
    let mut loop_packet = Vec::new();
    loop_packet.extend_from_slice(&0x1111u16.to_be_bytes());
    loop_packet.extend_from_slice(&0x0100u16.to_be_bytes());
    loop_packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    loop_packet.extend_from_slice(&0u16.to_be_bytes());
    loop_packet.extend_from_slice(&0u16.to_be_bytes());
    loop_packet.extend_from_slice(&0u16.to_be_bytes());
    // Pointer to itself: offset 12 pointing to offset 12 -> 0xC00C
    loop_packet.extend_from_slice(&0xC00Cu16.to_be_bytes());

    assert!(DnsMessage::from_wire(&loop_packet).is_err());
}
