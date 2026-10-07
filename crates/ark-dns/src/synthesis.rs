//! Synthesis of RFC 1035 DNS answers from `DomainResolveResponse`.
//!
//! Handles:
//! - Extracting IPv4 addresses for `A` records from raw IPs or multiaddrs (e.g. `/ip4/1.2.3.4/...`).
//! - Extracting IPv6 addresses for `AAAA` records from raw IPs or multiaddrs (e.g. `/ip6/2001:.../...`).
//! - Synthesizing TXT records containing peer ID (`target_peer_id`), owner key (`owner_key_id`), and optional ECH keys.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ark_protocol::proto::DomainResolveResponse;

use crate::wire::{DnsClass, DnsRecord, DnsRecordData, DnsRecordType};

/// Parse an IP address of type `T` from a raw IP string or a multiaddr path (e.g. `/<proto>/<ip>/...`).
fn parse_ip_or_multiaddr<T: std::str::FromStr>(addr_str: &str, proto_prefix: &str) -> Option<T> {
    let trimmed = addr_str.trim();
    if let Ok(ip) = trimmed.parse::<T>() {
        return Some(ip);
    }

    if trimmed.starts_with(proto_prefix) {
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() > 2 {
            if let Ok(ip) = parts[2].parse::<T>() {
                return Some(ip);
            }
        }
    }

    None
}

/// Extract IPv4 address from string if present.
pub fn extract_ipv4(addr_str: &str) -> Option<Ipv4Addr> {
    if let Some(ip4) = parse_ip_or_multiaddr::<Ipv4Addr>(addr_str, "/ip4/") {
        return Some(ip4);
    }
    if let Ok(IpAddr::V4(ip)) = addr_str.trim().parse::<IpAddr>() {
        return Some(ip);
    }
    None
}

/// Extract IPv6 address from string if present.
pub fn extract_ipv6(addr_str: &str) -> Option<Ipv6Addr> {
    if let Some(ip6) = parse_ip_or_multiaddr::<Ipv6Addr>(addr_str, "/ip6/") {
        return Some(ip6);
    }
    if let Ok(IpAddr::V6(ip)) = addr_str.trim().parse::<IpAddr>() {
        return Some(ip);
    }
    None
}

/// Synthesize DNS resource records from a `DomainResolveResponse` matching the query type.
pub fn synthesize_dns_answers(
    qname: &str,
    qtype: DnsRecordType,
    response: &DomainResolveResponse,
    ttl: u32,
) -> Vec<DnsRecord> {
    let mut answers = Vec::new();

    match qtype {
        DnsRecordType::A => {
            for addr in &response.routing_addrs {
                if let Some(ip4) = extract_ipv4(addr) {
                    answers.push(DnsRecord {
                        name: qname.to_string(),
                        rtype: DnsRecordType::A,
                        rclass: DnsClass::IN,
                        ttl,
                        rdata: DnsRecordData::A(ip4),
                    });
                }
            }
        }
        DnsRecordType::AAAA => {
            for addr in &response.routing_addrs {
                if let Some(ip6) = extract_ipv6(addr) {
                    answers.push(DnsRecord {
                        name: qname.to_string(),
                        rtype: DnsRecordType::AAAA,
                        rclass: DnsClass::IN,
                        ttl,
                        rdata: DnsRecordData::AAAA(ip6),
                    });
                }
            }
        }
        DnsRecordType::TXT => {
            let mut txt_entries = Vec::new();

            if !response.target_peer_id.is_empty() {
                txt_entries.push(format!("peer={}", hex::encode(&response.target_peer_id)));
            }

            if !response.owner_key_id.is_empty() {
                txt_entries.push(format!("owner={}", hex::encode(&response.owner_key_id)));
            }

            if !response.ech_public_key.is_empty() {
                txt_entries.push(format!("ech={}", hex::encode(&response.ech_public_key)));
            }

            if response.expires_at > 0 && response.expires_at != u64::MAX {
                txt_entries.push(format!("expires_at={}", response.expires_at));
            }

            if !txt_entries.is_empty() {
                answers.push(DnsRecord {
                    name: qname.to_string(),
                    rtype: DnsRecordType::TXT,
                    rclass: DnsClass::IN,
                    ttl,
                    rdata: DnsRecordData::TXT(txt_entries),
                });
            }
        }
        _ => {}
    }

    answers
}
