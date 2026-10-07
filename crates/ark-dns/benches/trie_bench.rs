use std::time::Instant;
use ark_dns::record::DomainRoutingRecord;
use ark_dns::SovereignDnsTrie;

fn main() {
    println!("=== ARK Sovereign DNS Patricia Trie Latency Benchmark ===");
    let trie = SovereignDnsTrie::new();

    let record_count = 10_000;
    println!("Prepopulating trie with {} domain records...", record_count);

    for i in 0..record_count {
        let rec = DomainRoutingRecord {
            fqdn: format!("node-{}.zone-{}.ark", i % 100, i),
            owner_key_id: [(i % 256) as u8; 16],
            target_peer_id: [(i % 256) as u8; 32],
            routing_addrs: vec![
                format!("/ip4/10.0.{}.{}/udp/4433/quic-v1", (i / 256) % 256, i % 256),
                format!("/ip6/2001:db8::{:x}/udp/4433/quic-v1", i),
            ],
            expires_at: 1_800_000_000 + i as u64,
            in_grace_period: false,
            epoch_timestamp: 1_700_000_000,
            ech_public_key: vec![0x01, 0x02, 0x03, 0x04],
        };
        trie.insert(rec);
    }

    assert_eq!(trie.len(), record_count);
    let root = trie.root_hash();
    print!("Trie root hash: ");
    for b in root {
        print!("{:02x}", b);
    }
    println!();

    // Warm up
    for i in 0..1_000 {
        let q = format!("node-{}.zone-{}.ark", i % 100, i);
        let _ = trie.get(&q);
    }

    // Benchmark lookups
    let lookup_iterations = 50_000;
    let start = Instant::now();
    for i in 0..lookup_iterations {
        let q = format!("node-{}.zone-{}.ark", i % 100, i % record_count);
        let res = trie.get(&q);
        assert!(res.is_some(), "Key must be present: {}", q);
    }
    let elapsed = start.elapsed();
    let per_lookup_micros = elapsed.as_secs_f64() * 1_000_000.0 / (lookup_iterations as f64);

    println!(
        "Results: {} lookups executed in {:?}\nAverage lookup latency: {:.4} µs (Budget: < 10.0 µs)",
        lookup_iterations, elapsed, per_lookup_micros
    );

    assert!(
        per_lookup_micros < 10.0,
        "Lookup latency failed budget: {:.4} µs >= 10.0 µs",
        per_lookup_micros
    );
    println!("SUCCESS: Lookup latency strictly < 10 µs confirmed.");
}
