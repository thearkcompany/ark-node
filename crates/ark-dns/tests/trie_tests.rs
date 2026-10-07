use std::sync::Arc;
use std::time::Instant;
use ark_dns::record::DomainRoutingRecord;
use ark_dns::trie::CompressedPatriciaTrie;

#[test]
fn test_trie_insert_get_single() {
    let trie = CompressedPatriciaTrie::new();
    let record = DomainRoutingRecord {
        fqdn: "alice.ark".to_string(),
        owner_key_id: [1u8; 16],
        target_peer_id: [2u8; 32],
        routing_addrs: vec!["/ip4/127.0.0.1/udp/4433/quic-v1".to_string()],
        expires_at: 1_800_000_000,
        in_grace_period: false,
        epoch_timestamp: 1_700_000_000,
        ech_public_key: vec![0xaa, 0xbb],
    };

    let updated = trie.insert(record.clone());
    assert_eq!(updated.len(), 1);
    assert!(!updated.is_empty());

    let found = updated.get("alice.ark");
    assert!(found.is_some());
    assert_eq!(found.unwrap().as_ref(), &record);

    assert!(updated.get("bob.ark").is_none());
}

#[test]
fn test_trie_prefix_compaction_and_splitting() {
    let mut trie = CompressedPatriciaTrie::new();

    // Insert keys sharing common prefixes
    let names = vec![
        "apple.ark",
        "app.ark",
        "application.ark",
        "apply.ark",
        "banana.ark",
        "band.ark",
        "bandana.ark",
        "c.ark",
    ];

    for name in &names {
        let record = DomainRoutingRecord {
            fqdn: name.to_string(),
            owner_key_id: [0u8; 16],
            target_peer_id: [0u8; 32],
            routing_addrs: vec![],
            expires_at: 2_000_000_000,
            in_grace_period: false,
            epoch_timestamp: 1_000,
            ech_public_key: vec![],
        };
        trie = trie.insert(record);
    }

    assert_eq!(trie.len(), names.len());

    for name in &names {
        let res = trie.get(name);
        assert!(res.is_some(), "Key {} should be present", name);
        assert_eq!(res.unwrap().fqdn, *name);
    }

    assert!(trie.get("appl.ark").is_none());
    assert!(trie.get("appl").is_none());
    assert!(trie.get("ban").is_none());
    assert!(trie.get("").is_none());
    assert!(trie.get("z.ark").is_none());
}

#[test]
fn test_trie_deletion_and_compaction() {
    let mut trie = CompressedPatriciaTrie::new();
    let r1 = DomainRoutingRecord {
        fqdn: "car.ark".to_string(),
        owner_key_id: [1; 16],
        target_peer_id: [1; 32],
        routing_addrs: vec![],
        expires_at: 100,
        in_grace_period: false,
        epoch_timestamp: 1,
        ech_public_key: vec![],
    };
    let r2 = DomainRoutingRecord {
        fqdn: "cart.ark".to_string(),
        owner_key_id: [2; 16],
        target_peer_id: [2; 32],
        routing_addrs: vec![],
        expires_at: 100,
        in_grace_period: false,
        epoch_timestamp: 1,
        ech_public_key: vec![],
    };
    let r3 = DomainRoutingRecord {
        fqdn: "cat.ark".to_string(),
        owner_key_id: [3; 16],
        target_peer_id: [3; 32],
        routing_addrs: vec![],
        expires_at: 100,
        in_grace_period: false,
        epoch_timestamp: 1,
        ech_public_key: vec![],
    };

    trie = trie.insert(r1);
    trie = trie.insert(r2);
    trie = trie.insert(r3);
    assert_eq!(trie.len(), 3);

    // Remove "cart.ark"
    let (trie2, removed) = trie.remove("cart.ark");
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().fqdn, "cart.ark");
    assert_eq!(trie2.len(), 2);
    assert!(trie2.get("cart.ark").is_none());
    assert!(trie2.get("car.ark").is_some());
    assert!(trie2.get("cat.ark").is_some());

    // Remove non-existent
    let (trie3, non_ex) = trie2.remove("dog.ark");
    assert!(non_ex.is_none());
    assert_eq!(trie3.len(), 2);

    // Remove remaining
    let (trie4, _) = trie3.remove("car.ark");
    let (trie5, _) = trie4.remove("cat.ark");
    assert_eq!(trie5.len(), 0);
    assert!(trie5.is_empty());
    assert!(trie5.get("car.ark").is_none());
}

#[test]
fn test_trie_empty_and_edge_cases() {
    let trie = CompressedPatriciaTrie::new();
    assert_eq!(trie.len(), 0);
    assert!(trie.is_empty());
    assert!(trie.get("").is_none());
    assert!(trie.get("anything").is_none());

    let (trie_del, removed) = trie.remove("foo");
    assert!(removed.is_none());
    assert_eq!(trie_del.len(), 0);

    // Root hash of empty trie
    let root_hash = trie.root_hash();
    assert_eq!(root_hash, [0u8; 32]);
}

#[test]
fn test_merkle_proof_generation_and_verification() {
    let mut trie = CompressedPatriciaTrie::new();
    let records = vec![
        DomainRoutingRecord {
            fqdn: "alice.ark".to_string(),
            owner_key_id: [1; 16],
            target_peer_id: [10; 32],
            routing_addrs: vec!["/ip4/1.2.3.4/udp/443/quic-v1".into()],
            expires_at: 1000,
            in_grace_period: false,
            epoch_timestamp: 10,
            ech_public_key: vec![],
        },
        DomainRoutingRecord {
            fqdn: "alex.ark".to_string(),
            owner_key_id: [2; 16],
            target_peer_id: [20; 32],
            routing_addrs: vec![],
            expires_at: 1000,
            in_grace_period: false,
            epoch_timestamp: 10,
            ech_public_key: vec![],
        },
        DomainRoutingRecord {
            fqdn: "bob.ark".to_string(),
            owner_key_id: [3; 16],
            target_peer_id: [30; 32],
            routing_addrs: vec![],
            expires_at: 1000,
            in_grace_period: false,
            epoch_timestamp: 10,
            ech_public_key: vec![],
        },
    ];

    for r in &records {
        trie = trie.insert(r.clone());
    }

    let root = trie.root_hash();
    assert_ne!(root, [0u8; 32]);

    for r in &records {
        let proof = trie.generate_merkle_proof(&r.fqdn).expect("proof should be generated");
        // Acceptance criterion: <= 256 bytes
        let serialized_len = proof.encoded_size();
        assert!(
            serialized_len <= 256,
            "Merkle proof size for {} was {} bytes (> 256 bytes)",
            r.fqdn,
            serialized_len
        );

        // Verification succeeds with correct root and record
        assert!(proof.verify(&root, r));

        // Verification fails with tampered record
        let mut tampered = r.clone();
        tampered.expires_at = 9999;
        assert!(!proof.verify(&root, &tampered));

        // Verification fails with wrong root
        let wrong_root = [0xff; 32];
        assert!(!proof.verify(&wrong_root, r));
    }

    // Proof generation for non-existent domain returns None
    assert!(trie.generate_merkle_proof("charlie.ark").is_none());
}

#[test]
fn test_lock_free_concurrent_access() {
    use ark_dns::SovereignDnsTrie;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    let dns_trie = Arc::new(SovereignDnsTrie::new());

    // Prepopulate 100 domains
    for i in 0..100 {
        let rec = DomainRoutingRecord {
            fqdn: format!("peer{}.ark", i),
            owner_key_id: [i as u8; 16],
            target_peer_id: [i as u8; 32],
            routing_addrs: vec![],
            expires_at: 1000,
            in_grace_period: false,
            epoch_timestamp: 1,
            ech_public_key: vec![],
        };
        dns_trie.insert(rec);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let mut reader_handles = vec![];

    // Spawn 8 reader threads
    for reader_idx in 0..8 {
        let trie_clone = Arc::clone(&dns_trie);
        let stop_clone = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut lookups = 0;
            while !stop_clone.load(Ordering::Relaxed) {
                let domain = format!("peer{}.ark", (reader_idx * 13 + lookups) % 100);
                let found = trie_clone.get(&domain);
                assert!(found.is_some());
                lookups += 1;
            }
            lookups
        });
        reader_handles.push(handle);
    }

    // Writer thread performs mutations
    let trie_writer = Arc::clone(&dns_trie);
    let writer_handle = thread::spawn(move || {
        for i in 100..200 {
            let rec = DomainRoutingRecord {
                fqdn: format!("peer{}.ark", i),
                owner_key_id: [i as u8; 16],
                target_peer_id: [i as u8; 32],
                routing_addrs: vec![],
                expires_at: 2000,
                in_grace_period: false,
                epoch_timestamp: 1,
                ech_public_key: vec![],
            };
            trie_writer.insert(rec);
            thread::sleep(Duration::from_micros(50));
        }
    });

    writer_handle.join().unwrap();
    stop.store(true, Ordering::Relaxed);

    let total_lookups: usize = reader_handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total_lookups > 10_000, "Readers should have executed tens of thousands of lock-free queries");
}

#[test]
fn test_lookup_latency_under_10_micros() {
    let trie = CompressedPatriciaTrie::new();
    let mut current = trie;

    // Populate 1000 realistic domains
    for i in 0..1000 {
        let rec = DomainRoutingRecord {
            fqdn: format!("sub-{}.service-{}.ark", i % 50, i),
            owner_key_id: [(i % 256) as u8; 16],
            target_peer_id: [(i % 256) as u8; 32],
            routing_addrs: vec![format!("/ip4/192.168.1.{}/udp/4433/quic-v1", i % 250)],
            expires_at: 1_800_000_000 + i as u64,
            in_grace_period: false,
            epoch_timestamp: 1_700_000_000,
            ech_public_key: vec![1, 2, 3, 4],
        };
        current = current.insert(rec);
    }

    // Measure latency for 5,000 lookups
    let query_domains: Vec<String> = (0..1000)
        .map(|i| format!("sub-{}.service-{}.ark", i % 50, i))
        .collect();

    // Warm-up
    for domain in &query_domains[0..100] {
        let _ = current.get(domain);
    }

    let iterations = 10_000;
    let start = Instant::now();
    for i in 0..iterations {
        let d = &query_domains[i % query_domains.len()];
        let val = current.get(d);
        assert!(val.is_some());
    }
    let elapsed = start.elapsed();
    let per_lookup_micros = elapsed.as_secs_f64() * 1_000_000.0 / (iterations as f64);

    println!(
        "Total elapsed for {} lookups: {:?}, avg per lookup: {:.3} µs",
        iterations, elapsed, per_lookup_micros
    );

    // Acceptance criterion: strictly below 10 µs
    assert!(
        per_lookup_micros < 10.0,
        "Lookup latency was {:.3} µs, expected strictly < 10.0 µs",
        per_lookup_micros
    );
}
