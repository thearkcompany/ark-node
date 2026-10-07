use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ark_dns::crypto_name::{
    derive_identity_hash, format_cryptographic_name, format_cryptographic_name_from_hash,
    is_cryptographic_name, parse_cryptographic_name, verify_cryptographic_name,
};
use ark_dns::overlay::{OverlayRecord, PrivateOverlayStore, DNS_PRIVATE_OVERLAYS_KEYSPACE};
use ark_dns::DnsError;
use ark_crypto::fn_dsa::FnDsaKeyPair;
use rand::rngs::OsRng;
use tempfile::tempdir;

#[test]
fn test_crypto_name_format_and_parse() {
    let mut rng = OsRng;
    let keypair = FnDsaKeyPair::generate(&mut rng);
    let expected_hash = derive_identity_hash(&keypair.public_key);

    let domain = format_cryptographic_name(&keypair.public_key).expect("format should succeed");
    assert!(domain.starts_with("ark1"));
    assert!(domain.ends_with(".ark"));
    assert!(is_cryptographic_name(&domain));

    let parsed_hash = parse_cryptographic_name(&domain).expect("parse should succeed");
    assert_eq!(parsed_hash, expected_hash);

    // Verify key matches domain
    assert!(verify_cryptographic_name(&domain, &keypair.public_key).is_ok());

    // Case insensitivity
    let upper_domain = domain.to_ascii_uppercase();
    let parsed_upper = parse_cryptographic_name(&upper_domain).expect("uppercase parse should succeed");
    assert_eq!(parsed_upper, expected_hash);

    // Identity mismatch
    let other_keypair = FnDsaKeyPair::generate(&mut rng);
    let mismatch_err = verify_cryptographic_name(&domain, &other_keypair.public_key);
    assert!(matches!(mismatch_err, Err(DnsError::IdentityMismatch { .. })));
}

#[test]
fn test_crypto_name_from_hash() {
    let dummy_hash = [0x5au8; 32];
    let domain = format_cryptographic_name_from_hash(&dummy_hash).expect("formatting hash succeeds");
    assert!(is_cryptographic_name(&domain));
    let parsed = parse_cryptographic_name(&domain).expect("parsing succeeds");
    assert_eq!(parsed, dummy_hash);
}

#[test]
fn test_crypto_name_invalid_inputs() {
    // Non-.ark domain
    assert!(matches!(
        parse_cryptographic_name("notanarkname.com"),
        Err(DnsError::InvalidDomainName(_))
    ));
    // Missing ark1 prefix
    assert!(matches!(
        parse_cryptographic_name("alice.ark"),
        Err(DnsError::NotCryptographicName(_))
    ));
    assert!(!is_cryptographic_name("alice.ark"));

    // Corrupt bech32 characters
    assert!(matches!(
        parse_cryptographic_name("ark1invalidbech32!!.ark"),
        Err(DnsError::InvalidBech32(_))
    ));

    // Wrong HRP (e.g. btc1...)
    assert!(matches!(
        parse_cryptographic_name("btc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqqqqq.ark"),
        Err(DnsError::NotCryptographicName(_))
    ));
}

#[test]
fn test_private_overlay_crud_and_isolation() {
    let dir = tempdir().unwrap();
    let storage_config = ark_storage::StorageConfig::frugal();
    let engine = ark_storage::StorageEngine::open(dir.path(), storage_config).unwrap();
    let store = PrivateOverlayStore::new(&engine).unwrap();

    let owner_a = [1u8; 32];
    let owner_b = [2u8; 32];

    let rec_a = OverlayRecord {
        domain: "nas.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        target_peer_id: Some("peer-a".to_string()),
        txt_records: vec!["cluster=home".to_string()],
        created_at: 1000,
    };

    let rec_b = OverlayRecord {
        domain: "nas.ark".to_string(),
        target_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        target_peer_id: Some("peer-b".to_string()),
        txt_records: vec!["cluster=office".to_string()],
        created_at: 1000,
    };

    let rec_a2 = OverlayRecord {
        domain: "gateway.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        target_peer_id: None,
        txt_records: vec![],
        created_at: 1001,
    };

    // Store for owner_a and owner_b
    store.put_overlay(&owner_a, &rec_a).unwrap();
    store.put_overlay(&owner_a, &rec_a2).unwrap();
    store.put_overlay(&owner_b, &rec_b).unwrap();

    // Isolated queries
    let retrieved_a = store.get_overlay(&owner_a, "nas.ark").unwrap().unwrap();
    assert_eq!(retrieved_a.target_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

    let retrieved_b = store.get_overlay(&owner_b, "nas.ark").unwrap().unwrap();
    assert_eq!(retrieved_b.target_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));

    // Case-insensitive lookup
    let retrieved_a_upper = store.get_overlay(&owner_a, "NAS.ARK").unwrap().unwrap();
    assert_eq!(retrieved_a_upper.domain, "nas.ark");

    // List records per owner
    let list_a = store.list_overlays(&owner_a).unwrap();
    assert_eq!(list_a.len(), 2);
    let list_b = store.list_overlays(&owner_b).unwrap();
    assert_eq!(list_b.len(), 1);
    assert_eq!(list_b[0].target_peer_id, Some("peer-b".to_string()));

    // Unknown domain
    assert!(store.get_overlay(&owner_a, "router.ark").unwrap().is_none());

    // Strict isolation: Public directory keyspaces in storage engine must not contain private overlay data
    let dummy_id = [0u8; 32];
    assert!(engine.get_envelope(&dummy_id).unwrap().is_none());
    assert_eq!(DNS_PRIVATE_OVERLAYS_KEYSPACE, "dns_private_overlays");

    // Delete for owner_a
    assert!(store.delete_overlay(&owner_a, "nas.ark").unwrap());
    assert!(store.get_overlay(&owner_a, "nas.ark").unwrap().is_none());
    // owner_b still intact
    assert!(store.get_overlay(&owner_b, "nas.ark").unwrap().is_some());
}

#[test]
fn test_private_overlay_persistence_across_restarts() {
    let dir = tempdir().unwrap();
    let owner = [42u8; 32];
    let rec = OverlayRecord {
        domain: "gateway.ark".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        target_peer_id: None,
        txt_records: vec!["version=1.0".to_string()],
        created_at: 12345,
    };

    {
        let engine = ark_storage::StorageEngine::open(dir.path(), ark_storage::StorageConfig::frugal()).unwrap();
        let store = PrivateOverlayStore::new(&engine).unwrap();
        store.put_overlay(&owner, &rec).unwrap();
    }

    // Reopen engine
    {
        let engine = ark_storage::StorageEngine::open(dir.path(), ark_storage::StorageConfig::frugal()).unwrap();
        let store = PrivateOverlayStore::new(&engine).unwrap();
        let retrieved = store.get_overlay(&owner, "gateway.ark").unwrap().unwrap();
        assert_eq!(retrieved.domain, "gateway.ark");
        assert_eq!(retrieved.target_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(retrieved.txt_records, vec!["version=1.0".to_string()]);
    }
}
