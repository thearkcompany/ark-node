use ark_crypto::fn_dsa::FnDsaKeyPair;
use ark_crypto::identity::Identity;
use ark_vpn::ipam::DeterministicIpam;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn test_deterministic_ipam_derivation_from_fn_dsa_keypair() {
    // Fixed deterministic seed to create reproducible FN-DSA-512 keypair
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = FnDsaKeyPair::generate(&mut rng);
    let identity = Identity::from_public_key(&keypair.public_key);

    let dual_stack_1 = DeterministicIpam::derive_from_ark_id(&identity.ark_id);
    let dual_stack_2 = DeterministicIpam::derive_from_ark_id(&identity.ark_id);

    // Invariable derivation
    assert_eq!(dual_stack_1, dual_stack_2);

    // IPv6 must be within fd00::/8 ULA prefix
    assert_eq!(dual_stack_1.ipv6.octets()[0], 0xfd);
    assert_eq!(dual_stack_1.ipv6.octets()[1], 0x00);

    // IPv4 must be within 100.64.0.0/10 CGNAT range:
    // First byte is 100
    // Second byte has top 2 bits 01 (between 64 and 127)
    let v4_octets = dual_stack_1.ipv4.octets();
    assert_eq!(v4_octets[0], 100);
    assert!(v4_octets[1] >= 64 && v4_octets[1] <= 127);
    assert_eq!(v4_octets[1] & 0xc0, 0x40);

    // Verify formal test vector persistence
    let expected_v6 = dual_stack_1.ipv6;
    let expected_v4 = dual_stack_1.ipv4;

    // Any regeneration with same seed must match the exact same IP addresses
    let mut rng_repeat = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair_repeat = FnDsaKeyPair::generate(&mut rng_repeat);
    let identity_repeat = Identity::from_public_key(&keypair_repeat.public_key);
    assert_eq!(identity.ark_id, identity_repeat.ark_id);

    let derived_repeat = DeterministicIpam::derive_from_ark_id(&identity_repeat.ark_id);
    assert_eq!(derived_repeat.ipv6, expected_v6);
    assert_eq!(derived_repeat.ipv4, expected_v4);
}

#[test]
fn test_deterministic_ipam_fixed_ark_id_vector() {
    // Fixed ArkID vector: all zeros except first and last byte
    let mut ark_id = [0u8; 32];
    ark_id[0] = 0xab;
    ark_id[31] = 0xcd;

    let derived = DeterministicIpam::derive_from_ark_id(&ark_id);
    assert_eq!(derived.ipv6.octets()[0], 0xfd);
    assert_eq!(derived.ipv6.octets()[1], 0x00);

    let v4_octets = derived.ipv4.octets();
    assert_eq!(v4_octets[0], 100);
    assert_eq!(v4_octets[1] & 0xc0, 0x40);

    // Exact reproducible values verification
    let derived2 = DeterministicIpam::derive_from_ark_id(&ark_id);
    assert_eq!(derived, derived2);
}

#[test]
fn test_deterministic_ipam_cluster_isolation() {
    let ark_id = [0x55u8; 32];
    let cluster_a = b"cluster-alpha";
    let cluster_b = b"cluster-beta";

    let ip_a = DeterministicIpam::derive_with_cluster(cluster_a, &ark_id);
    let ip_b = DeterministicIpam::derive_with_cluster(cluster_b, &ark_id);

    assert_ne!(ip_a, ip_b);
    assert_eq!(ip_a.ipv6.octets()[0], 0xfd);
    assert_eq!(ip_a.ipv6.octets()[1], 0x00);
    assert_eq!(ip_b.ipv6.octets()[0], 0xfd);
    assert_eq!(ip_b.ipv6.octets()[1], 0x00);
    assert_eq!(ip_a.ipv4.octets()[0], 100);
    assert_eq!(ip_a.ipv4.octets()[1] & 0xc0, 0x40);
    assert_eq!(ip_b.ipv4.octets()[0], 100);
    assert_eq!(ip_b.ipv4.octets()[1] & 0xc0, 0x40);
}
