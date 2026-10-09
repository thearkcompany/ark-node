use ark_crypto::identity::PersistentIdentity;
use ark_vpn::framing::frame_micro_packet;
use ark_vpn::relay::{BlindRelayNode, RelayConfig, RelayEnvelope, RelayProfile};
use rand_chacha::rand_core::SeedableRng;
use std::net::SocketAddr;

#[tokio::test]
async fn test_blind_relay_zero_knowledge_forwarding() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x1111);
    // Test that a BlindRelayNode forwards opaque envelopes between sender and recipient
    // without knowing session keys, unable to decrypt or inspect the payload.
    let relay_id = PersistentIdentity::generate(&mut rng);
    let relay_config = RelayConfig {
        profile: RelayProfile::Homelab,
        max_active_peers: 100,
        rate_limit_per_peer_pps: 1000,
    };
    let relay = BlindRelayNode::new(relay_id, relay_config);

    let client_a_id = PersistentIdentity::generate(&mut rng);
    let client_b_id = PersistentIdentity::generate(&mut rng);

    let client_a_addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let client_b_addr: SocketAddr = "127.0.0.1:4002".parse().unwrap();

    // Register routing table / peers on the relay
    relay.register_client(client_a_id.ark_id, client_a_addr);
    relay.register_client(client_b_id.ark_id, client_b_addr);

    // Client A sends an encrypted PQMT / micro-packet envelope to Relay, destined for Client B
    let dummy_secret_key = [0x42u8; 32];
    let secret_plaintext = b"top-secret-sovereign-payload";
    let encrypted_payload = frame_micro_packet(777, 1, &dummy_secret_key, secret_plaintext);

    let envelope = RelayEnvelope {
        sender_id: client_a_id.ark_id,
        recipient_id: client_b_id.ark_id,
        opaque_payload: encrypted_payload.to_vec(),
    };

    // Forward through relay
    let forwarded = relay
        .forward_envelope(envelope.clone())
        .expect("Forwarding must succeed");

    assert_eq!(forwarded.dest_addr, client_b_addr);
    assert_eq!(forwarded.envelope.recipient_id, client_b_id.ark_id);
    assert_eq!(forwarded.envelope.sender_id, client_a_id.ark_id);
    assert_eq!(forwarded.envelope.opaque_payload, envelope.opaque_payload);

    // Verify Relay does NOT possess or derive session key, nor inspect payload
    assert!(relay.can_decrypt_payload() == false);

    // Verify metrics updated
    let stats = relay.stats();
    assert_eq!(stats.relayed_packets, 1);
    assert_eq!(stats.relayed_bytes, envelope.opaque_payload.len() as u64);
    assert_eq!(stats.dropped_packets, 0);
}

#[tokio::test]
async fn test_blind_relay_profile_modes() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x2222);
    let relay_id_1 = PersistentIdentity::generate(&mut rng);
    let homelab_relay = BlindRelayNode::new(
        relay_id_1,
        RelayConfig {
            profile: RelayProfile::Homelab,
            max_active_peers: 10,
            rate_limit_per_peer_pps: 500,
        },
    );
    assert_eq!(homelab_relay.profile(), RelayProfile::Homelab);

    let relay_id_2 = PersistentIdentity::generate(&mut rng);
    let turbo_relay = BlindRelayNode::new(
        relay_id_2,
        RelayConfig {
            profile: RelayProfile::TurboRelay,
            max_active_peers: 1000,
            rate_limit_per_peer_pps: 10000,
        },
    );
    assert_eq!(turbo_relay.profile(), RelayProfile::TurboRelay);
}

#[tokio::test]
async fn test_blind_relay_drop_unknown_recipient() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x3333);
    let relay_id = PersistentIdentity::generate(&mut rng);
    let relay = BlindRelayNode::new(relay_id, RelayConfig::default());

    let client_a_id = PersistentIdentity::generate(&mut rng);
    let unknown_id = PersistentIdentity::generate(&mut rng);

    relay.register_client(client_a_id.ark_id, "127.0.0.1:4001".parse().unwrap());

    let envelope = RelayEnvelope {
        sender_id: client_a_id.ark_id,
        recipient_id: unknown_id.ark_id,
        opaque_payload: vec![1, 2, 3, 4],
    };

    let res = relay.forward_envelope(envelope);
    assert!(res.is_err());
    let stats = relay.stats();
    assert_eq!(stats.dropped_packets, 1);
    assert_eq!(stats.unknown_recipient_drops, 1);
}
