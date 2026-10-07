use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ark_crypto::fn_dsa::{FnDsaKeyPair, FN_DSA_512_SIGNATURE_SIZE};
use ark_time::{DualCuckooAntiReplay, PeerMedianTime};
use ark_vpn::framing::frame_micro_packet;
use ark_vpn::ipam::DeterministicIpam;
use ark_vpn::pqmt::VpnSession;
use ark_vpn::roaming::RoamingTable;
use ark_vpn::VpnError;
use rand::rngs::OsRng;

fn create_test_session(session_id: u32, peer_ark_id: [u8; 32]) -> (VpnSession, [u8; 32], [u8; 32]) {
    let send_key = [1u8; 32];
    let recv_key = [2u8; 32];
    let session = VpnSession {
        session_id,
        peer_ark_id,
        send_key,
        recv_key,
        send_seq: 1,
        recv_seq: 0,
    };
    (session, send_key, recv_key)
}

#[test]
fn test_bidirectional_ip_to_peer_lookup() {
    let table = RoamingTable::new();

    let peer_ark_id_1 = [0x11u8; 32];
    let (session_1, _, _) = create_test_session(101, peer_ark_id_1);
    let endpoint_1: SocketAddr = "192.168.1.50:51820".parse().unwrap();
    let addrs_1 = DeterministicIpam::derive_from_ark_id(&peer_ark_id_1);

    table.insert_session(session_1, endpoint_1, None, 1000);

    // 1. Lookup by session_id
    let entry = table.get_by_session_id(101).expect("Session 101 should exist");
    assert_eq!(entry.ark_id, peer_ark_id_1);
    assert_eq!(entry.physical_endpoint, endpoint_1);
    assert_eq!(entry.virtual_addrs.ipv6, addrs_1.ipv6);
    assert_eq!(entry.virtual_addrs.ipv4, addrs_1.ipv4);

    // 2. Lookup by ArkID
    let entry_by_ark = table.get_by_ark_id(&peer_ark_id_1).expect("Lookup by ArkID");
    assert_eq!(entry_by_ark.session.session_id, 101);

    // 3. Lookup by IPv6 ULA
    let entry_by_v6 = table.get_by_ipv6(&addrs_1.ipv6).expect("Lookup by IPv6");
    assert_eq!(entry_by_v6.session.session_id, 101);

    // 4. Lookup by IPv4 CGNAT
    let entry_by_v4 = table.get_by_ipv4(&addrs_1.ipv4).expect("Lookup by IPv4");
    assert_eq!(entry_by_v4.session.session_id, 101);

    // Non-existent lookups
    let unknown_ark = [0x99u8; 32];
    assert!(table.get_by_ark_id(&unknown_ark).is_none());
    assert!(table.get_by_ipv6(&"fd00::ffff".parse().unwrap()).is_none());
    assert!(table.get_by_ipv4(&"100.64.0.1".parse().unwrap()).is_none());
}

#[test]
fn test_seamless_roaming_transition_dynamic_endpoint_update() {
    let table = RoamingTable::new();

    let peer_ark_id = [0x22u8; 32];
    let (session, _, recv_key) = create_test_session(202, peer_ark_id);
    let initial_endpoint: SocketAddr = "192.168.1.10:45000".parse().unwrap();
    table.insert_session(session, initial_endpoint, None, 1000);

    let entry = table.get_by_session_id(202).unwrap();
    assert_eq!(entry.physical_endpoint, initial_endpoint);

    // Peer switches from Wi-Fi (192.168.1.10:45000) to Cellular (203.0.113.88:62000)
    let cellular_endpoint: SocketAddr = "203.0.113.88:62000".parse().unwrap();
    let data_payload = b"GET /vpn/traffic HTTP/1.1\r\n";
    let seq = 1;
    let packet = frame_micro_packet(202, seq, &recv_key, data_payload);

    let (sid, s_seq, payload) = table
        .process_data_packet_and_roam(&packet, cellular_endpoint, 1005, 1005)
        .expect("Valid authenticated packet should roam seamlessly");

    assert_eq!(sid, 202);
    assert_eq!(s_seq, 1);
    assert_eq!(payload, data_payload);

    // Endpoint must now be updated dynamically to the cellular endpoint
    let updated_entry = table.get_by_session_id(202).unwrap();
    assert_eq!(updated_entry.physical_endpoint, cellular_endpoint);
    assert_eq!(updated_entry.last_seen_epoch_secs, 1005);
    // Post-quantum session state preserved
    assert_eq!(updated_entry.session.recv_seq, 1);
    assert_eq!(updated_entry.session.recv_key, recv_key);
}

#[test]
fn test_anti_hijacking_mac_tampering_rejected() {
    let table = RoamingTable::new();

    let peer_ark_id = [0x33u8; 32];
    let (session, _, recv_key) = create_test_session(303, peer_ark_id);
    let legitimate_endpoint: SocketAddr = "10.0.0.2:51820".parse().unwrap();
    table.insert_session(session, legitimate_endpoint, None, 1000);

    let attacker_endpoint: SocketAddr = "198.51.100.99:9999".parse().unwrap();
    let data_payload = b"tampered message";
    let seq = 1;
    let valid_packet = frame_micro_packet(303, seq, &recv_key, data_payload);

    // Attacker modifies a byte in the payload or header MAC
    let mut tampered_packet = valid_packet.to_vec();
    let last = tampered_packet.len() - 1;
    tampered_packet[last] ^= 0xFF;

    let res = table.process_data_packet_and_roam(&tampered_packet, attacker_endpoint, 1002, 1002);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), VpnError::SessionMacInvalid);

    // Physical endpoint must NOT have been updated to attacker's IP
    let entry = table.get_by_session_id(303).unwrap();
    assert_eq!(entry.physical_endpoint, legitimate_endpoint);
}

#[test]
fn test_anti_hijacking_temporal_clock_drift_window() {
    let table = RoamingTable::new();

    let peer_ark_id = [0x44u8; 32];
    let (session, _, recv_key) = create_test_session(404, peer_ark_id);
    let legitimate_endpoint: SocketAddr = "10.0.0.4:51820".parse().unwrap();
    table.insert_session(session, legitimate_endpoint, None, 1000);

    let hijacked_endpoint: SocketAddr = "203.0.113.55:12345".parse().unwrap();
    let packet = frame_micro_packet(404, 1, &recv_key, b"hello");

    // Case 1: Packet timestamp too far in past (> 30s drift)
    let past_timestamp = 1000 - 35; // 35 seconds skew
    let res_past = table.process_data_packet_and_roam(&packet, hijacked_endpoint, past_timestamp, 1000);
    assert!(matches!(res_past, Err(VpnError::ClockDriftExceeded(diff, 30)) if diff == -35));

    // Endpoint NOT updated
    assert_eq!(table.get_by_session_id(404).unwrap().physical_endpoint, legitimate_endpoint);

    // Case 2: Packet timestamp too far in future (> 30s drift)
    let future_timestamp = 1000 + 45; // 45 seconds skew
    let res_future = table.process_data_packet_and_roam(&packet, hijacked_endpoint, future_timestamp, 1000);
    assert!(matches!(res_future, Err(VpnError::ClockDriftExceeded(diff, 30)) if diff == 45));

    // Endpoint still NOT updated
    assert_eq!(table.get_by_session_id(404).unwrap().physical_endpoint, legitimate_endpoint);

    // Case 3: Packet timestamp within valid window (+/- 30s, e.g. delta 15s)
    let valid_timestamp = 1000 + 15;
    let res_valid = table.process_data_packet_and_roam(&packet, hijacked_endpoint, valid_timestamp, 1000);
    assert!(res_valid.is_ok());

    // Endpoint IS updated
    assert_eq!(table.get_by_session_id(404).unwrap().physical_endpoint, hijacked_endpoint);
}

#[test]
fn test_anti_hijacking_anti_replay_filter_defense() {
    let table = RoamingTable::new();

    let peer_ark_id = [0x55u8; 32];
    let (session, _, recv_key) = create_test_session(505, peer_ark_id);
    let endpoint_a: SocketAddr = "192.168.1.20:51820".parse().unwrap();
    table.insert_session(session, endpoint_a, None, 1000);

    let packet = frame_micro_packet(505, 1, &recv_key, b"replay payload");

    // First arrival: valid
    let res1 = table.process_data_packet_and_roam(&packet, endpoint_a, 1002, 1002);
    assert!(res1.is_ok());

    // Attacker intercepts and replays identical packet from attacker IP
    let attacker_endpoint: SocketAddr = "198.51.100.77:8888".parse().unwrap();
    let res2 = table.process_data_packet_and_roam(&packet, attacker_endpoint, 1002, 1002);
    assert_eq!(res2.unwrap_err(), VpnError::AntiReplayRejected);

    // Routing table MUST NOT be hijacked to attacker IP
    let entry = table.get_by_session_id(505).unwrap();
    assert_eq!(entry.physical_endpoint, endpoint_a);
}

#[test]
fn test_anti_hijacking_fn_dsa_signature_verification() {
    let mut rng = OsRng;
    let keypair = FnDsaKeyPair::generate(&mut rng);
    let pubkey = keypair.public_key;

    let table = RoamingTable::new();
    let peer_ark_id = [0x66u8; 32];
    let (session, _, _) = create_test_session(606, peer_ark_id);
    let initial_endpoint: SocketAddr = "10.1.1.1:51820".parse().unwrap();
    table.insert_session(session, initial_endpoint, Some(pubkey), 2000);

    let new_endpoint: SocketAddr = "10.2.2.2:51820".parse().unwrap();
    let control_msg = b"ARK-ROAMING-CONTROL-MESSAGE-MIGRATE";
    let sig_bytes = keypair.sign(control_msg).expect("Sign control msg");
    let mut signature = [0u8; FN_DSA_512_SIGNATURE_SIZE];
    signature.copy_from_slice(&sig_bytes[..FN_DSA_512_SIGNATURE_SIZE]);

    // 1. Valid signature -> Roaming accepted
    let res = table.process_signed_roaming_and_roam(
        606,
        control_msg,
        &signature,
        new_endpoint,
        2005,
        2005,
    );
    assert!(res.is_ok());
    assert_eq!(table.get_by_session_id(606).unwrap().physical_endpoint, new_endpoint);

    // 2. Tampered signature or message -> Rejected, endpoint untouched
    let tampered_endpoint: SocketAddr = "198.51.100.1:4444".parse().unwrap();
    let tampered_msg = b"ARK-ROAMING-CONTROL-MESSAGE-TAMPERED";
    let res_tampered = table.process_signed_roaming_and_roam(
        606,
        tampered_msg,
        &signature,
        tampered_endpoint,
        2010,
        2010,
    );
    assert!(res_tampered.is_err());
    assert_eq!(table.get_by_session_id(606).unwrap().physical_endpoint, new_endpoint);
}

#[test]
fn test_idle_session_expiration_garbage_collection() {
    let pmt = Arc::new(PeerMedianTime::new());
    let anti_replay = Arc::new(DualCuckooAntiReplay::new());
    let idle_timeout = Duration::from_secs(60);

    let table = RoamingTable::with_config(pmt, anti_replay, idle_timeout);

    let peer_ark_id_1 = [0x71u8; 32];
    let (session_1, _, _) = create_test_session(701, peer_ark_id_1);
    let addr_1 = DeterministicIpam::derive_from_ark_id(&peer_ark_id_1);

    let peer_ark_id_2 = [0x72u8; 32];
    let (session_2, _, _) = create_test_session(702, peer_ark_id_2);
    let addr_2 = DeterministicIpam::derive_from_ark_id(&peer_ark_id_2);

    let ep1: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let ep2: SocketAddr = "10.0.0.2:2000".parse().unwrap();

    // Session 1 last seen at epoch 1000
    table.insert_session(session_1, ep1, None, 1000);
    // Session 2 last seen at epoch 1050
    table.insert_session(session_2, ep2, None, 1050);

    assert_eq!(table.session_count(), 2);

    // At epoch 1070:
    // Session 1: 1070 - 1000 = 70s (> 60s timeout) -> Expired
    // Session 2: 1070 - 1050 = 20s (<= 60s timeout) -> Kept active
    let evicted = table.prune_idle_sessions(1070);
    assert_eq!(evicted, 1);
    assert_eq!(table.session_count(), 1);

    // Verify session 1 is completely gone from all indices
    assert!(table.get_by_session_id(701).is_none());
    assert!(table.get_by_ark_id(&peer_ark_id_1).is_none());
    assert!(table.get_by_ipv6(&addr_1.ipv6).is_none());
    assert!(table.get_by_ipv4(&addr_1.ipv4).is_none());

    // Verify session 2 is still active in all indices
    assert!(table.get_by_session_id(702).is_some());
    assert!(table.get_by_ark_id(&peer_ark_id_2).is_some());
    assert!(table.get_by_ipv6(&addr_2.ipv6).is_some());
    assert!(table.get_by_ipv4(&addr_2.ipv4).is_some());
}
