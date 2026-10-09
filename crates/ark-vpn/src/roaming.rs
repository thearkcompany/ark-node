//! Seamless Roaming Table and Anti-Hijacking Defense.
//!
//! Provides:
//! - Dynamic in-memory session routing table mapping peer `ArkID`, virtual IPv6 ULA,
//!   IPv4 CGNAT alias, and physical UDP endpoints (`SocketAddr`).
//! - Anti-hijacking defense: Physical endpoint `(IP:port)` is ONLY dynamically updated
//!   after:
//!   1. Strict validation of symmetric KMAC256 tag or FN-DSA-512 signature;
//!   2. Validation of temporal clock window (+/- 30s via Peer-Median-Time clock / `ark-time`);
//!   3. Verification and acceptance against in-memory anti-replay filter (Dual generational Cuckoo filter).
//! - Seamless roaming transition: Dynamic update of active UDP socket destination when a peer switches
//!   networks without resetting post-quantum session state.
//! - Bidirectional IP-to-Peer lookup: O(1) lookup of peer sessions indexed by IPv6 ULA (`Ipv6Addr`),
//!   IPv4 CGNAT alias (`Ipv4Addr`), and 32-byte `ArkID`.
//! - Idle session expiration: Configurable session garbage collection / prune evicting stale roaming entries.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ark_core::traits::AntiReplayFilter;
use ark_crypto::fn_dsa::{verify_fn_dsa_512, FN_DSA_512_PUBKEY_SIZE, FN_DSA_512_SIGNATURE_SIZE};
use ark_time::{DriftValidator, DualCuckooAntiReplay, PeerMedianTime};

use crate::error::{Result, VpnError};
use crate::framing::MicroHeader;
use crate::ipam::{DeterministicIpam, DualStackAddress};
use crate::pqmt::VpnSession;

/// Default idle session timeout (e.g. 180 seconds).
pub const DEFAULT_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Metadata and state for an active roaming peer session.
#[derive(Debug, Clone)]
pub struct PeerSessionEntry {
    pub ark_id: [u8; 32],
    pub virtual_addrs: DualStackAddress,
    pub physical_endpoint: SocketAddr,
    pub session: VpnSession,
    pub fn_dsa_pubkey: Option<[u8; FN_DSA_512_PUBKEY_SIZE]>,
    pub last_seen_epoch_secs: u64,
}

/// Seamless Roaming Table maintaining bidirectional lookups and protecting against hijacking.
pub struct RoamingTable {
    pmt: Arc<PeerMedianTime>,
    anti_replay: Arc<DualCuckooAntiReplay>,
    idle_timeout: Duration,

    // Primary session store by session_id
    sessions_by_id: RwLock<HashMap<u32, PeerSessionEntry>>,
    // Index: ArkID -> session_id
    by_ark_id: RwLock<HashMap<[u8; 32], u32>>,
    // Index: IPv6 ULA -> session_id
    by_ipv6: RwLock<HashMap<Ipv6Addr, u32>>,
    // Index: IPv4 CGNAT -> session_id
    by_ipv4: RwLock<HashMap<Ipv4Addr, u32>>,
}

impl RoamingTable {
    /// Create a new RoamingTable with default PMT clock, anti-replay filter, and default timeout.
    pub fn new() -> Self {
        Self::with_config(
            Arc::new(PeerMedianTime::new()),
            Arc::new(DualCuckooAntiReplay::new()),
            DEFAULT_SESSION_IDLE_TIMEOUT,
        )
    }

    /// Create a new RoamingTable with explicit dependencies and idle timeout.
    pub fn with_config(
        pmt: Arc<PeerMedianTime>,
        anti_replay: Arc<DualCuckooAntiReplay>,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            pmt,
            anti_replay,
            idle_timeout,
            sessions_by_id: RwLock::new(HashMap::new()),
            by_ark_id: RwLock::new(HashMap::new()),
            by_ipv6: RwLock::new(HashMap::new()),
            by_ipv4: RwLock::new(HashMap::new()),
        }
    }

    /// Access the PeerMedianTime clock.
    pub fn pmt(&self) -> &Arc<PeerMedianTime> {
        &self.pmt
    }

    /// Access the anti-replay filter.
    pub fn anti_replay(&self) -> &Arc<DualCuckooAntiReplay> {
        &self.anti_replay
    }

    /// Register an established session into the roaming table.
    pub fn insert_session(
        &self,
        session: VpnSession,
        physical_endpoint: SocketAddr,
        fn_dsa_pubkey: Option<[u8; FN_DSA_512_PUBKEY_SIZE]>,
        now_epoch_secs: u64,
    ) {
        let ark_id = session.peer_ark_id;
        let virtual_addrs = DeterministicIpam::derive_from_ark_id(&ark_id);
        let session_id = session.session_id;

        let entry = PeerSessionEntry {
            ark_id,
            virtual_addrs: virtual_addrs.clone(),
            physical_endpoint,
            session,
            fn_dsa_pubkey,
            last_seen_epoch_secs: now_epoch_secs,
        };

        let mut s_guard = self.sessions_by_id.write().unwrap();
        let mut ark_guard = self.by_ark_id.write().unwrap();
        let mut v6_guard = self.by_ipv6.write().unwrap();
        let mut v4_guard = self.by_ipv4.write().unwrap();

        // If old session existed for this session_id or ark_id, cleanup old indexes
        if let Some(old_entry) = s_guard.remove(&session_id) {
            ark_guard.remove(&old_entry.ark_id);
            v6_guard.remove(&old_entry.virtual_addrs.ipv6);
            v4_guard.remove(&old_entry.virtual_addrs.ipv4);
        }
        if let Some(old_sid) = ark_guard.get(&ark_id) {
            if *old_sid != session_id {
                if let Some(old_entry) = s_guard.remove(old_sid) {
                    v6_guard.remove(&old_entry.virtual_addrs.ipv6);
                    v4_guard.remove(&old_entry.virtual_addrs.ipv4);
                }
            }
        }

        ark_guard.insert(ark_id, session_id);
        v6_guard.insert(virtual_addrs.ipv6, session_id);
        v4_guard.insert(virtual_addrs.ipv4, session_id);
        s_guard.insert(session_id, entry);
    }

    /// Lookup peer session entry by session ID.
    pub fn get_by_session_id(&self, session_id: u32) -> Option<PeerSessionEntry> {
        self.sessions_by_id
            .read()
            .unwrap()
            .get(&session_id)
            .cloned()
    }

    /// Fast O(1) lookup of peer session by 32-byte ArkID.
    pub fn get_by_ark_id(&self, ark_id: &[u8; 32]) -> Option<PeerSessionEntry> {
        let ark_guard = self.by_ark_id.read().unwrap();
        let session_id = ark_guard.get(ark_id)?;
        self.sessions_by_id.read().unwrap().get(session_id).cloned()
    }

    /// Fast O(1) lookup of peer session by IPv6 ULA.
    pub fn get_by_ipv6(&self, ipv6: &Ipv6Addr) -> Option<PeerSessionEntry> {
        let v6_guard = self.by_ipv6.read().unwrap();
        let session_id = v6_guard.get(ipv6)?;
        self.sessions_by_id.read().unwrap().get(session_id).cloned()
    }

    /// Fast O(1) lookup of peer session by IPv4 CGNAT alias.
    pub fn get_by_ipv4(&self, ipv4: &Ipv4Addr) -> Option<PeerSessionEntry> {
        let v4_guard = self.by_ipv4.read().unwrap();
        let session_id = v4_guard.get(ipv4)?;
        self.sessions_by_id.read().unwrap().get(session_id).cloned()
    }

    /// Total active peer sessions in table.
    pub fn session_count(&self) -> usize {
        self.sessions_by_id.read().unwrap().len()
    }

    /// Validate temporal clock window (+/- 30s) against Peer-Median-Time clock.
    pub fn validate_temporal_window(
        &self,
        packet_timestamp_secs: u64,
        local_secs: u64,
    ) -> Result<()> {
        let network_consensus_secs = self.pmt.network_time_secs(local_secs);
        DriftValidator::validate_timestamp(packet_timestamp_secs, network_consensus_secs).map_err(
            |e| match e {
                ark_core::error::ArkError::ClockDriftExceeded(diff, max) => {
                    VpnError::ClockDriftExceeded(diff, max)
                }
                _ => VpnError::HijackingRejected(format!("Temporal validation failed: {:?}", e)),
            },
        )
    }

    /// Check and insert packet identifier into the anti-replay Cuckoo filter.
    pub fn validate_anti_replay(&self, replay_tag: &[u8]) -> Result<()> {
        self.anti_replay
            .check_and_insert(replay_tag)
            .map_err(|_| VpnError::AntiReplayRejected)?;
        Ok(())
    }

    /// Process an authenticated incoming data packet and dynamically roam physical endpoint.
    ///
    /// Validates:
    /// 1. Strict symmetric KMAC256 tag verification (via `recv_key`);
    /// 2. Temporal clock window (+/- 30s vs PMT);
    /// 3. In-memory anti-replay filter check & monotonic sequence acceptance.
    ///
    /// If all three checks pass, updates `physical_endpoint` seamlessly and updates `last_seen`.
    pub fn process_data_packet_and_roam(
        &self,
        packet_bytes: &[u8],
        from_endpoint: SocketAddr,
        packet_timestamp_secs: u64,
        local_secs: u64,
    ) -> Result<(u32, u32, Vec<u8>)> {
        if packet_bytes.len() < crate::framing::MICRO_HEADER_SIZE {
            return Err(VpnError::FramingError(
                "Packet too short for MicroHeader".into(),
            ));
        }

        let header = MicroHeader::from_bytes(&packet_bytes[..crate::framing::MICRO_HEADER_SIZE])?;
        let payload = &packet_bytes[crate::framing::MICRO_HEADER_SIZE..];

        // 1. Strict temporal window check (+/- 30s via PMT)
        self.validate_temporal_window(packet_timestamp_secs, local_secs)?;

        // 2. Anti-replay check via Dual Cuckoo filter:
        // Construct unique replay token = [session_id (4B) | sequence_nonce (4B) | timestamp (8B)]
        let mut replay_item = [0u8; 16];
        replay_item[0..4].copy_from_slice(&header.session_id.to_be_bytes());
        replay_item[4..8].copy_from_slice(&header.sequence_nonce.to_be_bytes());
        replay_item[8..16].copy_from_slice(&packet_timestamp_secs.to_be_bytes());
        self.validate_anti_replay(&replay_item)?;

        // 3. Strict cryptographic verification: KMAC256 validation & monotonic sequence update
        let mut s_guard = self.sessions_by_id.write().unwrap();
        let entry = s_guard
            .get_mut(&header.session_id)
            .ok_or(VpnError::SessionNotFound(header.session_id))?;

        header.verify_mac(&entry.session.recv_key, payload)?;
        entry.session.accept_recv_seq(header.sequence_nonce)?;

        // Seamless Roaming Transition: Dynamic update of endpoint and timestamp
        entry.physical_endpoint = from_endpoint;
        entry.last_seen_epoch_secs = local_secs;

        Ok((header.session_id, header.sequence_nonce, payload.to_vec()))
    }

    /// Process an authenticated handshake or roaming control packet authenticated via FN-DSA-512.
    ///
    /// Validates:
    /// 1. Strict FN-DSA-512 digital signature verification over the signed data;
    /// 2. Temporal clock window (+/- 30s vs PMT);
    /// 3. In-memory anti-replay filter check.
    ///
    /// If all three checks pass, updates `physical_endpoint` seamlessly and updates `last_seen`.
    pub fn process_signed_roaming_and_roam(
        &self,
        session_id: u32,
        signed_data: &[u8],
        signature: &[u8; FN_DSA_512_SIGNATURE_SIZE],
        from_endpoint: SocketAddr,
        packet_timestamp_secs: u64,
        local_secs: u64,
    ) -> Result<()> {
        // 1. Strict temporal window check (+/- 30s via PMT)
        self.validate_temporal_window(packet_timestamp_secs, local_secs)?;

        // 2. Anti-replay check
        let mut replay_item = Vec::with_capacity(signed_data.len() + 8);
        replay_item.extend_from_slice(signed_data);
        replay_item.extend_from_slice(&packet_timestamp_secs.to_be_bytes());
        self.validate_anti_replay(&replay_item)?;

        // 3. Strict FN-DSA-512 signature verification
        let mut s_guard = self.sessions_by_id.write().unwrap();
        let entry = s_guard
            .get_mut(&session_id)
            .ok_or(VpnError::SessionNotFound(session_id))?;

        let pubkey = entry.fn_dsa_pubkey.ok_or_else(|| {
            VpnError::HijackingRejected("No FN-DSA pubkey registered for session".into())
        })?;

        verify_fn_dsa_512(&pubkey, signed_data, signature).map_err(|e| {
            VpnError::HijackingRejected(format!("FN-DSA signature verification failed: {:?}", e))
        })?;

        // Seamless Roaming Transition
        entry.physical_endpoint = from_endpoint;
        entry.last_seen_epoch_secs = local_secs;

        Ok(())
    }

    /// Garbage collection / prune evicting stale roaming entries if no valid packet was received
    /// within `idle_timeout` window.
    ///
    /// Returns the number of evicted sessions.
    pub fn prune_idle_sessions(&self, current_epoch_secs: u64) -> usize {
        let timeout_secs = self.idle_timeout.as_secs();

        let mut s_guard = self.sessions_by_id.write().unwrap();
        let mut ark_guard = self.by_ark_id.write().unwrap();
        let mut v6_guard = self.by_ipv6.write().unwrap();
        let mut v4_guard = self.by_ipv4.write().unwrap();

        let expired_ids: Vec<u32> = s_guard
            .iter()
            .filter_map(|(&sid, entry)| {
                if current_epoch_secs.saturating_sub(entry.last_seen_epoch_secs) > timeout_secs {
                    Some(sid)
                } else {
                    None
                }
            })
            .collect();

        for sid in &expired_ids {
            if let Some(entry) = s_guard.remove(sid) {
                ark_guard.remove(&entry.ark_id);
                v6_guard.remove(&entry.virtual_addrs.ipv6);
                v4_guard.remove(&entry.virtual_addrs.ipv4);
            }
        }

        expired_ids.len()
    }
}

impl Default for RoamingTable {
    fn default() -> Self {
        Self::new()
    }
}
