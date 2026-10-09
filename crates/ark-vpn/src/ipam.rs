//! Deterministic Dual-Stack IPAM (ACP-07 / ADR-0013).
//!
//! Provides deterministic Layer-3 addressing derived directly from the canonical 32-byte ArkID
//! (`SHA3-256(PublicKey)`):
//! - IPv6 Unique Local Address (`fd00::/8`): Prefix `fd00::` with the bottom 120 bits derived from `SHA3-256(ArkID)`.
//! - Synthetic IPv4 CGNAT alias (`100.64.0.0/10`): Derived from `SHA3-256(ArkID)` within the 22-bit host space.

use sha3::{Digest, Sha3_256};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Dual-Stack addressing container for a participant node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DualStackAddress {
    /// Deterministic IPv6 ULA (`fd00::/8`)
    pub ipv6: Ipv6Addr,
    /// Deterministic IPv4 CGNAT alias (`100.64.0.0/10`)
    pub ipv4: Ipv4Addr,
}

pub struct DeterministicIpam;

impl DeterministicIpam {
    /// Derive a deterministic dual-stack address pair from a 32-byte `ArkID`.
    ///
    /// - IPv6: `fd00::/8` prefix, with the remaining 120 bits derived deterministically from `SHA3-256(ark_id)`.
    ///   Octet 0 is `0xfd`, octet 1 is `0x00`, followed by bytes 2..16 from the hash.
    ///
    /// - IPv4: `100.64.0.0/10` CGNAT alias (RFC 6598).
    ///   Base IP is `100.64.0.0` (0x64400000). The 22 host bits are extracted from the hash,
    ///   ensuring the derived address always falls strictly within `100.64.0.0/10` (100.64.0.0 - 100.127.255.255).
    pub fn derive_from_ark_id(ark_id: &[u8; 32]) -> DualStackAddress {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ARK-VPN-IPAM-V1");
        hasher.update(ark_id);
        let hash = hasher.finalize();
        Self::derive_from_hash(&hash)
    }

    /// Derive from cluster context and ArkID if cluster isolation is required.
    pub fn derive_with_cluster(cluster_id: &[u8], ark_id: &[u8; 32]) -> DualStackAddress {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ARK-VPN-IPAM-CLUSTER-V1");
        hasher.update(cluster_id);
        hasher.update(ark_id);
        let hash = hasher.finalize();
        Self::derive_from_hash(&hash)
    }

    /// Common internal helper to compute IPv6 ULA and IPv4 CGNAT from a 32-byte hash.
    fn derive_from_hash(hash: &[u8]) -> DualStackAddress {
        // 1. IPv6 derivation: fd00::/8
        let mut v6_octets = [0u8; 16];
        v6_octets[0] = 0xfd;
        v6_octets[1] = 0x00;
        // Remaining 14 bytes (112 bits) plus 8 bits: total 120 bits.
        // Copy 14 bytes (octets 2..16) directly from hash
        v6_octets[2..16].copy_from_slice(&hash[0..14]);
        let ipv6 = Ipv6Addr::from(v6_octets);

        // 2. IPv4 derivation: 100.64.0.0/10
        // 100.64.0.0 in u32 is (100 << 24) | (64 << 16) = 0x6440_0000
        // Host bits mask: 22 bits -> 0x003F_FFFF
        let host_raw = u32::from_be_bytes([0, hash[14], hash[15], hash[16]]);
        let host_bits = host_raw & 0x003F_FFFF;
        let cgnat_base: u32 = (100 << 24) | (64 << 16);
        let ipv4_u32 = cgnat_base | host_bits;
        let ipv4 = Ipv4Addr::from(ipv4_u32);

        DualStackAddress { ipv6, ipv4 }
    }
}
