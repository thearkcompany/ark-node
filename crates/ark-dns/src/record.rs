//! Domain Routing Record definition conforming to GCP-08 and ADR-0010.

use sha3::{Digest, Sha3_256};

/// Canonical Domain Routing Record representing the resolution data
/// for a sovereign `.ark` domain name in the routing table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRoutingRecord {
    /// Fully qualified domain name (e.g. `alice.ark`).
    pub fqdn: String,
    /// Truncated 16-byte owner key identifier derived from ArkID.
    pub owner_key_id: [u8; 16],
    /// Target 32-byte peer ArkID identity.
    pub target_peer_id: [u8; 32],
    /// Multiaddresses for routing (e.g. `/ip4/127.0.0.1/udp/4433/quic-v1`).
    pub routing_addrs: Vec<String>,
    /// Expiration epoch timestamp in seconds.
    pub expires_at: u64,
    /// Indicates whether the domain is currently in the 14-day quarantine grace period.
    pub in_grace_period: bool,
    /// Epoch timestamp when the record was registered/renewed.
    pub epoch_timestamp: u64,
    /// Encrypted Client Hello (ECH) public key bytes for encrypted SNI.
    pub ech_public_key: Vec<u8>,
}

impl DomainRoutingRecord {
    /// Compute deterministic 32-byte SHA3-256 digest of this canonical record.
    pub fn compute_record_digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ARK-DNS-RECORD-V1");
        hasher.update((self.fqdn.len() as u32).to_be_bytes());
        hasher.update(self.fqdn.as_bytes());
        hasher.update(self.owner_key_id);
        hasher.update(self.target_peer_id);
        hasher.update((self.routing_addrs.len() as u32).to_be_bytes());
        for addr in &self.routing_addrs {
            hasher.update((addr.len() as u32).to_be_bytes());
            hasher.update(addr.as_bytes());
        }
        hasher.update(self.expires_at.to_be_bytes());
        hasher.update([if self.in_grace_period { 1u8 } else { 0u8 }]);
        hasher.update(self.epoch_timestamp.to_be_bytes());
        hasher.update((self.ech_public_key.len() as u32).to_be_bytes());
        hasher.update(&self.ech_public_key);
        hasher.finalize().into()
    }
}
