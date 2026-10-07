//! Sovereign DNS (.ark) subsystem implementing GCP-08 and ACP-0008.

pub mod crypto_name;
pub mod error;
pub mod overlay;

pub use crypto_name::{
    derive_identity_hash, format_cryptographic_name, format_cryptographic_name_from_hash,
    is_cryptographic_name, parse_cryptographic_name, verify_cryptographic_name,
};
pub use error::{DnsError, Result};
pub use overlay::{OverlayRecord, PrivateOverlayStore, DNS_PRIVATE_OVERLAYS_KEYSPACE};

pub struct SovereignDnsTrie {
    // Radix trie structure placeholder for .ark resolution (Issue #29)
}

impl SovereignDnsTrie {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SovereignDnsTrie {
    fn default() -> Self {
        Self::new()
    }
}
