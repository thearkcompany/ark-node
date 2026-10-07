//! Sovereign DNS (.ark) subsystem implementing GCP-08 and ACP-0008.

pub mod crypto_name;
pub mod error;
pub mod overlay;
pub mod record;
pub mod trie;

use std::sync::Arc;
use arc_swap::ArcSwap;

pub use crypto_name::{
    derive_identity_hash, format_cryptographic_name, format_cryptographic_name_from_hash,
    is_cryptographic_name, parse_cryptographic_name, verify_cryptographic_name,
};
pub use error::{DnsError, Result};
pub use overlay::{OverlayRecord, PrivateOverlayStore, DNS_PRIVATE_OVERLAYS_KEYSPACE};
pub use record::DomainRoutingRecord;
pub use trie::{CompressedPatriciaTrie, MerkleProof, MerkleProofStep};

/// Thread-safe, lock-free Sovereign DNS Trie container.
///
/// Uses `ArcSwap` to provide zero-lock contention read access with
/// predictable $\mathcal{O}(k) < 10\ \mu\text{s}$ domain lookups regardless of
/// concurrent write mutations.
#[derive(Debug)]
pub struct SovereignDnsTrie {
    inner: ArcSwap<CompressedPatriciaTrie>,
}

impl Default for SovereignDnsTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl SovereignDnsTrie {
    /// Create a new empty SovereignDnsTrie.
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(CompressedPatriciaTrie::new()),
        }
    }

    /// Number of domain records registered in the trie.
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    /// Check if the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }

    /// Current 32-byte SHA3-256 Merkle root hash of the trie.
    pub fn root_hash(&self) -> [u8; 32] {
        self.inner.load().root_hash()
    }

    /// Lock-free lookup of a domain routing record.
    /// Operates in $\mathcal{O}(k) < 10\ \mu\text{s}$ time with zero lock contention.
    pub fn get(&self, fqdn: &str) -> Option<Arc<DomainRoutingRecord>> {
        self.inner.load().get(fqdn)
    }

    /// Insert or update a domain routing record atomically using Copy-on-Write.
    pub fn insert(&self, record: DomainRoutingRecord) {
        self.inner.rcu(|current| current.insert(record.clone()));
    }

    /// Remove a domain routing record atomically using Copy-on-Write.
    /// Returns the removed record if found.
    pub fn remove(&self, fqdn: &str) -> Option<Arc<DomainRoutingRecord>> {
        let mut removed = None;
        self.inner.rcu(|current| {
            let (updated, rem) = current.remove(fqdn);
            removed = rem;
            updated
        });
        removed
    }

    /// Generate a compact Merkle inclusion proof (<= 256 bytes) for a domain.
    pub fn generate_merkle_proof(&self, fqdn: &str) -> Option<MerkleProof> {
        self.inner.load().generate_merkle_proof(fqdn)
    }

    /// Return an immutable snapshot of the underlying CompressedPatriciaTrie.
    pub fn snapshot(&self) -> Arc<CompressedPatriciaTrie> {
        self.inner.load_full()
    }
}
