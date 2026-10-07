//! Sovereign DNS Engine unified facade (GCP-08, ADR-0010, Issue #33).
//!
//! Orchestrates the three-tier resolution pipeline:
//! 1. Tier 1: Cryptographic names (`ark1<bech32>.ark`) -> O(1) direct derivation.
//! 2. Tier 2: Private Overlay -> local Fjall storage check (`dns_private_overlays` keyspace) for caller ArkID.
//! 3. Tier 3: Public Patricia Trie -> lock-free trie lookup, checking lease lifecycle and Merkle inclusion proof.

use std::sync::Arc;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::proto::DomainResolveResponse;
use ark_storage::StorageEngine;
use prost::Message;

use crate::anti_sybil::{validate_dns_claim, L2ContractVerifier};
use crate::crypto_name::{is_cryptographic_name, parse_cryptographic_name};
use crate::error::{DnsError, Result};
use crate::lifecycle::{LeaseLifecycleEngine, SystemTimeProvider, TimeProvider};
use crate::overlay::{OverlayRecord, PrivateOverlayStore};
use crate::record::DomainRoutingRecord;
use crate::SovereignDnsTrie;

/// Packet handling trait for binary wire dispatch.
pub trait DnsPacketHandler {
    /// Handle a DNS domain lookup and return encoded protobuf bytes.
    fn handle_dns_query_packet(&self, fqdn: &str, caller_ark_id: Option<&[u8; 32]>) -> Result<Vec<u8>>;
}

/// Unified Sovereign DNS Engine facade.
#[derive(Clone)]
pub struct SovereignDnsEngine<T: TimeProvider = SystemTimeProvider, V: L2ContractVerifier = Arc<dyn L2ContractVerifier>> {
    overlay_store: Arc<PrivateOverlayStore>,
    lifecycle_engine: LeaseLifecycleEngine<T>,
    l2_verifier: Arc<V>,
    default_caller_ark_id: Option<[u8; 32]>,
}

impl<T: TimeProvider, V: L2ContractVerifier> SovereignDnsEngine<T, V> {
    /// Return a builder to configure the engine.
    pub fn builder() -> SovereignDnsEngineBuilder<T, V> {
        SovereignDnsEngineBuilder::new()
    }

    /// Access reference to underlying `PrivateOverlayStore`.
    pub fn overlay_store(&self) -> &Arc<PrivateOverlayStore> {
        &self.overlay_store
    }

    /// Access reference to underlying `LeaseLifecycleEngine`.
    pub fn lifecycle_engine(&self) -> &LeaseLifecycleEngine<T> {
        &self.lifecycle_engine
    }

    /// Access reference to underlying `SovereignDnsTrie`.
    pub fn trie(&self) -> &Arc<SovereignDnsTrie> {
        self.lifecycle_engine.trie()
    }

    /// Current root hash of the public Patricia Trie.
    pub fn root_hash(&self) -> [u8; 32] {
        self.lifecycle_engine.trie().root_hash()
    }

    /// Configured default caller ArkID, if any.
    pub fn default_caller_ark_id(&self) -> Option<&[u8; 32]> {
        self.default_caller_ark_id.as_ref()
    }

    /// Strict Three-Tier domain resolution:
    /// 1. Tier 1: Cryptographic names (`ark1<bech32>.ark`)
    /// 2. Tier 2: Private Overlay (checked if `caller_ark_id` is supplied or default is configured)
    /// 3. Tier 3: Public Patricia Trie with Merkle inclusion proof
    pub fn resolve(&self, fqdn: &str, caller_ark_id: Option<&[u8; 32]>) -> Result<DomainResolveResponse> {
        let trimmed = fqdn.trim();

        // 1. Tier 1: Cryptographic names (ark1<bech32>.ark)
        if is_cryptographic_name(trimmed) {
            let identity_hash = parse_cryptographic_name(trimmed)?;
            let epoch_now = self.lifecycle_engine.time_provider().now_secs();
            let mut owner_key = [0u8; 16];
            owner_key.copy_from_slice(&identity_hash[..16]);

            return Ok(DomainResolveResponse {
                owner_key_id: owner_key.to_vec(),
                target_peer_id: identity_hash.to_vec(),
                routing_addrs: Vec::new(),
                expires_at: u64::MAX,
                in_grace_period: false,
                merkle_inclusion_proof: Vec::new(),
                epoch_timestamp: epoch_now,
                ech_public_key: Vec::new(),
            });
        }

        // 2. Tier 2: Private Overlay
        let effective_caller = caller_ark_id.or(self.default_caller_ark_id.as_ref());
        if let Some(caller) = effective_caller {
            if let Some(overlay) = self.overlay_store.get_overlay(caller, trimmed)? {
                let epoch_now = self.lifecycle_engine.time_provider().now_secs();
                let mut owner_key = [0u8; 16];
                owner_key.copy_from_slice(&caller[..16]);

                let target_peer = overlay
                    .target_peer_id
                    .as_ref()
                    .map(|p| p.as_bytes().to_vec())
                    .unwrap_or_else(|| caller.to_vec());

                return Ok(DomainResolveResponse {
                    owner_key_id: owner_key.to_vec(),
                    target_peer_id: target_peer,
                    routing_addrs: vec![overlay.target_ip.to_string()],
                    expires_at: u64::MAX,
                    in_grace_period: false,
                    merkle_inclusion_proof: Vec::new(),
                    epoch_timestamp: epoch_now,
                    ech_public_key: Vec::new(),
                });
            }
        }

        // 3. Tier 3: Public Patricia Trie
        let record_opt = self.lifecycle_engine.resolve(trimmed)?;
        match record_opt {
            Some(record) => {
                let proof_bytes = self
                    .lifecycle_engine
                    .trie()
                    .generate_merkle_proof(trimmed)
                    .map(|p| p.to_bytes())
                    .unwrap_or_default();

                Ok(DomainResolveResponse {
                    owner_key_id: record.owner_key_id.to_vec(),
                    target_peer_id: record.target_peer_id.to_vec(),
                    routing_addrs: record.routing_addrs.clone(),
                    expires_at: record.expires_at,
                    in_grace_period: record.in_grace_period,
                    merkle_inclusion_proof: proof_bytes,
                    epoch_timestamp: record.epoch_timestamp,
                    ech_public_key: record.ech_public_key.clone(),
                })
            }
            None => Err(DnsError::NotFound(trimmed.to_string())),
        }
    }

    /// Register a public sovereign domain from a `KIND_DNS_CLAIM_PUBLIC` envelope.
    ///
    /// Validates 16-bit PoW, FQDN schema, and Ark Pay L2 escrow bond via `anti_sybil::validate_dns_claim`,
    /// then registers the lease in the Patricia Trie.
    pub fn register_public_domain(&self, claim_envelope: &ArkEnvelope) -> Result<()> {
        let claim = validate_dns_claim(claim_envelope, self.l2_verifier.as_ref())?;
        let (target_peer_id, routing_addrs, ech_public_key) = Self::extract_envelope_payload(claim_envelope);

        self.lifecycle_engine.register_claim(
            &claim,
            target_peer_id,
            routing_addrs,
            ech_public_key,
        )
    }

    /// Renew an existing public domain lease from a `KIND_DNS_CLAIM_PUBLIC` envelope.
    ///
    /// Validates the claim envelope and verifies owner monopoly during Active / Grace Period states.
    pub fn renew_public_domain(&self, claim_envelope: &ArkEnvelope) -> Result<()> {
        let claim = validate_dns_claim(claim_envelope, self.l2_verifier.as_ref())?;
        let (target_peer_id, routing_addrs, ech_public_key) = Self::extract_envelope_payload(claim_envelope);

        self.lifecycle_engine.renew_claim(
            &claim,
            target_peer_id,
            routing_addrs,
            ech_public_key,
        )
    }

    /// Sweep and evict all expired public domain records past their 14-day grace period.
    pub fn evict_expired(&self) -> Vec<Arc<DomainRoutingRecord>> {
        self.lifecycle_engine.evict_expired()
    }

    /// CRUD: Register or update a private overlay record for the specified owner ArkID.
    pub fn register_private_overlay(&self, owner_ark_id: &[u8; 32], record: &OverlayRecord) -> Result<()> {
        self.overlay_store.put_overlay(owner_ark_id, record)
    }

    /// CRUD: Retrieve a private overlay record for a specific owner ArkID and domain.
    pub fn get_private_overlay(&self, owner_ark_id: &[u8; 32], domain: &str) -> Result<Option<OverlayRecord>> {
        self.overlay_store.get_overlay(owner_ark_id, domain)
    }

    /// CRUD: Remove a private overlay record for a specific owner ArkID and domain.
    pub fn remove_private_overlay(&self, owner_ark_id: &[u8; 32], domain: &str) -> Result<bool> {
        self.overlay_store.delete_overlay(owner_ark_id, domain)
    }

    /// CRUD: List all private overlay records belonging strictly to a specific owner ArkID.
    pub fn list_private_overlays(&self, owner_ark_id: &[u8; 32]) -> Result<Vec<OverlayRecord>> {
        self.overlay_store.list_overlays(owner_ark_id)
    }

    fn extract_envelope_payload(envelope: &ArkEnvelope) -> ([u8; 32], Vec<String>, Vec<u8>) {
        let payload = &envelope.payload;
        if payload.len() >= 32 {
            let mut target_peer_id = [0u8; 32];
            target_peer_id.copy_from_slice(&payload[..32]);

            let mut offset = 32;
            let routing_addrs = if payload.len() >= offset + 4 {
                let addrs_len = u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                if payload.len() >= offset + addrs_len {
                    let slice = &payload[offset..offset + addrs_len];
                    offset += addrs_len;
                    serde_json::from_slice::<Vec<String>>(slice).unwrap_or_default()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            let ech_public_key = if payload.len() > offset {
                payload[offset..].to_vec()
            } else {
                Vec::new()
            };

            (target_peer_id, routing_addrs, ech_public_key)
        } else {
            let mut target_peer_id = [0u8; 32];
            if envelope.sender_id.len() >= 32 {
                target_peer_id.copy_from_slice(&envelope.sender_id[..32]);
            }
            (target_peer_id, Vec::new(), Vec::new())
        }
    }
}

impl<T: TimeProvider, V: L2ContractVerifier> DnsPacketHandler for SovereignDnsEngine<T, V> {
    fn handle_dns_query_packet(&self, fqdn: &str, caller_ark_id: Option<&[u8; 32]>) -> Result<Vec<u8>> {
        let response = self.resolve(fqdn, caller_ark_id)?;
        Ok(response.encode_to_vec())
    }
}

/// Builder for `SovereignDnsEngine`.
pub struct SovereignDnsEngineBuilder<T: TimeProvider, V: L2ContractVerifier> {
    storage_engine: Option<StorageEngine>,
    overlay_store: Option<Arc<PrivateOverlayStore>>,
    trie: Option<Arc<SovereignDnsTrie>>,
    time_provider: Option<Arc<T>>,
    l2_verifier: Option<Arc<V>>,
    default_caller_ark_id: Option<[u8; 32]>,
}

impl<T: TimeProvider, V: L2ContractVerifier> Default for SovereignDnsEngineBuilder<T, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: TimeProvider, V: L2ContractVerifier> SovereignDnsEngineBuilder<T, V> {
    pub fn new() -> Self {
        Self {
            storage_engine: None,
            overlay_store: None,
            trie: None,
            time_provider: None,
            l2_verifier: None,
            default_caller_ark_id: None,
        }
    }

    pub fn storage(mut self, storage: StorageEngine) -> Self {
        self.storage_engine = Some(storage);
        self
    }

    pub fn overlay_store(mut self, store: Arc<PrivateOverlayStore>) -> Self {
        self.overlay_store = Some(store);
        self
    }

    pub fn trie(mut self, trie: Arc<SovereignDnsTrie>) -> Self {
        self.trie = Some(trie);
        self
    }

    pub fn time_provider(mut self, time_provider: Arc<T>) -> Self {
        self.time_provider = Some(time_provider);
        self
    }

    pub fn l2_verifier(mut self, l2_verifier: Arc<V>) -> Self {
        self.l2_verifier = Some(l2_verifier);
        self
    }

    pub fn default_caller_ark_id(mut self, caller_ark_id: [u8; 32]) -> Self {
        self.default_caller_ark_id = Some(caller_ark_id);
        self
    }

    pub fn build(self) -> Result<SovereignDnsEngine<T, V>> {
        let overlay_store = match (self.overlay_store, self.storage_engine) {
            (Some(store), _) => store,
            (None, Some(storage)) => Arc::new(PrivateOverlayStore::new(&storage)?),
            (None, None) => {
                return Err(DnsError::InvalidRecord(
                    "Either storage or overlay_store must be provided to SovereignDnsEngineBuilder".to_string(),
                ));
            }
        };

        let trie = self.trie.unwrap_or_else(|| Arc::new(SovereignDnsTrie::new()));

        let time_provider = self.time_provider.ok_or_else(|| {
            DnsError::InvalidRecord("TimeProvider must be provided to SovereignDnsEngineBuilder".to_string())
        })?;

        let l2_verifier = self.l2_verifier.ok_or_else(|| {
            DnsError::InvalidRecord("L2ContractVerifier must be provided to SovereignDnsEngineBuilder".to_string())
        })?;

        let lifecycle_engine = LeaseLifecycleEngine::with_time_provider(trie, time_provider);

        Ok(SovereignDnsEngine {
            overlay_store,
            lifecycle_engine,
            l2_verifier,
            default_caller_ark_id: self.default_caller_ark_id,
        })
    }
}
