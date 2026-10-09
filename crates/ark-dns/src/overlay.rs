//! Private overlay management (Tier 2) in ark-storage.
//!
//! Stores private overlay DNS records (e.g. `nas.ark`, `gateway.ark`) isolated
//! per owner ArkID / cluster in the `dns_private_overlays` keyspace.

use crate::error::{DnsError, Result};
use ark_storage::{Keyspace, StorageEngine};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const DNS_PRIVATE_OVERLAYS_KEYSPACE: &str = "dns_private_overlays";

/// A private overlay DNS record mapping a domain within a private cluster/homelab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayRecord {
    pub domain: String,
    pub target_ip: IpAddr,
    pub target_peer_id: Option<String>,
    pub txt_records: Vec<String>,
    pub created_at: u64,
}

/// Store abstraction for private overlays backed by Fjall LSM keyspace.
pub struct PrivateOverlayStore {
    keyspace: Keyspace,
}

impl PrivateOverlayStore {
    /// Open or create the `dns_private_overlays` keyspace in the provided `StorageEngine`.
    pub fn new(engine: &StorageEngine) -> Result<Self> {
        let keyspace = engine
            .open_keyspace(DNS_PRIVATE_OVERLAYS_KEYSPACE)
            .map_err(DnsError::Storage)?;
        Ok(Self { keyspace })
    }

    /// Creates the composite key: `[owner_ark_id: 32 bytes] || [domain (lowercase UTF-8 bytes)]`
    fn make_key(owner_ark_id: &[u8; 32], domain: &str) -> Vec<u8> {
        let lower = domain.to_ascii_lowercase();
        let mut key = Vec::with_capacity(32 + lower.len());
        key.extend_from_slice(owner_ark_id);
        key.extend_from_slice(lower.as_bytes());
        key
    }

    /// Stores or updates a private overlay record for the specified owner ArkID.
    pub fn put_overlay(&self, owner_ark_id: &[u8; 32], record: &OverlayRecord) -> Result<()> {
        let key = Self::make_key(owner_ark_id, &record.domain);
        let serialized =
            serde_json::to_vec(record).map_err(|e| DnsError::Serialization(e.to_string()))?;
        self.keyspace.insert(key, serialized).map_err(|e| {
            DnsError::Storage(ark_storage::ArkStorageError::Database(e.to_string()))
        })?;
        Ok(())
    }

    /// Retrieves a private overlay record for a specific owner ArkID and domain.
    pub fn get_overlay(
        &self,
        owner_ark_id: &[u8; 32],
        domain: &str,
    ) -> Result<Option<OverlayRecord>> {
        let key = Self::make_key(owner_ark_id, domain);
        if let Some(bytes) = self
            .keyspace
            .get(&key)
            .map_err(|e| DnsError::Storage(ark_storage::ArkStorageError::Database(e.to_string())))?
        {
            let record: OverlayRecord = serde_json::from_slice(&bytes)
                .map_err(|e| DnsError::Serialization(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// Deletes a private overlay record for a specific owner ArkID and domain.
    /// Returns `true` if the record existed and was deleted.
    pub fn delete_overlay(&self, owner_ark_id: &[u8; 32], domain: &str) -> Result<bool> {
        let key = Self::make_key(owner_ark_id, domain);
        let exists = self
            .keyspace
            .get(&key)
            .map_err(|e| DnsError::Storage(ark_storage::ArkStorageError::Database(e.to_string())))?
            .is_some();
        if exists {
            self.keyspace.remove(key).map_err(|e| {
                DnsError::Storage(ark_storage::ArkStorageError::Database(e.to_string()))
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Lists all private overlay records belonging strictly to a specific owner ArkID.
    pub fn list_overlays(&self, owner_ark_id: &[u8; 32]) -> Result<Vec<OverlayRecord>> {
        let mut results = Vec::new();
        for item in self.keyspace.iter() {
            let (key, val) = item.into_inner().map_err(|e| {
                DnsError::Storage(ark_storage::ArkStorageError::Database(e.to_string()))
            })?;
            if key.len() >= 32 && &key[..32] == owner_ark_id {
                let record: OverlayRecord = serde_json::from_slice(&val)
                    .map_err(|e| DnsError::Serialization(e.to_string()))?;
                results.push(record);
            }
        }
        Ok(results)
    }
}
