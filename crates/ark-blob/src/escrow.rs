//! Layer 2 Escrow Verification for ark-blob (GCP-10, ADR-0011).
//!
//! Enforces that public network persistence requires an active sponsorship contract
//! verified via `TAG_L2_CONTRACT` (`0x000F`).
//! Provides a pluggable `BlobEscrowVerifier` trait and standard mock implementations.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::error::Result;

/// Pluggable verifier trait for Ark Pay Layer 2 escrow sponsorship contracts.
pub trait BlobEscrowVerifier: Send + Sync {
    /// Verify whether an escrow contract ID is valid, active, and fully sponsors storage for the given BlobCID.
    ///
    /// - `contract_id`: Identifier of the L2 escrow contract (from TAG_L2_CONTRACT 0x000F).
    /// - `blob_cid`: 32-byte canonical BlobCID.
    fn verify_blob_escrow(&self, contract_id: &[u8], blob_cid: &[u8; 32]) -> Result<bool>;
}

impl<T: BlobEscrowVerifier + ?Sized> BlobEscrowVerifier for Arc<T> {
    fn verify_blob_escrow(&self, contract_id: &[u8], blob_cid: &[u8; 32]) -> Result<bool> {
        (**self).verify_blob_escrow(contract_id, blob_cid)
    }
}

impl<T: BlobEscrowVerifier + ?Sized> BlobEscrowVerifier for &T {
    fn verify_blob_escrow(&self, contract_id: &[u8], blob_cid: &[u8; 32]) -> Result<bool> {
        (**self).verify_blob_escrow(contract_id, blob_cid)
    }
}

/// Permissive verifier that accepts any non-empty contract (useful for local development or trusted setups).
#[derive(Clone, Debug, Default)]
pub struct PermissiveBlobEscrowVerifier;

impl PermissiveBlobEscrowVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl BlobEscrowVerifier for PermissiveBlobEscrowVerifier {
    fn verify_blob_escrow(&self, contract_id: &[u8], _blob_cid: &[u8; 32]) -> Result<bool> {
        // Must contain at least non-empty contract bytes
        Ok(!contract_id.is_empty())
    }
}

type AllowedBlobContracts = Arc<RwLock<HashSet<(Vec<u8>, [u8; 32])>>>;

/// Strict mock verifier maintaining an explicit whitelist of sponsored `(contract_id, blob_cid)` pairs.
/// By default rejects any unsponsored blobs or unknown contracts.
#[derive(Clone, Debug, Default)]
pub struct MockBlobEscrowVerifier {
    allowed_contracts: AllowedBlobContracts,
    allowed_global_contracts: Arc<RwLock<HashSet<Vec<u8>>>>,
}

impl MockBlobEscrowVerifier {
    pub fn new() -> Self {
        Self {
            allowed_contracts: Arc::new(RwLock::new(HashSet::new())),
            allowed_global_contracts: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Register a valid sponsorship contract specifically bound to a given BlobCID.
    pub fn allow_blob_contract(&self, contract_id: &[u8], blob_cid: &[u8; 32]) {
        let mut set = self.allowed_contracts.write().unwrap();
        set.insert((contract_id.to_vec(), *blob_cid));
    }

    /// Register a globally valid sponsorship contract accepted for any blob.
    pub fn allow_contract(&self, contract_id: &[u8]) {
        let mut set = self.allowed_global_contracts.write().unwrap();
        set.insert(contract_id.to_vec());
    }

    /// Revoke a contract.
    pub fn revoke_contract(&self, contract_id: &[u8]) {
        let mut globals = self.allowed_global_contracts.write().unwrap();
        globals.remove(contract_id);
        let mut specific = self.allowed_contracts.write().unwrap();
        specific.retain(|(c, _)| c != contract_id);
    }
}

impl BlobEscrowVerifier for MockBlobEscrowVerifier {
    fn verify_blob_escrow(&self, contract_id: &[u8], blob_cid: &[u8; 32]) -> Result<bool> {
        if contract_id.is_empty() {
            return Ok(false);
        }

        let globals = self.allowed_global_contracts.read().unwrap();
        if globals.contains(contract_id) {
            return Ok(true);
        }

        let specific = self.allowed_contracts.read().unwrap();
        Ok(specific.contains(&(contract_id.to_vec(), *blob_cid)))
    }
}
