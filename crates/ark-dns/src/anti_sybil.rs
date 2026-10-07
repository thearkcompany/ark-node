//! Anti-Sybil Proof-of-Work (16-bit) and Ark Pay L2 Escrow Verification (GCP-08).
//!
//! Validates canonical `KIND_DNS_CLAIM_PUBLIC` (`0x3000_0002`, Retention Class 3) envelopes:
//! - Rejects invalid kinds or corrupt wire formats.
//! - Verifies 16-bit leading zero Proof-of-Work on the canonical SHA3-256 envelope ID digest in constant time.
//! - Validates and extracts `TAG_PARAM_D` (FQDN, 0x0004), `TAG_DNS_LEASE_EPOCH` (0x001B), and `TAG_L2_CONTRACT` (0x000F).
//! - Enforces pluggable `L2ContractVerifier` escrow verification.

use subtle::ConstantTimeEq;
use ark_core::FastHeader;
use ark_protocol::envelope::ArkEnvelope;
use ark_storage::compute_envelope_id;
use crate::error::{DnsError, Result};

/// Canonical envelope kind for public sovereign DNS claims (Retention Class 3).
pub const KIND_DNS_CLAIM_PUBLIC: u32 = 0x3000_0002;

/// Tag definitions for sovereign DNS claim envelopes conforming to GCP-08 and ADR-0010.
pub const TAG_PARAM_D: u32 = 0x0004;
pub const TAG_NONCE: u32 = 0x000A;
pub const TAG_L2_CONTRACT: u32 = 0x000F;
pub const TAG_DNS_LEASE_EPOCH: u32 = 0x001B;

/// Suffix for sovereign domain names.
pub const SOVEREIGN_DNS_SUFFIX: &str = ".ark";

/// Pluggable verifier trait for Ark Pay Layer 2 escrow contracts.
pub trait L2ContractVerifier: Send + Sync {
    /// Verify an escrow contract deposit on Ark Pay L2 for the given owner key ID.
    fn verify_escrow_contract(&self, contract_id: &[u8], owner_key_id: &[u8]) -> Result<bool>;
}

/// Validated Human-Readable Public DNS claim metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDnsClaim {
    /// Normalized Fully Qualified Domain Name (e.g. `alice.ark`).
    pub fqdn: String,
    /// Lease expiration epoch in seconds.
    pub lease_epoch: u64,
    /// L2 Escrow contract identifier bytes.
    pub contract_id: Vec<u8>,
    /// 16-byte owner key ID derived from ArkID / fast header.
    pub owner_key_id: [u8; 16],
    /// Canonical 32-byte envelope ID digest.
    pub envelope_id: [u8; 32],
}

/// Constant-time check for at least 16 leading zero bits on a 32-byte digest.
///
/// In big-endian/standard byte order, 16 leading zero bits correspond to the first
/// two bytes being 0x00 (`hash[0] == 0` and `hash[1] == 0`).
#[inline]
pub fn has_16_leading_zero_bits(hash: &[u8; 32]) -> bool {
    let check_bytes = &hash[0..2];
    let zero_bytes = [0u8; 2];
    check_bytes.ct_eq(&zero_bytes).into()
}

/// Count leading zero bits in a 32-byte digest (for diagnostics / error reporting).
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> usize {
    let mut zeros = 0;
    for byte in hash {
        let lz = byte.leading_zeros() as usize;
        zeros += lz;
        if lz < 8 {
            break;
        }
    }
    zeros
}

/// Validates a domain name string as a sovereign `.ark` FQDN according to RFC 1035 / GCP-08 rules:
/// - Must end with `.ark` (case-insensitive).
/// - Must have at least one non-empty label before `.ark`.
/// - Each label must be 1..=63 ASCII characters.
/// - Valid characters are lowercase alphanumeric `[a-z0-9]` and hyphens `-`.
/// - Hyphens cannot be leading or trailing in any label.
/// - Total FQDN length cannot exceed 253 characters.
pub fn validate_fqdn(fqdn_str: &str) -> Result<String> {
    let lower = fqdn_str.trim().to_ascii_lowercase();

    if !lower.ends_with(SOVEREIGN_DNS_SUFFIX) {
        return Err(DnsError::InvalidDomainName(format!(
            "FQDN must end with '{}'",
            SOVEREIGN_DNS_SUFFIX
        )));
    }

    if lower.len() > 253 {
        return Err(DnsError::InvalidDomainName(format!(
            "FQDN exceeds 253 characters: {} chars",
            lower.len()
        )));
    }

    let without_suffix = &lower[..lower.len() - SOVEREIGN_DNS_SUFFIX.len()];
    if without_suffix.is_empty() {
        return Err(DnsError::InvalidDomainName(
            "Empty domain label before .ark suffix".to_string(),
        ));
    }

    let labels: Vec<&str> = without_suffix.split('.').collect();
    for label in labels {
        if label.is_empty() {
            return Err(DnsError::InvalidDomainName(
                "Domain contains empty label (consecutive dots)".to_string(),
            ));
        }
        if label.len() > 63 {
            return Err(DnsError::InvalidDomainName(format!(
                "Domain label exceeds 63 characters: '{}'",
                label
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DnsError::InvalidDomainName(format!(
                "Domain label cannot start or end with hyphen: '{}'",
                label
            )));
        }
        for ch in label.chars() {
            if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' {
                return Err(DnsError::InvalidDomainName(format!(
                    "Invalid character in domain label '{}': '{}'",
                    label, ch
                )));
            }
        }
    }

    Ok(lower)
}

/// Validate a `KIND_DNS_CLAIM_PUBLIC` registration envelope against anti-Sybil PoW,
/// FQDN formatting, and Ark Pay L2 escrow contract.
pub fn validate_dns_claim<V: L2ContractVerifier + ?Sized>(
    envelope: &ArkEnvelope,
    l2_verifier: &V,
) -> Result<ValidatedDnsClaim> {
    // 1. Validate envelope wire format and header
    if envelope.magic != b"ARK1" {
        return Err(DnsError::InvalidRecord("Invalid envelope magic bytes".to_string()));
    }

    let fast_header = if envelope.fast_header.len() >= 64 {
        let bytes: [u8; 64] = envelope.fast_header[..64]
            .try_into()
            .map_err(|_| DnsError::InvalidRecord("Corrupt fast_header size".to_string()))?;
        FastHeader::from_bytes(&bytes)
            .map_err(|e| DnsError::InvalidRecord(format!("Invalid fast_header: {}", e)))?
    } else {
        return Err(DnsError::InvalidRecord("Corrupt fast_header length < 64 bytes".to_string()));
    };

    // Verify kind matches KIND_DNS_CLAIM_PUBLIC (0x3000_0002)
    // FastHeader fast_tag carries the kind in ark protocol / storage
    let mut kind = fast_header.fast_tag;

    // Also check tag_type == 0 if present (explicit kind tag)
    for tag in &envelope.tags {
        if tag.tag_type == 0 {
            if tag.tag_value.len() == 4 {
                kind = u32::from_be_bytes(tag.tag_value[..4].try_into().unwrap());
            } else if tag.tag_value.is_empty() {
                kind = 0;
            }
        }
    }

    if kind != KIND_DNS_CLAIM_PUBLIC {
        return Err(DnsError::InvalidRecord(format!(
            "Invalid envelope kind: 0x{:08X}, expected KIND_DNS_CLAIM_PUBLIC (0x{:08X})",
            kind, KIND_DNS_CLAIM_PUBLIC
        )));
    }

    // 2. Validate presence of required tags before PoW verification
    let nonce_tag = envelope
        .tags
        .iter()
        .find(|t| t.tag_type == TAG_NONCE)
        .ok_or(DnsError::MissingTag(TAG_NONCE))?;

    if nonce_tag.tag_value.is_empty() {
        return Err(DnsError::InvalidRecord("Empty TAG_NONCE value".to_string()));
    }

    let param_d_tag = envelope
        .tags
        .iter()
        .find(|t| t.tag_type == TAG_PARAM_D)
        .ok_or(DnsError::MissingTag(TAG_PARAM_D))?;

    let lease_tag = envelope
        .tags
        .iter()
        .find(|t| t.tag_type == TAG_DNS_LEASE_EPOCH)
        .ok_or(DnsError::MissingTag(TAG_DNS_LEASE_EPOCH))?;

    let l2_tag = envelope
        .tags
        .iter()
        .find(|t| t.tag_type == TAG_L2_CONTRACT)
        .ok_or(DnsError::MissingTag(TAG_L2_CONTRACT))?;

    if l2_tag.tag_value.is_empty() {
        return Err(DnsError::InvalidRecord("Empty TAG_L2_CONTRACT value".to_string()));
    }

    // 3. Extract and validate TAG_PARAM_D (FQDN)
    let raw_fqdn = std::str::from_utf8(&param_d_tag.tag_value)
        .map_err(|e| DnsError::InvalidDomainName(format!("Invalid UTF-8 in TAG_PARAM_D: {}", e)))?;

    let fqdn = validate_fqdn(raw_fqdn)?;

    // 4. Validate 16-bit Proof-of-Work
    // Calculate canonical SHA3-256 envelope ID digest
    let envelope_id = compute_envelope_id(envelope)
        .map_err(|e| DnsError::InvalidRecord(format!("Failed to compute envelope ID: {}", e)))?;

    // Verify constant-time 16 leading zero bits
    if !has_16_leading_zero_bits(&envelope_id) {
        let actual_zeros = count_leading_zero_bits(&envelope_id);
        return Err(DnsError::InsufficientProofOfWork {
            required_bits: 16,
            actual_bits: actual_zeros,
        });
    }

    // 5. Extract and validate TAG_DNS_LEASE_EPOCH
    let lease_epoch = if lease_tag.tag_value.len() == 8 {
        u64::from_be_bytes(lease_tag.tag_value[..8].try_into().unwrap())
    } else if lease_tag.tag_value.len() == 4 {
        u32::from_be_bytes(lease_tag.tag_value[..4].try_into().unwrap()) as u64
    } else {
        return Err(DnsError::InvalidRecord(format!(
            "Invalid TAG_DNS_LEASE_EPOCH length: {} bytes (expected 4 or 8 bytes)",
            lease_tag.tag_value.len()
        )));
    };

    // 5. Extract and validate TAG_L2_CONTRACT
    let l2_tag = envelope
        .tags
        .iter()
        .find(|t| t.tag_type == TAG_L2_CONTRACT)
        .ok_or(DnsError::MissingTag(TAG_L2_CONTRACT))?;

    if l2_tag.tag_value.is_empty() {
        return Err(DnsError::InvalidRecord("Empty TAG_L2_CONTRACT value".to_string()));
    }

    // 6. Validate L2 escrow contract via L2ContractVerifier
    let owner_key_id = fast_header.sender_key_id;
    let is_verified = l2_verifier.verify_escrow_contract(&l2_tag.tag_value, &owner_key_id)?;
    if !is_verified {
        return Err(DnsError::UnverifiedL2Contract(format!(
            "L2 contract 0x{} not verified for owner 0x{}",
            hex_fmt(&l2_tag.tag_value),
            hex_fmt(&owner_key_id)
        )));
    }

    Ok(ValidatedDnsClaim {
        fqdn,
        lease_epoch,
        contract_id: l2_tag.tag_value.clone(),
        owner_key_id,
        envelope_id,
    })
}

fn hex_fmt(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
