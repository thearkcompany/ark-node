//! Cryptographic name (Tier 1) parser, resolver and validator for sovereign DNS (.ark).
//!
//! Cryptographic names format: `ark1<bech32>.ark`
//! IdentityHash = SHA3-256(0x01 || FN_DSA_PubKey)
//!
//! Validated and resolved in O(1) time without directory queries.

use sha3::{Digest, Sha3_256};
use bech32::{Bech32, Hrp};
use crate::error::{DnsError, Result};

pub const CRYPTO_NAME_HRP: &str = "ark";
pub const CRYPTO_NAME_PREFIX: &str = "ark1";
pub const CRYPTO_NAME_SUFFIX: &str = ".ark";
pub const FN_DSA_PUBKEY_PREFIX_BYTE: u8 = 0x01;

/// Derives the canonical 32-byte IdentityHash from an FN-DSA public key:
/// IdentityHash = SHA3-256(0x01 || FN_DSA_PubKey)
pub fn derive_identity_hash(fn_dsa_pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([FN_DSA_PUBKEY_PREFIX_BYTE]);
    hasher.update(fn_dsa_pubkey);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Formats a cryptographic domain name for a given FN-DSA public key.
/// Returns a string formatted as `ark1<bech32>.ark`.
pub fn format_cryptographic_name(fn_dsa_pubkey: &[u8]) -> Result<String> {
    let identity_hash = derive_identity_hash(fn_dsa_pubkey);
    format_cryptographic_name_from_hash(&identity_hash)
}

/// Formats a cryptographic domain name directly from a 32-byte IdentityHash.
pub fn format_cryptographic_name_from_hash(identity_hash: &[u8; 32]) -> Result<String> {
    let hrp = Hrp::parse(CRYPTO_NAME_HRP)
        .map_err(|e| DnsError::InvalidBech32(e.to_string()))?;
    let bech32_str = bech32::encode::<Bech32>(hrp, identity_hash)
        .map_err(|e| DnsError::InvalidBech32(e.to_string()))?;
    Ok(format!("{}{}", bech32_str, CRYPTO_NAME_SUFFIX))
}

/// Determines if a domain name matches the cryptographic name format (`ark1...ark`).
pub fn is_cryptographic_name(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    lower.starts_with(CRYPTO_NAME_PREFIX) && lower.ends_with(CRYPTO_NAME_SUFFIX)
}

/// Parses a cryptographic domain name (`ark1<bech32>.ark`) in O(1) time
/// and extracts its 32-byte IdentityHash.
pub fn parse_cryptographic_name(domain: &str) -> Result<[u8; 32]> {
    let lower = domain.to_ascii_lowercase();
    if !lower.ends_with(CRYPTO_NAME_SUFFIX) {
        return Err(DnsError::InvalidDomainName(format!(
            "Domain '{}' does not end with '{}'",
            domain, CRYPTO_NAME_SUFFIX
        )));
    }

    if !lower.starts_with(CRYPTO_NAME_PREFIX) {
        return Err(DnsError::NotCryptographicName(format!(
            "Domain '{}' does not have cryptographic prefix '{}'",
            domain, CRYPTO_NAME_PREFIX
        )));
    }

    // Strip the trailing ".ark"
    let bech32_part = &lower[..lower.len() - CRYPTO_NAME_SUFFIX.len()];

    let (hrp, data) = bech32::decode(bech32_part)
        .map_err(|e| DnsError::InvalidBech32(e.to_string()))?;

    if hrp.as_str() != CRYPTO_NAME_HRP {
        return Err(DnsError::InvalidBech32(format!(
            "Expected HRP '{}', got '{}'",
            CRYPTO_NAME_HRP,
            hrp.as_str()
        )));
    }

    if data.len() != 32 {
        return Err(DnsError::InvalidBech32(format!(
            "Expected 32-byte decoded identity hash, got {} bytes",
            data.len()
        )));
    }

    let mut identity_hash = [0u8; 32];
    identity_hash.copy_from_slice(&data);
    Ok(identity_hash)
}

/// Verifies in O(1) time that a given cryptographic domain name matches the provided FN-DSA public key.
pub fn verify_cryptographic_name(domain: &str, fn_dsa_pubkey: &[u8]) -> Result<[u8; 32]> {
    let expected_hash = parse_cryptographic_name(domain)?;
    let actual_hash = derive_identity_hash(fn_dsa_pubkey);

    if expected_hash != actual_hash {
        return Err(DnsError::IdentityMismatch {
            expected_hex: hex_fmt(&expected_hash),
            actual_hex: hex_fmt(&actual_hash),
        });
    }

    Ok(expected_hash)
}

fn hex_fmt(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
