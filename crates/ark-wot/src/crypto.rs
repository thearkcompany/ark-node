//! Cryptographic Attestations, Revocations and Canonical Envelope Packaging for Web-of-Trust (ACP-04).

use ark_core::error::{ArkError, Result};
use ark_core::fast_header::FastHeader;
use ark_crypto::fn_dsa::{verify_fn_dsa_512, FnDsaKeyPair, FN_DSA_512_PUBKEY_SIZE};
use ark_crypto::kmac::Kmac256;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const KIND_WOT_ATTESTATION: u32 = 0x000A;
pub const KIND_WOT_REVOCATION: u32 = 0x000B;

pub const TAG_WOT_ISSUER: u32 = 0x000A_0001;
pub const TAG_WOT_SUBJECT: u32 = 0x000A_0002;
pub const TAG_WOT_PUBKEY: u32 = 0x000A_0003;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope(pub u32);

impl CapabilityScope {
    pub const RELAY: Self = Self(1 << 0);
    pub const STORAGE: Self = Self(1 << 1);
    pub const COMPUTE: Self = Self(1 << 2);
    pub const DISCOVERY: Self = Self(1 << 3);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilityScopes(pub u32);

impl CapabilityScopes {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn insert(&mut self, scope: CapabilityScope) {
        self.0 |= scope.0;
    }

    pub fn contains(&self, scope: CapabilityScope) -> bool {
        (self.0 & scope.0) == scope.0
    }
}

/// Signed Web-of-Trust Attestation certifying confidence in a subject node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustAttestation {
    pub issuer_id: [u8; 32],
    pub subject_id: [u8; 32],
    pub score_weight: f64,
    pub capability_scopes: CapabilityScopes,
    pub issued_at_pmt: u64,
    pub expires_at_pmt: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

impl TrustAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn create_and_sign(
        issuer_id: [u8; 32],
        subject_id: [u8; 32],
        score_weight: f64,
        capability_scopes: CapabilityScopes,
        issued_at_pmt: u64,
        expires_at_pmt: u64,
        nonce: u64,
        keypair: &FnDsaKeyPair,
    ) -> Result<Self> {
        if !(0.0..=1.0).contains(&score_weight) {
            return Err(ArkError::CryptoError("score_weight must be in [0.0, 1.0]".into()));
        }

        let mut attestation = Self {
            issuer_id,
            subject_id,
            score_weight,
            capability_scopes,
            issued_at_pmt,
            expires_at_pmt,
            nonce,
            signature: Vec::new(),
        };

        let digest = attestation.signing_digest();
        let sig = keypair.sign(&digest)?;
        attestation.signature = sig;

        Ok(attestation)
    }

    /// Canonical message digest for signing/verification using KMAC256 identity digest.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&self.issuer_id);
        data.extend_from_slice(&self.subject_id);
        data.extend_from_slice(&self.score_weight.to_be_bytes());
        data.extend_from_slice(&self.capability_scopes.0.to_be_bytes());
        data.extend_from_slice(&self.issued_at_pmt.to_be_bytes());
        data.extend_from_slice(&self.expires_at_pmt.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());

        let mac = Kmac256::mac(b"ARK-WOT-ATTESTATION-V1", &data, 32);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&mac);
        digest
    }

    /// Verifies the attestation signature against issuer public key and ensures pubkey derives issuer_id.
    pub fn verify_signature(&self, issuer_pubkey: &[u8]) -> Result<()> {
        if issuer_pubkey.len() != FN_DSA_512_PUBKEY_SIZE {
            return Err(ArkError::CryptoError("Invalid issuer public key size".into()));
        }

        // Verify ArkID derivation: issuer_id = SHA3-256(pubkey)
        let derived_issuer_id: [u8; 32] = Sha3_256::digest(issuer_pubkey).into();
        if self.issuer_id != [0u8; 32] && self.issuer_id != derived_issuer_id {
            return Err(ArkError::CryptoError("Public key does not match issuer_id".into()));
        }

        if !(0.0..=1.0).contains(&self.score_weight) {
            return Err(ArkError::CryptoError("Invalid score_weight out of range".into()));
        }

        let digest = self.signing_digest();
        verify_fn_dsa_512(issuer_pubkey, &digest, &self.signature)
    }

    /// Serializes attestation using CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| ArkError::SerializationError(e.to_string()))?;
        Ok(buf)
    }

    /// Deserializes attestation from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|e| ArkError::SerializationError(e.to_string()))
    }

    /// Packages the attestation into an ArkEnvelope with KIND_WOT_ATTESTATION (0x000A)
    pub fn to_envelope(&self, issuer_pubkey: &[u8]) -> Result<ArkEnvelope> {
        let payload = self.to_cbor()?;

        let mut sender_key_id = [0u8; 16];
        sender_key_id.copy_from_slice(&self.issuer_id[..16]);
        let mut recipient_key_id = [0u8; 16];
        recipient_key_id.copy_from_slice(&self.subject_id[..16]);

        let fast_header = FastHeader::new(
            0,
            payload.len() as u32,
            KIND_WOT_ATTESTATION,
            sender_key_id,
            recipient_key_id,
            self.nonce,
        );

        let mut param_d = Vec::with_capacity(64);
        param_d.extend_from_slice(&self.issuer_id);
        param_d.extend_from_slice(&self.subject_id);

        let tags = vec![
            BinaryTag::new(0, KIND_WOT_ATTESTATION.to_be_bytes().to_vec()),
            BinaryTag::new(ark_storage::TAG_PARAM_D, param_d),
            BinaryTag::new(TAG_WOT_ISSUER, self.issuer_id.to_vec()),
            BinaryTag::new(TAG_WOT_SUBJECT, self.subject_id.to_vec()),
            BinaryTag::new(TAG_WOT_PUBKEY, issuer_pubkey.to_vec()),
        ];

        ArkEnvelope::new(
            fast_header.to_bytes(),
            self.issuer_id,
            self.subject_id,
            payload,
            self.signature.clone(),
            0,
            tags,
            self.issued_at_pmt,
        )
    }

    /// Reconstructs TrustAttestation from an ArkEnvelope.
    pub fn from_envelope(envelope: &ArkEnvelope) -> Result<Self> {
        let kind = ark_storage::get_envelope_kind(envelope);
        if kind != KIND_WOT_ATTESTATION {
            return Err(ArkError::SerializationError(format!(
                "Invalid envelope kind: 0x{:04x}, expected KIND_WOT_ATTESTATION (0x{:04x})",
                kind, KIND_WOT_ATTESTATION
            )));
        }

        Self::from_cbor(&envelope.payload)
    }
}

/// Signed Web-of-Trust Revocation cancelling previously issued attestations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustRevocation {
    pub issuer_id: [u8; 32],
    pub subject_id: [u8; 32],
    pub revoked_at_pmt: u64,
    pub reason: String,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

impl TrustRevocation {
    pub fn create_and_sign(
        issuer_id: [u8; 32],
        subject_id: [u8; 32],
        revoked_at_pmt: u64,
        reason: String,
        nonce: u64,
        keypair: &FnDsaKeyPair,
    ) -> Result<Self> {
        let mut revocation = Self {
            issuer_id,
            subject_id,
            revoked_at_pmt,
            reason,
            nonce,
            signature: Vec::new(),
        };

        let digest = revocation.signing_digest();
        let sig = keypair.sign(&digest)?;
        revocation.signature = sig;

        Ok(revocation)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&self.issuer_id);
        data.extend_from_slice(&self.subject_id);
        data.extend_from_slice(&self.revoked_at_pmt.to_be_bytes());
        data.extend_from_slice(self.reason.as_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());

        let mac = Kmac256::mac(b"ARK-WOT-REVOCATION-V1", &data, 32);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&mac);
        digest
    }

    pub fn verify_signature(&self, issuer_pubkey: &[u8]) -> Result<()> {
        if issuer_pubkey.len() != FN_DSA_512_PUBKEY_SIZE {
            return Err(ArkError::CryptoError("Invalid issuer public key size".into()));
        }

        let derived_issuer_id: [u8; 32] = Sha3_256::digest(issuer_pubkey).into();
        if self.issuer_id != [0u8; 32] && self.issuer_id != derived_issuer_id {
            return Err(ArkError::CryptoError("Public key does not match issuer_id".into()));
        }

        let digest = self.signing_digest();
        verify_fn_dsa_512(issuer_pubkey, &digest, &self.signature)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| ArkError::SerializationError(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|e| ArkError::SerializationError(e.to_string()))
    }

    pub fn to_envelope(&self, issuer_pubkey: &[u8]) -> Result<ArkEnvelope> {
        let payload = self.to_cbor()?;

        let mut sender_key_id = [0u8; 16];
        sender_key_id.copy_from_slice(&self.issuer_id[..16]);
        let mut recipient_key_id = [0u8; 16];
        recipient_key_id.copy_from_slice(&self.subject_id[..16]);

        let fast_header = FastHeader::new(
            0,
            payload.len() as u32,
            KIND_WOT_REVOCATION,
            sender_key_id,
            recipient_key_id,
            self.nonce,
        );

        let tags = vec![
            BinaryTag::new(0, KIND_WOT_REVOCATION.to_be_bytes().to_vec()),
            BinaryTag::new(TAG_WOT_ISSUER, self.issuer_id.to_vec()),
            BinaryTag::new(TAG_WOT_SUBJECT, self.subject_id.to_vec()),
            BinaryTag::new(TAG_WOT_PUBKEY, issuer_pubkey.to_vec()),
        ];

        ArkEnvelope::new(
            fast_header.to_bytes(),
            self.issuer_id,
            self.subject_id,
            payload,
            self.signature.clone(),
            0,
            tags,
            self.revoked_at_pmt,
        )
    }

    pub fn from_envelope(envelope: &ArkEnvelope) -> Result<Self> {
        let kind = ark_storage::get_envelope_kind(envelope);
        if kind != KIND_WOT_REVOCATION {
            return Err(ArkError::SerializationError(format!(
                "Invalid envelope kind: 0x{:04x}, expected KIND_WOT_REVOCATION (0x{:04x})",
                kind, KIND_WOT_REVOCATION
            )));
        }

        Self::from_cbor(&envelope.payload)
    }
}
