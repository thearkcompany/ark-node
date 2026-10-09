//! Post-Quantum Mesh Tunneling (PQMT) engine.
//!
//! Provides:
//! - ML-KEM-768 shared secret encapsulation/decapsulation.
//! - FN-DSA-512 authenticated handshake negotiation.
//! - Handshake transition: FastHeader (64B) initial handshake -> MicroHeader (16B) continuous data.
//! - Ephemeral session table with replay protection and sequence counter tracking.
//! - Line-speed zero-copy packet framing and deframing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ark_crypto::fn_dsa::{verify_fn_dsa_512, FN_DSA_512_PUBKEY_SIZE, FN_DSA_512_SIGNATURE_SIZE};
use ark_crypto::identity::PersistentIdentity;
use ark_crypto::kmac::Kmac256;
use ark_crypto::ml_kem::{
    ml_kem_encapsulate, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBKEY_SIZE,
    ML_KEM_768_SHARED_SECRET_SIZE,
};
use ark_protocol::envelope::ArkEnvelope;
use bytes::Bytes;
use rand_core::CryptoRngCore;

use crate::error::{Result, VpnError};
use crate::framing::{
    deframe_fast_packet, deframe_micro_packet, frame_fast_packet, frame_micro_packet,
    KIND_VPN_HANDSHAKE,
};

/// Handshake message types
pub const HANDSHAKE_INIT_TAG: u8 = 0x01;
pub const HANDSHAKE_RESP_TAG: u8 = 0x02;

/// Domain separation strings for key derivation
const VPN_KDF_DOMAIN_INIT_TO_RESP: &[u8] = b"ARK-VPN-KDF-V1-INITIATOR-TO-RESPONDER";
const VPN_KDF_DOMAIN_RESP_TO_INIT: &[u8] = b"ARK-VPN-KDF-V1-RESPONDER-TO-INITIATOR";

/// Initiator handshake payload:
/// [1B Tag: 0x01]
/// [4B Proposed Session ID]
/// [897B FN-DSA-512 Public Key]
/// [1184B ML-KEM-768 Public Key]
/// [8B Timestamp]
/// [666B FN-DSA-512 Signature over (tag + session_id + fn_dsa_pk + ml_kem_pk + timestamp)]
#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub proposed_session_id: u32,
    pub fn_dsa_pubkey: [u8; FN_DSA_512_PUBKEY_SIZE],
    pub ml_kem_pubkey: [u8; ML_KEM_768_PUBKEY_SIZE],
    pub timestamp: u64,
    pub signature: [u8; FN_DSA_512_SIGNATURE_SIZE],
}

impl HandshakeInit {
    pub const PAYLOAD_SIZE: usize =
        1 + 4 + FN_DSA_512_PUBKEY_SIZE + ML_KEM_768_PUBKEY_SIZE + 8 + FN_DSA_512_SIGNATURE_SIZE;

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::PAYLOAD_SIZE);
        buf.push(HANDSHAKE_INIT_TAG);
        buf.extend_from_slice(&self.proposed_session_id.to_be_bytes());
        buf.extend_from_slice(&self.fn_dsa_pubkey);
        buf.extend_from_slice(&self.ml_kem_pubkey);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::PAYLOAD_SIZE {
            return Err(VpnError::HandshakeFailed(format!(
                "Invalid HandshakeInit size: expected {}, got {}",
                Self::PAYLOAD_SIZE,
                bytes.len()
            )));
        }

        if bytes[0] != HANDSHAKE_INIT_TAG {
            return Err(VpnError::HandshakeFailed(format!(
                "Invalid HandshakeInit tag: expected 0x01, got 0x{:02x}",
                bytes[0]
            )));
        }

        let mut offset = 1;
        let proposed_session_id = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut fn_dsa_pubkey = [0u8; FN_DSA_512_PUBKEY_SIZE];
        fn_dsa_pubkey.copy_from_slice(&bytes[offset..offset + FN_DSA_512_PUBKEY_SIZE]);
        offset += FN_DSA_512_PUBKEY_SIZE;

        let mut ml_kem_pubkey = [0u8; ML_KEM_768_PUBKEY_SIZE];
        ml_kem_pubkey.copy_from_slice(&bytes[offset..offset + ML_KEM_768_PUBKEY_SIZE]);
        offset += ML_KEM_768_PUBKEY_SIZE;

        let timestamp = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let mut signature = [0u8; FN_DSA_512_SIGNATURE_SIZE];
        signature.copy_from_slice(&bytes[offset..offset + FN_DSA_512_SIGNATURE_SIZE]);

        Ok(Self {
            proposed_session_id,
            fn_dsa_pubkey,
            ml_kem_pubkey,
            timestamp,
            signature,
        })
    }

    pub fn signed_data(
        proposed_session_id: u32,
        fn_dsa_pubkey: &[u8; FN_DSA_512_PUBKEY_SIZE],
        ml_kem_pubkey: &[u8; ML_KEM_768_PUBKEY_SIZE],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut data =
            Vec::with_capacity(1 + 4 + FN_DSA_512_PUBKEY_SIZE + ML_KEM_768_PUBKEY_SIZE + 8);
        data.push(HANDSHAKE_INIT_TAG);
        data.extend_from_slice(&proposed_session_id.to_be_bytes());
        data.extend_from_slice(fn_dsa_pubkey);
        data.extend_from_slice(ml_kem_pubkey);
        data.extend_from_slice(&timestamp.to_be_bytes());
        data
    }

    pub fn verify_signature(&self) -> Result<()> {
        let data = Self::signed_data(
            self.proposed_session_id,
            &self.fn_dsa_pubkey,
            &self.ml_kem_pubkey,
            self.timestamp,
        );
        verify_fn_dsa_512(&self.fn_dsa_pubkey, &data, &self.signature).map_err(|e| {
            VpnError::HandshakeFailed(format!("Signature verification failed: {:?}", e))
        })
    }
}

/// Responder handshake payload:
/// [1B Tag: 0x02]
/// [4B Session ID]
/// [897B FN-DSA-512 Public Key]
/// [1088B ML-KEM-768 Ciphertext]
/// [8B Timestamp]
/// [666B FN-DSA-512 Signature over (tag + session_id + fn_dsa_pk + ciphertext + timestamp)]
#[derive(Debug, Clone)]
pub struct HandshakeResp {
    pub session_id: u32,
    pub fn_dsa_pubkey: [u8; FN_DSA_512_PUBKEY_SIZE],
    pub ciphertext: [u8; ML_KEM_768_CIPHERTEXT_SIZE],
    pub timestamp: u64,
    pub signature: [u8; FN_DSA_512_SIGNATURE_SIZE],
}

impl HandshakeResp {
    pub const PAYLOAD_SIZE: usize =
        1 + 4 + FN_DSA_512_PUBKEY_SIZE + ML_KEM_768_CIPHERTEXT_SIZE + 8 + FN_DSA_512_SIGNATURE_SIZE;

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::PAYLOAD_SIZE);
        buf.push(HANDSHAKE_RESP_TAG);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.fn_dsa_pubkey);
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::PAYLOAD_SIZE {
            return Err(VpnError::HandshakeFailed(format!(
                "Invalid HandshakeResp size: expected {}, got {}",
                Self::PAYLOAD_SIZE,
                bytes.len()
            )));
        }

        if bytes[0] != HANDSHAKE_RESP_TAG {
            return Err(VpnError::HandshakeFailed(format!(
                "Invalid HandshakeResp tag: expected 0x02, got 0x{:02x}",
                bytes[0]
            )));
        }

        let mut offset = 1;
        let session_id = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut fn_dsa_pubkey = [0u8; FN_DSA_512_PUBKEY_SIZE];
        fn_dsa_pubkey.copy_from_slice(&bytes[offset..offset + FN_DSA_512_PUBKEY_SIZE]);
        offset += FN_DSA_512_PUBKEY_SIZE;

        let mut ciphertext = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
        ciphertext.copy_from_slice(&bytes[offset..offset + ML_KEM_768_CIPHERTEXT_SIZE]);
        offset += ML_KEM_768_CIPHERTEXT_SIZE;

        let timestamp = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let mut signature = [0u8; FN_DSA_512_SIGNATURE_SIZE];
        signature.copy_from_slice(&bytes[offset..offset + FN_DSA_512_SIGNATURE_SIZE]);

        Ok(Self {
            session_id,
            fn_dsa_pubkey,
            ciphertext,
            timestamp,
            signature,
        })
    }

    pub fn signed_data(
        session_id: u32,
        fn_dsa_pubkey: &[u8; FN_DSA_512_PUBKEY_SIZE],
        ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_SIZE],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut data =
            Vec::with_capacity(1 + 4 + FN_DSA_512_PUBKEY_SIZE + ML_KEM_768_CIPHERTEXT_SIZE + 8);
        data.push(HANDSHAKE_RESP_TAG);
        data.extend_from_slice(&session_id.to_be_bytes());
        data.extend_from_slice(fn_dsa_pubkey);
        data.extend_from_slice(ciphertext);
        data.extend_from_slice(&timestamp.to_be_bytes());
        data
    }

    pub fn verify_signature(&self) -> Result<()> {
        let data = Self::signed_data(
            self.session_id,
            &self.fn_dsa_pubkey,
            &self.ciphertext,
            self.timestamp,
        );
        verify_fn_dsa_512(&self.fn_dsa_pubkey, &data, &self.signature).map_err(|e| {
            VpnError::HandshakeFailed(format!("Signature verification failed: {:?}", e))
        })
    }
}

/// Active Post-Quantum Session State.
#[derive(Debug, Clone)]
pub struct VpnSession {
    pub session_id: u32,
    pub peer_ark_id: [u8; 32],
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_seq: u32,
    pub recv_seq: u32,
}

impl VpnSession {
    /// Advance outgoing sequence number.
    pub fn next_send_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }

    /// Check and advance incoming sequence number with anti-replay protection.
    pub fn accept_recv_seq(&mut self, seq: u32) -> Result<()> {
        // Enforce strictly monotonic sequence numbers for the session
        if seq <= self.recv_seq && self.recv_seq != 0 {
            return Err(VpnError::ReplayDetected(seq));
        }
        self.recv_seq = seq;
        Ok(())
    }
}

/// Derive distinct directional 32-byte session keys from the shared secret.
pub fn derive_session_keys(
    shared_secret: &[u8; ML_KEM_768_SHARED_SECRET_SIZE],
    session_id: u32,
) -> ([u8; 32], [u8; 32]) {
    // Key 1: Initiator -> Responder
    let mut kmac1 = Kmac256::new(shared_secret);
    kmac1.update(VPN_KDF_DOMAIN_INIT_TO_RESP);
    kmac1.update(&session_id.to_be_bytes());
    let mut k1 = [0u8; 32];
    kmac1.finalize(&mut k1);

    // Key 2: Responder -> Initiator
    let mut kmac2 = Kmac256::new(shared_secret);
    kmac2.update(VPN_KDF_DOMAIN_RESP_TO_INIT);
    kmac2.update(&session_id.to_be_bytes());
    let mut k2 = [0u8; 32];
    kmac2.finalize(&mut k2);

    (k1, k2)
}

/// PQMT Engine managing sessions and packet framing.
pub struct PqmtEngine {
    identity: Arc<PersistentIdentity>,
    sessions: RwLock<HashMap<u32, VpnSession>>,
    next_session_id: RwLock<u32>,
}

impl PqmtEngine {
    pub fn new(identity: PersistentIdentity) -> Self {
        Self {
            identity: Arc::new(identity),
            sessions: RwLock::new(HashMap::new()),
            next_session_id: RwLock::new(100),
        }
    }

    pub fn with_arc(identity: Arc<PersistentIdentity>) -> Self {
        Self {
            identity,
            sessions: RwLock::new(HashMap::new()),
            next_session_id: RwLock::new(100),
        }
    }

    /// Local identity reference.
    pub fn identity(&self) -> &PersistentIdentity {
        &self.identity
    }

    /// Local identity Arc reference.
    pub fn identity_arc(&self) -> &Arc<PersistentIdentity> {
        &self.identity
    }

    /// Generate an initial handshake envelope (FastHeader) to initiate a tunnel with a peer.
    pub fn create_handshake_init<R: CryptoRngCore>(
        &self,
        recipient_key_id: [u8; 16],
        timestamp: u64,
        _rng: &mut R,
    ) -> Result<Bytes> {
        let proposed_session_id = {
            let mut id = self.next_session_id.write().unwrap();
            let current = *id;
            *id = id.wrapping_add(1);
            current
        };

        let fn_dsa_pk = self.identity.fn_dsa_keypair.public_key;
        let ml_kem_pk = self.identity.ml_kem_keypair.public_key;

        let signed_data =
            HandshakeInit::signed_data(proposed_session_id, &fn_dsa_pk, &ml_kem_pk, timestamp);
        let sig_bytes = self
            .identity
            .fn_dsa_keypair
            .sign(&signed_data)
            .map_err(|e| VpnError::Crypto(e.to_string()))?;

        let mut signature = [0u8; FN_DSA_512_SIGNATURE_SIZE];
        signature.copy_from_slice(&sig_bytes[..FN_DSA_512_SIGNATURE_SIZE]);

        let init = HandshakeInit {
            proposed_session_id,
            fn_dsa_pubkey: fn_dsa_pk,
            ml_kem_pubkey: ml_kem_pk,
            timestamp,
            signature,
        };

        let payload = init.serialize();
        let packet = frame_fast_packet(
            0,
            self.identity.sender_key_id,
            recipient_key_id,
            proposed_session_id as u64,
            &payload,
        );

        Ok(packet)
    }

    /// Process a received HandshakeInit, encapsulate ML-KEM-768 shared secret,
    /// establish the session on the responder side, and produce a HandshakeResp packet (FastHeader).
    pub fn handle_handshake_init<R: CryptoRngCore>(
        &self,
        packet: Bytes,
        timestamp: u64,
        rng: &mut R,
    ) -> Result<Bytes> {
        let (fast_hdr, payload) = deframe_fast_packet(packet)?;
        if fast_hdr.fast_tag != KIND_VPN_HANDSHAKE {
            return Err(VpnError::FramingError(format!(
                "Expected KIND_VPN_HANDSHAKE (0x{:04x}), got 0x{:04x}",
                KIND_VPN_HANDSHAKE, fast_hdr.fast_tag
            )));
        }

        let init = HandshakeInit::deserialize(&payload)?;
        init.verify_signature()?;

        // Perform ML-KEM-768 encapsulation against initiator's public key
        let (ciphertext, shared_secret) = ml_kem_encapsulate(&init.ml_kem_pubkey, rng)
            .map_err(|e| VpnError::Crypto(e.to_string()))?;

        let session_id = init.proposed_session_id;
        let (init_to_resp_key, resp_to_init_key) = derive_session_keys(&shared_secret, session_id);

        let peer_identity = ark_crypto::identity::Identity::from_public_key(&init.fn_dsa_pubkey);

        // Responder: send_key = resp_to_init_key, recv_key = init_to_resp_key
        let session = VpnSession {
            session_id,
            peer_ark_id: peer_identity.ark_id,
            send_key: resp_to_init_key,
            recv_key: init_to_resp_key,
            send_seq: 1,
            recv_seq: 0,
        };

        self.sessions.write().unwrap().insert(session_id, session);

        // Sign response
        let fn_dsa_pk = self.identity.fn_dsa_keypair.public_key;
        let signed_data =
            HandshakeResp::signed_data(session_id, &fn_dsa_pk, &ciphertext, timestamp);
        let sig_bytes = self
            .identity
            .fn_dsa_keypair
            .sign(&signed_data)
            .map_err(|e| VpnError::Crypto(e.to_string()))?;
        let mut signature = [0u8; FN_DSA_512_SIGNATURE_SIZE];
        signature.copy_from_slice(&sig_bytes[..FN_DSA_512_SIGNATURE_SIZE]);

        let resp = HandshakeResp {
            session_id,
            fn_dsa_pubkey: fn_dsa_pk,
            ciphertext,
            timestamp,
            signature,
        };

        let resp_payload = resp.serialize();
        let resp_packet = frame_fast_packet(
            0,
            self.identity.sender_key_id,
            fast_hdr.sender_key_id,
            session_id as u64,
            &resp_payload,
        );

        Ok(resp_packet)
    }

    /// Process a received HandshakeResp on initiator side, decapsulate ML-KEM-768 shared secret,
    /// and establish session on initiator side.
    pub fn handle_handshake_resp(&self, packet: Bytes) -> Result<u32> {
        let (fast_hdr, payload) = deframe_fast_packet(packet)?;
        if fast_hdr.fast_tag != KIND_VPN_HANDSHAKE {
            return Err(VpnError::FramingError(format!(
                "Expected KIND_VPN_HANDSHAKE (0x{:04x}), got 0x{:04x}",
                KIND_VPN_HANDSHAKE, fast_hdr.fast_tag
            )));
        }

        let resp = HandshakeResp::deserialize(&payload)?;
        resp.verify_signature()?;

        // Decapsulate shared secret using initiator's ML-KEM secret key
        let shared_secret = self
            .identity
            .ml_kem_keypair
            .decapsulate(&resp.ciphertext)
            .map_err(|e| VpnError::Crypto(e.to_string()))?;

        let session_id = resp.session_id;
        let (init_to_resp_key, resp_to_init_key) = derive_session_keys(&shared_secret, session_id);

        let peer_identity = ark_crypto::identity::Identity::from_public_key(&resp.fn_dsa_pubkey);

        // Initiator: send_key = init_to_resp_key, recv_key = resp_to_init_key
        let session = VpnSession {
            session_id,
            peer_ark_id: peer_identity.ark_id,
            send_key: init_to_resp_key,
            recv_key: resp_to_init_key,
            send_seq: 1,
            recv_seq: 0,
        };

        self.sessions.write().unwrap().insert(session_id, session);
        Ok(session_id)
    }

    /// Access a session clone by session ID.
    pub fn get_session(&self, session_id: u32) -> Option<VpnSession> {
        self.sessions.read().unwrap().get(&session_id).cloned()
    }

    /// Insert or update an active session.
    pub fn insert_session(&self, session: VpnSession) {
        self.sessions
            .write()
            .unwrap()
            .insert(session.session_id, session);
    }

    /// Encapsulate an ongoing IP data packet into a low-overhead MicroHeader frame (16B header).
    pub fn frame_data_packet(&self, session_id: u32, ip_packet: &[u8]) -> Result<Bytes> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(&session_id)
            .ok_or(VpnError::SessionNotFound(session_id))?;

        let seq = session.next_send_seq();
        let frame = frame_micro_packet(session_id, seq, &session.send_key, ip_packet);
        Ok(frame)
    }

    /// Deframe and validate an incoming MicroHeader data packet.
    /// Checks session MAC and enforces anti-replay sequence checking.
    pub fn deframe_data_packet(&self, packet: Bytes) -> Result<(u32, u32, Bytes)> {
        if packet.len() < 16 {
            return Err(VpnError::FramingError(
                "Packet too short for MicroHeader".into(),
            ));
        }

        let session_id = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let seq = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        let recv_key = {
            let sessions = self.sessions.read().unwrap();
            let session = sessions
                .get(&session_id)
                .ok_or(VpnError::SessionNotFound(session_id))?;
            session.recv_key
        };

        let (_header, payload) = deframe_micro_packet(&recv_key, packet)?;

        {
            let mut sessions = self.sessions.write().unwrap();
            let session = sessions
                .get_mut(&session_id)
                .ok_or(VpnError::SessionNotFound(session_id))?;
            session.accept_recv_seq(seq)?;
        }

        Ok((session_id, seq, payload))
    }

    /// Wrap a framed packet into a canonical `ArkEnvelope` classified as RetentionClass::Class0 (RAM-only).
    pub fn wrap_in_envelope(
        &self,
        kind: u32,
        recipient_id: [u8; 32],
        payload: Vec<u8>,
        timestamp: u64,
    ) -> Result<ArkEnvelope> {
        crate::framing::wrap_envelope(self.identity.ark_id, recipient_id, kind, payload, timestamp)
    }

    /// Unwrap an `ArkEnvelope` validating RetentionClass::Class0 and extracting payload.
    pub fn unwrap_envelope(
        &self,
        envelope: &ArkEnvelope,
    ) -> Result<crate::framing::UnwrappedVpnPayload> {
        crate::framing::unwrap_envelope(envelope)
    }
}
