//! Ephemeral wire framing for Post-Quantum Mesh Tunneling (PQMT).
//!
//! Provides:
//! - Handshake wire framing using canonical 64-byte `FastHeader` (aligned to L1 cache lines).
//! - Continuous data packet wire framing using compact 16-byte `MicroHeader`.
//! - Zero-copy packet framing and parsing with `Bytes` / `BytesMut`.
//! - KMAC256 message authentication (`session_mac`).

use ark_core::constants::FAST_HEADER_SIZE;
use ark_core::FastHeader;
use ark_crypto::kmac::Kmac256;
use bytemuck::{Pod, Zeroable};
use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Result, VpnError};

/// Envelope kind for ongoing tunneled data packets.
pub const KIND_VPN_DATA: u32 = 0x0008;

/// Envelope kind for initial tunnel handshake and key exchange.
pub const KIND_VPN_HANDSHAKE: u32 = 0x0009;

/// Size of the compact MicroHeader in bytes.
pub const MICRO_HEADER_SIZE: usize = 16;

/// Customization string domain for session MAC generation.
pub const VPN_SESSION_MAC_DOMAIN: &[u8] = b"ARK-VPN-SESSION-MAC-V1";

/// 16-byte MicroHeader for wire-speed low-overhead continuous tunneled data packets.
///
/// Layout:
/// - `session_id`: 4 bytes (u32, big-endian)
/// - `sequence_nonce`: 4 bytes (u32, big-endian)
/// - `session_mac`: 8 bytes (truncated KMAC256 authentication tag)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
pub struct MicroHeader {
    pub session_id: u32,
    pub sequence_nonce: u32,
    pub session_mac: [u8; 8],
}

// Compile-time assertion that MicroHeader is exactly 16 bytes
const _: () = assert!(std::mem::size_of::<MicroHeader>() == MICRO_HEADER_SIZE);

impl MicroHeader {
    /// Construct a new MicroHeader.
    pub fn new(session_id: u32, sequence_nonce: u32, session_mac: [u8; 8]) -> Self {
        Self {
            session_id,
            sequence_nonce,
            session_mac,
        }
    }

    /// Serialize this MicroHeader to a 16-byte array.
    pub fn to_bytes(&self) -> [u8; MICRO_HEADER_SIZE] {
        let mut bytes = [0u8; MICRO_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.sequence_nonce.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.session_mac);
        bytes
    }

    /// Parse a MicroHeader from a 16-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MICRO_HEADER_SIZE {
            return Err(VpnError::FramingError(format!(
                "MicroHeader buffer underflow: expected at least {} bytes, got {}",
                MICRO_HEADER_SIZE,
                bytes.len()
            )));
        }

        let session_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let sequence_nonce = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut session_mac = [0u8; 8];
        session_mac.copy_from_slice(&bytes[8..16]);

        Ok(Self {
            session_id,
            sequence_nonce,
            session_mac,
        })
    }

    /// Compute 8-byte session MAC using KMAC256 over session_id, sequence_nonce, and payload.
    pub fn compute_mac(
        session_key: &[u8],
        session_id: u32,
        sequence_nonce: u32,
        payload: &[u8],
    ) -> [u8; 8] {
        let mut kmac = Kmac256::new(session_key);
        kmac.update(VPN_SESSION_MAC_DOMAIN);
        kmac.update(&session_id.to_be_bytes());
        kmac.update(&sequence_nonce.to_be_bytes());
        kmac.update(payload);
        let mut out = [0u8; 8];
        kmac.finalize(&mut out);
        out
    }

    /// Verify the 8-byte session MAC in constant time.
    pub fn verify_mac(&self, session_key: &[u8], payload: &[u8]) -> Result<()> {
        let expected =
            Self::compute_mac(session_key, self.session_id, self.sequence_nonce, payload);
        if subtle_slices_equal(&self.session_mac, &expected) {
            Ok(())
        } else {
            Err(VpnError::SessionMacInvalid)
        }
    }
}

/// Constant-time slice comparison to prevent timing leaks.
#[inline]
fn subtle_slices_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

/// Encapsulate a payload into a MicroHeader framed packet buffer zero-copy.
pub fn frame_micro_packet(
    session_id: u32,
    sequence_nonce: u32,
    session_key: &[u8],
    payload: &[u8],
) -> Bytes {
    let mac = MicroHeader::compute_mac(session_key, session_id, sequence_nonce, payload);
    let header = MicroHeader::new(session_id, sequence_nonce, mac);

    let mut buf = BytesMut::with_capacity(MICRO_HEADER_SIZE + payload.len());
    buf.put_slice(&header.to_bytes());
    buf.put_slice(payload);
    buf.freeze()
}

/// Deframe a MicroHeader framed packet buffer zero-copy, validating header and session MAC.
pub fn deframe_micro_packet(session_key: &[u8], mut packet: Bytes) -> Result<(MicroHeader, Bytes)> {
    if packet.len() < MICRO_HEADER_SIZE {
        return Err(VpnError::FramingError(format!(
            "Packet smaller than MicroHeader size: {} < {}",
            packet.len(),
            MICRO_HEADER_SIZE
        )));
    }

    let header_bytes = &packet[..MICRO_HEADER_SIZE];
    let header = MicroHeader::from_bytes(header_bytes)?;
    let payload = packet.split_off(MICRO_HEADER_SIZE);

    header.verify_mac(session_key, &payload)?;

    Ok((header, payload))
}

/// Handshake FastHeader envelope frame helper.
///
/// Encapsulates handshake payload with a 64-byte FastHeader aligned to L1 cache lines.
pub fn frame_fast_packet(
    flags: u16,
    sender_key_id: [u8; 16],
    recipient_key_id: [u8; 16],
    sequence_nonce: u64,
    payload: &[u8],
) -> Bytes {
    let envelope_len = (FAST_HEADER_SIZE + payload.len()) as u32;
    let fast_header = FastHeader::new(
        flags,
        envelope_len,
        KIND_VPN_HANDSHAKE,
        sender_key_id,
        recipient_key_id,
        sequence_nonce,
    );

    let mut buf = BytesMut::with_capacity(FAST_HEADER_SIZE + payload.len());
    buf.put_slice(&fast_header.to_bytes());
    buf.put_slice(payload);
    buf.freeze()
}

/// Deframe a FastHeader framed packet zero-copy.
pub fn deframe_fast_packet(mut packet: Bytes) -> Result<(FastHeader, Bytes)> {
    if packet.len() < FAST_HEADER_SIZE {
        return Err(VpnError::FramingError(format!(
            "Packet smaller than FastHeader size: {} < {}",
            packet.len(),
            FAST_HEADER_SIZE
        )));
    }

    let mut header_bytes = [0u8; FAST_HEADER_SIZE];
    header_bytes.copy_from_slice(&packet[..FAST_HEADER_SIZE]);

    let fast_header = FastHeader::from_bytes(&header_bytes)
        .map_err(|e| VpnError::FramingError(format!("Invalid FastHeader: {:?}", e)))?;

    let payload = packet.split_off(FAST_HEADER_SIZE);
    Ok((fast_header, payload))
}

/// Wrap a tunneled payload (wire packet or handshake) into an `ArkEnvelope` with RetentionClass::Class0 (RAM-only).
pub fn wrap_envelope(
    sender_id: [u8; 32],
    recipient_id: [u8; 32],
    kind: u32,
    payload: Vec<u8>,
    timestamp: u64,
) -> Result<ark_protocol::envelope::ArkEnvelope> {
    let fast_header = [0u8; FAST_HEADER_SIZE];
    let tags = vec![ark_protocol::tags::BinaryTag::new(
        0,
        kind.to_be_bytes().to_vec(),
    )];

    ark_protocol::envelope::ArkEnvelope::new(
        fast_header,
        sender_id,
        recipient_id,
        payload,
        vec![], // No separate signature needed for ephemeral class 0 data
        ark_protocol::tags::TAG_MASK_ROUTING, // Enforce routing flag -> RetentionClass::Class0
        tags,
        timestamp,
    )
    .map_err(|e| VpnError::Crypto(e.to_string()))
}

/// Unwrapped VPN payload tuple: `(kind, sender_id, recipient_id, payload)`
pub type UnwrappedVpnPayload = (u32, [u8; 32], [u8; 32], Vec<u8>);

/// Unwrap and validate an `ArkEnvelope` containing tunneled wire traffic.
/// Verifies retention class 0 classification, expected kind (KIND_VPN_DATA or KIND_VPN_HANDSHAKE),
/// and extracts `(kind, sender_id, recipient_id, payload)`.
pub fn unwrap_envelope(
    envelope: &ark_protocol::envelope::ArkEnvelope,
) -> Result<UnwrappedVpnPayload> {
    let mut sender_id = [0u8; 32];
    if envelope.sender_id.len() == 32 {
        sender_id.copy_from_slice(&envelope.sender_id);
    } else {
        return Err(VpnError::FramingError(
            "Invalid envelope sender_id length".into(),
        ));
    }

    let mut recipient_id = [0u8; 32];
    if envelope.recipient_id.len() == 32 {
        recipient_id.copy_from_slice(&envelope.recipient_id);
    } else {
        return Err(VpnError::FramingError(
            "Invalid envelope recipient_id length".into(),
        ));
    }

    // Extract kind from tag 0
    let kind = envelope
        .tags
        .iter()
        .find(|t| t.tag_type == 0 && t.tag_value.len() == 4)
        .map(|t| {
            u32::from_be_bytes([
                t.tag_value[0],
                t.tag_value[1],
                t.tag_value[2],
                t.tag_value[3],
            ])
        })
        .unwrap_or(0);

    if kind != KIND_VPN_DATA && kind != KIND_VPN_HANDSHAKE {
        return Err(VpnError::FramingError(format!(
            "Unsupported VPN envelope kind: 0x{:04x}",
            kind
        )));
    }

    // Verify Class 0 classification invariant (TAG_MASK_ROUTING or VPN kinds)
    let is_class_0 = (envelope.core_tag_mask & ark_protocol::tags::TAG_MASK_ROUTING) != 0
        || kind == KIND_VPN_DATA
        || kind == KIND_VPN_HANDSHAKE;

    if !is_class_0 {
        return Err(VpnError::FramingError(
            "Envelope violates Class 0 Ephemeral retention invariant".into(),
        ));
    }

    Ok((kind, sender_id, recipient_id, envelope.payload.clone()))
}
