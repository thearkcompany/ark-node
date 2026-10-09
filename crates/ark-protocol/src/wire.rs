//! Wire-framing protocol codec combining raw 64-byte FastHeader prefix and Protobuf ArkEnvelope.

use crate::envelope::ArkEnvelope;
use ark_core::constants::{FAST_HEADER_SIZE, MAX_ENVELOPE_SIZE};
use ark_core::error::{ArkError, Result};
use ark_core::fast_header::FastHeader;

pub struct WireFrame;

impl WireFrame {
    /// Serializes a complete wire datagram: 64-byte raw FastHeader followed by Protobuf-encoded ArkEnvelope
    pub fn encode(header: &FastHeader, envelope: &ArkEnvelope) -> Result<Vec<u8>> {
        header.validate()?;
        let env_bytes = envelope.encode_to_vec()?;

        let total_size = FAST_HEADER_SIZE + env_bytes.len();
        if total_size > MAX_ENVELOPE_SIZE + FAST_HEADER_SIZE {
            return Err(ArkError::EnvelopeTooLarge(
                total_size,
                MAX_ENVELOPE_SIZE + FAST_HEADER_SIZE,
            ));
        }

        let mut out = Vec::with_capacity(total_size);
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&env_bytes);
        Ok(out)
    }

    /// Deserializes incoming network bytes into zero-copy FastHeader and decoded ArkEnvelope
    pub fn decode(wire_bytes: &[u8]) -> Result<(FastHeader, ArkEnvelope)> {
        if wire_bytes.len() < FAST_HEADER_SIZE {
            return Err(ArkError::FrameTooShort(wire_bytes.len()));
        }

        let mut header_buf = [0u8; FAST_HEADER_SIZE];
        header_buf.copy_from_slice(&wire_bytes[..FAST_HEADER_SIZE]);

        let header = FastHeader::from_bytes(&header_buf)?;

        let envelope = ArkEnvelope::decode_from_slice(&wire_bytes[FAST_HEADER_SIZE..])?;

        Ok((header, envelope))
    }

    /// Zero-copy fast inspection of the raw 64-byte header directly from a datagram slice
    pub fn inspect_header(wire_bytes: &[u8]) -> Result<FastHeader> {
        if wire_bytes.len() < FAST_HEADER_SIZE {
            return Err(ArkError::FrameTooShort(wire_bytes.len()));
        }

        let mut header_buf = [0u8; FAST_HEADER_SIZE];
        header_buf.copy_from_slice(&wire_bytes[..FAST_HEADER_SIZE]);

        FastHeader::from_bytes(&header_buf)
    }
}
