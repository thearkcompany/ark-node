//! ArkEnvelope v1 canonical transport container with rigid <= 64 KB ceiling.

use ark_core::constants::{MAGIC_BYTES, MAX_ENVELOPE_SIZE, MAX_PAYLOAD_SIZE};
use ark_core::error::{ArkError, Result};
use crate::tags::BinaryTag;
use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct ArkEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    pub magic: Vec<u8>,

    #[prost(bytes = "vec", tag = "2")]
    pub fast_header: Vec<u8>,

    #[prost(bytes = "vec", tag = "3")]
    pub sender_id: Vec<u8>,

    #[prost(bytes = "vec", tag = "4")]
    pub recipient_id: Vec<u8>,

    #[prost(bytes = "vec", tag = "5")]
    pub payload: Vec<u8>,

    #[prost(bytes = "vec", tag = "6")]
    pub signature: Vec<u8>,

    #[prost(uint64, tag = "7")]
    pub core_tag_mask: u64,

    #[prost(message, repeated, tag = "8")]
    pub tags: Vec<BinaryTag>,

    #[prost(uint64, tag = "9")]
    pub timestamp: u64,
}

impl ArkEnvelope {
    pub fn new(
        fast_header: [u8; 64],
        sender_id: [u8; 32],
        recipient_id: [u8; 32],
        payload: Vec<u8>,
        signature: Vec<u8>,
        core_tag_mask: u64,
        tags: Vec<BinaryTag>,
        timestamp: u64,
    ) -> Result<Self> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ArkError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_SIZE));
        }

        let envelope = Self {
            magic: MAGIC_BYTES.to_vec(),
            fast_header: fast_header.to_vec(),
            sender_id: sender_id.to_vec(),
            recipient_id: recipient_id.to_vec(),
            payload,
            signature,
            core_tag_mask,
            tags,
            timestamp,
        };

        let encoded_len = envelope.encoded_len();
        if encoded_len > MAX_ENVELOPE_SIZE {
            return Err(ArkError::EnvelopeTooLarge(encoded_len, MAX_ENVELOPE_SIZE));
        }

        Ok(envelope)
    }

    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf)
            .map_err(|e| ArkError::SerializationError(e.to_string()))?;

        if buf.len() > MAX_ENVELOPE_SIZE {
            return Err(ArkError::EnvelopeTooLarge(buf.len(), MAX_ENVELOPE_SIZE));
        }

        Ok(buf)
    }

    pub fn decode_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_SIZE {
            return Err(ArkError::EnvelopeTooLarge(bytes.len(), MAX_ENVELOPE_SIZE));
        }

        let env = Self::decode(bytes)
            .map_err(|e| ArkError::SerializationError(e.to_string()))?;

        if env.magic != MAGIC_BYTES {
            return Err(ArkError::InvalidMagic(0));
        }

        Ok(env)
    }
}
