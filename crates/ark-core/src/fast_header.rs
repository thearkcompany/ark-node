//! 64-byte Fast-Header aligned to modern CPU L1 Cache Line (64 Bytes)
//! Facilitates zero-copy inline routing and immediate filtering before full envelope decoding.

use crate::constants::{FAST_HEADER_SIZE, MAGIC_VALUE};
use crate::error::{ArkError, Result};
use bytemuck::{Pod, Zeroable};

#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
pub struct FastHeader {
    /// Protocol Magic Value (0x41524B31)
    pub magic: u32,
    /// Protocol Version (v1)
    pub version: u16,
    /// Packet flags & dispatch hint
    pub flags: u16,
    /// Total envelope byte length
    pub envelope_len: u32,
    /// Fast checksum / ephemeral tag (e.g. CRC32-C or truncated KMAC)
    pub fast_tag: u32,
    /// Truncated Sender Key ID (first 16 bytes of SHA3-256(pubkey))
    pub sender_key_id: [u8; 16],
    /// Truncated Recipient or Ephemeral ID (16 bytes)
    pub recipient_key_id: [u8; 16],
    /// Session Epoch / Sequence Nonce (8 bytes)
    pub sequence_nonce: u64,
    /// Reserved for future extensions / L1 pad to precisely 64 bytes
    pub _reserved: [u8; 8],
}

// Compile-time assertion that FastHeader is exactly 64 bytes
const _: () = assert!(std::mem::size_of::<FastHeader>() == FAST_HEADER_SIZE);
const _: () = assert!(std::mem::align_of::<FastHeader>() == 64);

impl FastHeader {
    pub fn new(
        flags: u16,
        envelope_len: u32,
        fast_tag: u32,
        sender_key_id: [u8; 16],
        recipient_key_id: [u8; 16],
        sequence_nonce: u64,
    ) -> Self {
        Self {
            magic: MAGIC_VALUE,
            version: 1,
            flags,
            envelope_len,
            fast_tag,
            sender_key_id,
            recipient_key_id,
            sequence_nonce,
            _reserved: [0u8; 8],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC_VALUE {
            return Err(ArkError::InvalidMagic(self.magic));
        }
        if self.version != 1 {
            return Err(ArkError::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        bytemuck::cast(*self)
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let header: Self = bytemuck::cast(*bytes);
        header.validate()?;
        Ok(header)
    }
}
