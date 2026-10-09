//! BinaryTag TLV and bitmask core_tag_mask management.

use prost::Message;

/// Bitmask flags for core_tag_mask (64-bit mask)
pub const TAG_MASK_ENCRYPTED: u64 = 1 << 0;
pub const TAG_MASK_SIGNED: u64 = 1 << 1;
pub const TAG_MASK_COMPRESSED: u64 = 1 << 2;
pub const TAG_MASK_URGENT: u64 = 1 << 3;
pub const TAG_MASK_REPLY: u64 = 1 << 4;
pub const TAG_MASK_ROUTING: u64 = 1 << 5;

#[derive(Clone, PartialEq, Message)]
pub struct BinaryTag {
    #[prost(uint32, tag = "1")]
    pub tag_type: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub tag_value: Vec<u8>,
}

impl BinaryTag {
    pub fn new(tag_type: u32, tag_value: Vec<u8>) -> Self {
        Self {
            tag_type,
            tag_value,
        }
    }
}

pub struct TagMask;

impl TagMask {
    pub fn has_flag(mask: u64, flag: u64) -> bool {
        (mask & flag) == flag
    }

    pub fn set_flag(mask: &mut u64, flag: u64) {
        *mask |= flag;
    }

    pub fn clear_flag(mask: &mut u64, flag: u64) {
        *mask &= !flag;
    }
}
