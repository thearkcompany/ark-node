pub mod envelope;
pub mod tags;
pub mod hashing;
pub mod wire;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/ark.protocol.v1.rs"));
}

pub use envelope::*;
pub use tags::*;
pub use hashing::*;
pub use wire::*;
pub use proto::{ArkNodeStatus, MstEntryWire, MstNodeWire, MstSyncRequest, MstSyncResponse};

impl From<envelope::ArkEnvelope> for proto::ArkEnvelope {
    fn from(env: envelope::ArkEnvelope) -> Self {
        proto::ArkEnvelope {
            magic: env.magic,
            fast_header: env.fast_header,
            sender_id: env.sender_id,
            recipient_id: env.recipient_id,
            payload: env.payload,
            signature: env.signature,
            core_tag_mask: env.core_tag_mask,
            tags: env.tags.into_iter().map(Into::into).collect(),
            timestamp: env.timestamp,
        }
    }
}

impl From<&envelope::ArkEnvelope> for proto::ArkEnvelope {
    fn from(env: &envelope::ArkEnvelope) -> Self {
        proto::ArkEnvelope {
            magic: env.magic.clone(),
            fast_header: env.fast_header.clone(),
            sender_id: env.sender_id.clone(),
            recipient_id: env.recipient_id.clone(),
            payload: env.payload.clone(),
            signature: env.signature.clone(),
            core_tag_mask: env.core_tag_mask,
            tags: env.tags.iter().map(Into::into).collect(),
            timestamp: env.timestamp,
        }
    }
}

impl From<proto::ArkEnvelope> for envelope::ArkEnvelope {
    fn from(proto: proto::ArkEnvelope) -> Self {
        envelope::ArkEnvelope {
            magic: proto.magic,
            fast_header: proto.fast_header,
            sender_id: proto.sender_id,
            recipient_id: proto.recipient_id,
            payload: proto.payload,
            signature: proto.signature,
            core_tag_mask: proto.core_tag_mask,
            tags: proto.tags.into_iter().map(Into::into).collect(),
            timestamp: proto.timestamp,
        }
    }
}

impl From<tags::BinaryTag> for proto::BinaryTag {
    fn from(tag: tags::BinaryTag) -> Self {
        proto::BinaryTag {
            tag_type: tag.tag_type,
            tag_value: tag.tag_value,
        }
    }
}

impl From<&tags::BinaryTag> for proto::BinaryTag {
    fn from(tag: &tags::BinaryTag) -> Self {
        proto::BinaryTag {
            tag_type: tag.tag_type,
            tag_value: tag.tag_value.clone(),
        }
    }
}

impl From<proto::BinaryTag> for tags::BinaryTag {
    fn from(proto: proto::BinaryTag) -> Self {
        tags::BinaryTag {
            tag_type: proto.tag_type,
            tag_value: proto.tag_value,
        }
    }
}


