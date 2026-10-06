//! Retention classes and classification for GCP-06.

use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::TAG_MASK_ROUTING;

pub const TAG_EXPIRATION: u32 = 0x0001_0001;
pub const TAG_PARAM_D: u32    = 0x0001_0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetentionClass {
    /// Class 0: Ephemeral / RAM-only events (kind in 20000..30000 or flag)
    Class0Ephemeral,
    /// Class 1: Permanent immutable records (kind in 1000..10000)
    Class1AppendOnly,
    /// Class 2: Simple replaceable records (kind in 10000..20000 or kind 0)
    Class2Replaceable,
    /// Class 3: Parameterized replaceable records (kind in 30000..40000 or carries TAG_PARAM_D)
    Class3ParamReplaceable,
    /// Class 4: Bounded TTL cache entries (carries TAG_EXPIRATION)
    Class4BoundedTtl,
    /// Class 5: Strict WORM audit receipts and equivocation proofs (kind >= 40000)
    Class5StrictWorm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionOutcome {
    Stored,
    Replaced,
    SupersededLww,
    EphemeralPassed,
    IdempotentDuplicate,
}

/// Deterministically classifies an ArkEnvelope into a RetentionClass according to GCP-06.
/// Priority rules:
/// 1. Ephemeral: if routing flag is set or kind in 20000..30000.
/// 2. TAG_EXPIRATION present -> Class 4 Bounded TTL.
/// 3. TAG_PARAM_D present or kind in 30000..40000 -> Class 3 Parameterized Replaceable.
/// 4. Strict WORM: kind >= 40000 -> Class 5 Strict WORM.
/// 5. Replaceable: kind == 0 or kind in 10000..20000 -> Class 2 Replaceable.
/// 6. Default: Class 1 Append-Only.
pub fn classify_retention(envelope: &ArkEnvelope) -> RetentionClass {
    let kind = get_envelope_kind(envelope);

    // 1. Ephemeral routing or kind 20000..30000
    if (envelope.core_tag_mask & TAG_MASK_ROUTING) != 0 || (20000..30000).contains(&kind) {
        return RetentionClass::Class0Ephemeral;
    }

    // 2. Class 4: TAG_EXPIRATION
    if envelope.tags.iter().any(|t| t.tag_type == TAG_EXPIRATION) {
        return RetentionClass::Class4BoundedTtl;
    }

    // 3. Class 3: TAG_PARAM_D or kind 30000..40000
    if envelope.tags.iter().any(|t| t.tag_type == TAG_PARAM_D) || (30000..40000).contains(&kind) {
        return RetentionClass::Class3ParamReplaceable;
    }

    // 4. Class 5: kind >= 40000
    if kind >= 40000 {
        return RetentionClass::Class5StrictWorm;
    }

    // 5. Class 2: kind 0 or 10000..20000
    if kind == 0 || (10000..20000).contains(&kind) {
        return RetentionClass::Class2Replaceable;
    }

    // 6. Default to Class 1 Append-Only
    RetentionClass::Class1AppendOnly
}

/// Extract numeric `kind` from fast_header or tag if present.
pub fn get_envelope_kind(envelope: &ArkEnvelope) -> u32 {
    // 1. Explicit kind tag (tag_type == 0)
    for tag in &envelope.tags {
        if tag.tag_type == 0 {
            if tag.tag_value.len() == 4 {
                return u32::from_be_bytes([
                    tag.tag_value[0],
                    tag.tag_value[1],
                    tag.tag_value[2],
                    tag.tag_value[3],
                ]);
            } else if tag.tag_value.is_empty() {
                return 0;
            }
        }
    }

    // 2. FastHeader fast_tag if set
    if envelope.fast_header.len() >= 64 {
        let fast_tag = u32::from_ne_bytes([
            envelope.fast_header[12],
            envelope.fast_header[13],
            envelope.fast_header[14],
            envelope.fast_header[15],
        ]);
        if fast_tag != 0 {
            return fast_tag;
        }
    }

    1 // default kind = 1 (regular immutable event)
}

/// Extract TAG_PARAM_D value if present.
pub fn get_envelope_param_d(envelope: &ArkEnvelope) -> Option<Vec<u8>> {
    for tag in &envelope.tags {
        if tag.tag_type == TAG_PARAM_D {
            return Some(tag.tag_value.clone());
        }
    }
    None
}

