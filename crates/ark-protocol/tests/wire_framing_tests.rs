use ark_core::constants::{FAST_HEADER_SIZE, MAGIC_VALUE, MAX_ENVELOPE_SIZE};
use ark_core::error::ArkError;
use ark_core::fast_header::FastHeader;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::hashing::calculate_canonical_id;
use ark_protocol::tags::{BinaryTag, TagMask, TAG_MASK_ENCRYPTED, TAG_MASK_SIGNED};
use ark_protocol::wire::WireFrame;
use prost::Message;

#[test]
fn test_wire_framing_roundtrip_and_zero_copy_inspection() {
    let sender_id = [0xAA; 16];
    let recipient_id = [0xBB; 16];
    let mut header = FastHeader::new(0x01, 256, 0x12345678, sender_id, recipient_id, 9999);

    let mut full_sender = [0u8; 32];
    full_sender[..16].copy_from_slice(&sender_id);
    let mut full_recipient = [0u8; 32];
    full_recipient[..16].copy_from_slice(&recipient_id);

    let payload = b"Hello Sovereign ARK PQC Network".to_vec();
    let signature = vec![0x39; 690];
    let mut mask = 0u64;
    TagMask::set_flag(&mut mask, TAG_MASK_ENCRYPTED);
    TagMask::set_flag(&mut mask, TAG_MASK_SIGNED);

    let tags = vec![BinaryTag::new(1, vec![0x01, 0x02])];
    let timestamp = 1700000000u64;

    let envelope = ArkEnvelope::new(
        header.to_bytes(),
        full_sender,
        full_recipient,
        payload.clone(),
        signature.clone(),
        mask,
        tags,
        timestamp,
    )
    .expect("Failed to create valid envelope");

    header.envelope_len = envelope.encoded_len() as u32;

    // Encode to wire format
    let wire_bytes = WireFrame::encode(&header, &envelope).expect("Failed to encode wire frame");
    assert!(wire_bytes.len() > FAST_HEADER_SIZE);

    // Test zero-copy header inspection
    let inspected_header = WireFrame::inspect_header(&wire_bytes).expect("Failed to inspect header");
    assert_eq!(inspected_header.magic, MAGIC_VALUE);
    assert_eq!(inspected_header.sender_key_id, sender_id);
    assert_eq!(inspected_header.recipient_key_id, recipient_id);
    assert_eq!(inspected_header.sequence_nonce, 9999);

    // Test full frame decode
    let (decoded_header, decoded_envelope) =
        WireFrame::decode(&wire_bytes).expect("Failed to decode wire frame");
    assert_eq!(decoded_header, header);
    assert_eq!(decoded_envelope.payload, payload);
    assert_eq!(decoded_envelope.signature, signature);
    assert_eq!(decoded_envelope.core_tag_mask, mask);
    assert_eq!(decoded_envelope.timestamp, timestamp);

    // Test canonical ID calculation (Encrypt-then-Sign)
    let canonical_id = calculate_canonical_id(&decoded_envelope);
    assert_eq!(canonical_id.len(), 32);
    assert_ne!(canonical_id, [0u8; 32]);
}

#[test]
fn test_wire_framing_rejects_invalid_magic() {
    let header = FastHeader::new(0, 50, 0, [0u8; 16], [0u8; 16], 1);
    let envelope = ArkEnvelope::new(
        header.to_bytes(),
        [0u8; 32],
        [0u8; 32],
        vec![1, 2, 3],
        vec![4, 5, 6],
        0,
        vec![],
        100,
    )
    .unwrap();

    let mut wire_bytes = WireFrame::encode(&header, &envelope).unwrap();
    // Corrupt magic bytes in the first 4 bytes of FastHeader
    wire_bytes[0] = 0xFF;

    let res = WireFrame::decode(&wire_bytes);
    match res {
        Err(ArkError::InvalidMagic(_)) => (),
        other => panic!("Expected InvalidMagic error, got {:?}", other),
    }
}

#[test]
fn test_wire_framing_rejects_truncated_frames() {
    let truncated_bytes = vec![0u8; 32]; // Less than 64 bytes
    let res = WireFrame::decode(&truncated_bytes);
    match res {
        Err(ArkError::FrameTooShort(32)) => (),
        other => panic!("Expected FrameTooShort, got {:?}", other),
    }
}

#[test]
fn test_envelope_strict_size_ceiling() {
    // Attempt creating envelope with payload exceeding maximum budget
    let huge_payload = vec![0u8; MAX_ENVELOPE_SIZE + 10];
    let res = ArkEnvelope::new(
        [0u8; 64],
        [0u8; 32],
        [0u8; 32],
        huge_payload,
        vec![],
        0,
        vec![],
        0,
    );
    match res {
        Err(ArkError::PayloadTooLarge(_, _)) => (),
        other => panic!("Expected PayloadTooLarge error, got {:?}", other),
    }
}
