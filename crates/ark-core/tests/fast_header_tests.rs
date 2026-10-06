use ark_core::constants::{FAST_HEADER_SIZE, MAGIC_VALUE};
use ark_core::error::ArkError;
use ark_core::fast_header::FastHeader;

#[test]
fn test_fast_header_size_and_alignment() {
    assert_eq!(std::mem::size_of::<FastHeader>(), 64);
    assert_eq!(std::mem::align_of::<FastHeader>(), 64);
}

#[test]
fn test_fast_header_serialization_roundtrip() {
    let sender = [1u8; 16];
    let recipient = [2u8; 16];
    let header = FastHeader::new(0x0001, 1024, 0xAABBCCDD, sender, recipient, 42);

    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), FAST_HEADER_SIZE);

    let decoded = FastHeader::from_bytes(&bytes).expect("Failed to decode valid FastHeader");
    assert_eq!(decoded, header);
    assert_eq!(decoded.magic, MAGIC_VALUE);
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.envelope_len, 1024);
    assert_eq!(decoded.sequence_nonce, 42);
}

#[test]
fn test_fast_header_rejects_invalid_magic() {
    let mut header = FastHeader::new(0, 100, 0, [0u8; 16], [0u8; 16], 1);
    header.magic = 0xDEADBEEF;

    let bytes = header.to_bytes();
    let res = FastHeader::from_bytes(&bytes);
    match res {
        Err(ArkError::InvalidMagic(magic)) => assert_eq!(magic, 0xDEADBEEF),
        _ => panic!("Expected InvalidMagic error"),
    }
}
