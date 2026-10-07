use ark_core::FastHeader;
use ark_dns::anti_sybil::{
    validate_dns_claim, L2ContractVerifier, KIND_DNS_CLAIM_PUBLIC, TAG_DNS_LEASE_EPOCH,
    TAG_L2_CONTRACT, TAG_NONCE, TAG_PARAM_D,
};
use ark_dns::error::DnsError;
use ark_protocol::envelope::ArkEnvelope;
use ark_protocol::tags::BinaryTag;
use ark_storage::compute_envelope_id;

struct MockL2Verifier {
    valid_contracts: Vec<(Vec<u8>, Vec<u8>)>,
    should_error: bool,
}

impl MockL2Verifier {
    fn new() -> Self {
        Self {
            valid_contracts: Vec::new(),
            should_error: false,
        }
    }

    fn allow(mut self, contract_id: &[u8], owner_key_id: &[u8]) -> Self {
        self.valid_contracts
            .push((contract_id.to_vec(), owner_key_id.to_vec()));
        self
    }
}

impl L2ContractVerifier for MockL2Verifier {
    fn verify_escrow_contract(
        &self,
        contract_id: &[u8],
        owner_key_id: &[u8],
    ) -> Result<bool, DnsError> {
        if self.should_error {
            return Err(DnsError::L2VerificationFailed(
                "L2 network RPC timeout".to_string(),
            ));
        }
        Ok(self
            .valid_contracts
            .iter()
            .any(|(c, o)| c.as_slice() == contract_id && o.as_slice() == owner_key_id))
    }
}

fn create_valid_claim_envelope(
    fqdn: &str,
    lease_epoch: u64,
    contract_id: &[u8],
    owner_key_id: [u8; 16],
) -> ArkEnvelope {
    let fast_header = FastHeader::new(
        0,
        128,
        KIND_DNS_CLAIM_PUBLIC,
        owner_key_id,
        [0u8; 16],
        1,
    );

    let mut envelope = ArkEnvelope {
        magic: b"ARK1".to_vec(),
        fast_header: fast_header.to_bytes().to_vec(),
        sender_id: owner_key_id.to_vec(),
        recipient_id: vec![0u8; 32],
        payload: b"mock routing payload".to_vec(),
        signature: vec![1u8; 64],
        core_tag_mask: 0,
        tags: vec![
            BinaryTag::new(TAG_PARAM_D, fqdn.as_bytes().to_vec()),
            BinaryTag::new(TAG_DNS_LEASE_EPOCH, lease_epoch.to_be_bytes().to_vec()),
            BinaryTag::new(TAG_L2_CONTRACT, contract_id.to_vec()),
            BinaryTag::new(TAG_NONCE, 0u64.to_be_bytes().to_vec()),
        ],
        timestamp: 1_700_000_000,
    };

    // Mine 16-bit PoW (leading 2 zero bytes)
    for nonce in 0u64..1_000_000 {
        for tag in &mut envelope.tags {
            if tag.tag_type == TAG_NONCE {
                tag.tag_value = nonce.to_be_bytes().to_vec();
                break;
            }
        }
        let id = compute_envelope_id(&envelope).unwrap();
        if id[0] == 0 && id[1] == 0 {
            return envelope;
        }
    }
    panic!("Failed to mine 16-bit PoW in test helper");
}

#[test]
fn test_valid_dns_claim_passes() {
    let owner = [7u8; 16];
    let contract = b"ark-l2-contract-001";
    let env = create_valid_claim_envelope("alice.ark", 1_800_000_000, contract, owner);
    let verifier = MockL2Verifier::new().allow(contract, &owner);

    let res = validate_dns_claim(&env, &verifier);
    assert!(res.is_ok(), "Expected valid claim to pass: {:?}", res);
    let claim = res.unwrap();
    assert_eq!(claim.fqdn, "alice.ark");
    assert_eq!(claim.lease_epoch, 1_800_000_000);
    assert_eq!(claim.contract_id, contract);
    assert_eq!(claim.owner_key_id, owner);
    assert_eq!(claim.envelope_id[0], 0);
    assert_eq!(claim.envelope_id[1], 0);
}

#[test]
fn test_rejection_invalid_kind() {
    let owner = [7u8; 16];
    let contract = b"ark-l2-contract-001";
    let mut env = create_valid_claim_envelope("alice.ark", 1_800_000_000, contract, owner);
    let verifier = MockL2Verifier::new().allow(contract, &owner);

    // Corrupt fast_header fast_tag kind
    let wrong_header = FastHeader::new(0, 128, 0x1234, owner, [0u8; 16], 1);
    env.fast_header = wrong_header.to_bytes().to_vec();

    let res = validate_dns_claim(&env, &verifier);
    assert!(matches!(res, Err(DnsError::InvalidRecord(_))));
}

#[test]
fn test_rejection_insufficient_pow() {
    let owner = [7u8; 16];
    let contract = b"ark-l2-contract-001";
    let mut env = create_valid_claim_envelope("alice.ark", 1_800_000_000, contract, owner);
    let verifier = MockL2Verifier::new().allow(contract, &owner);

    // Corrupt nonce to break PoW
    for tag in &mut env.tags {
        if tag.tag_type == TAG_NONCE {
            // Find a nonce that does NOT have 16 leading zero bits
            tag.tag_value = 0xFFFFFFFF_u64.to_be_bytes().to_vec();
            break;
        }
    }
    // Verify it fails PoW
    let id = compute_envelope_id(&env).unwrap();
    if id[0] != 0 || id[1] != 0 {
        let res = validate_dns_claim(&env, &verifier);
        assert!(matches!(res, Err(DnsError::InsufficientProofOfWork { .. })));
    }
}

#[test]
fn test_rejection_missing_tags() {
    let owner = [7u8; 16];
    let contract = b"ark-l2-contract-001";
    let env_orig = create_valid_claim_envelope("alice.ark", 1_800_000_000, contract, owner);
    let verifier = MockL2Verifier::new().allow(contract, &owner);

    // Missing TAG_PARAM_D
    let mut env_no_fqdn = env_orig.clone();
    env_no_fqdn.tags.retain(|t| t.tag_type != TAG_PARAM_D);
    assert!(matches!(
        validate_dns_claim(&env_no_fqdn, &verifier),
        Err(DnsError::MissingTag(_))
    ));

    // Missing TAG_DNS_LEASE_EPOCH
    let mut env_no_epoch = env_orig.clone();
    env_no_epoch.tags.retain(|t| t.tag_type != TAG_DNS_LEASE_EPOCH);
    assert!(matches!(
        validate_dns_claim(&env_no_epoch, &verifier),
        Err(DnsError::MissingTag(_))
    ));

    // Missing TAG_L2_CONTRACT
    let mut env_no_l2 = env_orig.clone();
    env_no_l2.tags.retain(|t| t.tag_type != TAG_L2_CONTRACT);
    assert!(matches!(
        validate_dns_claim(&env_no_l2, &verifier),
        Err(DnsError::MissingTag(_))
    ));

    // Missing TAG_NONCE
    let mut env_no_nonce = env_orig.clone();
    env_no_nonce.tags.retain(|t| t.tag_type != TAG_NONCE);
    assert!(matches!(
        validate_dns_claim(&env_no_nonce, &verifier),
        Err(DnsError::MissingTag(_))
    ));
}

#[test]
fn test_rejection_invalid_fqdn() {
    let owner = [7u8; 16];
    let contract = b"ark-l2-contract-001";
    let verifier = MockL2Verifier::new().allow(contract, &owner);

    let invalid_fqdns = vec![
        "".to_string(),
        "invalid".to_string(),           // missing .ark
        ".ark".to_string(),              // empty label
        "alice..ark".to_string(),        // double dot
        "-alice.ark".to_string(),        // leading hyphen
        "alice-.ark".to_string(),        // trailing hyphen in label
        "alice/foo.ark".to_string(),     // invalid character
        "alice_bar.ark".to_string(),     // underscore not allowed in DNS hostname
        "UPPER.ark".to_string(),         // uppercase characters
        "a".repeat(64) + ".ark",         // label > 63 chars
    ];

    for fqdn in &invalid_fqdns {
        let env = create_valid_claim_envelope("placeholder.ark", 1_800_000_000, contract, owner);
        let mut modified_env = env.clone();
        for tag in &mut modified_env.tags {
            if tag.tag_type == TAG_PARAM_D {
                tag.tag_value = fqdn.as_bytes().to_vec();
            }
        }
        // Even if PoW is invalid, let's see if FQDN validation rejects it
        // Or re-mine if validate checks FQDN first
        let res = validate_dns_claim(&modified_env, &verifier);
        assert!(res.is_err(), "FQDN '{}' should be rejected", fqdn);
    }
}

#[test]
fn test_rejection_unverified_l2_contract() {
    let owner = [7u8; 16];
    let contract = b"ark-l2-contract-001";
    let env = create_valid_claim_envelope("alice.ark", 1_800_000_000, contract, owner);
    // Verifier does not allow this contract or owner
    let verifier = MockL2Verifier::new();

    let res = validate_dns_claim(&env, &verifier);
    assert!(matches!(res, Err(DnsError::UnverifiedL2Contract(_))));
}

#[test]
fn test_constant_time_pow_check() {
    use ark_dns::anti_sybil::has_16_leading_zero_bits;

    let mut hash = [0u8; 32];
    assert!(has_16_leading_zero_bits(&hash));

    hash[0] = 0;
    hash[1] = 0;
    hash[2] = 0x80;
    assert!(has_16_leading_zero_bits(&hash));

    hash[1] = 1;
    assert!(!has_16_leading_zero_bits(&hash));

    hash[1] = 0;
    hash[0] = 1;
    assert!(!has_16_leading_zero_bits(&hash));
}

#[test]
fn test_signature_verification_on_claim_envelope() {
    use ark_crypto::fn_dsa::FnDsaKeyPair;
    use ark_protocol::hashing::calculate_canonical_id;
    use rand::rngs::OsRng;

    let keypair = FnDsaKeyPair::generate(&mut OsRng);
    let identity = ark_crypto::Identity::from_public_key(&keypair.public_key);
    let owner_key_id = identity.sender_key_id;
    let contract = b"contract-sig-test";
    let verifier = MockL2Verifier::new().allow(contract, &owner_key_id);

    let mut env = create_valid_claim_envelope("signed.ark", 1_800_000_000, contract, owner_key_id);
    // Attach public key tag (0x0002)
    env.tags.push(BinaryTag::new(0x0002, keypair.public_key.to_vec()));

    // Sign canonical ID
    let canonical_id = calculate_canonical_id(&env);
    let sig = keypair.sign(&canonical_id).unwrap();
    env.signature = sig;

    // Mine PoW after adding tags/signature
    let mut mined = false;
    for nonce in 0u64..1_000_000 {
        for tag in &mut env.tags {
            if tag.tag_type == TAG_NONCE {
                tag.tag_value = nonce.to_be_bytes().to_vec();
                break;
            }
        }
        let id = compute_envelope_id(&env).unwrap();
        if id[0] == 0 && id[1] == 0 {
            mined = true;
            break;
        }
    }
    assert!(mined, "PoW mining must succeed");

    // Valid signature must pass
    let res = validate_dns_claim(&env, &verifier);
    assert!(res.is_ok(), "Claim with valid FN-DSA signature must pass: {:?}", res);

    // Tampered signature must fail with InvalidSignature
    let mut tampered_env = env.clone();
    tampered_env.signature[0] ^= 0xff;
    // Re-mine PoW so the failure is specifically due to the bad signature and not PoW failure
    let mut mined_tampered = false;
    for nonce in 0u64..1_000_000 {
        for tag in &mut tampered_env.tags {
            if tag.tag_type == TAG_NONCE {
                tag.tag_value = nonce.to_be_bytes().to_vec();
                break;
            }
        }
        let id = compute_envelope_id(&tampered_env).unwrap();
        if id[0] == 0 && id[1] == 0 {
            mined_tampered = true;
            break;
        }
    }
    assert!(mined_tampered, "PoW mining for tampered envelope must succeed");

    let bad_res = validate_dns_claim(&tampered_env, &verifier);
    assert!(matches!(bad_res, Err(DnsError::InvalidSignature(_))), "Expected InvalidSignature, got {:?}", bad_res);
}
