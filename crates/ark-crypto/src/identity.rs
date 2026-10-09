//! Cryptographic identity management and ArkID derivation.
//! ArkID = SHA3-256(PublicKey)
//! SenderKeyID = First 16 bytes of ArkID

use ark_core::traits::ArkIdentity;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub ark_id: [u8; 32],
    pub sender_key_id: [u8; 16],
    pub public_key: Vec<u8>,
}

impl Identity {
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();

        let mut ark_id = [0u8; 32];
        ark_id.copy_from_slice(&hash);

        let mut sender_key_id = [0u8; 16];
        sender_key_id.copy_from_slice(&hash[0..16]);

        Self {
            ark_id,
            sender_key_id,
            public_key: pubkey.to_vec(),
        }
    }

    pub fn ark_id_hex(&self) -> String {
        hex_fmt(&self.ark_id)
    }
}

impl ArkIdentity for Identity {
    fn ark_id(&self) -> &[u8; 32] {
        &self.ark_id
    }

    fn sender_key_id(&self) -> [u8; 16] {
        self.sender_key_id
    }
}

pub fn hex_fmt(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

use crate::fn_dsa::{FnDsaKeyPair, FN_DSA_512_PUBKEY_SIZE, FN_DSA_512_SECKEY_SIZE};
use crate::ml_kem::{MlKemKeyPair, ML_KEM_768_PUBKEY_SIZE, ML_KEM_768_SECKEY_SIZE};
use crate::secure_mem::LockedBuffer;
use ark_core::error::{ArkError, Result};
use rand_core::CryptoRngCore;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

pub const PERSISTENT_IDENTITY_MAGIC: [u8; 4] = *b"ARKK"; // ARKK = ARK Key

/// Full node identity containing both FN-DSA-512 and ML-KEM-768 key pairs,
/// with private keys locked in memory using `LockedBuffer`.
pub struct PersistentIdentity {
    pub ark_id: [u8; 32],
    pub sender_key_id: [u8; 16],
    pub fn_dsa_keypair: FnDsaKeyPair,
    pub fn_dsa_secret_key: LockedBuffer<[u8; FN_DSA_512_SECKEY_SIZE]>,
    pub ml_kem_keypair: MlKemKeyPair,
    pub ml_kem_secret_key: LockedBuffer<[u8; ML_KEM_768_SECKEY_SIZE]>,
}

impl PersistentIdentity {
    /// Generate a new post-quantum identity (FN-DSA-512 + ML-KEM-768)
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let fn_dsa_keypair = FnDsaKeyPair::generate(rng);
        let ml_kem_keypair = MlKemKeyPair::generate(rng);

        let id = Identity::from_public_key(&fn_dsa_keypair.public_key);
        let fn_dsa_secret_key = LockedBuffer::new(fn_dsa_keypair.secret_key);
        let ml_kem_secret_key = LockedBuffer::new(ml_kem_keypair.secret_key);

        Self {
            ark_id: id.ark_id,
            sender_key_id: id.sender_key_id,
            fn_dsa_keypair,
            fn_dsa_secret_key,
            ml_kem_keypair,
            ml_kem_secret_key,
        }
    }

    pub fn ark_id_hex(&self) -> String {
        hex_fmt(&self.ark_id)
    }

    /// Serialize identity bytes:
    /// [4B Magic: ARKK][1B Version: 1][897B FN-DSA PK][1281B FN-DSA SK][1184B ML-KEM PK][2400B ML-KEM SK]
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_size = 4
            + 1
            + FN_DSA_512_PUBKEY_SIZE
            + FN_DSA_512_SECKEY_SIZE
            + ML_KEM_768_PUBKEY_SIZE
            + ML_KEM_768_SECKEY_SIZE;
        let mut buf = Vec::with_capacity(total_size);
        buf.extend_from_slice(&PERSISTENT_IDENTITY_MAGIC);
        buf.push(1); // format version
        buf.extend_from_slice(&self.fn_dsa_keypair.public_key);
        buf.extend_from_slice(&*self.fn_dsa_secret_key);
        buf.extend_from_slice(&self.ml_kem_keypair.public_key);
        buf.extend_from_slice(&*self.ml_kem_secret_key);
        buf
    }

    /// Deserialize identity from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let expected_size = 4
            + 1
            + FN_DSA_512_PUBKEY_SIZE
            + FN_DSA_512_SECKEY_SIZE
            + ML_KEM_768_PUBKEY_SIZE
            + ML_KEM_768_SECKEY_SIZE;
        if bytes.len() != expected_size {
            return Err(ArkError::CryptoError(format!(
                "Invalid identity file size: expected {} bytes, got {}",
                expected_size,
                bytes.len()
            )));
        }

        if bytes[0..4] != PERSISTENT_IDENTITY_MAGIC {
            return Err(ArkError::CryptoError(
                "Invalid identity key magic bytes".into(),
            ));
        }

        let version = bytes[4];
        if version != 1 {
            return Err(ArkError::CryptoError(format!(
                "Unsupported identity key version: {}",
                version
            )));
        }

        let mut offset = 5;

        let mut fn_dsa_pk = [0u8; FN_DSA_512_PUBKEY_SIZE];
        fn_dsa_pk.copy_from_slice(&bytes[offset..offset + FN_DSA_512_PUBKEY_SIZE]);
        offset += FN_DSA_512_PUBKEY_SIZE;

        let mut fn_dsa_sk = [0u8; FN_DSA_512_SECKEY_SIZE];
        fn_dsa_sk.copy_from_slice(&bytes[offset..offset + FN_DSA_512_SECKEY_SIZE]);
        offset += FN_DSA_512_SECKEY_SIZE;

        let mut ml_kem_pk = [0u8; ML_KEM_768_PUBKEY_SIZE];
        ml_kem_pk.copy_from_slice(&bytes[offset..offset + ML_KEM_768_PUBKEY_SIZE]);
        offset += ML_KEM_768_PUBKEY_SIZE;

        let mut ml_kem_sk = [0u8; ML_KEM_768_SECKEY_SIZE];
        ml_kem_sk.copy_from_slice(&bytes[offset..offset + ML_KEM_768_SECKEY_SIZE]);

        let id = Identity::from_public_key(&fn_dsa_pk);
        let fn_dsa_keypair = FnDsaKeyPair {
            public_key: fn_dsa_pk,
            secret_key: fn_dsa_sk,
        };
        let ml_kem_keypair = MlKemKeyPair {
            public_key: ml_kem_pk,
            secret_key: ml_kem_sk,
        };

        Ok(Self {
            ark_id: id.ark_id,
            sender_key_id: id.sender_key_id,
            fn_dsa_keypair,
            fn_dsa_secret_key: LockedBuffer::new(fn_dsa_sk),
            ml_kem_keypair,
            ml_kem_secret_key: LockedBuffer::new(ml_kem_sk),
        })
    }

    /// Save identity to path with strict POSIX permissions 0600 (user read/write only)
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(ArkError::IoError)?;
        }

        let mut open_options = OpenOptions::new();
        open_options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_options.mode(0o600);
        }

        let mut file = open_options.open(path).map_err(ArkError::IoError)?;

        // Ensure permissions are strictly 0600 even if the file already existed with different perms
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, permissions).map_err(ArkError::IoError)?;
        }

        let bytes = self.to_bytes();
        file.write_all(&bytes).map_err(ArkError::IoError)?;
        file.flush().map_err(ArkError::IoError)?;

        Ok(())
    }

    /// Load identity from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .open(path.as_ref())
            .map_err(ArkError::IoError)?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(ArkError::IoError)?;

        Self::from_bytes(&bytes)
    }
}

impl ArkIdentity for PersistentIdentity {
    fn ark_id(&self) -> &[u8; 32] {
        &self.ark_id
    }

    fn sender_key_id(&self) -> [u8; 16] {
        self.sender_key_id
    }
}
