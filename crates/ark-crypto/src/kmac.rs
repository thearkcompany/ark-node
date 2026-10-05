//! KMAC256 ("ARK-KMAC256-V1") for Stateless Retry Cookies and envelope integrity tags.

use ark_core::constants::KMAC_CUSTOM_STRING;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    CShake256, CShake256Core,
};

/// Computes KMAC256 with key, data, and protocol customization string "ARK-KMAC256-V1"
pub struct Kmac256 {
    hasher: CShake256,
}

impl Kmac256 {
    pub fn new(key: &[u8]) -> Self {
        let core = CShake256Core::new(KMAC_CUSTOM_STRING);
        let mut hasher = CShake256::from_core(core);
        // Encode key bytepad according to NIST SP 800-185 KMAC structure
        hasher.update(&(key.len() as u64).to_be_bytes());
        hasher.update(key);
        Self { hasher }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(self, out: &mut [u8]) {
        let mut reader = self.hasher.finalize_xof();
        reader.read(out);
    }

    /// Convenience one-shot function
    pub fn mac(key: &[u8], data: &[u8], output_len: usize) -> Vec<u8> {
        let mut kmac = Self::new(key);
        kmac.update(data);
        let mut out = vec![0u8; output_len];
        kmac.finalize(&mut out);
        out
    }

    /// Tag generator for retry cookies (32 bytes)
    pub fn generate_cookie_tag(key: &[u8], client_addr: &[u8], token: &[u8]) -> [u8; 32] {
        let mut kmac = Self::new(key);
        kmac.update(client_addr);
        kmac.update(token);
        let mut out = [0u8; 32];
        kmac.finalize(&mut out);
        out
    }
}
