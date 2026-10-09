//! Stateless Retry Cookies (RFC 9000 section 8.1 compliant) using KMAC256 anti-DoS protection.

use ark_core::error::{ArkError, Result};
use ark_crypto::Kmac256;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RetryCookieManager {
    secret_key: [u8; 32],
}

impl RetryCookieManager {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self { secret_key }
    }

    /// Generate an authentic stateless retry token for an incoming client address
    pub fn generate_cookie(&self, client_addr: SocketAddr) -> Vec<u8> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut token_data = Vec::with_capacity(48);
        token_data.extend_from_slice(&now.to_be_bytes()); // 8 bytes timestamp
        let addr_str = client_addr.to_string();
        token_data.extend_from_slice(addr_str.as_bytes());

        let tag =
            Kmac256::generate_cookie_tag(&self.secret_key, addr_str.as_bytes(), &now.to_be_bytes());

        let mut out = Vec::with_capacity(8 + 32);
        out.extend_from_slice(&now.to_be_bytes());
        out.extend_from_slice(&tag);
        out
    }

    /// Validate the incoming stateless retry cookie
    pub fn validate_cookie(
        &self,
        client_addr: SocketAddr,
        cookie: &[u8],
        max_age_secs: u64,
    ) -> Result<()> {
        if cookie.len() != 40 {
            return Err(ArkError::InvalidRetryCookie);
        }

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&cookie[0..8]);
        let ts = u64::from_be_bytes(ts_bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < ts || (now - ts) > max_age_secs {
            return Err(ArkError::InvalidRetryCookie);
        }

        let addr_str = client_addr.to_string();
        let expected_tag =
            Kmac256::generate_cookie_tag(&self.secret_key, addr_str.as_bytes(), &ts_bytes);

        if cookie[8..40] != expected_tag {
            return Err(ArkError::InvalidRetryCookie);
        }

        Ok(())
    }
}
