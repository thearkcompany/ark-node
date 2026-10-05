//! Fundamental traits for ARK protocol engines and services.

use crate::error::Result;
use async_trait::async_trait;

/// Identity provider trait for signing and key agreement
pub trait ArkIdentity {
    fn ark_id(&self) -> &[u8; 32];
    fn sender_key_id(&self) -> [u8; 16];
}

/// Abstract transport layer capable of sending and receiving envelopes
#[async_trait]
pub trait ArkTransport: Send + Sync {
    async fn send(&self, destination: &str, envelope_bytes: &[u8]) -> Result<()>;
    async fn receive(&self) -> Result<Vec<u8>>;
}

/// Anti-replay tracker interface
pub trait AntiReplayFilter: Send + Sync {
    fn check_and_insert(&self, item: &[u8]) -> Result<bool>;
}
