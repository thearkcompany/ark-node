//! Unified NodeRuntime daemon and envelope dispatcher facade.
//!
//! Provides the primary operational core for the ARK Sovereign P2P Network,
//! encapsulating network listening, task supervision, wire demux, and subsystem dispatch.

pub mod error;

pub use error::{ArkRuntimeError, Result};
