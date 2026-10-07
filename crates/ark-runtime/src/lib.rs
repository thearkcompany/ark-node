//! Unified NodeRuntime daemon and envelope dispatcher facade.
//!
//! Provides the primary operational core for the ARK Sovereign P2P Network,
//! encapsulating network listening, task supervision, wire demux, and subsystem dispatch.

pub mod config;
pub mod error;
pub mod runtime;

pub use config::{NodeRuntimeConfig, NodeRuntimeStatus, Role};
pub use error::{ArkRuntimeError, Result};
pub use runtime::{NodeHandle, NodeRuntimeBuilder};
