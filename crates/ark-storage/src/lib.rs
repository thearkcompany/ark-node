//! ark-storage: Embedded Fjall LSM storage engine with deterministic GCP-06 retention classes.

pub mod config;
pub mod engine;
pub mod error;
pub mod retention;

pub use config::StorageConfig;
pub use engine::{compute_envelope_id, StorageEngine};
pub use error::{ArkStorageError, Result};
pub use retention::{
    classify_retention, get_envelope_kind, RetentionClass, RetentionOutcome, TAG_EXPIRATION,
    TAG_PARAM_D,
};
