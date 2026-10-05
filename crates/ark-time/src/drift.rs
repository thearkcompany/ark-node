//! Clock drift validation enforcing strict limit of ±30 seconds.

use ark_core::constants::MAX_CLOCK_DRIFT_SECS;
use ark_core::error::{ArkError, Result};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DriftValidator;

impl DriftValidator {
    /// Validates that an incoming timestamp is within ±30s of reference time
    pub fn validate_timestamp(timestamp_secs: u64, reference_secs: u64) -> Result<()> {
        let diff = (timestamp_secs as i64) - (reference_secs as i64);
        if diff.abs() > MAX_CLOCK_DRIFT_SECS {
            return Err(ArkError::ClockDriftExceeded(diff, MAX_CLOCK_DRIFT_SECS));
        }
        Ok(())
    }

    /// Validates an incoming timestamp against local system clock
    pub fn validate_now(timestamp_secs: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self::validate_timestamp(timestamp_secs, now)
    }
}
