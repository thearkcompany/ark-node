//! Ark Cron: Event-driven recurring task scheduler synchronized with
//! decentralized consensus time (Peer-Median-Time / ark-time) rather than local wall-clock.
//!
//! Enforces a strict "Skip Missed Intervals" policy: if a node is offline for hours or days,
//! upon reconnect only the single latest pending run is enqueued, completely suppressing
//! catch-up storms.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

use crate::error::{PaasError, Result};
use crate::queue::{ArkQueue, Task};
pub use ark_time::MockPmtClock;
pub use ark_time::PmtClock;

/// Standard 5-field cron schedule: minute, hour, day of month, month, day of week.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronSchedule {
    raw: String,
    // Bitmask sets for each field:
    // minute: 0..=59 (60 bits)
    minute_mask: u64,
    // hour: 0..=23 (24 bits)
    hour_mask: u32,
    // day of month: 1..=31 (32 bits, bit N corresponds to day N)
    dom_mask: u32,
    // month: 1..=12 (16 bits, bit N corresponds to month N)
    month_mask: u16,
    // day of week: 0..=6 (0 = Sunday, 7 also accepted as Sunday)
    dow_mask: u8,
}

impl CronSchedule {
    /// Parse and validate a standard 5-field cron expression:
    /// `minute hour day-of-month month day-of-week`
    pub fn parse(expr: &str) -> Result<Self> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(PaasError::InvalidArgument(format!(
                "Cron expression must contain exactly 5 fields, got {}: '{}'",
                fields.len(),
                expr
            )));
        }

        let minute_mask = parse_field(fields[0], 0, 59).map_err(|e| {
            PaasError::InvalidArgument(format!("Invalid minute field '{}': {}", fields[0], e))
        })?;
        let hour_mask = parse_field(fields[1], 0, 23).map_err(|e| {
            PaasError::InvalidArgument(format!("Invalid hour field '{}': {}", fields[1], e))
        })? as u32;
        let dom_mask = parse_field(fields[2], 1, 31).map_err(|e| {
            PaasError::InvalidArgument(format!("Invalid day-of-month field '{}': {}", fields[2], e))
        })? as u32;
        let month_mask = parse_field(fields[3], 1, 12).map_err(|e| {
            PaasError::InvalidArgument(format!("Invalid month field '{}': {}", fields[3], e))
        })? as u16;
        let dow_mask = parse_dow_field(fields[4]).map_err(|e| {
            PaasError::InvalidArgument(format!("Invalid day-of-week field '{}': {}", fields[4], e))
        })?;

        Ok(Self {
            raw: expr.to_string(),
            minute_mask,
            hour_mask,
            dom_mask,
            month_mask,
            dow_mask,
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Evaluates if the cron schedule matches the specified Unix timestamp (floored to minute).
    pub fn matches_timestamp(&self, timestamp_secs: u64) -> bool {
        let dt = unix_to_utc(timestamp_secs);
        let minute_bit = 1u64 << dt.minute;
        let hour_bit = 1u32 << dt.hour;
        let dom_bit = 1u32 << dt.day;
        let month_bit = 1u16 << dt.month;
        let dow_bit = 1u8 << dt.weekday;

        (self.minute_mask & minute_bit != 0)
            && (self.hour_mask & hour_bit != 0)
            && (self.dom_mask & dom_bit != 0)
            && (self.month_mask & month_bit != 0)
            && (self.dow_mask & dow_bit != 0)
    }

    /// Finds the latest trigger time in `[from_secs + 1, to_secs]`.
    /// Used for "Skip Missed Intervals" policy: finding only the most recent trigger in an interval.
    pub fn latest_trigger_in_range(&self, from_secs: u64, to_secs: u64) -> Option<u64> {
        if from_secs >= to_secs {
            return None;
        }

        // Align to minute boundaries
        let mut curr_min = (to_secs / 60) * 60;
        let min_bound = (from_secs / 60) * 60;

        // Search backwards minute-by-minute up to a practical scan limit or until from_secs
        // If the gap is huge (e.g. days/months), searching backwards minute-by-minute guarantees
        // finding the most recent trigger quickly because recurring crons fire frequently relative to the gap.
        // As a safeguard, scan backwards up to 7 * 24 * 60 minutes (1 week) or until min_bound.
        let max_steps = 7 * 24 * 60;
        let mut steps = 0;

        while curr_min > min_bound && steps < max_steps {
            if self.matches_timestamp(curr_min) {
                return Some(curr_min);
            }
            if curr_min < 60 {
                break;
            }
            curr_min -= 60;
            steps += 1;
        }

        None
    }
}

impl FromStr for CronSchedule {
    type Err = PaasError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Helper to parse numeric subexpressions like "*", "*/5", "1-5", "1,2,3" into a bitmask.
fn parse_field(s: &str, min: u32, max: u32) -> std::result::Result<u64, String> {
    let mut mask = 0u64;

    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("Empty element in list".to_string());
        }

        if part == "*" {
            for v in min..=max {
                mask |= 1u64 << v;
            }
        } else if let Some(step_str) = part.strip_prefix("*/") {
            let step: u32 = step_str
                .parse()
                .map_err(|_| format!("Invalid step in '{}'", part))?;
            if step == 0 {
                return Err("Step cannot be 0".to_string());
            }
            let mut v = min;
            while v <= max {
                mask |= 1u64 << v;
                v += step;
            }
        } else if part.contains('/') {
            let slash_parts: Vec<&str> = part.split('/').collect();
            if slash_parts.len() != 2 {
                return Err(format!("Invalid step syntax in '{}'", part));
            }
            let range_part = slash_parts[0];
            let step: u32 = slash_parts[1]
                .parse()
                .map_err(|_| format!("Invalid step in '{}'", part))?;
            if step == 0 {
                return Err("Step cannot be 0".to_string());
            }

            let (start, end) = parse_range(range_part, min, max)?;
            let mut v = start;
            while v <= end {
                mask |= 1u64 << v;
                v += step;
            }
        } else if part.contains('-') {
            let (start, end) = parse_range(part, min, max)?;
            for v in start..=end {
                mask |= 1u64 << v;
            }
        } else {
            let val: u32 = part
                .parse()
                .map_err(|_| format!("Invalid integer '{}'", part))?;
            if val < min || val > max {
                return Err(format!("Value {} out of bounds [{}..={}]", val, min, max));
            }
            mask |= 1u64 << val;
        }
    }

    Ok(mask)
}

fn parse_range(s: &str, min: u32, max: u32) -> std::result::Result<(u32, u32), String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid range syntax: '{}'", s));
    }
    let start: u32 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid start '{}'", parts[0]))?;
    let end: u32 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid end '{}'", parts[1]))?;
    if start > end {
        return Err(format!("Range start {} > end {}", start, end));
    }
    if start < min || end > max {
        return Err(format!(
            "Range {}-{} out of bounds [{}..={}]",
            start, end, min, max
        ));
    }
    Ok((start, end))
}

fn parse_dow_field(s: &str) -> std::result::Result<u8, String> {
    // Weekday 0-7, where 0 and 7 are Sunday
    let mask64 = parse_field(s, 0, 7)?;
    let mut dow_mask = (mask64 & 0x7F) as u8;
    // If bit 7 is set (Sunday as 7), also set bit 0 (Sunday as 0)
    if (mask64 & (1 << 7)) != 0 {
        dow_mask |= 1;
    }
    Ok(dow_mask)
}

/// Simple UTC broken-down time representation computed without external chrono crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcDateTime {
    pub year: i32,
    pub month: u32,   // 1..=12
    pub day: u32,     // 1..=31
    pub hour: u32,    // 0..=23
    pub minute: u32,  // 0..=59
    pub second: u32,  // 0..=59
    pub weekday: u32, // 0..=6 (0 = Sunday)
}

/// Convert Unix timestamp in seconds to broken-down UTC date time.
pub fn unix_to_utc(secs: u64) -> UtcDateTime {
    let second = (secs % 60) as u32;
    let total_minutes = secs / 60;
    let minute = (total_minutes % 60) as u32;
    let total_hours = total_minutes / 60;
    let hour = (total_hours % 24) as u32;
    let days_since_epoch = (total_hours / 24) as i64;

    // Days since epoch: 1970-01-01 was Thursday (weekday 4).
    // Weekday: 0 = Sunday, 1 = Monday, ..., 4 = Thursday.
    let weekday = ((days_since_epoch + 4) % 7 + 7) % 7;

    // Civil date algorithm from Euclidean Affine calendar (Howard Hinnant)
    let z = days_since_epoch + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    UtcDateTime {
        year: y as i32,
        month: m,
        day: d,
        hour,
        minute,
        second,
        weekday: weekday as u32,
    }
}

/// Recurring cron job specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    pub id: String,
    pub schedule: CronSchedule,
    pub payload: Vec<u8>,
    /// Last recorded PMT tick (in seconds) when this job was triggered or initialized.
    pub last_executed_pmt: Option<u64>,
}

impl CronJob {
    pub fn new(id: impl Into<String>, schedule: CronSchedule, payload: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            schedule,
            payload,
            last_executed_pmt: None,
        }
    }

    pub fn with_last_executed(mut self, last_pmt: u64) -> Self {
        self.last_executed_pmt = Some(last_pmt);
        self
    }
}

/// ArkCron: Event-driven recurring task scheduler synchronized with decentralized
/// Peer-Median-Time (PMT).
pub struct ArkCron<C: PmtClock> {
    clock: Arc<C>,
    jobs: RwLock<Vec<CronJob>>,
}

impl<C: PmtClock> ArkCron<C> {
    pub fn new(clock: Arc<C>) -> Self {
        Self {
            clock,
            jobs: RwLock::new(Vec::new()),
        }
    }

    /// Add a recurring job. If `last_executed_pmt` is None, it defaults to the current clock time
    /// so it doesn't immediately fire for historical points prior to registration.
    pub fn add_job(&self, mut job: CronJob) {
        if job.last_executed_pmt.is_none() {
            job.last_executed_pmt = Some(self.clock.now_pmt());
        }
        self.jobs.write().push(job);
    }

    /// Number of registered recurring jobs.
    pub fn jobs_count(&self) -> usize {
        self.jobs.read().len()
    }

    /// Evaluate triggers against current PMT and enqueue pending tasks into ArkQueue.
    ///
    /// Implements the strict **Skip Missed Intervals** policy:
    /// If an extended offline gap occurred since `last_executed_pmt` (hours/days),
    /// we evaluate `[last_executed_pmt + 1, current_pmt]`.
    /// If one or more scheduled fire times occurred during the gap, **only the single latest**
    /// pending execution is enqueued into `ArkQueue`.
    /// `last_executed_pmt` is then advanced to `current_pmt`.
    ///
    /// Returns the list of enqueued task IDs.
    pub fn tick(&self, queue: &ArkQueue) -> Result<Vec<String>> {
        let current_pmt = self.clock.now_pmt();
        let mut enqueued = Vec::new();

        let mut jobs = self.jobs.write();
        for job in jobs.iter_mut() {
            let last_pmt = job.last_executed_pmt.unwrap_or(current_pmt);
            if current_pmt <= last_pmt {
                continue;
            }

            // Find if there is a match in range (last_pmt, current_pmt]
            if let Some(trigger_pmt) = job.schedule.latest_trigger_in_range(last_pmt, current_pmt) {
                // Generate a deterministic or uniquely qualified task id for this trigger
                let task_id = format!("cron-{}-{}", job.id, trigger_pmt);
                let task = Task::new(task_id, 0, job.payload.clone());

                queue
                    .enqueue(task)
                    .map_err(|e| PaasError::QueueError(e.to_string()))?;
                enqueued.push(format!("cron-{}-{}", job.id, trigger_pmt));
            }

            // Advance last_executed_pmt to current_pmt to skip missed intervals
            job.last_executed_pmt = Some(current_pmt);
        }

        Ok(enqueued)
    }
}
