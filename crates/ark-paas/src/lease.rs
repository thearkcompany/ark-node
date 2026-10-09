use crate::queue::Task;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// An active in-memory execution lease associated with a dispatched task.
#[derive(Debug)]
pub struct JobLease {
    task: Task,
    granted_at: Instant,
    lease_duration: Duration,
    acked: Arc<AtomicBool>,
}

impl JobLease {
    pub fn new(task: Task, lease_duration: Duration, acked: Arc<AtomicBool>) -> Self {
        Self {
            task,
            granted_at: Instant::now(),
            lease_duration,
            acked,
        }
    }

    pub fn task(&self) -> &Task {
        &self.task
    }

    pub fn is_expired(&self) -> bool {
        self.granted_at.elapsed() > self.lease_duration
    }

    pub fn remaining_duration(&self) -> Duration {
        self.lease_duration
            .saturating_sub(self.granted_at.elapsed())
    }

    pub fn is_acked(&self) -> bool {
        self.acked.load(Ordering::Acquire)
    }

    pub(crate) fn mark_acked(&self) {
        self.acked.store(true, Ordering::Release);
    }
}
