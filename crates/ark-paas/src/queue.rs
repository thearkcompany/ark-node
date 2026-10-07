use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use ark_storage::{Keyspace, KeyspaceCreateOptions, PersistMode, StorageEngine};
use crate::error::{ArkQueueError, QueueResult as Result};
use crate::lease::JobLease;

/// Task lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Dispatched,
    Completed,
    Failed,
    DeadLetter,
}

/// Outcome of applying a concurrent mutation under MERGE_POLICY_LWW_BIVARIATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LwwOutcome {
    Applied,
    Superseded,
}

/// Deterministic Bivariate LWW comparison: max(lamport_clock) followed by lexicographical tie-break max(id).
pub fn bivariate_lww_cmp(a: &Task, b: &Task) -> std::cmp::Ordering {
    a.lamport_clock
        .cmp(&b.lamport_clock)
        .then_with(|| a.id.cmp(&b.id))
}

/// A job/task managed by ArkQueue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub lamport_clock: u64,
    pub payload: Vec<u8>,
    pub status: TaskStatus,
    pub attempts: u32,
    pub max_attempts: u32,
}

impl Task {
    pub fn new(id: impl Into<String>, lamport_clock: u64, payload: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            lamport_clock,
            payload,
            status: TaskStatus::Pending,
            attempts: 0,
            max_attempts: 3,
        }
    }
}

/// Configuration for ArkQueue.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub lease_duration: Duration,
    pub max_attempts: u32,
    pub keyspace_name: String,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            lease_duration: Duration::from_secs(30),
            max_attempts: 3,
            keyspace_name: "paas_queue_tasks".to_string(),
        }
    }
}

/// Active tracked lease state in memory.
struct ActiveLeaseEntry {
    task: Task,
    lease_granted_at: std::time::Instant,
    lease_duration: Duration,
    acked: Arc<AtomicBool>,
}

/// ArkQueue: causally ordered, crash-resilient asynchronous task queue
/// persisted in ark-storage (Fjall LSM keyspace) with in-memory ACK elision.
pub struct ArkQueue {
    storage: Arc<StorageEngine>,
    tasks_keyspace: Keyspace,
    config: QueueConfig,
    lamport_counter: AtomicU64,
    ready_queue: Arc<Mutex<VecDeque<String>>>,
    active_leases: Arc<DashMap<String, ActiveLeaseEntry>>,
    completed_in_memory: Arc<DashMap<String, Task>>,
    dlq: Arc<Mutex<VecDeque<Task>>>,
    disk_sync_counter: AtomicU64,
}

impl ArkQueue {
    pub fn open(storage: Arc<StorageEngine>, config: QueueConfig) -> Result<Self> {
        let tasks_keyspace = storage
            .db()
            .keyspace(&config.keyspace_name, || {
                KeyspaceCreateOptions::default()
            })
            .map_err(|e| ArkQueueError::Database(e.to_string()))?;

        let queue = Self {
            storage,
            tasks_keyspace,
            config,
            lamport_counter: AtomicU64::new(0),
            ready_queue: Arc::new(Mutex::new(VecDeque::new())),
            active_leases: Arc::new(DashMap::new()),
            completed_in_memory: Arc::new(DashMap::new()),
            dlq: Arc::new(Mutex::new(VecDeque::new())),
            disk_sync_counter: AtomicU64::new(0),
        };

        // Rehydrate unacknowledged jobs from LSM storage on startup
        queue.rehydrate_from_storage()?;

        Ok(queue)
    }

    /// Enqueue an ingested task, durably writing to Fjall LSM storage (Class 1 retention semantics).
    pub fn enqueue(&self, mut task: Task) -> Result<String> {
        let task_id = task.id.clone();
        let current_clock = self.lamport_counter.fetch_add(1, Ordering::SeqCst) + 1;
        if task.lamport_clock == 0 {
            task.lamport_clock = current_clock;
        } else {
            // Advance local clock if task clock is higher
            self.lamport_counter.fetch_max(task.lamport_clock, Ordering::SeqCst);
        }

        task.status = TaskStatus::Pending;
        task.max_attempts = self.config.max_attempts;

        // Persist durably to Fjall LSM
        let key = task_id.as_bytes();
        let bytes = serde_json::to_vec(&task)
            .map_err(|e| ArkQueueError::Serialization(e.to_string()))?;

        self.tasks_keyspace
            .insert(key, bytes)
            .map_err(|e| ArkQueueError::Database(e.to_string()))?;

        // Synchronous write durability for Class 1 retention on ingest
        self.storage
            .db()
            .persist(PersistMode::SyncAll)
            .map_err(|e| ArkQueueError::Database(e.to_string()))?;
        self.disk_sync_counter.fetch_add(1, Ordering::SeqCst);

        self.ready_queue.lock().push_back(task_id.clone());

        Ok(task_id)
    }

    /// Number of synchronous disk fsync operations executed by the queue.
    pub fn disk_sync_writes_count(&self) -> u64 {
        self.disk_sync_counter.load(Ordering::SeqCst)
    }

    /// Number of currently active job leases in memory.
    pub fn active_leases_count(&self) -> usize {
        self.active_leases.len()
    }

    /// Check if a task is marked as completed in RAM (ACK elided).
    pub fn is_completed_in_memory(&self, task_id: &str) -> bool {
        self.completed_in_memory.contains_key(task_id)
    }

    /// Complete a task during its active JobLease window (In-Memory ACK Elision).
    /// Eliminates synchronous disk write I/O on normal completions.
    pub fn complete(&self, lease: &JobLease) -> Result<()> {
        let task_id = &lease.task().id;

        if lease.is_expired() {
            return Err(ArkQueueError::LeaseExpired(format!(
                "Lease for task {} has expired",
                task_id
            )));
        }

        // Mark lease as acked in memory
        lease.mark_acked();

        // Remove from active leases
        if let Some((_, mut entry)) = self.active_leases.remove(task_id) {
            entry.task.status = TaskStatus::Completed;
            // Record completed in RAM without immediate disk write I/O!
            self.completed_in_memory.insert(task_id.clone(), entry.task);
        } else {
            let mut completed_task = lease.task().clone();
            completed_task.status = TaskStatus::Completed;
            self.completed_in_memory.insert(task_id.clone(), completed_task);
        }

        Ok(())
    }

    /// Flush completed in-memory tasks to LSM storage lazily during periodic compactions/maintenance.
    /// Returns the number of tombstone/completed entries persisted.
    pub fn flush_completed_to_storage(&self) -> Result<usize> {
        let mut count = 0;
        for item in self.completed_in_memory.iter() {
            let task = item.value();
            self.persist_task_to_storage(task)?;
            count += 1;
        }
        Ok(count)
    }

    /// Retrieve a task by ID (checking memory overrides first, then LSM keyspace).
    pub fn get_task(&self, task_id: &str) -> Result<Option<Task>> {
        if let Some(task) = self.completed_in_memory.get(task_id) {
            return Ok(Some(task.clone()));
        }
        if let Some(entry) = self.active_leases.get(task_id) {
            return Ok(Some(entry.task.clone()));
        }
        self.read_task_from_storage(task_id)
    }

    /// Resolve concurrent job state mutations and prevent sibling buildup in the LSM-tree
    /// via MERGE_POLICY_LWW_BIVARIATE: max(lamport_clock) followed by lexicographical tie-break max(id).
    pub fn apply_mutation_lww(&self, mutation: Task) -> Result<LwwOutcome> {
        let task_id = &mutation.id;
        self.lamport_counter.fetch_max(mutation.lamport_clock, Ordering::SeqCst);

        let existing = self.get_task(task_id)?;
        if let Some(existing_task) = existing {
            if bivariate_lww_cmp(&mutation, &existing_task).is_gt() {
                // Mutation wins! Apply write to LSM
                self.persist_task_to_storage(&mutation)?;
                // Update in memory if present
                if self.completed_in_memory.contains_key(task_id) {
                    self.completed_in_memory.insert(task_id.clone(), mutation);
                }
                Ok(LwwOutcome::Applied)
            } else {
                // Existing task wins or is identical
                Ok(LwwOutcome::Superseded)
            }
        } else {
            // New task
            self.persist_task_to_storage(&mutation)?;
            Ok(LwwOutcome::Applied)
        }
    }

    /// Helper to persist a task record to Fjall LSM storage.
    fn persist_task_to_storage(&self, task: &Task) -> Result<()> {
        let key = task.id.as_bytes();
        let bytes = serde_json::to_vec(task)
            .map_err(|e| ArkQueueError::Serialization(e.to_string()))?;
        self.tasks_keyspace
            .insert(key, bytes)
            .map_err(|e| ArkQueueError::Database(e.to_string()))?;
        Ok(())
    }

    /// Dispatches the next available task granting an in-memory JobLease.
    pub fn dispatch(&self) -> Result<Option<JobLease>> {
        let mut ready = self.ready_queue.lock();
        while let Some(task_id) = ready.pop_front() {
            // Read task from memory or storage
            if let Some(mut task) = self.get_task(&task_id)? {
                if task.status == TaskStatus::Completed || task.status == TaskStatus::DeadLetter {
                    continue;
                }
                task.attempts += 1;
                task.status = TaskStatus::Dispatched;

                // Update storage with incremented attempts & status
                self.persist_task_to_storage(&task)?;

                let acked_flag = Arc::new(AtomicBool::new(false));
                let entry = ActiveLeaseEntry {
                    task: task.clone(),
                    lease_granted_at: std::time::Instant::now(),
                    lease_duration: self.config.lease_duration,
                    acked: acked_flag.clone(),
                };

                self.active_leases.insert(task_id.clone(), entry);

                let lease = JobLease::new(task, self.config.lease_duration, acked_flag);
                return Ok(Some(lease));
            }
        }
        Ok(None)
    }

    /// Process expired active leases: unacknowledged tasks whose lease duration has elapsed
    /// are either re-enqueued for retry or routed to the Dead-Letter Queue (DLQ) if attempts >= max_attempts.
    pub fn process_expired_leases(&self) -> Result<usize> {
        let mut expired_keys = Vec::new();
        let now = std::time::Instant::now();

        for entry in self.active_leases.iter() {
            let task_id = entry.key();
            let lease_entry = entry.value();
            if !lease_entry.acked.load(Ordering::Acquire)
                && now.duration_since(lease_entry.lease_granted_at) >= lease_entry.lease_duration
            {
                expired_keys.push(task_id.clone());
            }
        }

        let mut processed = 0;
        for task_id in expired_keys {
            if let Some((_, mut lease_entry)) = self.active_leases.remove(&task_id) {
                if lease_entry.acked.load(Ordering::Acquire) {
                    continue;
                }

                processed += 1;
                if lease_entry.task.attempts >= self.config.max_attempts {
                    // Route to Dead-Letter Queue
                    lease_entry.task.status = TaskStatus::DeadLetter;
                    self.persist_task_to_storage(&lease_entry.task)?;
                    self.dlq.lock().push_back(lease_entry.task);
                } else {
                    // Re-enqueue for retry
                    lease_entry.task.status = TaskStatus::Pending;
                    self.persist_task_to_storage(&lease_entry.task)?;
                    self.ready_queue.lock().push_back(task_id);
                }
            }
        }

        Ok(processed)
    }

    /// Get current number of items in the Dead-Letter Queue.
    pub fn dlq_len(&self) -> usize {
        self.dlq.lock().len()
    }

    /// Pop the next item from the Dead-Letter Queue.
    pub fn pop_dlq(&self) -> Option<Task> {
        self.dlq.lock().pop_front()
    }

    /// Read task from disk keyspace.
    fn read_task_from_storage(&self, task_id: &str) -> Result<Option<Task>> {
        let key = task_id.as_bytes();
        if let Some(bytes) = self
            .tasks_keyspace
            .get(key)
            .map_err(|e| ArkQueueError::Database(e.to_string()))?
        {
            let task: Task = serde_json::from_slice(&bytes)
                .map_err(|e| ArkQueueError::Serialization(e.to_string()))?;
            Ok(Some(task))
        } else {
            Ok(None)
        }
    }

    /// Rehydrate tasks from LSM storage on restart or open.
    fn rehydrate_from_storage(&self) -> Result<()> {
        let mut rehydrated = Vec::new();

        for item in self.tasks_keyspace.iter() {
            let val = item.value().map_err(|e| ArkQueueError::Database(e.to_string()))?;
            if let Ok(task) = serde_json::from_slice::<Task>(&val) {
                if task.status == TaskStatus::Pending || task.status == TaskStatus::Dispatched {
                    rehydrated.push(task);
                }
            }
        }

        // Sort by Lamport clock, then by ID for deterministic causal order
        rehydrated.sort_by(|a, b| {
            a.lamport_clock
                .cmp(&b.lamport_clock)
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut ready = self.ready_queue.lock();
        for task in rehydrated {
            self.lamport_counter.fetch_max(task.lamport_clock, Ordering::SeqCst);
            ready.push_back(task.id);
        }

        Ok(())
    }
}
