use std::sync::Arc;
use std::time::Duration;
use ark_paas::queue::{ArkQueue, QueueConfig, Task, TaskStatus};
use ark_storage::{StorageConfig, StorageEngine};
use tempfile::tempdir;

#[test]
fn test_task_enqueue_and_class1_durability() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));
    let queue = ArkQueue::open(storage.clone(), QueueConfig::default()).expect("open queue");

    let task = Task::new("task-1", 1, b"execute compute 1".to_vec());
    let task_id = queue.enqueue(task.clone()).expect("enqueue task");
    assert_eq!(task_id, "task-1");

    // Must be dispatched
    let lease = queue.dispatch().expect("dispatch").expect("job lease granted");
    assert_eq!(lease.task().id, "task-1");
    assert_eq!(lease.task().payload, b"execute compute 1");
    assert_eq!(lease.task().status, TaskStatus::Dispatched);
}

#[test]
fn test_in_memory_ack_elision_happy_path() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));
    let queue = ArkQueue::open(storage.clone(), QueueConfig {
        lease_duration: Duration::from_secs(5),
        max_attempts: 3,
        keyspace_name: "paas_queue_tasks".to_string(),
    }).expect("open queue");

    let task = Task::new("task-elide-1", 1, b"compute fast".to_vec());
    queue.enqueue(task).expect("enqueue task");

    let lease = queue.dispatch().expect("dispatch").expect("lease");
    assert_eq!(lease.task().id, "task-elide-1");
    assert_eq!(queue.active_leases_count(), 1);

    // Completing within lease duration resolves in RAM (ACK elision)
    let sync_writes_before = queue.disk_sync_writes_count();
    queue.complete(&lease).expect("complete task");

    // Must be marked as acked in memory and removed from active leases
    assert!(lease.is_acked());
    assert_eq!(queue.active_leases_count(), 0);
    assert_eq!(queue.is_completed_in_memory("task-elide-1"), true);
    // Crucial: ACK elision must not have triggered immediate synchronous disk fsync
    let sync_writes_after = queue.disk_sync_writes_count();
    assert_eq!(sync_writes_after, sync_writes_before);

    // Further dispatch returns None because task is already resolved
    assert!(queue.dispatch().expect("dispatch").is_none());
}

#[test]
fn test_bivariate_lww_conflict_resolution() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));
    let queue = ArkQueue::open(storage.clone(), QueueConfig::default()).expect("open queue");

    // Case 1: Higher Lamport clock wins regardless of arrival order
    let task_v1 = Task::new("job-42", 10, b"mutation v1".to_vec());
    let task_v2 = Task::new("job-42", 15, b"mutation v2 - higher clock".to_vec());

    queue.apply_mutation_lww(task_v1).expect("apply v1");
    queue.apply_mutation_lww(task_v2).expect("apply v2");

    let current = queue.get_task("job-42").expect("get").expect("found");
    assert_eq!(current.lamport_clock, 15);
    assert_eq!(current.payload, b"mutation v2 - higher clock");

    // Attempting to apply an older mutation (lower clock) is superseded
    let task_stale = Task::new("job-42", 12, b"stale mutation".to_vec());
    let outcome = queue.apply_mutation_lww(task_stale).expect("apply stale");
    assert_eq!(outcome, ark_paas::queue::LwwOutcome::Superseded);

    let current = queue.get_task("job-42").expect("get").expect("found");
    assert_eq!(current.lamport_clock, 15);
    assert_eq!(current.payload, b"mutation v2 - higher clock");

    // Case 2: Clock tie broken by lexicographical max(payload_hash/id)
    // Same lamport clock (20): tie-break max(id)
    let task_tie_a = Task::new("job-tie-alpha", 20, b"alpha".to_vec());
    let task_tie_b = Task::new("job-tie-beta", 20, b"beta".to_vec());

    // When comparing two tasks under same clock, lexicographical max(id) deterministically wins
    assert!(ark_paas::queue::bivariate_lww_cmp(&task_tie_b, &task_tie_a).is_gt());
}

#[test]
fn test_lease_timeout_and_dlq_routing() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));
    // Short lease: 50 milliseconds
    let queue = ArkQueue::open(storage.clone(), QueueConfig {
        lease_duration: Duration::from_millis(50),
        max_attempts: 3,
        keyspace_name: "paas_queue_tasks".to_string(),
    }).expect("open queue");

    let task = Task::new("retry-job", 1, b"flaky task".to_vec());
    queue.enqueue(task).expect("enqueue");

    // Attempt 1: dispatch and let lease expire
    let lease1 = queue.dispatch().expect("dispatch 1").expect("lease 1");
    assert_eq!(lease1.task().attempts, 1);
    std::thread::sleep(Duration::from_millis(60));
    assert!(lease1.is_expired());

    // Process timeouts -> re-enqueued for attempt 2
    let timed_out_count = queue.process_expired_leases().expect("process timeouts");
    assert_eq!(timed_out_count, 1);

    // Attempt 2: dispatch and let lease expire
    let lease2 = queue.dispatch().expect("dispatch 2").expect("lease 2");
    assert_eq!(lease2.task().attempts, 2);
    std::thread::sleep(Duration::from_millis(60));
    let timed_out_count2 = queue.process_expired_leases().expect("process timeouts");
    assert_eq!(timed_out_count2, 1);

    // Attempt 3: dispatch and let lease expire (reaches max_attempts: 3)
    let lease3 = queue.dispatch().expect("dispatch 3").expect("lease 3");
    assert_eq!(lease3.task().attempts, 3);
    std::thread::sleep(Duration::from_millis(60));
    let timed_out_count3 = queue.process_expired_leases().expect("process timeouts");
    assert_eq!(timed_out_count3, 1);

    // After 3 failed attempts, task must be routed to Dead-Letter Queue (DLQ)
    assert!(queue.dispatch().expect("no more tasks in main queue").is_none());
    assert_eq!(queue.dlq_len(), 1);

    let dlq_task = queue.pop_dlq().expect("dlq task present");
    assert_eq!(dlq_task.id, "retry-job");
    assert_eq!(dlq_task.status, TaskStatus::DeadLetter);
    assert_eq!(dlq_task.attempts, 3);
}

#[test]
fn test_crash_recovery_rehydration() {
    let dir = tempdir().expect("tempdir");

    // Phase 1: Open queue, enqueue 2 tasks, dispatch 1 but do not ack (simulating crash)
    {
        let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));
        let queue = ArkQueue::open(storage.clone(), QueueConfig::default()).expect("open queue");

        queue.enqueue(Task::new("job-crash-1", 100, b"task 1".to_vec())).expect("enqueue 1");
        queue.enqueue(Task::new("job-crash-2", 200, b"task 2".to_vec())).expect("enqueue 2");

        let lease = queue.dispatch().expect("dispatch").expect("lease");
        assert_eq!(lease.task().id, "job-crash-1");
        // Simulated crash before ACK! (lease dropped without complete())
    }

    // Phase 2: Restart node / reopen queue from storage
    {
        let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("reopen storage"));
        let queue = ArkQueue::open(storage.clone(), QueueConfig::default()).expect("reopen queue");

        // Both unacknowledged jobs must be rehydrated from LSM storage in causal order
        let lease1 = queue.dispatch().expect("dispatch").expect("lease 1");
        assert_eq!(lease1.task().id, "job-crash-1");

        let lease2 = queue.dispatch().expect("dispatch").expect("lease 2");
        assert_eq!(lease2.task().id, "job-crash-2");

        // Now complete them with lazy flush
        queue.complete(&lease1).expect("complete 1");
        queue.complete(&lease2).expect("complete 2");
        queue.flush_completed_to_storage().expect("lazy flush completed");

        assert!(queue.dispatch().expect("empty").is_none());
    }

        // Phase 3: Reopen again - completed tasks must not be re-enqueued
    {
        let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("reopen storage 2"));
        let queue = ArkQueue::open(storage.clone(), QueueConfig::default()).expect("reopen queue 2");
        assert!(queue.dispatch().expect("empty").is_none());
    }
}

#[test]
fn test_concurrent_queue_benchmark_zero_disk_stalls() {
    let dir = tempdir().expect("tempdir");
    let storage = Arc::new(StorageEngine::open(dir.path(), StorageConfig::frugal()).expect("open storage"));
    let queue = Arc::new(ArkQueue::open(storage.clone(), QueueConfig {
        lease_duration: Duration::from_secs(10),
        max_attempts: 3,
        keyspace_name: "paas_queue_tasks".to_string(),
    }).expect("open queue"));

    let num_tasks = 200;
    for i in 0..num_tasks {
        let task = Task::new(format!("bench-job-{}", i), i as u64 + 1, vec![0x42; 64]);
        queue.enqueue(task).expect("enqueue");
    }

    let initial_sync_writes = queue.disk_sync_writes_count();
    assert_eq!(initial_sync_writes, num_tasks as u64);

    let start = std::time::Instant::now();

    // Spawn 8 worker threads concurrently dispatching and completing tasks via ACK elision
    let mut handles = Vec::new();
    for _ in 0..8 {
        let q = queue.clone();
        handles.push(std::thread::spawn(move || {
            let mut completed = 0;
            while let Ok(Some(lease)) = q.dispatch() {
                // Simulate fast micro-task execution
                q.complete(&lease).expect("complete");
                completed += 1;
            }
            completed
        }));
    }

    let total_completed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    let elapsed = start.elapsed();

    assert_eq!(total_completed, num_tasks);
    // ZERO disk fsync stalls during execution phase
    assert_eq!(queue.disk_sync_writes_count(), initial_sync_writes);
    assert_eq!(queue.active_leases_count(), 0);

    println!(
        "Concurrent queue benchmark: processed {} tasks in {:?} ({:.2} tasks/sec)",
        num_tasks,
        elapsed,
        (num_tasks as f64) / elapsed.as_secs_f64()
    );
}



