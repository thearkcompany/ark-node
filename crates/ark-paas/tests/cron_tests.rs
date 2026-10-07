use std::sync::Arc;
use tempfile::tempdir;

use ark_paas::cron::{unix_to_utc, ArkCron, CronJob, CronSchedule, MockPmtClock, PmtClock};
use ark_paas::queue::{ArkQueue, QueueConfig};
use ark_storage::{StorageConfig, StorageEngine};

#[test]
fn test_cron_expression_parsing_valid_and_invalid() {
    // Valid 5-field cron expressions
    assert!(CronSchedule::parse("* * * * *").is_ok());
    assert!(CronSchedule::parse("*/5 * * * *").is_ok());
    assert!(CronSchedule::parse("0 0 * * *").is_ok()); // Daily midnight
    assert!(CronSchedule::parse("30 4 1,15 * 5").is_ok()); // At 04:30 on 1st, 15th and on Friday
    assert!(CronSchedule::parse("0-30/10 12 * 1-6 1-5").is_ok()); // Complex ranges and steps

    // Invalid cron expressions
    assert!(CronSchedule::parse("* * * *").is_err()); // Only 4 fields
    assert!(CronSchedule::parse("* * * * * *").is_err()); // 6 fields (unsupported / not 5-field)
    assert!(CronSchedule::parse("60 * * * *").is_err()); // Minute 60 is out of bounds [0..=59]
    assert!(CronSchedule::parse("* 24 * * *").is_err()); // Hour 24 is out of bounds [0..=23]
    assert!(CronSchedule::parse("* * 0 * *").is_err()); // Day of month 0 is out of bounds [1..=31]
    assert!(CronSchedule::parse("* * 32 * *").is_err()); // Day of month 32 is out of bounds
    assert!(CronSchedule::parse("* * * 0 *").is_err()); // Month 0 is out of bounds [1..=12]
    assert!(CronSchedule::parse("* * * 13 *").is_err()); // Month 13 is out of bounds
    assert!(CronSchedule::parse("* * * * 8").is_err()); // Weekday 8 is out of bounds [0..=7]
    assert!(CronSchedule::parse("*/0 * * * *").is_err()); // Step 0 invalid
    assert!(CronSchedule::parse("10-5 * * * *").is_err()); // Reverse range invalid
}

#[test]
fn test_unix_to_utc_calendar_conversion() {
    // 0 = 1970-01-01 00:00:00 UTC (Thursday, weekday 4)
    let dt0 = unix_to_utc(0);
    assert_eq!(dt0.year, 1970);
    assert_eq!(dt0.month, 1);
    assert_eq!(dt0.day, 1);
    assert_eq!(dt0.hour, 0);
    assert_eq!(dt0.minute, 0);
    assert_eq!(dt0.second, 0);
    assert_eq!(dt0.weekday, 4);

    // 2026-10-07 00:00:00 UTC = 1791331200
    // Wednesday (weekday 3)
    let dt_2026 = unix_to_utc(1791331200);
    assert_eq!(dt_2026.year, 2026);
    assert_eq!(dt_2026.month, 10);
    assert_eq!(dt_2026.day, 7);
    assert_eq!(dt_2026.hour, 0);
    assert_eq!(dt_2026.minute, 0);
    assert_eq!(dt_2026.second, 0);
    assert_eq!(dt_2026.weekday, 3);
}

#[test]
fn test_mock_pmt_clock_fast_forward_and_set() {
    let clock = MockPmtClock::new(1000);
    assert_eq!(clock.now_pmt(), 1000);

    clock.set_time(5000);
    assert_eq!(clock.now_pmt(), 5000);

    let next = clock.advance(3600);
    assert_eq!(next, 8600);
    assert_eq!(clock.now_pmt(), 8600);
}

#[test]
fn test_cron_trigger_evaluation_on_tick() {
    let tmp = tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(tmp.path(), StorageConfig::frugal()).unwrap());
    let queue = ArkQueue::open(storage, QueueConfig::default()).unwrap();

    // Start at 2026-10-07 12:00:00 UTC (1791374400)
    let initial_time = 1791374400u64;
    let clock = Arc::new(MockPmtClock::new(initial_time));
    let cron = ArkCron::new(clock.clone());

    // Schedule: every 5 minutes ("*/5 * * * *")
    let schedule = CronSchedule::parse("*/5 * * * *").unwrap();
    let job = CronJob::new("heartbeat", schedule, b"ping".to_vec())
        .with_last_executed(initial_time);
    cron.add_job(job);

    // Advance by 1 minute: 12:01 (no trigger)
    clock.advance(60);
    let enqueued = cron.tick(&queue).unwrap();
    assert!(enqueued.is_empty());
    assert!(queue.dispatch().unwrap().is_none());

    // Advance by 4 minutes: 12:05 (matches */5)
    clock.advance(240);
    let enqueued = cron.tick(&queue).unwrap();
    assert_eq!(enqueued.len(), 1);
    assert_eq!(enqueued[0], format!("cron-heartbeat-{}", initial_time + 300));

    // Verify task is ready in ArkQueue
    let lease = queue.dispatch().unwrap().expect("Job should be dispatched");
    assert_eq!(lease.task().id, format!("cron-heartbeat-{}", initial_time + 300));
    assert_eq!(lease.task().payload, b"ping");
    queue.complete(&lease).unwrap();
}

#[test]
fn test_strict_skip_missed_intervals_policy_avoids_catchup_storm() {
    let tmp = tempdir().unwrap();
    let storage = Arc::new(StorageEngine::open(tmp.path(), StorageConfig::frugal()).unwrap());
    let queue = ArkQueue::open(storage, QueueConfig::default()).unwrap();

    // Start at 2026-10-07 00:00:00 UTC (1791331200)
    let initial_time = 1791331200u64;
    let clock = Arc::new(MockPmtClock::new(initial_time));
    let cron = ArkCron::new(clock.clone());

    // Schedule: runs every 10 minutes ("*/10 * * * *")
    let schedule = CronSchedule::parse("*/10 * * * *").unwrap();
    let job = CronJob::new("periodic-sync", schedule, b"sync-payload".to_vec())
        .with_last_executed(initial_time);
    cron.add_job(job);

    // Simulate an extended offline gap of 24 hours (86,400 seconds = 144 missed intervals!)
    let offline_duration = 24 * 3600u64;
    clock.advance(offline_duration);

    // On reconnect / restart tick, verify Skip Missed Intervals policy:
    // Only EXACTLY 1 task must be enqueued (the single most recent scheduled execution),
    // NOT 144 retroactive tasks!
    let enqueued = cron.tick(&queue).unwrap();
    assert_eq!(
        enqueued.len(),
        1,
        "Skip-Missed policy must enqueue exactly 1 task for the latest interval, got {}",
        enqueued.len()
    );

    // The single latest execution should be at the 24h boundary (1791331200 + 86400)
    let expected_latest_trigger = initial_time + offline_duration;
    assert_eq!(enqueued[0], format!("cron-periodic-sync-{}", expected_latest_trigger));

    // Verify ArkQueue contains ONLY 1 dispatched item
    let first_dispatch = queue.dispatch().unwrap();
    assert!(first_dispatch.is_some());
    let lease = first_dispatch.unwrap();
    assert_eq!(lease.task().id, format!("cron-periodic-sync-{}", expected_latest_trigger));
    queue.complete(&lease).unwrap();

    // Verify queue is now empty (no catch-up storm queued!)
    let second_dispatch = queue.dispatch().unwrap();
    assert!(second_dispatch.is_none(), "Queue must have no trailing tasks from catch-up storm");

    // Tick again at the same timestamp: should produce 0 new tasks
    let subsequent_enqueued = cron.tick(&queue).unwrap();
    assert!(subsequent_enqueued.is_empty());
}
