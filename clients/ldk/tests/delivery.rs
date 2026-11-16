use std::time::{Duration, Instant};

use ldk_watchtower_client::{
    ClientStore, DeliveryAttempt, DeliveryCoordinator, DeliveryStatus, PendingAppointment,
    RetryPolicy, StorageError, SubmissionError, TowerClient, TowerConfig,
};
use lightning::bitcoin::{hashes::Hash, Txid};
use lightning::ln::types::ChannelId;
use mockito::{Matcher, Server};
use rusqlite::Connection;
use teos_common::{
    cryptography, protos::AddAppointmentResponse, receipts::AppointmentReceipt, TowerId,
};

mod common;

struct Fixture {
    dir: tempfile::TempDir,
    store: ClientStore,
    job: PendingAppointment,
    tower_key: lightning::bitcoin::secp256k1::SecretKey,
    tower_id: TowerId,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ClientStore::open(dir.path().join("client.sqlite")).unwrap();
        let entry = common::justice(vec![common::htlc(true, false), common::to_local(144, 0)]);
        let job = store
            .prepare_appointment(ChannelId([1; 32]), &entry)
            .unwrap()
            .pending_appointment()
            .unwrap()
            .clone();
        let (tower_key, key) = cryptography::get_random_keypair();
        Self {
            dir,
            store,
            job,
            tower_key,
            tower_id: teos_common::UserId(key),
        }
    }
    fn coordinator(&self, url: &str) -> DeliveryCoordinator {
        self.coordinator_with_policy(
            url,
            RetryPolicy::new(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                None,
            )
            .unwrap(),
        )
    }
    fn coordinator_with_policy(&self, url: &str, policy: RetryPolicy) -> DeliveryCoordinator {
        let client =
            TowerClient::new(TowerConfig::new(self.tower_id, url, Duration::from_secs(2)).unwrap())
                .unwrap();
        DeliveryCoordinator::new(client, policy, policy)
    }
    fn body(&self, job: &PendingAppointment) -> String {
        let mut receipt = AppointmentReceipt::new(job.signature().into(), 100);
        receipt.sign(&self.tower_key);
        serde_json::to_string(&AddAppointmentResponse {
            locator: job.appointment().locator.to_vec(),
            start_block: 100,
            signature: receipt.signature().unwrap(),
            available_slots: 99,
            subscription_expiry: 1000,
        })
        .unwrap()
    }
    fn add_job(&mut self, value: u8) -> PendingAppointment {
        let txid = Txid::from_byte_array([value; 32]);
        let mut entry = common::justice(vec![common::to_local_with_fee(txid, 144, 0, 1000)]);
        entry.revoked_commitment_txid = txid;
        self.store
            .prepare_appointment(ChannelId([1; 32]), &entry)
            .unwrap()
            .pending_appointment()
            .unwrap()
            .clone()
    }
    fn attempt(&mut self, coordinator: &mut DeliveryCoordinator, now: Instant) -> DeliveryAttempt {
        let (recovery, mut attempts, events) =
            coordinator.poll(&mut self.store, now).unwrap().into_parts();
        assert!(recovery.failures().is_empty());
        assert!(events.is_empty());
        assert_eq!(attempts.len(), 1);
        attempts.pop().unwrap()
    }
}

#[test]
fn rejects_invalid_retry_settings() {
    assert!(RetryPolicy::new(
        Duration::ZERO,
        Duration::from_secs(2),
        Duration::from_secs(4),
        None
    )
    .is_err());
    assert!(RetryPolicy::new(
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_secs(4),
        None
    )
    .is_err());
    assert!(RetryPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::ZERO,
        None
    )
    .is_err());
    assert!(RetryPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
        Some(Duration::ZERO)
    )
    .is_err());
}

#[tokio::test]
async fn recovers_jobs_and_skips_saved_deliveries_after_restart() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    f.store = ClientStore::open(f.dir.path().join("client.sqlite")).unwrap();
    let attempt = f.attempt(&mut coordinator, now);
    let completion = attempt.send().await;
    assert!(matches!(
        coordinator
            .finish(&mut f.store, completion, now)
            .unwrap()
            .status(),
        DeliveryStatus::Delivered
    ));
    let mut restarted = f.coordinator(&server.url());
    let (_, attempts, events) = restarted.poll(&mut f.store, now).unwrap().into_parts();
    assert!(attempts.is_empty());
    assert!(events.is_empty());
    assert!(f
        .store
        .pending_appointment(f.job.channel_id(), f.job.commitment_txid())
        .unwrap()
        .is_some());
    mock.assert_async().await;
}

#[tokio::test]
async fn retries_service_unavailable_with_capped_backoff_and_elapsed_window() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(503)
        .with_body(r#"{"error":"unavailable","error_code":32}"#)
        .expect(4)
        .create_async()
        .await;
    let start = Instant::now();
    let mut now = start;
    let mut coordinator = f.coordinator_with_policy(
        &server.url(),
        RetryPolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(6),
            None,
        )
        .unwrap(),
    );
    for (index, wait) in [1, 2, 2, 0].into_iter().enumerate() {
        let completion = f.attempt(&mut coordinator, now).send().await;
        let event = coordinator.finish(&mut f.store, completion, now).unwrap();
        if index < 3 {
            now += Duration::from_secs(wait);
            assert!(
                matches!(event.status(), DeliveryStatus::RetryScheduled { next_attempt_at, .. } if *next_attempt_at == now)
            );
            assert_eq!(coordinator.next_retry_at(), Some(now));
            assert!(coordinator
                .poll(&mut f.store, now - Duration::from_millis(1))
                .unwrap()
                .attempts()
                .is_empty());
        } else {
            assert!(matches!(event.status(), DeliveryStatus::Exhausted { .. }));
        }
    }
    assert!(coordinator
        .poll(&mut f.store, now + Duration::from_secs(100))
        .unwrap()
        .attempts()
        .is_empty());
    mock.assert_async().await;
}

#[tokio::test]
async fn does_not_retry_subscription_payload_triggered_or_unknown_rejections() {
    for code in [7, 33, 34, 35, 999] {
        let mut server = Server::new_async().await;
        let mut f = Fixture::new();
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(503)
            .with_body(serde_json::json!({"error":"rejected", "error_code":code}).to_string())
            .expect(1)
            .create_async()
            .await;
        let register = server
            .mock("POST", "/register")
            .expect(0)
            .create_async()
            .await;
        let now = Instant::now();
        let mut coordinator = f.coordinator_with_policy(
            &server.url(),
            RetryPolicy::new(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Some(Duration::from_secs(10)),
            )
            .unwrap(),
        );
        let completion = f.attempt(&mut coordinator, now).send().await;
        assert!(
            matches!(coordinator.finish(&mut f.store, completion, now).unwrap().status(), DeliveryStatus::Stopped { error: SubmissionError::Rejected { error_code: Some(returned), .. } } if *returned == code)
        );
        assert!(coordinator
            .poll(&mut f.store, now + Duration::from_secs(100))
            .unwrap()
            .attempts()
            .is_empty());
        mock.assert_async().await;
        register.assert_async().await;
    }
}

#[tokio::test]
async fn receipt_save_retries_do_not_resend_and_retain_verified_receipts_when_exhausted() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON appointment_receipts BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    let completion = f.attempt(&mut coordinator, now).send().await;
    assert!(matches!(
        coordinator
            .finish(&mut f.store, completion, now)
            .unwrap()
            .status(),
        DeliveryStatus::StorageFailure {
            next_attempt_at: Some(_),
            ..
        }
    ));
    for offset in [1, 3] {
        let (_, attempts, events) = coordinator
            .poll(&mut f.store, now + Duration::from_secs(offset))
            .unwrap()
            .into_parts();
        assert!(attempts.is_empty());
        assert!(matches!(
            events[0].status(),
            DeliveryStatus::StorageFailure { .. }
        ));
    }
    assert_eq!(coordinator.unsaved_receipts().count(), 1);
    assert_eq!(coordinator.next_retry_at(), None);
    db.execute_batch("DROP TRIGGER fail_receipt").unwrap();
    assert!(coordinator.retry_job(
        f.job.channel_id(),
        f.job.commitment_txid(),
        now + Duration::from_secs(4)
    ));
    let (_, attempts, events) = coordinator
        .poll(&mut f.store, now + Duration::from_secs(4))
        .unwrap()
        .into_parts();
    assert!(attempts.is_empty());
    assert!(matches!(events[0].status(), DeliveryStatus::Delivered));
    assert_eq!(coordinator.unsaved_receipts().count(), 0);
    mock.assert_async().await;
}

#[tokio::test]
async fn corrupt_rows_and_rejected_jobs_do_not_block_healthy_jobs() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let rejected = f.add_job(8);
    let healthy = f.add_job(9);
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute(
        "UPDATE pending_appointments SET signature='bad' WHERE commitment_txid=?1",
        [&f.job.commitment_txid().to_byte_array()[..]],
    )
    .unwrap();
    let bad = server
        .mock("POST", "/add_appointment")
        .match_body(Matcher::PartialJson(
            serde_json::json!({"signature":rejected.signature()}),
        ))
        .with_status(400)
        .with_body(r#"{"error":"invalid","error_code":33}"#)
        .expect(1)
        .create_async()
        .await;
    let good = server
        .mock("POST", "/add_appointment")
        .match_body(Matcher::PartialJson(
            serde_json::json!({"signature":healthy.signature()}),
        ))
        .with_status(200)
        .with_body(f.body(&healthy))
        .expect(1)
        .create_async()
        .await;
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    let (recovery, attempts, _) = coordinator.poll(&mut f.store, now).unwrap().into_parts();
    assert_eq!(recovery.failures().len(), 1);
    assert_eq!(attempts.len(), 2);
    let mut delivered = 0;
    for attempt in attempts {
        if matches!(
            coordinator
                .finish(&mut f.store, attempt.send().await, now)
                .unwrap()
                .status(),
            DeliveryStatus::Delivered
        ) {
            delivered += 1;
        }
    }
    assert_eq!(delivered, 1);
    bad.assert_async().await;
    good.assert_async().await;
}

#[tokio::test]
async fn in_flight_attempts_are_not_duplicated_and_dropped_attempts_can_retry() {
    let mut f = Fixture::new();
    let now = Instant::now();
    let mut coordinator = f.coordinator("http://127.0.0.1:0");
    let attempt = f.attempt(&mut coordinator, now);
    assert!(coordinator
        .poll(&mut f.store, now)
        .unwrap()
        .attempts()
        .is_empty());
    drop(attempt);
    let (_, attempts, events) = coordinator.poll(&mut f.store, now).unwrap().into_parts();
    assert!(attempts.is_empty());
    assert!(matches!(
        events[0].status(),
        DeliveryStatus::Cancelled {
            next_attempt_at: Some(_)
        }
    ));
    assert_eq!(
        coordinator
            .poll(&mut f.store, now + Duration::from_secs(1))
            .unwrap()
            .attempts()
            .len(),
        1
    );
}

#[tokio::test]
async fn retries_then_delivers_and_skips_the_persisted_receipt() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    let failed = server
        .mock("POST", "/add_appointment")
        .with_status(503)
        .with_body(r#"{"error":"unavailable","error_code":32}"#)
        .expect(1)
        .create_async()
        .await;
    let completion = f.attempt(&mut coordinator, now).send().await;
    coordinator.finish(&mut f.store, completion, now).unwrap();
    failed.assert_async().await;
    drop(failed);
    let good = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let due = now + Duration::from_secs(1);
    let completion = f.attempt(&mut coordinator, due).send().await;
    assert!(matches!(
        coordinator
            .finish(&mut f.store, completion, due)
            .unwrap()
            .status(),
        DeliveryStatus::Delivered
    ));
    assert!(coordinator
        .poll(&mut f.store, due)
        .unwrap()
        .attempts()
        .is_empty());
    good.assert_async().await;
}

#[tokio::test]
async fn classifies_connection_failures_proxy_errors_and_invalid_responses() {
    let mut f = Fixture::new();
    let now = Instant::now();
    let mut coordinator = f.coordinator("http://127.0.0.1:0");
    let completion = f.attempt(&mut coordinator, now).send().await;
    assert!(matches!(
        coordinator
            .finish(&mut f.store, completion, now)
            .unwrap()
            .status(),
        DeliveryStatus::RetryScheduled {
            error: SubmissionError::Request(_),
            ..
        }
    ));
    for (status, invalid_signature) in [(502, false), (429, false), (200, false), (200, true)] {
        let mut server = Server::new_async().await;
        let body = if invalid_signature {
            let mut response: serde_json::Value = serde_json::from_str(&f.body(&f.job)).unwrap();
            response["signature"] = serde_json::json!("invalid");
            response.to_string()
        } else {
            "<html>unavailable</html>".into()
        };
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(status)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let mut coordinator = f.coordinator(&server.url());
        let completion = f.attempt(&mut coordinator, now).send().await;
        let event = coordinator.finish(&mut f.store, completion, now).unwrap();
        if status != 200 {
            assert!(matches!(
                event.status(),
                DeliveryStatus::RetryScheduled { .. }
            ));
        } else if invalid_signature {
            assert!(matches!(
                event.status(),
                DeliveryStatus::Stopped {
                    error: SubmissionError::InvalidSignature
                }
            ));
        } else {
            assert!(matches!(
                event.status(),
                DeliveryStatus::Stopped {
                    error: SubmissionError::InvalidResponse(_)
                }
            ));
        }
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn refuses_a_completion_from_another_coordinator() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let now = Instant::now();
    let mut issuer = f.coordinator(&server.url());
    let mut other = f.coordinator(&server.url());
    let completion = f.attempt(&mut issuer, now).send().await;
    assert!(other.finish(&mut f.store, completion, now).is_err());
    assert!(f
        .store
        .appointment_receipt(f.tower_id, f.job.channel_id(), f.job.commitment_txid())
        .unwrap()
        .is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn poll_skips_corrupt_historical_receipts_while_explicit_loading_reports_them() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    let completion = f.attempt(&mut coordinator, now).send().await;
    coordinator.finish(&mut f.store, completion, now).unwrap();
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute("UPDATE appointment_receipts SET tower_signature='bad'", [])
        .unwrap();
    let (_, attempts, events) = coordinator.poll(&mut f.store, now).unwrap().into_parts();
    assert!(attempts.is_empty());
    assert!(events.is_empty());
    assert!(matches!(
        f.store
            .appointment_receipt(f.tower_id, f.job.channel_id(), f.job.commitment_txid()),
        Err(StorageError::InvalidAppointmentReceipt)
    ));
    mock.assert_async().await;
}

#[tokio::test]
async fn a_job_corrupted_during_save_backoff_stops_retries_and_keeps_the_receipt() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON appointment_receipts BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    let completion = f.attempt(&mut coordinator, now).send().await;
    coordinator.finish(&mut f.store, completion, now).unwrap();
    db.execute("UPDATE pending_appointments SET signature='bad'", [])
        .unwrap();
    let (recovery, attempts, events) = coordinator
        .poll(&mut f.store, now + Duration::from_secs(1))
        .unwrap()
        .into_parts();
    assert_eq!(recovery.failures().len(), 1);
    assert!(attempts.is_empty());
    assert!(matches!(
        events[0].status(),
        DeliveryStatus::StorageFailure {
            error: StorageError::InvalidPendingAppointment,
            next_attempt_at: None
        }
    ));
    assert_eq!(coordinator.next_retry_at(), None);
    assert_eq!(coordinator.unsaved_receipts().count(), 1);
    mock.assert_async().await;
}

#[test]
fn defaults_allow_long_outages_and_optional_automatic_rearming() {
    let policy = RetryPolicy::default();
    assert_eq!(policy.initial_delay(), Duration::from_secs(1));
    assert_eq!(policy.max_delay(), Duration::from_secs(60));
    assert_eq!(policy.max_elapsed_time(), Duration::from_secs(3600));
    assert_eq!(
        policy.auto_retry_delay(),
        Some(Duration::from_secs(8 * 3600))
    );
}

#[tokio::test]
async fn retryable_exhaustion_cools_down_then_starts_a_new_cycle() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(503)
        .with_body(r#"{"error":"unavailable","error_code":32}"#)
        .expect(4)
        .create_async()
        .await;
    let policy = RetryPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let mut coordinator = f.coordinator_with_policy(&server.url(), policy);
    let start = Instant::now();
    for offset in [0, 1, 3] {
        let now = start + Duration::from_secs(offset);
        let completion = f.attempt(&mut coordinator, now).send().await;
        let event = coordinator.finish(&mut f.store, completion, now).unwrap();
        if offset == 3 {
            assert!(
                matches!(event.status(), DeliveryStatus::CoolingDown { next_attempt_at, .. } if *next_attempt_at == start + Duration::from_secs(14))
            );
        }
    }
    assert!(coordinator
        .poll(&mut f.store, start + Duration::from_secs(13))
        .unwrap()
        .attempts()
        .is_empty());
    assert_eq!(
        coordinator.next_retry_at(),
        Some(start + Duration::from_secs(14))
    );
    let completion = f
        .attempt(&mut coordinator, start + Duration::from_secs(14))
        .send()
        .await;
    let event = coordinator
        .finish(&mut f.store, completion, start + Duration::from_secs(14))
        .unwrap();
    assert!(
        matches!(event.status(), DeliveryStatus::RetryScheduled { next_attempt_at, .. } if *next_attempt_at == start + Duration::from_secs(15))
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn persistence_has_its_own_window_and_cooldown_without_resending() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON appointment_receipts BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let client = TowerClient::new(
        TowerConfig::new(f.tower_id, &server.url(), Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let save_policy = RetryPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let mut coordinator = DeliveryCoordinator::new(client, RetryPolicy::default(), save_policy);
    let start = Instant::now();
    let completion = f.attempt(&mut coordinator, start).send().await;
    coordinator.finish(&mut f.store, completion, start).unwrap();
    let (_, attempts, events) = coordinator
        .poll(&mut f.store, start + Duration::from_secs(1))
        .unwrap()
        .into_parts();
    assert!(attempts.is_empty());
    assert!(
        matches!(events[0].status(), DeliveryStatus::StorageFailure { next_attempt_at: Some(at), .. } if *at == start + Duration::from_secs(12))
    );
    db.execute_batch("DROP TRIGGER fail_receipt").unwrap();
    assert!(coordinator
        .poll(&mut f.store, start + Duration::from_secs(11))
        .unwrap()
        .events()
        .is_empty());
    let (_, attempts, events) = coordinator
        .poll(&mut f.store, start + Duration::from_secs(12))
        .unwrap()
        .into_parts();
    assert!(attempts.is_empty());
    assert!(matches!(events[0].status(), DeliveryStatus::Delivered));
    assert_eq!(coordinator.unsaved_receipts().count(), 0);
    mock.assert_async().await;
}

#[tokio::test]
async fn a_receipt_recorded_during_an_in_flight_send_does_not_invalidate_completion() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let mut coordinator = f.coordinator(&server.url());
    let now = Instant::now();
    let completion = f.attempt(&mut coordinator, now).send().await;
    // Simulate another delivery path recording the same valid receipt.
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    let response: AddAppointmentResponse = serde_json::from_str(&f.body(&f.job)).unwrap();
    db.execute(
        "INSERT INTO appointment_receipts VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            f.tower_id.to_vec(),
            &f.job.channel_id().0[..],
            &f.job.commitment_txid().to_byte_array()[..],
            f.job.signature(),
            response.start_block,
            response.signature
        ],
    )
    .unwrap();
    assert!(coordinator
        .poll(&mut f.store, now)
        .unwrap()
        .attempts()
        .is_empty());
    assert!(matches!(
        coordinator
            .finish(&mut f.store, completion, now)
            .unwrap()
            .status(),
        DeliveryStatus::Delivered
    ));
    mock.assert_async().await;
}

#[test]
fn removed_waiting_jobs_are_reported_pruned_and_can_be_discovered_again() {
    let mut f = Fixture::new();
    let now = Instant::now();
    let mut coordinator = f.coordinator("http://127.0.0.1:0");
    drop(f.attempt(&mut coordinator, now));
    coordinator.poll(&mut f.store, now).unwrap();
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute("DELETE FROM pending_appointments", []).unwrap();
    let (_, attempts, events) = coordinator.poll(&mut f.store, now).unwrap().into_parts();
    assert!(attempts.is_empty());
    assert!(matches!(events[0].status(), DeliveryStatus::Removed));
    assert_eq!(coordinator.next_retry_at(), None);
    // Restore the identical payload for this test; never change plaintext under
    // the same commitment-derived key and fixed nonce in a recovery policy.
    let entry = common::justice(vec![common::to_local(144, 0)]);
    f.store
        .prepare_appointment(f.job.channel_id(), &entry)
        .unwrap();
    assert_eq!(
        coordinator
            .poll(&mut f.store, now)
            .unwrap()
            .attempts()
            .len(),
        1
    );
}

#[tokio::test]
async fn delivered_history_is_filtered_before_validation_and_per_tower() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    let completion = f.attempt(&mut coordinator, now).send().await;
    coordinator.finish(&mut f.store, completion, now).unwrap();
    let other_tower = teos_common::UserId(cryptography::get_random_keypair().1);
    assert_eq!(
        f.store
            .undelivered_appointments(other_tower)
            .unwrap()
            .jobs()
            .len(),
        1
    );
    let db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute("UPDATE pending_appointments SET signature='bad'", [])
        .unwrap();
    for _ in 0..2 {
        let (recovery, attempts, events) =
            coordinator.poll(&mut f.store, now).unwrap().into_parts();
        assert!(recovery.jobs().is_empty());
        // A historical corrupt job would fail validation if the filter ran later.
        assert!(recovery.failures().is_empty());
        assert!(attempts.is_empty());
        assert!(events.is_empty());
    }
    assert_eq!(f.store.pending_appointments().unwrap().failures().len(), 1);
    mock.assert_async().await;
}

#[tokio::test]
async fn late_polling_enters_cooldown_instead_of_sending_outside_the_window() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(503)
        .with_body("unavailable")
        .expect(1)
        .create_async()
        .await;
    let policy = RetryPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let mut coordinator = f.coordinator_with_policy(&server.url(), policy);
    let start = Instant::now();
    let completion = f.attempt(&mut coordinator, start).send().await;
    coordinator.finish(&mut f.store, completion, start).unwrap();
    let (_, attempts, events) = coordinator
        .poll(&mut f.store, start + Duration::from_secs(4))
        .unwrap()
        .into_parts();
    assert!(attempts.is_empty());
    assert!(
        matches!(events[0].status(), DeliveryStatus::RetryWindowElapsed { next_attempt_at: Some(at) } if *at == start + Duration::from_secs(14))
    );
    assert_eq!(
        coordinator
            .poll(&mut f.store, start + Duration::from_secs(14))
            .unwrap()
            .attempts()
            .len(),
        1
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn request_time_counts_toward_the_window_and_code_255_is_retryable() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(500)
        .with_body(r#"{"error":"internal error","error_code":255}"#)
        .expect(1)
        .create_async()
        .await;
    let policy = RetryPolicy::new(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let mut coordinator = f.coordinator_with_policy(&server.url(), policy);
    let start = Instant::now();
    let completion = f.attempt(&mut coordinator, start).send().await;
    let event = coordinator
        .finish(&mut f.store, completion, start + Duration::from_secs(5))
        .unwrap();
    assert!(
        matches!(event.status(), DeliveryStatus::CoolingDown { next_attempt_at, .. } if *next_attempt_at == start + Duration::from_secs(15))
    );
    mock.assert_async().await;
}

// Repeatable discovery benchmark. Run with --release -- --ignored --nocapture;
// TEOS_BENCH_JOBS controls history size. Timings are diagnostic, never assertions.
#[tokio::test]
#[ignore = "manual performance measurement with delivered history"]
async fn benchmark_poll_with_delivered_history() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job))
        .expect(1)
        .create_async()
        .await;
    let now = Instant::now();
    let mut coordinator = f.coordinator(&server.url());
    let completion = f.attempt(&mut coordinator, now).send().await;
    coordinator.finish(&mut f.store, completion, now).unwrap();
    let count = std::env::var("TEOS_BENCH_JOBS")
        .ok()
        .map(|value| value.parse::<u32>().unwrap())
        .unwrap_or(2000)
        .max(1);
    let mut db = Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    let tx = db.transaction().unwrap();
    // Clone the valid seed job/receipt under distinct channel IDs. The signed
    // payload is identical, so this does not reuse a nonce with changed plaintext.
    for value in 1..count {
        let mut channel = [0u8; 32];
        channel[..4].copy_from_slice(&value.to_be_bytes());
        tx.execute("INSERT INTO pending_appointments SELECT ?1, commitment_txid, user_id, locator, encrypted_blob, to_self_delay, signature FROM pending_appointments WHERE channel_id=?2", rusqlite::params![&channel[..], &f.job.channel_id().0[..]]).unwrap();
        tx.execute("INSERT INTO appointment_receipts SELECT tower_id, ?1, commitment_txid, user_signature, start_block, tower_signature FROM appointment_receipts WHERE tower_id=?3 AND channel_id=?2", rusqlite::params![&channel[..], &f.job.channel_id().0[..], f.tower_id.to_vec()]).unwrap();
    }
    tx.commit().unwrap();
    for poll in 1..=5 {
        let started = Instant::now();
        let (recovery, attempts, events) =
            coordinator.poll(&mut f.store, now).unwrap().into_parts();
        let elapsed = started.elapsed();
        assert!(recovery.jobs().is_empty());
        assert!(recovery.failures().is_empty());
        assert!(attempts.is_empty());
        assert!(events.is_empty());
        eprintln!("{count} delivered jobs, poll {poll}: {elapsed:?}");
    }
    mock.assert_async().await;
}

#[tokio::test]
async fn default_network_policy_keeps_retrying_beyond_three_seconds() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(503)
        .with_body("unavailable")
        .expect(4)
        .create_async()
        .await;
    let mut coordinator = f.coordinator_with_policy(&server.url(), RetryPolicy::default());
    let start = Instant::now();
    for (offset, next_offset) in [(0, 1), (1, 3), (3, 7), (7, 15)] {
        let now = start + Duration::from_secs(offset);
        let completion = f.attempt(&mut coordinator, now).send().await;
        let event = coordinator.finish(&mut f.store, completion, now).unwrap();
        assert!(
            matches!(event.status(), DeliveryStatus::RetryScheduled { next_attempt_at, .. } if *next_attempt_at == start + Duration::from_secs(next_offset))
        );
    }
    mock.assert_async().await;
}
