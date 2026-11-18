use std::sync::Arc;
use std::time::{Duration, Instant};

use ldk_watchtower_client::{
    ClientStore, DeliveryAttempt, DeliveryCoordinator, LdkAdapterEvent, LdkWatchtowerAdapter,
    LdkWatchtowerWorker, PendingAppointment, RetryPolicy, TowerClient, TowerConfig,
};
use lightning::chain::chainmonitor::WatchtowerPersist;
use lightning::ln::types::ChannelId;
use lightning::sign::InMemorySigner as LdkSigner;
use lightning::util::logger::{Logger, Record};

struct NoopLogger;
impl Logger for NoopLogger {
    fn log(&self, _: Record<'_>) {}
}
type InMemorySigner = LdkSigner<NoopLogger>;
use lightning::util::wakers::Notifier;
use mockito::{Matcher, Server};
use teos_common::{
    cryptography, protos::AddAppointmentResponse, receipts::AppointmentReceipt, TowerId,
};

mod common;

const CHANNEL: ChannelId = ChannelId([1; 32]);
struct Fixture {
    dir: tempfile::TempDir,
    worker: LdkWatchtowerWorker,
    adapter: LdkWatchtowerAdapter,
    towers: Vec<(TowerId, lightning::bitcoin::secp256k1::SecretKey)>,
}
impl Fixture {
    fn new(urls: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = ClientStore::open(dir.path().join("client.sqlite")).unwrap();
        let mut towers = Vec::new();
        let coordinators = urls
            .iter()
            .map(|url| {
                let (key, public) = cryptography::get_random_keypair();
                let id = teos_common::UserId(public);
                towers.push((id, key));
                let client =
                    TowerClient::new(TowerConfig::new(id, url, Duration::from_secs(2)).unwrap())
                        .unwrap();
                DeliveryCoordinator::new(client, RetryPolicy::default(), RetryPolicy::default())
            })
            .collect();
        let worker = LdkWatchtowerWorker::new(
            store,
            coordinators,
            1000,
            common::to_local(144, 0).output[0].script_pubkey.clone(),
        )
        .unwrap();
        let adapter = worker.adapter();
        Self {
            dir,
            worker,
            adapter,
            towers,
        }
    }
    fn body(&self, job: &PendingAppointment, tower: usize) -> String {
        let mut receipt = AppointmentReceipt::new(job.signature().into(), 100);
        receipt.sign(&self.towers[tower].1);
        serde_json::to_string(&AddAppointmentResponse {
            locator: job.appointment().locator.to_vec(),
            start_block: 100,
            signature: receipt.signature().unwrap(),
            available_slots: 99,
            subscription_expiry: 1000,
        })
        .unwrap()
    }
    fn attempts(&mut self, now: Instant) -> (Vec<DeliveryAttempt>, Vec<LdkAdapterEvent>) {
        let (batches, events) = self.worker.poll(now).into_parts();
        let mut attempts = Vec::new();
        for (_, batch) in batches {
            let (recovery, due, _) = batch.into_parts();
            assert!(recovery.failures().is_empty());
            attempts.extend(due);
        }
        (attempts, events)
    }
    fn job(&self) -> PendingAppointment {
        self.worker.store().pending_appointments().unwrap().jobs()[0].clone()
    }
}
fn completed(adapter: &LdkWatchtowerAdapter) -> Vec<(ChannelId, lightning::bitcoin::Txid)> {
    <LdkWatchtowerAdapter as WatchtowerPersist<InMemorySigner>>::get_and_clear_completed_justice_persists(adapter)
}

#[tokio::test]
async fn acknowledges_only_after_a_verified_receipt_is_saved_and_notifies_ldk() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LdkWatchtowerAdapter>();
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let notifier = Arc::new(Notifier::new());
    <LdkWatchtowerAdapter as WatchtowerPersist<InMemorySigner>>::register_event_notifier(
        &f.adapter,
        notifier.clone(),
    );
    let wake = notifier.get_future();
    let entry = common::justice(vec![common::to_local(144, 0)]);
    let txid = entry.revoked_commitment_txid;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
    let now = Instant::now();
    let (mut attempts, events) = f.attempts(now);
    assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::Coverage { coverage, .. } if coverage.is_complete())));
    assert!(completed(&f.adapter).is_empty());
    let job = f.job();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 0))
        .expect(1)
        .create_async()
        .await;
    let completion = attempts.pop().unwrap().send().await;
    assert!(completed(&f.adapter).is_empty());
    let events = f.worker.finish(completion, now).unwrap();
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::AcknowledgmentQueued { .. })));
    tokio::time::timeout(Duration::from_secs(1), wake)
        .await
        .unwrap();
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    assert!(completed(&f.adapter).is_empty());
    assert!(f
        .worker
        .store()
        .appointment_receipt(f.towers[0].0, CHANNEL, txid)
        .unwrap()
        .is_some());
    mock.assert_async().await;
}

#[tokio::test]
async fn htlc_unknown_and_missing_claims_are_not_acknowledged() {
    let mut unknown = common::to_local(144, 1);
    unknown.input[0].witness.clear();
    for txs in [
        vec![common::to_local(144, 0), common::htlc(true, false)],
        vec![common::to_local(144, 0), unknown],
        vec![common::htlc(false, true)],
        vec![],
    ] {
        let mut server = Server::new_async().await;
        let mut f = Fixture::new(&[&server.url()]);
        f.adapter
            .queue_justice_transactions(CHANNEL, Ok(vec![common::justice(txs)]));
        let now = Instant::now();
        let (attempts, events) = f.attempts(now);
        assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::Coverage { coverage, .. } if !coverage.is_complete())));
        for attempt in attempts {
            let mock = server
                .mock("POST", "/add_appointment")
                .with_status(200)
                .with_body(f.body(attempt.job(), 0))
                .expect(1)
                .create_async()
                .await;
            f.worker.finish(attempt.send().await, now).unwrap();
            mock.assert_async().await;
        }
        assert!(completed(&f.adapter).is_empty());
    }
}

#[tokio::test]
async fn saved_receipts_allow_repeated_offers_without_resending_and_preserve_fee_payload() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let entry = common::justice(vec![common::to_local(144, 0)]);
    let txid = entry.revoked_commitment_txid;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry.clone()]));
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    assert_eq!(attempts.len(), 1);
    let original = f.job();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&original, 0))
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local_with_fee(
            txid, 144, 0, 2000,
        )])]),
    );
    assert!(f.attempts(now).0.is_empty());
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    assert_eq!(f.job(), original);
    mock.assert_async().await;
}

#[tokio::test]
async fn new_incomplete_or_unavailable_snapshots_invalidate_queued_acknowledgments() {
    for unavailable in [false, true] {
        let mut server = Server::new_async().await;
        let mut f = Fixture::new(&[&server.url()]);
        f.adapter.queue_justice_transactions(
            CHANNEL,
            Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
        );
        let now = Instant::now();
        let (mut attempts, _) = f.attempts(now);
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(200)
            .with_body(f.body(&f.job(), 0))
            .expect(1)
            .create_async()
            .await;
        f.worker
            .finish(attempts.pop().unwrap().send().await, now)
            .unwrap();
        let snapshot = if unavailable {
            Err(())
        } else {
            Ok(vec![common::justice(vec![
                common::to_local(144, 0),
                common::htlc(true, false),
            ])])
        };
        f.adapter.queue_justice_transactions(CHANNEL, snapshot);
        assert!(completed(&f.adapter).is_empty());
        let (_, events) = f.attempts(now);
        if unavailable {
            assert!(events
                .iter()
                .any(|event| matches!(event, LdkAdapterEvent::SignerUnavailable { .. })));
        }
        assert!(completed(&f.adapter).is_empty());
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn every_required_tower_must_have_a_persisted_receipt() {
    let mut first = Server::new_async().await;
    let mut second = Server::new_async().await;
    let mut f = Fixture::new(&[&first.url(), &second.url()]);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let now = Instant::now();
    let (attempts, _) = f.attempts(now);
    let job = f.job();
    let first_mock = first
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 0))
        .expect(1)
        .create_async()
        .await;
    let failed = second
        .mock("POST", "/add_appointment")
        .with_status(503)
        .with_body("unavailable")
        .expect(1)
        .create_async()
        .await;
    for attempt in attempts {
        f.worker.finish(attempt.send().await, now).unwrap();
    }
    assert!(completed(&f.adapter).is_empty());
    failed.assert_async().await;
    drop(failed);
    let good = second
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 1))
        .expect(1)
        .create_async()
        .await;
    let (mut retry, _) = f.attempts(now + Duration::from_secs(1));
    assert_eq!(retry.len(), 1);
    f.worker
        .finish(
            retry.pop().unwrap().send().await,
            now + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    first_mock.assert_async().await;
    good.assert_async().await;
}

#[tokio::test]
async fn failed_receipt_saves_do_not_ack_and_successful_local_retry_does() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job(), 0))
        .expect(1)
        .create_async()
        .await;
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON appointment_receipts BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    f.worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert!(completed(&f.adapter).is_empty());
    assert_eq!(f.worker.unsaved_receipts().count(), 1);
    db.execute_batch("DROP TRIGGER fail_receipt").unwrap();
    assert!(f.attempts(now + Duration::from_secs(1)).0.is_empty());
    assert_eq!(completed(&f.adapter).len(), 1);
    assert_eq!(f.worker.unsaved_receipts().count(), 0);
    mock.assert_async().await;
}

#[tokio::test]
async fn a_covered_commitment_completes_independently_of_an_htlc_commitment() {
    use lightning::bitcoin::{hashes::Hash, Txid};
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let txid = Txid::from_byte_array([8; 32]);
    let mut covered = common::justice(vec![common::to_local_with_fee(txid, 144, 0, 1000)]);
    covered.revoked_commitment_txid = txid;
    let incomplete = common::justice(vec![common::to_local(144, 0), common::htlc(true, false)]);
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![incomplete, covered]));
    let now = Instant::now();
    let (attempts, _) = f.attempts(now);
    assert_eq!(attempts.len(), 2);
    for attempt in attempts {
        let mock = server
            .mock("POST", "/add_appointment")
            .match_body(Matcher::PartialJson(
                serde_json::json!({"signature":attempt.job().signature()}),
            ))
            .with_status(200)
            .with_body(f.body(attempt.job(), 0))
            .expect(1)
            .create_async()
            .await;
        f.worker.finish(attempt.send().await, now).unwrap();
        mock.assert_async().await;
    }
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
}

#[tokio::test]
async fn preparing_can_retry_after_storage_repair_without_a_new_ldk_offer() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_job BEFORE INSERT ON pending_appointments BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let now = Instant::now();
    let (attempts, events) = f.attempts(now);
    assert!(attempts.is_empty());
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::PreparationFailed { .. })));
    assert!(f.worker.has_pending_preparations());
    assert!(completed(&f.adapter).is_empty());
    db.execute_batch("DROP TRIGGER fail_job").unwrap();
    let (mut attempts, _) = f.attempts(now);
    assert!(!f.worker.has_pending_preparations());
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job(), 0))
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert_eq!(completed(&f.adapter).len(), 1);
    mock.assert_async().await;
}

#[test]
fn requires_a_nonempty_unique_tower_set_and_valid_signing_settings() {
    use ldk_watchtower_client::LdkAdapterConfigError;
    use lightning::bitcoin::ScriptBuf;
    let destination = common::to_local(144, 0).output[0].script_pubkey.clone();
    assert!(matches!(
        LdkWatchtowerWorker::new(
            ClientStore::open(":memory:").unwrap(),
            vec![],
            1000,
            destination.clone()
        ),
        Err(LdkAdapterConfigError::NoTowers)
    ));
    assert!(matches!(
        LdkWatchtowerWorker::new(
            ClientStore::open(":memory:").unwrap(),
            vec![],
            0,
            destination.clone()
        ),
        Err(LdkAdapterConfigError::ZeroFeeRate)
    ));
    assert!(matches!(
        LdkWatchtowerWorker::new(
            ClientStore::open(":memory:").unwrap(),
            vec![],
            1000,
            ScriptBuf::new()
        ),
        Err(LdkAdapterConfigError::EmptyDestination)
    ));
    let tower_id = teos_common::UserId(cryptography::get_random_keypair().1);
    let client = TowerClient::new(
        TowerConfig::new(tower_id, "http://127.0.0.1:0", Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    let make = || {
        DeliveryCoordinator::new(
            client.clone(),
            RetryPolicy::default(),
            RetryPolicy::default(),
        )
    };
    assert!(
        matches!(LdkWatchtowerWorker::new(ClientStore::open(":memory:").unwrap(), vec![make(), make()], 1000, destination), Err(LdkAdapterConfigError::DuplicateTower(id)) if id == tower_id)
    );
}

#[tokio::test]
async fn restart_reconstructs_eligibility_and_uses_saved_receipts() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let entry = common::justice(vec![common::to_local(144, 0)]);
    let txid = entry.revoked_commitment_txid;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry.clone()]));
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job(), 0))
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    let store = ClientStore::open(f.dir.path().join("client.sqlite")).unwrap();
    let client = TowerClient::new(
        TowerConfig::new(f.towers[0].0, &server.url(), Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    f.worker = LdkWatchtowerWorker::new(
        store,
        vec![DeliveryCoordinator::new(
            client,
            RetryPolicy::default(),
            RetryPolicy::default(),
        )],
        1000,
        common::to_local(144, 0).output[0].script_pubkey.clone(),
    )
    .unwrap();
    f.adapter = f.worker.adapter();
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
    assert!(f.attempts(now).0.is_empty());
    // Registering LDK's notifier after completion was queued must still wake it.
    let notifier = Arc::new(Notifier::new());
    <LdkWatchtowerAdapter as WatchtowerPersist<InMemorySigner>>::register_event_notifier(
        &f.adapter,
        notifier.clone(),
    );
    tokio::time::timeout(Duration::from_secs(1), notifier.get_future())
        .await
        .unwrap();
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    mock.assert_async().await;
}

#[tokio::test]
async fn duplicate_entries_and_ambiguous_to_local_claims_do_not_authorize_ack() {
    for entries in [
        vec![common::justice(vec![
            common::to_local(144, 0),
            common::to_local(144, 1),
        ])],
        vec![
            common::justice(vec![common::to_local(144, 0)]),
            common::justice(vec![common::to_local(144, 0)]),
        ],
    ] {
        let mut f = Fixture::new(&["http://127.0.0.1:0"]);
        f.adapter.queue_justice_transactions(CHANNEL, Ok(entries));
        let (attempts, events) = f.attempts(Instant::now());
        assert!(attempts.is_empty());
        assert!(events.iter().any(|event| matches!(
            event,
            LdkAdapterEvent::PreparationFailed { .. } | LdkAdapterEvent::DuplicateCommitment { .. }
        )));
        assert!(completed(&f.adapter).is_empty());
    }
}

#[tokio::test]
async fn a_saved_payload_for_another_outpoint_cannot_cover_a_new_offer() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job(), 0))
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert_eq!(completed(&f.adapter).len(), 1);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 1)])]),
    );
    let (attempts, events) = f.attempts(now);
    assert!(attempts.is_empty());
    assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::Coverage { coverage, .. } if coverage.to_local() && !coverage.stored_claim_matches() && !coverage.is_complete())));
    assert!(completed(&f.adapter).is_empty());
    mock.assert_async().await;
}

#[tokio::test]
async fn a_new_signer_failure_blocks_completion_of_an_older_in_flight_snapshot() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job(), 0))
        .expect(1)
        .create_async()
        .await;
    let completion = attempts.pop().unwrap().send().await;
    let wake = f.adapter.work_available();
    f.adapter.queue_justice_transactions(CHANNEL, Err(()));
    tokio::time::timeout(Duration::from_secs(1), wake)
        .await
        .unwrap();
    f.worker.finish(completion, now).unwrap();
    assert!(completed(&f.adapter).is_empty());
    let (_, events) = f.attempts(now);
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::SignerUnavailable { .. })));
    assert!(completed(&f.adapter).is_empty());
    mock.assert_async().await;
}

#[test]
fn a_receipt_for_a_replaced_database_job_cannot_satisfy_an_old_snapshot() {
    use lightning::bitcoin::hashes::Hash;
    let mut f = Fixture::new(&["http://127.0.0.1:0"]);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let now = Instant::now();
    let (attempts, _) = f.attempts(now);
    let original = f.job();
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    // Deliberately simulate an unsupported database replacement, not a production
    // recovery policy: changed plaintext must not reuse TEOS's fixed nonce/key.
    db.execute("DELETE FROM pending_appointments", []).unwrap();
    f.worker
        .store_mut()
        .prepare_appointment(CHANNEL, &common::justice(vec![common::to_local(144, 1)]))
        .unwrap();
    let replacement = f.job();
    assert_ne!(replacement.signature(), original.signature());
    let response: AddAppointmentResponse = serde_json::from_str(&f.body(&replacement, 0)).unwrap();
    db.execute(
        "INSERT INTO appointment_receipts VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            f.towers[0].0.to_vec(),
            &CHANNEL.0[..],
            &replacement.commitment_txid().to_byte_array()[..],
            replacement.signature(),
            response.start_block,
            response.signature
        ],
    )
    .unwrap();
    assert!(f
        .worker
        .store()
        .appointment_receipt(f.towers[0].0, CHANNEL, replacement.commitment_txid())
        .unwrap()
        .is_some());
    let (_, events) = f.attempts(now);
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::ReceiptCheckFailed { .. })));
    assert!(completed(&f.adapter).is_empty());
    drop(attempts);
}

#[tokio::test]
async fn stopped_jobs_require_explicit_rearming_without_automatic_registration() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    let job = f.job();
    let register = server
        .mock("POST", "/register")
        .expect(0)
        .create_async()
        .await;
    let rejected = server
        .mock("POST", "/add_appointment")
        .with_status(401)
        .with_body(r#"{"error":"subscription issue","error_code":7}"#)
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert!(completed(&f.adapter).is_empty());
    assert!(f.attempts(now + Duration::from_secs(100)).0.is_empty());
    rejected.assert_async().await;
    drop(rejected);
    assert!(f.worker.retry_job(
        f.towers[0].0,
        CHANNEL,
        job.commitment_txid(),
        now + Duration::from_secs(100)
    ));
    let good = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 0))
        .expect(1)
        .create_async()
        .await;
    let (mut attempts, _) = f.attempts(now + Duration::from_secs(100));
    f.worker
        .finish(
            attempts.pop().unwrap().send().await,
            now + Duration::from_secs(100),
        )
        .unwrap();
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    good.assert_async().await;
    register.assert_async().await;
}

#[tokio::test]
async fn corrupt_saved_receipts_cannot_authorize_acknowledgment() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let entry = common::justice(vec![common::to_local(144, 0)]);
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry.clone()]));
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&f.job(), 0))
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert_eq!(completed(&f.adapter).len(), 1);
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute("UPDATE appointment_receipts SET tower_signature='bad'", [])
        .unwrap();
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
    let (attempts, events) = f.attempts(now);
    assert!(attempts.is_empty());
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::ReceiptCheckFailed { .. })));
    assert!(completed(&f.adapter).is_empty());
    mock.assert_async().await;
}

#[tokio::test]
async fn finishing_one_commitment_does_not_audit_unrelated_pending_commitments() {
    use lightning::bitcoin::{hashes::Hash, Txid};
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let first_entry = common::justice(vec![common::to_local(144, 0)]);
    let first_txid = first_entry.revoked_commitment_txid;
    let other_txid = Txid::from_byte_array([8; 32]);
    let mut other_entry =
        common::justice(vec![common::to_local_with_fee(other_txid, 144, 0, 1000)]);
    other_entry.revoked_commitment_txid = other_txid;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![first_entry, other_entry]));
    let now = Instant::now();
    let (mut attempts, _) = f.attempts(now);
    let index = attempts
        .iter()
        .position(|attempt| attempt.job().commitment_txid() == first_txid)
        .unwrap();
    let first = attempts.swap_remove(index);
    let other = attempts.pop().unwrap();
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute(
        "INSERT INTO appointment_receipts VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            f.towers[0].0.to_vec(),
            &CHANNEL.0[..],
            &other_txid.to_byte_array()[..],
            other.job().signature(),
            100,
            "invalid"
        ],
    )
    .unwrap();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(first.job(), 0))
        .expect(1)
        .create_async()
        .await;
    let events = f.worker.finish(first.send().await, now).unwrap();
    assert!(!events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::ReceiptCheckFailed { .. })));
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, first_txid)]);
    // Polling reconciles the remaining candidate and exposes its invalid evidence.
    let (_, events) = f.attempts(now);
    assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::ReceiptCheckFailed { commitment_txid, .. } if *commitment_txid == other_txid)));
    assert!(completed(&f.adapter).is_empty());
    drop(other);
    mock.assert_async().await;
}
