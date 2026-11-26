use std::sync::Arc;
use std::time::{Duration, Instant};

use ldk_watchtower_client::{
    ClientStore, CoverageOutcome, DeliveryAttempt, DeliveryCoordinator, LdkAdapterEvent,
    LdkWatchtowerAdapter, LdkWatchtowerWorker, PendingAppointment, PreparationError,
    ProtectionScope, ReofferBlockedReason, RetryPolicy, StorageError, TowerClient, TowerConfig,
};
use lightning::bitcoin::hashes::Hash;
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
            ProtectionScope::ToLocalOnly,
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
    fn restart(&mut self, urls: &[&str], fee: u64) {
        self.restart_with_destination(
            urls,
            fee,
            common::to_local(144, 0).output[0].script_pubkey.clone(),
        );
    }
    fn restart_with_destination(
        &mut self,
        urls: &[&str],
        fee: u64,
        destination: lightning::bitcoin::ScriptBuf,
    ) {
        let coordinators = self
            .towers
            .iter()
            .zip(urls)
            .map(|((id, _), url)| {
                DeliveryCoordinator::new(
                    TowerClient::new(TowerConfig::new(*id, url, Duration::from_secs(2)).unwrap())
                        .unwrap(),
                    RetryPolicy::default(),
                    RetryPolicy::default(),
                )
            })
            .collect();
        self.worker = LdkWatchtowerWorker::new(
            ProtectionScope::ToLocalOnly,
            ClientStore::open(self.dir.path().join("client.sqlite")).unwrap(),
            coordinators,
            fee,
            destination,
        )
        .unwrap();
        self.adapter = self.worker.adapter();
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
    assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::Coverage { coverage, .. } if coverage.outcome(ProtectionScope::ToLocalOnly) == CoverageOutcome::ToLocalAppointment)));
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
async fn recognized_htlcs_are_excluded_while_unknown_claims_block_acknowledgment() {
    let mut unknown = common::to_local(144, 1);
    unknown.input[0].witness.clear();
    for (txs, should_ack) in [
        (
            vec![common::to_local(144, 0), common::htlc(true, false)],
            true,
        ),
        (vec![common::to_local(144, 0), unknown.clone()], false),
        (vec![unknown], false),
        (vec![common::htlc(false, true)], true),
        (vec![], true),
    ] {
        let mut server = Server::new_async().await;
        let mut f = Fixture::new(&[&server.url()]);
        let entry = common::justice(txs);
        let txid = entry.revoked_commitment_txid;
        f.adapter
            .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
        let now = Instant::now();
        let (attempts, events) = f.attempts(now);
        assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::Coverage { coverage, .. } if coverage.satisfies(ProtectionScope::ToLocalOnly) == should_ack)));
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
        assert_eq!(!completed(&f.adapter).is_empty(), should_ack);
        let records = f.worker.store().coverage_records(CHANNEL, txid).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].completion_ready(), should_ack);
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
        let mut unknown = common::to_local(144, 1);
        unknown.input[0].witness.clear();
        let snapshot = if unavailable {
            Err(())
        } else {
            Ok(vec![common::justice(vec![
                common::to_local(144, 0),
                unknown,
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
async fn both_to_local_and_htlc_bearing_commitments_complete_under_the_selected_scope() {
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
    let acks = completed(&f.adapter);
    assert_eq!(acks.len(), 2);
    assert!(acks.contains(&(CHANNEL, txid)));
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
            ProtectionScope::ToLocalOnly,
            ClientStore::open(":memory:").unwrap(),
            vec![],
            1000,
            destination.clone()
        ),
        Err(LdkAdapterConfigError::NoTowers)
    ));
    assert!(matches!(
        LdkWatchtowerWorker::new(
            ProtectionScope::ToLocalOnly,
            ClientStore::open(":memory:").unwrap(),
            vec![],
            0,
            destination.clone()
        ),
        Err(LdkAdapterConfigError::ZeroFeeRate)
    ));
    assert!(matches!(
        LdkWatchtowerWorker::new(
            ProtectionScope::ToLocalOnly,
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
        matches!(LdkWatchtowerWorker::new(ProtectionScope::ToLocalOnly, ClientStore::open(":memory:").unwrap(), vec![make(), make()], 1000, destination), Err(LdkAdapterConfigError::DuplicateTower(id)) if id == tower_id)
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
        ProtectionScope::ToLocalOnly,
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
    assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::Coverage { coverage, .. } if coverage.to_local() && !coverage.stored_claim_matches() && !coverage.satisfies(ProtectionScope::ToLocalOnly))));
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
    let replacement_payload = teos_common::appointment::Appointment::new(
        original.appointment().locator,
        cryptography::encrypt(&common::to_local(144, 1), &original.commitment_txid()).unwrap(),
        144,
    );
    let signature = f
        .worker
        .store_mut()
        .load_or_create_identity()
        .unwrap()
        .sign(&replacement_payload.to_vec());
    db.execute(
        "UPDATE pending_appointments SET encrypted_blob=?1, signature=?2",
        rusqlite::params![replacement_payload.encrypted_blob, signature],
    )
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
    assert!(events.iter().any(|event| matches!(
        event,
        LdkAdapterEvent::CoverageStorageFailed {
            error: ldk_watchtower_client::StorageError::InvalidPendingAppointment,
            ..
        }
    )));
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

#[tokio::test]
async fn htlc_only_and_empty_snapshots_persist_the_reason_without_a_tower_request() {
    for (txs, outcome, excluded) in [
        (
            vec![common::htlc(true, false)],
            CoverageOutcome::NoToLocalClaimAtFeeRate,
            1,
        ),
        (vec![], CoverageOutcome::NoClaimsAtFeeRate, 0),
    ] {
        let mut server = Server::new_async().await;
        let mut f = Fixture::new(&[&server.url()]);
        let mock = server
            .mock("POST", "/add_appointment")
            .expect(0)
            .create_async()
            .await;
        let entry = common::justice(txs);
        let txid = entry.revoked_commitment_txid;
        f.adapter
            .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
        let (attempts, events) = f.attempts(Instant::now());
        assert!(attempts.is_empty());
        assert!(events.iter().any(|event| matches!(event,
            LdkAdapterEvent::NoApplicableClaimAtFeeRate { commitment_txid, feerate_per_kw: 1000, outcome: observed, coverage_id, .. }
            if *commitment_txid == txid && *observed == outcome && *coverage_id > 0
        )));
        assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
        let reopened = ClientStore::open(f.dir.path().join("client.sqlite")).unwrap();
        let records = reopened.coverage_records(CHANNEL, txid).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.scope(), ProtectionScope::ToLocalOnly);
        assert_eq!(record.outcome(), outcome);
        assert_eq!(record.excluded_htlc_claims(), excluded);
        assert_eq!(record.feerate_per_kw(), 1000);
        assert_eq!(record.required_towers(), &[f.towers[0].0]);
        assert!(record.client_signature().is_none());
        assert!(record.completion_ready());
        assert!(reopened.pending_appointments().unwrap().jobs().is_empty());
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn a_coverage_write_failure_withholds_ack_and_retries_the_snapshot_after_repair() {
    let mut f = Fixture::new(&["http://127.0.0.1:0"]);
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_coverage BEFORE INSERT ON coverage_records BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let entry = common::justice(vec![common::htlc(true, false)]);
    let txid = entry.revoked_commitment_txid;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
    let (attempts, events) = f.attempts(Instant::now());
    assert!(attempts.is_empty());
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::CoverageStorageFailed { .. })));
    assert!(completed(&f.adapter).is_empty());
    assert!(f.worker.has_pending_preparations());
    assert!(f
        .worker
        .store()
        .coverage_records(CHANNEL, txid)
        .unwrap()
        .is_empty());
    db.execute_batch("DROP TRIGGER fail_coverage").unwrap();
    f.attempts(Instant::now());
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    assert!(f.worker.store().coverage_records(CHANNEL, txid).unwrap()[0].completion_ready());
}

#[tokio::test]
async fn a_completion_marker_failure_keeps_coverage_pending_without_resubmission() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let entry = common::justice(vec![common::to_local(144, 0), common::htlc(true, false)]);
    let txid = entry.revoked_commitment_txid;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
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
    db.execute_batch("CREATE TRIGGER fail_completion BEFORE UPDATE OF completion_ready ON coverage_records BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let events = f
        .worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::CoverageStorageFailed { .. })));
    assert!(completed(&f.adapter).is_empty());
    assert!(!f.worker.store().coverage_records(CHANNEL, txid).unwrap()[0].completion_ready());
    assert!(f
        .worker
        .store()
        .appointment_receipt(f.towers[0].0, CHANNEL, txid)
        .unwrap()
        .is_some());
    assert_eq!(
        db.query_row("SELECT count(*) FROM delivered_appointments", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "delivery descriptor must roll back with the completion marker"
    );
    db.execute_batch("DROP TRIGGER fail_completion").unwrap();
    assert!(f.attempts(now).0.is_empty());
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    let record = &f.worker.store().coverage_records(CHANNEL, txid).unwrap()[0];
    assert_eq!(record.excluded_htlc_claims(), 1);
    assert!(record.completion_ready());
    mock.assert_async().await;
}

#[test]
fn identical_observations_are_reused_and_changed_exclusions_preserve_history() {
    let mut f = Fixture::new(&["http://127.0.0.1:0"]);
    let entry = common::justice(vec![common::htlc(true, false)]);
    let txid = entry.revoked_commitment_txid;
    let now = Instant::now();
    for _ in 0..2 {
        f.adapter
            .queue_justice_transactions(CHANNEL, Ok(vec![entry.clone()]));
        assert!(f.attempts(now).0.is_empty());
        assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    }
    let original = f.worker.store().coverage_records(CHANNEL, txid).unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(
        f.worker.store().coverage_record(original[0].id()).unwrap(),
        Some(original[0].clone())
    );
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![
            common::htlc(true, false),
            common::htlc(false, true),
        ])]),
    );
    f.attempts(now);
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    let records = f.worker.store().coverage_records(CHANNEL, txid).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0], original[0]);
    assert_eq!(records[1].excluded_htlc_claims(), 2);
    assert!(records[1].completion_ready());
}

#[tokio::test]
async fn changed_coverage_metadata_cannot_authorize_an_in_flight_acknowledgment() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let entry = common::justice(vec![common::to_local(144, 0), common::htlc(true, false)]);
    let txid = entry.revoked_commitment_txid;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
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
    db.execute("UPDATE coverage_records SET unclassified_claims=1", [])
        .unwrap();
    let events = f
        .worker
        .finish(attempts.pop().unwrap().send().await, now)
        .unwrap();
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::CoverageStorageFailed { .. })));
    assert!(completed(&f.adapter).is_empty());
    assert!(!f.worker.store().coverage_records(CHANNEL, txid).unwrap()[0].completion_ready());
    db.execute("UPDATE coverage_records SET unclassified_claims=0", [])
        .unwrap();
    assert!(f.attempts(now).0.is_empty());
    assert_eq!(completed(&f.adapter), vec![(CHANNEL, txid)]);
    mock.assert_async().await;
}

async fn completed_fixture(server: &mut Server) -> (Fixture, PendingAppointment, mockito::Mock) {
    let mut f = Fixture::new(&[&server.url()]);
    let entry = common::justice(vec![common::to_local(144, 0), common::htlc(true, false)]);
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
    let (mut attempts, _) = f.attempts(Instant::now());
    let job = f.job();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 0))
        .expect(1)
        .create_async()
        .await;
    let events = f
        .worker
        .finish(attempts.pop().unwrap().send().await, Instant::now())
        .unwrap();
    assert!(events
        .iter()
        .any(|event| matches!(event, LdkAdapterEvent::AcknowledgmentQueued { .. })));
    // Leave the acknowledgment in memory: simulate a crash before LDK consumes it.
    (f, job, mock)
}

fn remove_payload(f: &Fixture) -> rusqlite::Connection {
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute("DELETE FROM pending_appointments", []).unwrap();
    db.execute_batch("CREATE TRIGGER forbid_reprepare BEFORE INSERT ON pending_appointments BEGIN SELECT RAISE(ABORT, 'must not reprepare'); END;").unwrap();
    db
}

#[tokio::test]
async fn deleted_payload_reoffer_replays_completed_delivery_after_restart_at_a_new_fee() {
    let mut server = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    let db = remove_payload(&f);
    db.execute("DELETE FROM client_identity", []).unwrap();
    f.restart(&[&server.url()], 2000);
    // At the higher fee LDK may omit the formerly generated HTLC claim. Keep
    // its old exclusion record and record the new snapshot's actual count.
    let entry = common::justice(vec![common::to_local_with_fee(
        job.commitment_txid(),
        144,
        0,
        2000,
    )]);
    assert!(matches!(
        f.worker.store_mut().prepare_appointment(CHANNEL, &entry),
        Err(PreparationError::Storage(
            StorageError::DeliveryHistoryRequiresReplay
        ))
    ));
    for _ in 0..2 {
        f.adapter
            .queue_justice_transactions(CHANNEL, Ok(vec![entry.clone()]));
        let (attempts, events) = f.attempts(Instant::now());
        assert!(attempts.is_empty());
        assert_eq!(
            completed(&f.adapter),
            vec![(CHANNEL, job.commitment_txid())]
        );
        assert!(events
            .iter()
            .any(|event| matches!(event, LdkAdapterEvent::AcknowledgmentQueued { .. })));
    }
    assert_eq!(
        db.query_row("SELECT count(*) FROM pending_appointments", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM client_identity", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let records = f
        .worker
        .store()
        .coverage_records(CHANNEL, job.commitment_txid())
        .unwrap();
    assert_eq!(
        records.len(),
        2,
        "identical replays must reuse their observation"
    );
    assert!(records
        .iter()
        .all(|record| record.completion_ready()
            && record.client_signature() == Some(job.signature())));
    assert_eq!(records[1].feerate_per_kw(), 2000);
    assert_eq!(records[0].excluded_htlc_claims(), 1);
    assert_eq!(records[1].excluded_htlc_claims(), 0);
    mock.assert_async().await;
}

#[tokio::test]
async fn deleted_payload_reoffer_blocks_an_added_required_tower_without_sending() {
    let mut server = Server::new_async().await;
    let mut other = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    let _db = remove_payload(&f);
    let (key, public) = cryptography::get_random_keypair();
    f.towers.push((teos_common::UserId(public), key));
    let no_send = other
        .mock("POST", "/add_appointment")
        .expect(0)
        .create_async()
        .await;
    f.restart(&[&server.url(), &other.url()], 1000);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let (attempts, events) = f.attempts(Instant::now());
    assert!(attempts.is_empty());
    assert!(completed(&f.adapter).is_empty());
    assert!(
        events.iter().any(|event| matches!(
            event,
            LdkAdapterEvent::ReofferBlocked {
                reason: ReofferBlockedReason::MissingReceipt(tower),
                ..
            } if *tower == f.towers[1].0
        )),
        "{events:?}"
    );
    assert!(f
        .worker
        .store()
        .pending_appointment(CHANNEL, job.commitment_txid())
        .unwrap()
        .is_none());
    mock.assert_async().await;
    no_send.assert_async().await;
}

#[tokio::test]
async fn deleted_payload_reoffer_rejects_changed_claims_missing_evidence_and_bad_receipts() {
    for case in [0, 2, 3, 4, 5, 7, 8, 10, 11] {
        let mut server = Server::new_async().await;
        let (mut f, job, mock) = completed_fixture(&mut server).await;
        let db = remove_payload(&f);
        let mut offered = common::justice(vec![common::to_local(144, 0)]);
        let reason = match case {
            0 => {
                offered.txs[0] = common::to_local(144, 1);
                ReofferBlockedReason::ClaimChanged
            }
            2 => {
                db.execute("DELETE FROM delivered_appointments", [])
                    .unwrap();
                ReofferBlockedReason::MissingDeliveryRecord
            }
            3 => {
                db.execute("UPDATE coverage_records SET completion_ready=0", [])
                    .unwrap();
                ReofferBlockedReason::IncompleteDelivery
            }
            4 => {
                db.execute("DELETE FROM appointment_receipts", []).unwrap();
                ReofferBlockedReason::MissingReceipt(f.towers[0].0)
            }
            5 => {
                db.execute(
                    "UPDATE appointment_receipts SET tower_signature='corrupt'",
                    [],
                )
                .unwrap();
                ReofferBlockedReason::InvalidReceipt(f.towers[0].0)
            }
            7 => {
                let mut receipt = AppointmentReceipt::new("different client signature".into(), 100);
                receipt.sign(&f.towers[0].1);
                db.execute(
                    "UPDATE appointment_receipts SET user_signature=?1, tower_signature=?2",
                    rusqlite::params![receipt.user_signature(), receipt.signature().unwrap()],
                )
                .unwrap();
                ReofferBlockedReason::InvalidReceipt(f.towers[0].0)
            }
            8 => {
                db.execute(
                    "UPDATE delivered_appointments SET claim_fingerprint=zeroblob(32)",
                    [],
                )
                .unwrap();
                ReofferBlockedReason::ClaimChanged
            }
            11 => {
                offered.txs[0] = common::to_local(145, 0);
                ReofferBlockedReason::ClaimChanged
            }
            _ => {
                offered.txs.push(common::to_local(144, 2));
                offered.txs[1].input[0].witness.clear();
                let classification = ldk_watchtower_client::classify_claims(&offered).unwrap();
                ReofferBlockedReason::UnclassifiedClaims(classification.unclassified().to_vec())
            }
        };
        f.restart(&[&server.url()], 1000);
        f.adapter
            .queue_justice_transactions(CHANNEL, Ok(vec![offered]));
        let (attempts, events) = f.attempts(Instant::now());
        assert!(attempts.is_empty());
        assert!(completed(&f.adapter).is_empty());
        assert!(events.iter().any(|event| matches!(event, LdkAdapterEvent::ReofferBlocked { reason: actual, .. } if *actual == reason)),
            "case {case}: {events:?}");
        assert!(f
            .worker
            .store()
            .pending_appointment(CHANNEL, job.commitment_txid())
            .unwrap()
            .is_none());
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn replay_keeps_delivered_protection_when_destinations_change_or_claims_are_omitted() {
    for case in [
        "destination",
        "configured_destination",
        "empty",
        "htlc_only",
    ] {
        let mut server = Server::new_async().await;
        let (mut f, job, mock) = completed_fixture(&mut server).await;
        let _db = remove_payload(&f);
        let mut offered = common::justice(vec![common::to_local(144, 0)]);
        let mut destination = offered.txs[0].output[0].script_pubkey.clone();
        let expected = match case {
            "destination" | "configured_destination" => {
                destination = lightning::bitcoin::ScriptBuf::from_bytes(vec![0x51]);
                if case == "destination" {
                    offered.txs[0].output[0].script_pubkey = destination.clone();
                }
                CoverageOutcome::ToLocalAppointment
            }
            "empty" => {
                offered.txs.clear();
                CoverageOutcome::NoClaimsAtFeeRate
            }
            _ => {
                offered.txs = vec![common::htlc(true, false)];
                CoverageOutcome::NoToLocalClaimAtFeeRate
            }
        };
        f.restart_with_destination(&[&server.url()], 2000, destination);
        f.adapter
            .queue_justice_transactions(CHANNEL, Ok(vec![offered]));
        let (attempts, events) = f.attempts(Instant::now());
        assert!(attempts.is_empty());
        assert_eq!(
            completed(&f.adapter),
            vec![(CHANNEL, job.commitment_txid())],
            "{case}: {events:?}"
        );
        let records = f
            .worker
            .store()
            .coverage_records(CHANNEL, job.commitment_txid())
            .unwrap();
        let current = records.last().unwrap();
        assert!(current.completion_ready());
        assert_eq!(current.feerate_per_kw(), 2000);
        assert_eq!(current.outcome(), expected);
        assert_eq!(
            current.client_signature(),
            (expected == CoverageOutcome::ToLocalAppointment).then_some(job.signature())
        );
        assert_eq!(records[0].client_signature(), Some(job.signature()));
        assert_eq!(records[0].outcome(), CoverageOutcome::ToLocalAppointment);
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn replay_requires_receipts_only_from_the_current_towers() {
    let mut first = Server::new_async().await;
    let mut second = Server::new_async().await;
    let mut f = Fixture::new(&[&first.url(), &second.url()]);
    let entry = common::justice(vec![common::to_local(144, 0)]);
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry.clone()]));
    let (attempts, _) = f.attempts(Instant::now());
    let job = f.job();
    let a = first
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 0))
        .expect(1)
        .create_async()
        .await;
    let b = second
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 1))
        .expect(1)
        .create_async()
        .await;
    for attempt in attempts {
        f.worker
            .finish(attempt.send().await, Instant::now())
            .unwrap();
    }
    let db = remove_payload(&f);
    db.execute(
        "DELETE FROM appointment_receipts WHERE tower_id=?1",
        [f.towers[1].0.to_vec()],
    )
    .unwrap();
    f.towers.truncate(1);
    f.restart(&[&first.url()], 1000);
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![entry]));
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    a.assert_async().await;
    b.assert_async().await;
}

#[tokio::test]
async fn replay_allows_an_added_tower_only_with_its_matching_receipt() {
    let mut first = Server::new_async().await;
    let mut second = Server::new_async().await;
    let (mut f, job, a) = completed_fixture(&mut first).await;
    let (key, public) = cryptography::get_random_keypair();
    let id = teos_common::UserId(public);
    f.towers.push((id, key));
    let b = second
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 1))
        .expect(1)
        .create_async()
        .await;
    // An independent delivery before cleanup provides evidence for the added
    // tower; replay need not require a prior observation listing that tower.
    TowerClient::new(TowerConfig::new(id, &second.url(), Duration::from_secs(2)).unwrap())
        .unwrap()
        .submit_appointment(f.worker.store_mut(), CHANNEL, job.commitment_txid())
        .await
        .unwrap();
    let _db = remove_payload(&f);
    f.restart(&[&first.url(), &second.url()], 1000);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    a.assert_async().await;
    b.assert_async().await;
}

#[tokio::test]
async fn cleanup_removes_only_the_completed_job_and_is_idempotent() {
    use ldk_watchtower_client::CleanupOutcome;
    let mut server = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    let identity = f
        .worker
        .store_mut()
        .load_or_create_identity()
        .unwrap()
        .user_id();
    let records = f
        .worker
        .store()
        .coverage_records(CHANNEL, job.commitment_txid())
        .unwrap();
    let receipt = f
        .worker
        .store()
        .appointment_receipt(f.towers[0].0, CHANNEL, job.commitment_txid())
        .unwrap();
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    let delivered: (String, Vec<u8>) = db
        .query_row(
            "SELECT client_signature, claim_fingerprint FROM delivered_appointments",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Removed
    );
    assert!(f
        .worker
        .store()
        .pending_appointment(CHANNEL, job.commitment_txid())
        .unwrap()
        .is_none());
    assert_eq!(
        f.worker
            .store()
            .coverage_records(CHANNEL, job.commitment_txid())
            .unwrap(),
        records
    );
    assert_eq!(
        f.worker
            .store()
            .appointment_receipt(f.towers[0].0, CHANNEL, job.commitment_txid())
            .unwrap(),
        receipt
    );
    assert_eq!(
        db.query_row(
            "SELECT client_signature, claim_fingerprint FROM delivered_appointments",
            [],
            |r| Ok((r.get(0)?, r.get(1)?))
        )
        .unwrap(),
        delivered
    );
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::AlreadyAbsent
    );
    assert_eq!(
        f.worker
            .store_mut()
            .load_or_create_identity()
            .unwrap()
            .user_id(),
        identity
    );
    // LDK has not consumed the first acknowledgment. Cleanup must still leave
    // enough evidence to reconstruct it after a crash and a new fee rate.
    f.restart(&[&server.url()], 2000);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local_with_fee(
            job.commitment_txid(),
            144,
            0,
            2000,
        )])]),
    );
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn cleanup_retains_incomplete_or_blocked_jobs_and_can_follow_a_repaired_offer() {
    use ldk_watchtower_client::CleanupOutcome;
    let mut server = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    let mut blocked = common::justice(vec![common::to_local(144, 0), common::htlc(true, false)]);
    blocked.txs.push(common::to_local(144, 2));
    blocked.txs[2].input[0].witness.clear();
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![blocked]));
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Retained,
        "a queued snapshot must be processed first"
    );
    f.attempts(Instant::now());
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Retained
    );
    // The repaired observation reuses an older ID. Cleanup must follow the
    // latest decision, not MAX(id), which still names the blocked observation.
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![
            common::to_local(144, 0),
            common::htlc(true, false),
        ])]),
    );
    f.attempts(Instant::now());
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![
            common::to_local(144, 0),
            common::to_local(144, 1),
        ])]),
    );
    f.attempts(Instant::now());
    f.restart(&[&server.url()], 1000);
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Retained,
        "a failed classification must invalidate cleanup eligibility durably"
    );
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![
            common::to_local(144, 0),
            common::htlc(true, false),
        ])]),
    );
    f.attempts(Instant::now());
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Removed
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn cleanup_retains_a_job_when_a_previous_blocked_observation_becomes_current_again() {
    use ldk_watchtower_client::CleanupOutcome;
    let mut server = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    completed(&f.adapter);

    let valid = common::justice(vec![common::to_local(144, 0), common::htlc(true, false)]);
    let mut blocked = valid.clone();
    let mut unknown = common::to_local(144, 2);
    unknown.input[0].witness.clear();
    blocked.txs.push(unknown);
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![blocked.clone()]));
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert!(completed(&f.adapter).is_empty());
    let records = f
        .worker
        .store()
        .coverage_records(CHANNEL, job.commitment_txid())
        .unwrap();
    assert!(records
        .iter()
        .any(|record| record.outcome() == CoverageOutcome::Blocked));
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Retained
    );

    // The repaired offer is already delivered, so it becomes completed without
    // another request. Keep the payload for the next observation.
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![valid]));
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    let repaired = f
        .worker
        .store()
        .coverage_records(CHANNEL, job.commitment_txid())
        .unwrap();
    assert_eq!(repaired, records, "repair reuses the completed observation");

    // This is the exact same blocked observation as before. No new row is
    // inserted, but it must replace the completed decision as the latest one.
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![blocked]));
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert!(completed(&f.adapter).is_empty());
    assert_eq!(
        f.worker
            .store()
            .coverage_records(CHANNEL, job.commitment_txid())
            .unwrap(),
        repaired,
        "the repeated blocked observation must reuse its existing row"
    );
    f.restart(&[&server.url()], 1000);
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Retained,
        "the latest blocked decision must survive reopening"
    );
    assert_eq!(f.job(), job);
    mock.assert_async().await;
}

#[tokio::test]
async fn cleanup_rechecks_delivery_evidence_and_never_deletes_on_failure() {
    use ldk_watchtower_client::CleanupOutcome;
    for case in 0..10 {
        let mut server = Server::new_async().await;
        let (mut f, job, mock) = completed_fixture(&mut server).await;
        let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
        match case {
            0 => {
                db.execute("DELETE FROM delivered_appointments", [])
                    .unwrap();
            }
            1 => {
                db.execute("UPDATE coverage_records SET completion_ready=0", [])
                    .unwrap();
            }
            2 => {
                db.execute("DELETE FROM appointment_receipts", []).unwrap();
            }
            3 => {
                db.execute(
                    "UPDATE appointment_receipts SET tower_signature='corrupt'",
                    [],
                )
                .unwrap();
            }
            4 => {
                db.execute(
                    "UPDATE delivered_appointments SET claim_fingerprint=zeroblob(32)",
                    [],
                )
                .unwrap();
            }
            5 => {
                db.execute("UPDATE pending_appointments SET signature='corrupt'", [])
                    .unwrap();
            }
            6 => {
                db.execute("UPDATE coverage_records SET client_signature='changed'", [])
                    .unwrap();
            }
            8 => {
                db.execute("DELETE FROM latest_coverage", []).unwrap();
            }
            9 => {
                db.execute("UPDATE latest_coverage SET coverage_id=-1", [])
                    .unwrap();
            }
            _ => {
                db.execute_batch("CREATE TRIGGER reject_cleanup AFTER DELETE ON pending_appointments BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;").unwrap();
            }
        }
        let result = f
            .worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid());
        if case <= 2 || case == 8 {
            assert_eq!(result.unwrap(), CleanupOutcome::Retained, "case {case}");
        } else {
            assert!(result.is_err(), "case {case}: {result:?}");
        }
        assert_eq!(
            db.query_row("SELECT count(*) FROM pending_appointments", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "case {case}"
        );
        if case == 7 {
            db.execute_batch("DROP TRIGGER reject_cleanup").unwrap();
            assert_eq!(
                f.worker
                    .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
                    .unwrap(),
                CleanupOutcome::Removed
            );
        }
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn cleanup_uses_current_required_towers_and_retains_jobs_still_needed_for_delivery() {
    use ldk_watchtower_client::CleanupOutcome;
    let mut first = Server::new_async().await;
    let mut second = Server::new_async().await;
    let (mut f, job, a) = completed_fixture(&mut first).await;
    let (key, public) = cryptography::get_random_keypair();
    f.towers.push((teos_common::UserId(public), key));
    f.restart(&[&first.url(), &second.url()], 1000);
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Retained
    );
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let (mut attempts, _) = f.attempts(Instant::now());
    assert_eq!(attempts.len(), 1);
    let b = second
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 1))
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, Instant::now())
        .unwrap();
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Removed
    );
    a.assert_async().await;
    b.assert_async().await;
}

#[tokio::test]
async fn cleanup_accepts_a_completed_no_claim_observation_and_preserves_original_delivery() {
    use ldk_watchtower_client::CleanupOutcome;
    let mut server = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    f.adapter
        .queue_justice_transactions(CHANNEL, Ok(vec![common::justice(vec![])]));
    f.attempts(Instant::now());
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Removed
    );
    f.restart(&[&server.url()], 1000);
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn cleanup_waits_for_outstanding_coordinator_state_even_if_a_receipt_was_saved_elsewhere() {
    use ldk_watchtower_client::CleanupOutcome;
    let mut server = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
    db.execute("DELETE FROM appointment_receipts", []).unwrap();
    let (attempts, _) = f.attempts(Instant::now());
    assert_eq!(attempts.len(), 1);
    let response: AddAppointmentResponse = serde_json::from_str(&f.body(&job, 0)).unwrap();
    db.execute(
        "INSERT INTO appointment_receipts VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            f.towers[0].0.to_vec(),
            &CHANNEL.0[..],
            &job.commitment_txid().to_byte_array()[..],
            job.signature(),
            response.start_block,
            response.signature,
        ],
    )
    .unwrap();
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Retained
    );
    drop(attempts);
    f.attempts(Instant::now());
    assert_eq!(
        f.worker
            .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
            .unwrap(),
        CleanupOutcome::Removed
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn upgrading_a_baseline_database_preserves_valid_delivery_cleanup_and_replay() {
    use ldk_watchtower_client::CleanupOutcome;
    for source_version in [0, 1] {
        let mut server = Server::new_async().await;
        let (mut f, job, mock) = completed_fixture(&mut server).await;
        let records = f
            .worker
            .store()
            .coverage_records(CHANNEL, job.commitment_txid())
            .unwrap();
        let db = rusqlite::Connection::open(f.dir.path().join("client.sqlite")).unwrap();
        // Recreate the baseline layout while retaining valid, operational evidence.
        // Both adoption and upgrading must preserve delivery, cleanup, and replay.
        db.execute("DROP TABLE tower_registry", []).unwrap();
        db.pragma_update(None, "user_version", source_version)
            .unwrap();
        f.restart(&[&server.url()], 1000);
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(f.job(), job);
        assert_eq!(
            f.worker
                .store()
                .coverage_records(CHANNEL, job.commitment_txid())
                .unwrap(),
            records
        );
        assert_eq!(
            f.worker
                .cleanup_completed_appointment(CHANNEL, job.commitment_txid())
                .unwrap(),
            CleanupOutcome::Removed
        );
        f.restart(&[&server.url()], 2000);
        f.adapter.queue_justice_transactions(
            CHANNEL,
            Ok(vec![common::justice(vec![common::to_local_with_fee(
                job.commitment_txid(),
                144,
                0,
                2000,
            )])]),
        );
        assert!(f.attempts(Instant::now()).0.is_empty());
        assert_eq!(
            completed(&f.adapter),
            vec![(CHANNEL, job.commitment_txid())]
        );
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn removing_saved_settings_preserves_delivery_evidence_and_the_running_worker() {
    let mut server = Server::new_async().await;
    let (mut f, job, mock) = completed_fixture(&mut server).await;
    let tower_id = f.towers[0].0;
    let config = TowerConfig::new(tower_id, &server.url(), Duration::from_secs(2)).unwrap();
    f.worker.store_mut().save_tower(&config).unwrap();
    let records = f
        .worker
        .store()
        .coverage_records(CHANNEL, job.commitment_txid())
        .unwrap();
    let receipt = f
        .worker
        .store()
        .appointment_receipt(tower_id, CHANNEL, job.commitment_txid())
        .unwrap();
    assert!(f.worker.store_mut().remove_tower(tower_id).unwrap());
    assert_eq!(f.job(), job);
    assert_eq!(
        f.worker
            .store()
            .coverage_records(CHANNEL, job.commitment_txid())
            .unwrap(),
        records
    );
    assert_eq!(
        f.worker
            .store()
            .appointment_receipt(tower_id, CHANNEL, job.commitment_txid())
            .unwrap(),
        receipt
    );
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![
            common::to_local(144, 0),
            common::htlc(true, false),
        ])]),
    );
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn removing_saved_settings_does_not_cancel_an_in_flight_delivery() {
    let mut server = Server::new_async().await;
    let mut f = Fixture::new(&[&server.url()]);
    let tower_id = f.towers[0].0;
    f.worker
        .store_mut()
        .save_tower(&TowerConfig::new(tower_id, &server.url(), Duration::from_secs(2)).unwrap())
        .unwrap();
    f.adapter.queue_justice_transactions(
        CHANNEL,
        Ok(vec![common::justice(vec![common::to_local(144, 0)])]),
    );
    let (mut attempts, _) = f.attempts(Instant::now());
    assert_eq!(attempts.len(), 1);
    let job = f.job();
    assert!(f.worker.store_mut().remove_tower(tower_id).unwrap());
    assert!(f.attempts(Instant::now()).0.is_empty());
    assert!(completed(&f.adapter).is_empty());
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(f.body(&job, 0))
        .expect(1)
        .create_async()
        .await;
    f.worker
        .finish(attempts.pop().unwrap().send().await, Instant::now())
        .unwrap();
    assert!(f
        .worker
        .store()
        .appointment_receipt(tower_id, CHANNEL, job.commitment_txid())
        .unwrap()
        .is_some());
    assert_eq!(
        completed(&f.adapter),
        vec![(CHANNEL, job.commitment_txid())]
    );
    mock.assert_async().await;
}
