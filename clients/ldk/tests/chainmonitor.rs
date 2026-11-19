//! Real LDK nodes and ChainMonitor, with either a mock tower or an opt-in live TEOS.

use std::future::Future;
use std::num::NonZeroUsize;
use std::path::Path;
use std::task::Poll;
use std::time::{Duration, Instant};

use futures_util::future::poll_fn;

use ldk_watchtower_client::{
    classify_claims, ClientStore, CoverageOutcome, DeliveryAttempt, DeliveryCoordinator,
    LdkAdapterEvent, LdkWatchtowerWorker, ProtectionScope, RetryPolicy, TowerClient, TowerConfig,
};
use lightning::bitcoin::{secp256k1::SecretKey, ScriptBuf};
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::chain::{BlockLocator, ChannelMonitorUpdateStatus, Watch};
use lightning::ln::functional_test_utils::{
    create_announced_chan_between_nodes, create_chanmon_cfgs, create_network, create_node_cfgs,
    create_node_chanmgrs, send_payment, test_default_channel_config, test_legacy_channel_config,
};
use lightning::sign::SignerProvider;
use lightning::util::config::UserConfig;
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning::util::test_channel_signer::TestChannelSigner;
use lightning::util::test_utils::TestChainMonitor;
use mockito::{Matcher, Server};
use teos_common::{
    cryptography,
    protos::{AddAppointmentRequest, AddAppointmentResponse},
    receipts::AppointmentReceipt,
};

#[path = "../examples/embedding.rs"]
pub mod embedding;

const FEE_RATE: u64 = 1000;

#[derive(Clone, Copy)]
enum WorkerDriver {
    Manual,
    Embedding,
    EmbeddingRetry,
}

fn open_worker(path: &Path, tower: TowerConfig, destination: ScriptBuf) -> LdkWatchtowerWorker {
    LdkWatchtowerWorker::new(
        ProtectionScope::ToLocalOnly,
        ClientStore::open(path).unwrap(),
        vec![DeliveryCoordinator::new(
            TowerClient::new(tower).unwrap(),
            RetryPolicy::default(),
            RetryPolicy::default(),
        )],
        FEE_RATE,
        destination,
    )
    .unwrap()
}

fn poll(worker: &mut LdkWatchtowerWorker) -> (Vec<DeliveryAttempt>, Vec<LdkAdapterEvent>) {
    let (batches, events) = worker.poll(Instant::now()).into_parts();
    let mut attempts = Vec::new();
    for (_, batch) in batches {
        let (recovery, sends, _) = batch.into_parts();
        assert!(recovery.failures().is_empty(), "{recovery:?}");
        attempts.extend(sends);
    }
    assert!(
        events.iter().all(|event| matches!(
            event,
            LdkAdapterEvent::Coverage { .. }
                | LdkAdapterEvent::NoApplicableClaimAtFeeRate { .. }
                | LdkAdapterEvent::AcknowledgmentQueued { .. }
        )),
        "unexpected adapter events: {events:?}"
    );
    (attempts, events)
}

async fn exercise(
    tower: TowerConfig,
    mut mock: Option<(&mut Server, SecretKey)>,
    channel_config: UserConfig,
    driver: WorkerDriver,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.sqlite");
    let chanmon_cfgs = create_chanmon_cfgs(2);
    let cfg = &chanmon_cfgs[1];
    let destination = cfg.keys_manager.get_destination_script([0; 32]).unwrap();
    let mut worker = open_worker(&path, tower.clone(), destination.clone());
    if mock.is_none() {
        TowerClient::new(tower.clone())
            .unwrap()
            .register(worker.store_mut())
            .await
            .expect("live tower registration must succeed");
    }
    let adapter = worker.adapter();
    let mut node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
    node_cfgs[1].chain_monitor = TestChainMonitor::new_with_watchtower(
        Some(&cfg.chain_source),
        &cfg.tx_broadcaster,
        &cfg.logger,
        &cfg.fee_estimator,
        &cfg.persister,
        &cfg.keys_manager,
        &adapter,
    );
    let anchors = channel_config
        .channel_handshake_config
        .negotiate_anchors_zero_fee_htlc_tx;
    let managers = create_node_chanmgrs(
        2,
        &node_cfgs,
        &[Some(channel_config.clone()), Some(channel_config)],
    );
    let nodes = create_network(2, &node_cfgs, &managers);
    let (_, _, channel, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    let channels = nodes[1].node.list_channels();
    assert_eq!(
        channels[0]
            .channel_type
            .as_ref()
            .unwrap()
            .supports_anchors_zero_fee_htlc_tx(),
        anchors,
        "fixture must negotiate the requested channel type",
    );
    // Ordinary payments revoke both HTLC-bearing and HTLC-free commitments.
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);

    let (retained, snapshot, first_txid) = {
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(channel)
            .unwrap();
        let claims = monitor
            .get_pending_justice_txs(FEE_RATE, destination.clone())
            .unwrap();
        assert!(!claims.is_empty());
        let mixed = claims
            .iter()
            .find(|entry| {
                let classification = classify_claims(entry).unwrap();
                classification.to_local().is_some() && classification.recognized_htlc_claims() > 0
            })
            .expect("fixture must include real to_local and HTLC claims together");
        (
            monitor.pending_justice_commitment_txids(),
            monitor.encode(),
            mixed.revoked_commitment_txid,
        )
    };
    let (mut attempts, _) = poll(&mut worker);
    assert!(!attempts.is_empty());
    let jobs = worker
        .store()
        .pending_appointments()
        .unwrap()
        .jobs()
        .to_vec();
    let mut mocks = Vec::new();
    let retry_txid = matches!(driver, WorkerDriver::EmbeddingRetry).then(|| {
        jobs.iter()
            .find(|job| job.commitment_txid() != first_txid)
            .expect("retry test needs an undelivered job after restart")
            .commitment_txid()
    });
    if let Some((server, key)) = mock.as_mut() {
        for job in &jobs {
            let mut receipt = AppointmentReceipt::new(job.signature().into(), 100);
            receipt.sign(key);
            let response = AddAppointmentResponse {
                locator: job.appointment().locator.to_vec(),
                start_block: 100,
                signature: receipt.signature().unwrap(),
                available_slots: 100,
                subscription_expiry: 10000,
            };
            let request = serde_json::to_value(AddAppointmentRequest {
                appointment: Some(job.appointment().clone().into()),
                signature: job.signature().into(),
            })
            .unwrap();
            if retry_txid == Some(job.commitment_txid()) {
                // Matching mocks serve expected hits in creation order: one 503,
                // then a signed receipt for the exact same saved request.
                mocks.push(
                    server
                        .mock("POST", "/add_appointment")
                        .match_body(Matcher::Json(request.clone()))
                        .with_status(503)
                        .with_body("temporarily unavailable")
                        .expect(1)
                        .create_async()
                        .await,
                );
            }
            mocks.push(
                server
                    .mock("POST", "/add_appointment")
                    .match_body(Matcher::Json(request))
                    .with_status(200)
                    .with_header("content-type", "application/json")
                    .with_body(serde_json::to_string(&response).unwrap())
                    .expect(1)
                    .create_async()
                    .await,
            );
        }
    }
    // Deliver a mixed to_local+HTLC commitment first, independent of job order.
    // Restart before ChainMonitor consumes its queued acknowledgment.
    let first_index = attempts
        .iter()
        .position(|attempt| attempt.job().commitment_txid() == first_txid)
        .expect("mixed commitment must have a to_local appointment to deliver");
    let first = attempts.swap_remove(first_index);
    let events = worker.finish(first.send().await, Instant::now()).unwrap();
    assert!(events.iter().any(|event| matches!(event,
        LdkAdapterEvent::AcknowledgmentQueued { commitment_txid, .. } if *commitment_txid == first_txid
    )), "first delivery did not produce an acknowledgment: {events:?}");
    assert_eq!(
        nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(channel)
            .unwrap()
            .pending_justice_commitment_txids(),
        retained
    );
    drop(attempts);
    drop(worker);

    let mut restarted = open_worker(&path, tower.clone(), destination.clone());
    let restarted_adapter = restarted.adapter();
    let keys = &cfg.keys_manager;
    let mut bytes = &snapshot[..];
    let (_, monitor) =
        <(BlockLocator, ChannelMonitor<TestChannelSigner>)>::read(&mut bytes, (keys, keys))
            .unwrap();
    assert!(bytes.is_empty());
    let chain_monitor = TestChainMonitor::new_with_watchtower(
        Some(&cfg.chain_source),
        &cfg.tx_broadcaster,
        &cfg.logger,
        &cfg.fee_estimator,
        &cfg.persister,
        keys,
        &restarted_adapter,
    );
    if !matches!(driver, WorkerDriver::Manual) {
        let shutdown = async {
            loop {
                let _ = chain_monitor.chain_monitor.release_pending_monitor_events();
                if chain_monitor
                    .chain_monitor
                    .get_monitor(channel)
                    .is_ok_and(|monitor| monitor.pending_justice_commitment_txids().is_empty())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let mut running = Box::pin(embedding::run_worker(
            &mut restarted,
            NonZeroUsize::new(2).unwrap(),
            shutdown,
        ));
        // Complete the initial poll before loading the monitor. Only the later
        // callback can wake snapshot classification and scope acknowledgment.
        poll_fn(|cx| {
            assert!(
                running.as_mut().poll(cx).is_pending(),
                "worker must wait while the monitor is not loaded"
            );
            Poll::Ready(())
        })
        .await;
        assert_eq!(
            chain_monitor.chain_monitor.watch_channel(channel, monitor),
            Ok(ChannelMonitorUpdateStatus::Completed)
        );
        tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .expect("worker must handle the new snapshot and any retry deadline");
    } else {
        assert_eq!(
            chain_monitor.chain_monitor.watch_channel(channel, monitor),
            Ok(ChannelMonitorUpdateStatus::Completed)
        );
        let (attempts, events) = poll(&mut restarted);
        assert!(attempts
            .iter()
            .all(|attempt| attempt.job().commitment_txid() != first_txid));
        assert_eq!(
            attempts.len(),
            jobs.len() - 1,
            "only jobs without receipts should be resent"
        );
        assert!(events.iter().any(|event| matches!(
            event,
            LdkAdapterEvent::AcknowledgmentQueued { commitment_txid, .. }
                if *commitment_txid == first_txid
        )));
        for attempt in attempts {
            let delivered_txid = attempt.job().commitment_txid();
            let events = restarted
                .finish(attempt.send().await, Instant::now())
                .unwrap();
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    LdkAdapterEvent::AcknowledgmentQueued { commitment_txid, .. }
                        if *commitment_txid == delivered_txid
                )),
                "delivery did not produce an acknowledgment: {events:?}"
            );
        }
    }
    // Use ChainMonitor's normal event-release path, rather than draining the
    // adapter or calling justice_persisted by hand.
    if matches!(driver, WorkerDriver::Manual) {
        assert_eq!(
            chain_monitor
                .chain_monitor
                .get_monitor(channel)
                .unwrap()
                .pending_justice_commitment_txids(),
            retained
        );
    }
    let _ = chain_monitor.chain_monitor.release_pending_monitor_events();
    assert!(chain_monitor
        .chain_monitor
        .get_monitor(channel)
        .unwrap()
        .pending_justice_commitment_txids()
        .is_empty());

    let reopened = ClientStore::open(&path).unwrap();
    for job in &jobs {
        let restored = reopened
            .pending_appointment(channel, job.commitment_txid())
            .unwrap()
            .unwrap();
        assert_eq!(
            &restored, job,
            "restart must preserve the exact encrypted and signed payload"
        );
        assert!(reopened
            .appointment_receipt(tower.tower_id(), channel, job.commitment_txid())
            .unwrap()
            .is_some());
    }
    let mut released_mixed_commitment = false;
    for txid in retained {
        let records = reopened.coverage_records(channel, txid).unwrap();
        assert!(!records.is_empty());
        assert!(records.iter().all(|record| record.completion_ready()));
        assert!(records
            .iter()
            .all(|record| record.outcome() != CoverageOutcome::Blocked));
        if txid == first_txid {
            released_mixed_commitment = records.iter().any(|record| {
                record.outcome() == CoverageOutcome::ToLocalAppointment
                    && record.excluded_htlc_claims() > 0
                    && record.completion_ready()
            });
        }
    }
    assert!(
        released_mixed_commitment,
        "the delivered mixed commitment must retain completed to_local coverage with HTLC exclusions"
    );
    for mock in mocks {
        mock.assert_async().await;
    }
}

async fn exercise_with_mock(channel_config: UserConfig, driver: WorkerDriver) {
    let mut server = Server::new_async().await;
    let (key, public) = cryptography::get_random_keypair();
    let tower = TowerConfig::new(
        teos_common::UserId(public),
        &server.url(),
        Duration::from_secs(5),
    )
    .unwrap();
    exercise(tower, Some((&mut server, key)), channel_config, driver).await;
}

#[tokio::test]
async fn real_chainmonitor_releases_scoped_commitments_after_delivery_and_restart() {
    exercise_with_mock(test_legacy_channel_config(), WorkerDriver::Manual).await;
}

#[tokio::test]
async fn real_anchor_chainmonitor_releases_scoped_commitments_after_delivery_and_restart() {
    exercise_with_mock(test_default_channel_config(), WorkerDriver::Manual).await;
}

#[tokio::test]
async fn embedding_worker_wakes_for_monitor_loaded_after_startup() {
    exercise_with_mock(test_default_channel_config(), WorkerDriver::Embedding).await;
}

#[tokio::test]
async fn embedding_worker_retries_a_temporary_failure_at_its_deadline() {
    exercise_with_mock(test_default_channel_config(), WorkerDriver::EmbeddingRetry).await;
}

#[tokio::test]
#[ignore = "requires TEOS_E2E_URL and TEOS_E2E_TOWER_ID for a live regtest tower; consumes slots"]
async fn live_teos_chainmonitor_delivery_and_restart() {
    let url = std::env::var("TEOS_E2E_URL").expect("set TEOS_E2E_URL to a regtest tower API URL");
    let id = std::env::var("TEOS_E2E_TOWER_ID")
        .expect("set TEOS_E2E_TOWER_ID to its compressed public key");
    let tower = TowerConfig::new(
        id.parse().expect("invalid tower public key"),
        &url,
        Duration::from_secs(10),
    )
    .unwrap();
    exercise(
        tower.clone(),
        None,
        test_legacy_channel_config(),
        WorkerDriver::Manual,
    )
    .await;
    exercise(
        tower,
        None,
        test_default_channel_config(),
        WorkerDriver::Embedding,
    )
    .await;
}
