//! Compile-checked wiring reference for an application which already owns an LDK node.
//! See the crate README for startup, monitor loading, and shutdown order.

use std::collections::VecDeque;
use std::error::Error;
use std::future::{pending, Future};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures_util::{stream::FuturesUnordered, StreamExt};
use ldk_watchtower_client::{
    ClientStore, CoverageOutcome, DeliveryCoordinator, DeliveryEvent, DeliveryStatus,
    LdkAdapterEvent, LdkWatchtowerAdapter, LdkWatchtowerWorker, ProtectionScope, RetryPolicy,
    TowerClient, TowerConfig,
};
use lightning::bitcoin::ScriptBuf;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::chain::Filter;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::sign::{EntropySource, PeerStorageKey};
use lightning::util::logger::Logger;

/// Select this through an explicit application command, not a retry loop.
pub enum RegistrationAction {
    UseSavedReceipts,
    RegisterOrRenew,
}

pub struct Settings {
    pub database: PathBuf,
    pub towers: Vec<TowerConfig>,
    pub registration: RegistrationAction,
    pub scope: ProtectionScope,
    pub feerate_per_kw: u64,
    pub destination: ScriptBuf,
}

/// Reopen the same database on restart. Registration failures are returned to the
/// caller: a lost response or failed save must not cause blind registration retries.
pub async fn open_watchtower(settings: Settings) -> Result<LdkWatchtowerWorker, Box<dyn Error>> {
    let clients = settings
        .towers
        .into_iter()
        .map(|config| {
            let id = config.tower_id();
            TowerClient::new(config).map(|client| (id, client))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let towers = clients
        .iter()
        .map(|(_, client)| {
            DeliveryCoordinator::new(
                client.clone(),
                RetryPolicy::default(),
                RetryPolicy::default(),
            )
        })
        .collect();
    let mut worker = LdkWatchtowerWorker::new(
        settings.scope,
        ClientStore::open(settings.database)?,
        towers,
        settings.feerate_per_kw,
        settings.destination,
    )?;
    let user_id = worker.store_mut().load_or_create_identity()?.user_id();
    // Validate the complete worker configuration before any remote registration.
    for (id, client) in clients {
        let receipt = match settings.registration {
            RegistrationAction::RegisterOrRenew => client.register(worker.store_mut()).await?,
            RegistrationAction::UseSavedReceipts => {
                worker.store().registration(id, user_id)?.ok_or(
                    "No saved registration: explicitly register this identity with the tower first",
                )?
            }
        };
        // A saved receipt is evidence of registration, not a live subscription check.
        eprintln!(
            "Tower {id}: recorded subscription expiry {}",
            receipt.subscription_expiry()
        );
    }
    Ok(worker)
}

/// Supply the same real implementations your node uses for monitor persistence,
/// chain filtering, broadcasting, fee estimation, logging, and entropy.
pub struct MonitorDependencies<C, T, F, L, P, ES> {
    pub chain_source: Option<C>,
    pub broadcaster: T,
    pub fee_estimator: F,
    pub logger: L,
    pub persister: P,
    pub entropy_source: ES,
    pub peer_storage_key: PeerStorageKey,
    pub deferred: bool,
}

/// Construct before loading any monitors. Give this ChainMonitor to ChannelManager
/// and the node's normal background event processing. Do not drain the adapter's
/// acknowledgments yourself; ChainMonitor consumes them through its monitor events.
#[allow(clippy::type_complexity)] // Mirrors LDK's generic ChainMonitor return type.
pub fn install_adapter<S, C, T, F, L, P, ES>(
    dependencies: MonitorDependencies<C, T, F, L, P, ES>,
    adapter: LdkWatchtowerAdapter,
) -> ChainMonitor<S, C, T, F, L, P, ES, LdkWatchtowerAdapter>
where
    S: EcdsaChannelSigner,
    C: Filter,
    T: BroadcasterInterface,
    F: FeeEstimator,
    L: Logger,
    P: Deref,
    P::Target: Persist<S>,
    ES: EntropySource,
{
    ChainMonitor::new_with_watchtower(
        dependencies.chain_source,
        dependencies.broadcaster,
        dependencies.logger,
        dependencies.fee_estimator,
        dependencies.persister,
        adapter,
        dependencies.entropy_source,
        dependencies.peer_storage_key,
        dependencies.deferred,
    )
}

/// Drive from one task on the application's Tokio runtime. `shutdown` should fire
/// after stopping new node activity. Finish active requests, leave queued jobs on
/// disk, and retain this worker to inspect/retry unsaved receipts before dropping it.
/// SQLite calls are synchronous; applications with strict executor latency needs
/// can dedicate a runtime thread to this loop.
pub async fn run_worker(
    worker: &mut LdkWatchtowerWorker,
    concurrency: NonZeroUsize,
    shutdown: impl Future<Output = ()>,
) {
    const STORAGE_RECHECK: Duration = Duration::from_secs(5);
    let adapter = worker.adapter();
    // Register before polling so a concurrent snapshot cannot be lost between
    // inspecting the inbox and going to sleep.
    let mut wake = Box::pin(adapter.work_available());
    let mut shutdown = Box::pin(shutdown);
    let mut queued = VecDeque::new();
    let mut active = FuturesUnordered::new();
    let mut poll_at = Some(Instant::now()); // Recover saved jobs even without a new snapshot.
    let mut stopping = false;

    loop {
        if !stopping && poll_at.is_some_and(|at| at <= Instant::now()) {
            let (batches, events) = worker.poll(Instant::now()).into_parts();
            let mut storage_problem = report_adapter_events(events);
            for (tower, batch) in batches {
                let (recovery, attempts, events) = batch.into_parts();
                for failure in recovery.failures() {
                    eprintln!(
                        "Tower {tower}, corrupt job row {}: {}",
                        failure.row_id(),
                        failure.error()
                    );
                    storage_problem = true;
                }
                for event in events {
                    report_delivery(tower, &event);
                }
                queued.extend(attempts);
            }
            // Preparation and coverage failures have no coordinator deadline.
            // Recheck after backoff so repaired storage is noticed without spinning.
            poll_at = (storage_problem || worker.has_pending_preparations())
                .then(|| Instant::now() + STORAGE_RECHECK);
        }
        while !stopping && active.len() < concurrency.get() {
            let Some(attempt) = queued.pop_front() else {
                break;
            };
            active.push(attempt.send());
        }
        if stopping && active.is_empty() {
            break;
        }

        let deadline = poll_at.into_iter().chain(worker.next_retry_at()).min();
        let timer = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => pending::<()>().await,
            }
        };
        tokio::select! {
            _ = &mut shutdown, if !stopping => {
                stopping = true;
                // Dropping a waiting attempt leaves its saved payload intact.
                queued.clear();
            }
            _ = &mut wake, if !stopping => {
                wake = Box::pin(adapter.work_available());
                poll_at = Some(Instant::now());
            }
            _ = timer, if !stopping => { poll_at = Some(Instant::now()); }
            Some(completion) = active.next(), if !active.is_empty() => {
                match worker.finish(completion, Instant::now()) {
                    Ok(events) => {
                        if report_adapter_events(events) {
                            poll_at = Some(Instant::now() + STORAGE_RECHECK);
                        }
                    }
                    Err(error) => {
                        // A completion can become stale if another path saved its receipt.
                        eprintln!("Watchtower completion: {error}");
                        poll_at = Some(Instant::now() + STORAGE_RECHECK);
                    }
                }
            }
        }
    }
    for receipt in worker.unsaved_receipts() {
        eprintln!("Unsaved verified receipt for tower {}: retain the worker and repair storage before exit", receipt.tower_id());
    }
}

/// Replace stderr reporting with the application's metrics and operator events.
/// Returns whether local evidence needs another check after storage backoff.
fn report_adapter_events(events: Vec<LdkAdapterEvent>) -> bool {
    let mut storage_problem = false;
    for event in events {
        match &event {
            LdkAdapterEvent::Coverage {
                channel_id,
                commitment_txid,
                coverage,
                ..
            } => {
                eprintln!("Coverage {channel_id}/{commitment_txid}: {} HTLC claims excluded, {} unclassified",
                    coverage.recognized_htlc_claims(), coverage.unclassified().len());
                if coverage.outcome(ProtectionScope::ToLocalOnly) == CoverageOutcome::Blocked {
                    eprintln!(
                        "Commitment remains retained: resolve unclassified or mismatched claims"
                    );
                }
            }
            LdkAdapterEvent::NoApplicableClaimAtFeeRate { feerate_per_kw, .. } => {
                eprintln!("No to_local claim generated at {feerate_per_kw} sat/kw: an output may be uneconomical; acknowledgment releases retention");
            }
            LdkAdapterEvent::CoverageStorageFailed { .. }
            | LdkAdapterEvent::ReceiptCheckFailed { .. }
            | LdkAdapterEvent::CoordinatorFailed { .. } => {
                storage_problem = true;
            }
            LdkAdapterEvent::Delivery { tower_id, event } => report_delivery(*tower_id, event),
            _ => {}
        }
        eprintln!("{event:?}");
    }
    storage_problem
}

fn report_delivery(tower: teos_common::TowerId, event: &DeliveryEvent) {
    match event.status() {
        DeliveryStatus::Stopped { .. }
        | DeliveryStatus::Exhausted { .. }
        | DeliveryStatus::StorageFailure {
            next_attempt_at: None,
            ..
        } => {
            eprintln!("Tower {tower}: intervention required; after repair or explicit renewal, call worker.retry_job for {}/{}",
                event.channel_id(), event.commitment_txid());
        }
        _ => {}
    }
    eprintln!("Tower {tower}: {event:?}");
}

#[cfg(not(test))]
fn main() {
    eprintln!("Embedding reference: call open_watchtower, install_adapter, and run_worker from your LDK application. See clients/ldk/README.md.");
}
