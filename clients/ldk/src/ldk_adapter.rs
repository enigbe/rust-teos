//! LDK callbacks capture signed snapshots; a caller-driven worker prepares and delivers them.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use lightning::bitcoin::{ScriptBuf, Txid};
use lightning::chain::chainmonitor::WatchtowerPersist;
use lightning::chain::channelmonitor::{ChannelMonitor, JusticeTransactions};
use lightning::chain::ChannelMonitorUpdateStatus;
use lightning::ln::types::ChannelId;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::util::wakers::{Future, Notifier};
use teos_common::{cryptography, TowerId};

use crate::dbm::CoverageCompletionError;
use crate::{
    ClaimClassification, ClientStore, CoverageOutcome, CoverageRecord, DeliveryBatch,
    DeliveryCompletion, DeliveryCoordinator, DeliveryEvent, InvalidDeliveryCompletion,
    PendingAppointment, PreparationError, ProtectionScope, StorageError, UnclassifiedClaim,
    VerifiedAppointmentReceipt,
};

type JobId = (ChannelId, Txid);
struct Snapshot {
    version: Arc<()>,
    transactions: Result<Vec<JusticeTransactions>, ()>,
}
#[derive(Default)]
struct Inbox {
    latest: HashMap<ChannelId, Arc<()>>,
    snapshots: HashMap<ChannelId, Snapshot>,
    completed: HashMap<JobId, Arc<()>>,
    ldk_notifier: Option<Arc<Notifier>>,
}
struct Shared {
    inbox: Mutex<Inbox>,
    work: Notifier,
}

/// An LDK watchtower persister suitable for [`lightning::chain::chainmonitor::ChainMonitor::new_with_watchtower`].
///
/// The callback signs using the configured fee rate and destination, queues a
/// complete snapshot, and returns InProgress. It performs no database or network
/// I/O and never calls back into ChainMonitor while its locks are held.
///
/// Keep the associated [`LdkWatchtowerWorker`] running. Only it queues individual
/// completions after the explicitly selected scope is durably fulfilled. Applicable
/// to_local claims require receipts from every configured tower. Recognized HTLCs
/// are excluded; unknown or inconsistent claims remain retained by LDK. The inbox
/// is in memory; LDK's retained monitor state supplies snapshots again on restart.
/// Configure the adapter before loading monitors.
#[derive(Clone)]
pub struct LdkWatchtowerAdapter {
    shared: Arc<Shared>,
    feerate_per_kw: u64,
    destination: ScriptBuf,
    scope: ProtectionScope,
}
impl LdkWatchtowerAdapter {
    /// Explicit protection scope whose fulfillment authorizes retention release.
    pub fn protection_scope(&self) -> ProtectionScope {
        self.scope
    }
    /// Queues the COMPLETE result of ChannelMonitor::get_pending_justice_txs for a
    /// channel, unchanged, using this adapter's configured fee rate and destination.
    /// This supports direct LDK integrations which drive the
    /// monitor API themselves; the WatchtowerPersist implementation calls it too.
    ///
    /// Never pass a filtered/subset snapshot: the scope decision must classify the
    /// whole commitment. New snapshots supersede earlier snapshots and queued completions
    /// for this channel. Err(()) represents signer unavailability and authorizes no ack.
    pub fn queue_justice_transactions(
        &self,
        channel_id: ChannelId,
        transactions: Result<Vec<JusticeTransactions>, ()>,
    ) {
        let version = Arc::new(());
        {
            let mut inbox = self.shared.inbox.lock().unwrap();
            inbox.latest.insert(channel_id, version.clone());
            inbox
                .completed
                .retain(|(channel, _), _| *channel != channel_id);
            inbox.snapshots.insert(
                channel_id,
                Snapshot {
                    version,
                    transactions,
                },
            );
        }
        self.shared.work.notify();
    }
    /// Wakes when a new LDK snapshot arrives. Also drive the worker at its retry
    /// deadline. Storage failures require caller-directed repair/backoff and polling.
    pub fn work_available(&self) -> Future {
        self.shared.work.get_future()
    }

    fn current(&self, channel_id: ChannelId, version: &Arc<()>) -> bool {
        self.shared
            .inbox
            .lock()
            .unwrap()
            .latest
            .get(&channel_id)
            .is_some_and(|latest| Arc::ptr_eq(latest, version))
    }
    fn queue_ack(&self, id: JobId, version: &Arc<()>) -> bool {
        let notifier = {
            let mut inbox = self.shared.inbox.lock().unwrap();
            if !inbox
                .latest
                .get(&id.0)
                .is_some_and(|latest| Arc::ptr_eq(latest, version))
            {
                return false;
            }
            if inbox.completed.contains_key(&id) {
                return false;
            }
            inbox.completed.insert(id, version.clone());
            inbox.ldk_notifier.clone()
        };
        if let Some(notifier) = notifier {
            notifier.notify();
        }
        true
    }
    fn take_completed(&self) -> Vec<JobId> {
        let mut inbox = self.shared.inbox.lock().unwrap();
        std::mem::take(&mut inbox.completed)
            .into_iter()
            .filter_map(|(id, version)| {
                inbox
                    .latest
                    .get(&id.0)
                    .filter(|latest| Arc::ptr_eq(latest, &version))
                    .map(|_| id)
            })
            .collect()
    }
}
impl<S: EcdsaChannelSigner> WatchtowerPersist<S> for LdkWatchtowerAdapter {
    fn persist_justice_txs(
        &self,
        channel_id: ChannelId,
        monitor: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        // Sign synchronously while the monitor is available, before handing off work.
        self.queue_justice_transactions(
            channel_id,
            monitor.get_pending_justice_txs(self.feerate_per_kw, self.destination.clone()),
        );
        ChannelMonitorUpdateStatus::InProgress
    }
    fn get_and_clear_completed_justice_persists(&self) -> Vec<JobId> {
        self.take_completed()
    }
    fn register_event_notifier(&self, notifier: Arc<Notifier>) {
        let pending = {
            let mut inbox = self.shared.inbox.lock().unwrap();
            inbox.ldk_notifier = Some(notifier.clone());
            !inbox.completed.is_empty()
        };
        if pending {
            notifier.notify();
        }
    }
}

struct ChannelWork {
    version: Arc<()>,
    entries: Vec<JusticeTransactions>,
    eligible: HashMap<Txid, CoverageRecord>,
}

/// Owns storage and delivery coordinators outside LDK's callback locks.
///
/// The protection scope is explicit. ToLocalOnly excludes recognized HTLC claims,
/// records their count durably, and requires every configured tower's receipt for
/// a generated to_local claim. HTLC-only/empty full snapshots record that no
/// to_local claim was generated at the configured fee rate and need no receipt.
/// This may reflect an uneconomical output, rather than an absent output. Once
/// acknowledged, that commitment cannot be recovered from retention at a lower fee.
/// Unknown/malformed claims and mismatched saved outpoints/scripts block completion.
/// Empty or duplicate tower sets are rejected.
/// Fee changes may reuse the original saved payload for the same outpoint/script.
/// Scope completion metadata is committed before releasing LDK's whole retention
/// entry, including excluded HTLC data.
///
/// Poll on adapter.work_available(), new jobs, and next_retry_at(). Drive returned
/// attempts with bounded concurrency and pass completions to finish(). Failed
/// preparations and coverage-completion failures remain queued; inspect events and
/// retry polling after storage repair/backoff. Coordinator deadlines do not schedule
/// preparation or coverage-record failures.
/// No tower registration, job cleanup, or direct ChainMonitor callback occurs here.
///
/// ```no_run
/// # use std::time::Instant;
/// # use ldk_watchtower_client::{LdkWatchtowerWorker, InvalidDeliveryCompletion};
/// # async fn drive_once(worker: &mut LdkWatchtowerWorker) -> Result<(), InvalidDeliveryCompletion> {
/// let (tower_batches, events) = worker.poll(Instant::now()).into_parts();
/// for event in events { eprintln!("{event:?}"); }
/// for (_tower_id, batch) in tower_batches {
///     let (recovery, attempts, events) = batch.into_parts();
///     for failure in recovery.failures() {
///         eprintln!("Pending row {}: {}", failure.row_id(), failure.error());
///     }
///     for event in events { eprintln!("{event:?}"); }
///     // These owned attempts can also run concurrently, with a caller-set limit.
///     for attempt in attempts {
///         let completion = attempt.send().await;
///         for event in worker.finish(completion, Instant::now())? {
///             eprintln!("{event:?}");
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct LdkWatchtowerWorker {
    store: ClientStore,
    towers: HashMap<TowerId, DeliveryCoordinator>,
    adapter: LdkWatchtowerAdapter,
    channels: HashMap<ChannelId, ChannelWork>,
}
impl LdkWatchtowerWorker {
    /// Creates a worker and its adapter, without network I/O. Register the persistent
    /// client identity with each tower explicitly before driving delivery.
    pub fn new(
        scope: ProtectionScope,
        store: ClientStore,
        towers: Vec<DeliveryCoordinator>,
        feerate_per_kw: u64,
        destination: ScriptBuf,
    ) -> Result<Self, LdkAdapterConfigError> {
        if feerate_per_kw == 0 {
            return Err(LdkAdapterConfigError::ZeroFeeRate);
        }
        if destination.is_empty() {
            return Err(LdkAdapterConfigError::EmptyDestination);
        }
        if towers.is_empty() {
            return Err(LdkAdapterConfigError::NoTowers);
        }
        let mut configured = HashMap::new();
        for tower in towers {
            let id = tower.tower_id();
            if configured.insert(id, tower).is_some() {
                return Err(LdkAdapterConfigError::DuplicateTower(id));
            }
        }
        let adapter = LdkWatchtowerAdapter {
            shared: Arc::new(Shared {
                inbox: Mutex::new(Inbox::default()),
                work: Notifier::new(),
            }),
            feerate_per_kw,
            destination,
            scope,
        };
        Ok(Self {
            store,
            towers: configured,
            adapter,
            channels: HashMap::new(),
        })
    }
    /// Returns the explicitly selected protection scope.
    pub fn protection_scope(&self) -> ProtectionScope {
        self.adapter.scope
    }
    /// Returns a cloneable, Send + Sync handle to install in ChainMonitor.
    pub fn adapter(&self) -> LdkWatchtowerAdapter {
        self.adapter.clone()
    }
    /// Provides explicit access to receipt inspection and the persistent identity.
    pub fn store(&self) -> &ClientStore {
        &self.store
    }
    /// Provides access for explicit registration, storage repair, and administration.
    pub fn store_mut(&mut self) -> &mut ClientStore {
        &mut self.store
    }
    /// Returns the earliest delivery/persistence retry or cooldown deadline.
    pub fn next_retry_at(&self) -> Option<Instant> {
        self.towers
            .values()
            .filter_map(DeliveryCoordinator::next_retry_at)
            .min()
    }
    /// Explicitly rearms a stopped/exhausted job after the caller addresses its
    /// cause, such as explicitly renewing registration. Never registers a tower.
    /// Save retries retain their receipt and do not resend. False means an unknown
    /// tower/job or a job which is already active.
    pub fn retry_job(
        &mut self,
        tower_id: TowerId,
        channel_id: ChannelId,
        commitment_txid: Txid,
        now: Instant,
    ) -> bool {
        self.towers
            .get_mut(&tower_id)
            .is_some_and(|coordinator| coordinator.retry_job(channel_id, commitment_txid, now))
    }
    /// Verified receipts retained by coordinators after save failures, including
    /// manual stops. Inspect/archive them without taking ownership or resending.
    pub fn unsaved_receipts(&self) -> impl Iterator<Item = &VerifiedAppointmentReceipt> {
        self.towers
            .values()
            .flat_map(|coordinator| coordinator.unsaved_receipts())
    }
    /// Whether a new snapshot or failed preparation still needs processing. A
    /// repeated storage failure needs caller backoff, not an immediate busy loop.
    pub fn has_pending_preparations(&self) -> bool {
        !self
            .adapter
            .shared
            .inbox
            .lock()
            .unwrap()
            .snapshots
            .is_empty()
            || self.channels.values().any(|work| !work.entries.is_empty())
    }

    /// Prepares queued snapshots, advances per-tower delivery, and checks for safe
    /// acknowledgments. Always inspect both adapter events and every tower batch's
    /// row failures/events. Network attempts own their data and do not borrow this worker.
    pub fn poll(&mut self, now: Instant) -> LdkDeliveryBatch {
        let mut events = Vec::new();
        self.prepare(&mut events);
        let mut deliveries = Vec::new();
        for (tower_id, coordinator) in &mut self.towers {
            match coordinator.poll(&mut self.store, now) {
                Ok(batch) => deliveries.push((*tower_id, batch)),
                Err(error) => events.push(LdkAdapterEvent::CoordinatorFailed {
                    tower_id: *tower_id,
                    error,
                }),
            }
        }
        self.check_acknowledgments(&mut events);
        LdkDeliveryBatch { deliveries, events }
    }

    /// Saves a network completion in its issuing coordinator, then checks receipts
    /// from all required towers when applicable. Failed saves or unresolved scope
    /// decisions never queue ack; recognized HTLC exclusions do not block ToLocalOnly.
    pub fn finish(
        &mut self,
        completion: DeliveryCompletion,
        now: Instant,
    ) -> Result<Vec<LdkAdapterEvent>, InvalidDeliveryCompletion> {
        let tower_id = completion.tower_id();
        let coordinator = self
            .towers
            .get_mut(&tower_id)
            .ok_or(InvalidDeliveryCompletion)?;
        let event = coordinator.finish(&mut self.store, completion, now)?;
        let id = (event.channel_id(), event.commitment_txid());
        let mut events = vec![LdkAdapterEvent::Delivery { tower_id, event }];
        // Completion cost depends on this commitment and required towers, not
        // every pending commitment. Poll handles startup/local-save reconciliation.
        self.check_acknowledgment(id, &mut events);
        self.prune_channel(id.0);
        Ok(events)
    }

    fn prepare(&mut self, events: &mut Vec<LdkAdapterEvent>) {
        let snapshots = std::mem::take(&mut self.adapter.shared.inbox.lock().unwrap().snapshots);
        for (channel_id, snapshot) in snapshots {
            self.channels.remove(&channel_id);
            match snapshot.transactions {
                Err(()) => events.push(LdkAdapterEvent::SignerUnavailable { channel_id }),
                Ok(mut entries) => {
                    let mut seen = HashSet::new();
                    let duplicates: HashSet<_> = entries
                        .iter()
                        .filter_map(|entry| {
                            (!seen.insert(entry.revoked_commitment_txid))
                                .then_some(entry.revoked_commitment_txid)
                        })
                        .collect();
                    for commitment_txid in &duplicates {
                        events.push(LdkAdapterEvent::DuplicateCommitment {
                            channel_id,
                            commitment_txid: *commitment_txid,
                        });
                    }
                    entries.retain(|entry| !duplicates.contains(&entry.revoked_commitment_txid));
                    self.channels.insert(
                        channel_id,
                        ChannelWork {
                            version: snapshot.version,
                            entries,
                            eligible: HashMap::new(),
                        },
                    );
                }
            }
        }
        let scope = self.adapter.scope;
        let feerate = self.adapter.feerate_per_kw;
        let required_towers: Vec<_> = self.towers.keys().copied().collect();
        for (channel_id, work) in &mut self.channels {
            if !self.adapter.current(*channel_id, &work.version) {
                continue;
            }
            for entry in std::mem::take(&mut work.entries) {
                let commitment_txid = entry.revoked_commitment_txid;
                match self.store.prepare_appointment(*channel_id, &entry) {
                    Ok(prepared) => {
                        let coverage = ClaimCoverage::from_preparation(
                            prepared.classification(),
                            prepared.pending_appointment(),
                        );
                        let signature = if coverage.to_local() {
                            prepared
                                .pending_appointment()
                                .map(PendingAppointment::signature)
                        } else {
                            None
                        };
                        let observation = CoverageRecord::observation(
                            (*channel_id, commitment_txid),
                            scope,
                            feerate,
                            &coverage,
                            signature,
                            required_towers.clone(),
                        );
                        drop(prepared);
                        match self.store.record_coverage(observation) {
                            Ok(record) => {
                                let coverage_id = record.id();
                                if matches!(
                                    record.outcome(),
                                    CoverageOutcome::NoToLocalClaimAtFeeRate
                                        | CoverageOutcome::NoClaimsAtFeeRate
                                ) {
                                    events.push(LdkAdapterEvent::NoApplicableClaimAtFeeRate {
                                        channel_id: *channel_id,
                                        commitment_txid,
                                        feerate_per_kw: feerate,
                                        outcome: record.outcome(),
                                        coverage_id,
                                    });
                                }
                                if coverage.satisfies(scope) {
                                    work.eligible.insert(commitment_txid, record);
                                }
                                events.push(LdkAdapterEvent::Coverage {
                                    channel_id: *channel_id,
                                    commitment_txid,
                                    coverage,
                                    coverage_id,
                                });
                            }
                            Err(error) => {
                                events.push(LdkAdapterEvent::CoverageStorageFailed {
                                    channel_id: *channel_id,
                                    commitment_txid,
                                    error,
                                });
                                work.entries.push(entry);
                            }
                        }
                    }
                    Err(error) => {
                        let retry = !matches!(error, PreparationError::Classification(_));
                        events.push(LdkAdapterEvent::PreparationFailed {
                            channel_id: *channel_id,
                            commitment_txid,
                            error,
                        });
                        if retry {
                            work.entries.push(entry);
                        }
                    }
                }
            }
        }
    }
    fn check_acknowledgments(&mut self, events: &mut Vec<LdkAdapterEvent>) {
        let candidates: Vec<_> = self
            .channels
            .iter()
            .flat_map(|(channel, work)| work.eligible.keys().map(|txid| (*channel, *txid)))
            .collect();
        for id in candidates {
            self.check_acknowledgment(id, events);
        }
        self.channels.retain(|channel_id, work| {
            self.adapter.current(*channel_id, &work.version)
                && (!work.entries.is_empty() || !work.eligible.is_empty())
        });
    }
    fn prune_channel(&mut self, channel_id: ChannelId) {
        if self.channels.get(&channel_id).is_some_and(|work| {
            !self.adapter.current(channel_id, &work.version)
                || (work.entries.is_empty() && work.eligible.is_empty())
        }) {
            self.channels.remove(&channel_id);
        }
    }
    fn check_acknowledgment(&mut self, id: JobId, events: &mut Vec<LdkAdapterEvent>) {
        let Some(work) = self.channels.get_mut(&id.0) else {
            return;
        };
        if !self.adapter.current(id.0, &work.version) {
            return;
        }
        let Some(record) = work.eligible.get(&id.1) else {
            return;
        };
        // Atomically recheck immutable metadata, source payload, and required
        // receipts, then persist scope completion before queueing LDK's ack.
        match self.store.complete_coverage(record) {
            Ok(true) => {
                if self.adapter.queue_ack(id, &work.version) {
                    events.push(LdkAdapterEvent::AcknowledgmentQueued {
                        channel_id: id.0,
                        commitment_txid: id.1,
                        scope: record.scope(),
                        coverage_id: record.id(),
                    });
                }
                work.eligible.remove(&id.1);
            }
            Ok(false) => {}
            Err(CoverageCompletionError::Receipt { tower_id, error }) => {
                events.push(LdkAdapterEvent::ReceiptCheckFailed {
                    channel_id: id.0,
                    commitment_txid: id.1,
                    tower_id,
                    error,
                });
            }
            Err(CoverageCompletionError::Storage(error)) => {
                events.push(LdkAdapterEvent::CoverageStorageFailed {
                    channel_id: id.0,
                    commitment_txid: id.1,
                    error,
                })
            }
        }
    }
}

/// Coverage of the currently supplied claims; it does not count channel outputs
/// LDK omitted as uneconomical. Full coverage and fulfillment of the explicitly
/// selected scope are separate facts; excluded HTLCs are never described as protected.
#[derive(Debug)]
pub struct ClaimCoverage {
    to_local: bool,
    recognized_htlc_claims: usize,
    unclassified: Vec<UnclassifiedClaim>,
    stored_claim_matches: bool,
}
impl ClaimCoverage {
    fn from_preparation(
        classification: &ClaimClassification<'_>,
        job: Option<&PendingAppointment>,
    ) -> Self {
        let stored_claim_matches =
            classification
                .to_local()
                .zip(job)
                .is_some_and(|(claim, job)| {
                    cryptography::decrypt(&job.appointment().encrypted_blob, &job.commitment_txid())
                        .ok()
                        .is_some_and(|saved| {
                            saved
                                .input
                                .first()
                                .zip(claim.transaction().input.first())
                                .is_some_and(|(saved, offered)| {
                                    saved.previous_output == offered.previous_output
                                        && saved.witness.last() == offered.witness.last()
                                })
                                && job.appointment().to_self_delay
                                    == u32::from(claim.to_self_delay())
                        })
                });
        Self {
            to_local: classification.to_local().is_some(),
            recognized_htlc_claims: classification.recognized_htlc_claims(),
            unclassified: classification.unclassified().to_vec(),
            stored_claim_matches,
        }
    }
    /// Whether a to_local claim was recognized in this snapshot.
    pub fn to_local(&self) -> bool {
        self.to_local
    }
    /// Recognized HTLC claims excluded from the current client's protection.
    pub fn recognized_htlc_claims(&self) -> usize {
        self.recognized_htlc_claims
    }
    /// Unknown claim formats, retaining their source indices and reasons.
    pub fn unclassified(&self) -> &[UnclassifiedClaim] {
        &self.unclassified
    }
    /// Whether the frozen appointment protects the same outpoint and revocation script.
    pub fn stored_claim_matches(&self) -> bool {
        self.stored_claim_matches
    }
    /// Decision under the selected scope. Unknown claims and saved-claim mismatches
    /// block completion; recognized HTLC-only and empty results need no appointment.
    pub fn outcome(&self, scope: ProtectionScope) -> CoverageOutcome {
        match scope {
            ProtectionScope::ToLocalOnly => crate::coverage::outcome(
                self.to_local,
                self.recognized_htlc_claims,
                self.unclassified.len(),
                self.stored_claim_matches,
            ),
        }
    }
    /// Whether the supplied claims can fulfill this scope, independently of whether
    /// required receipts and the durable completion record are already saved.
    pub fn satisfies(&self, scope: ProtectionScope) -> bool {
        self.outcome(scope) != CoverageOutcome::Blocked
    }
}

/// Validated prerequisites for signing and an unambiguous set of required towers.
#[derive(Debug, PartialEq, Eq)]
pub enum LdkAdapterConfigError {
    ZeroFeeRate,
    EmptyDestination,
    NoTowers,
    DuplicateTower(TowerId),
}
impl fmt::Display for LdkAdapterConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroFeeRate => write!(f, "LDK justice fee rate must be nonzero"),
            Self::EmptyDestination => write!(f, "LDK justice destination script must not be empty"),
            Self::NoTowers => write!(f, "At least one required tower must be configured"),
            Self::DuplicateTower(id) => {
                write!(f, "Required tower {id} is configured more than once")
            }
        }
    }
}
impl Error for LdkAdapterConfigError {}

/// Preparation/coverage and delivery diagnostics. Inspect them even when other
/// commitments succeed. Acknowledgment means the selected scope was fulfilled;
/// it does not imply that deliberately excluded HTLC claims are protected.
#[derive(Debug)]
pub enum LdkAdapterEvent {
    /// No to_local claim was generated. This does not establish that no revocable
    /// output exists: LDK may omit an uneconomical claim at this fee rate.
    NoApplicableClaimAtFeeRate {
        channel_id: ChannelId,
        commitment_txid: Txid,
        feerate_per_kw: u64,
        outcome: CoverageOutcome,
        coverage_id: i64,
    },
    Coverage {
        channel_id: ChannelId,
        commitment_txid: Txid,
        coverage: ClaimCoverage,
        coverage_id: i64,
    },
    SignerUnavailable {
        channel_id: ChannelId,
    },
    DuplicateCommitment {
        channel_id: ChannelId,
        commitment_txid: Txid,
    },
    PreparationFailed {
        channel_id: ChannelId,
        commitment_txid: Txid,
        error: PreparationError,
    },
    CoverageStorageFailed {
        channel_id: ChannelId,
        commitment_txid: Txid,
        error: StorageError,
    },
    CoordinatorFailed {
        tower_id: TowerId,
        error: StorageError,
    },
    ReceiptCheckFailed {
        channel_id: ChannelId,
        commitment_txid: Txid,
        tower_id: TowerId,
        error: StorageError,
    },
    Delivery {
        tower_id: TowerId,
        event: DeliveryEvent,
    },
    AcknowledgmentQueued {
        channel_id: ChannelId,
        commitment_txid: Txid,
        scope: ProtectionScope,
        coverage_id: i64,
    },
}

/// Per-tower coordinator batches plus adapter diagnostics. Sending attempts from
/// these batches requires no worker/store borrow. Inspect every batch's recovery
/// failures and events, as well as adapter events. Bound network concurrency.
pub struct LdkDeliveryBatch {
    deliveries: Vec<(TowerId, DeliveryBatch)>,
    events: Vec<LdkAdapterEvent>,
}
impl LdkDeliveryBatch {
    /// Per-tower recovery, scheduling events, and owned network attempts.
    pub fn deliveries(&self) -> &[(TowerId, DeliveryBatch)] {
        &self.deliveries
    }
    /// Snapshot, coverage, preparation, and acknowledgment diagnostics.
    pub fn events(&self) -> &[LdkAdapterEvent] {
        &self.events
    }
    /// Transfers batches and diagnostics to the caller.
    pub fn into_parts(self) -> (Vec<(TowerId, DeliveryBatch)>, Vec<LdkAdapterEvent>) {
        (self.deliveries, self.events)
    }
}
