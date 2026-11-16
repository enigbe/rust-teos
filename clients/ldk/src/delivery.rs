//! Caller-driven delivery scheduling. Network attempts own their data and never borrow storage.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lightning::bitcoin::Txid;
use lightning::ln::types::ChannelId;
use teos_common::{errors, TowerId};

use crate::dbm::DeliveryJobStatus;
use crate::{
    ClientStore, PendingAppointment, PendingAppointmentRecovery, StorageError, SubmissionError,
    TowerClient, VerifiedAppointmentReceipt,
};

type JobId = (ChannelId, Txid);

/// Capped exponential backoff within an elapsed-time window, with optional rearming.
/// The window includes request time and starts when the first attempt is issued.
/// No new attempt is issued at or beyond its deadline. Cooldown starts at the end of the
/// window, or at the completion of a request that outlasted it, whichever is later.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    initial_delay: Duration,
    max_delay: Duration,
    max_elapsed_time: Duration,
    auto_retry_delay: Option<Duration>,
}
impl RetryPolicy {
    /// Requires nonzero delays/window, initial_delay <= max_delay, and representable
    /// deadlines. `None` disables automatic rearming after retryable exhaustion.
    /// Error classification is fixed; this never enables automatic registration.
    pub fn new(
        initial_delay: Duration,
        max_delay: Duration,
        max_elapsed_time: Duration,
        auto_retry_delay: Option<Duration>,
    ) -> Result<Self, InvalidRetryPolicy> {
        let now = Instant::now();
        if initial_delay.is_zero()
            || max_delay < initial_delay
            || max_elapsed_time.is_zero()
            || auto_retry_delay.is_some_and(|delay| delay.is_zero())
            || now.checked_add(max_delay).is_none()
            || now.checked_add(max_elapsed_time).is_none()
            || auto_retry_delay.is_some_and(|delay| now.checked_add(delay).is_none())
        {
            return Err(InvalidRetryPolicy);
        }
        Ok(Self {
            initial_delay,
            max_delay,
            max_elapsed_time,
            auto_retry_delay,
        })
    }
    /// Returns the delay after the first failure of each cycle.
    pub fn initial_delay(&self) -> Duration {
        self.initial_delay
    }
    /// Returns the cap on exponential backoff.
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }
    /// Returns the active retry window, including network or storage operation time.
    pub fn max_elapsed_time(&self) -> Duration {
        self.max_elapsed_time
    }
    /// Returns the cooldown after exhaustion, or None for explicit rearming only.
    pub fn auto_retry_delay(&self) -> Option<Duration> {
        self.auto_retry_delay
    }

    fn cooldown(&self, base: Instant) -> Option<Schedule> {
        base.checked_add(self.auto_retry_delay?)
            .map(|at| Schedule { at, restart: true })
    }
    fn failed(&self, cycle: &mut Cycle, now: Instant) -> Option<Schedule> {
        cycle.failures = cycle.failures.saturating_add(1);
        let delay = 1u32
            .checked_shl(cycle.failures.saturating_sub(1))
            .and_then(|factor| self.initial_delay.checked_mul(factor))
            .unwrap_or(self.max_delay)
            .min(self.max_delay);
        let deadline = cycle.deadline(self);
        match now.checked_add(delay) {
            Some(at) if at < deadline => Some(Schedule { at, restart: false }),
            _ => self.cooldown(now.max(deadline)),
        }
    }
    fn wake(&self, cycle: Cycle, schedule: Schedule, now: Instant) -> Wake {
        if schedule.restart {
            return Wake::Ready(Cycle::new(now));
        }
        let deadline = cycle.deadline(self);
        if now < deadline {
            return Wake::Ready(cycle);
        }
        let next = self.cooldown(deadline);
        match next {
            Some(next) if next.at <= now => Wake::Ready(Cycle::new(now)),
            _ => Wake::Deferred(cycle, next),
        }
    }
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_elapsed_time: Duration::from_secs(3600),
            auto_retry_delay: Some(Duration::from_secs(8 * 3600)),
        }
    }
}
/// Invalid backoff delays, elapsed-time window, or cooldown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRetryPolicy;
impl fmt::Display for InvalidRetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Retry policy requires nonzero, representable delays/window and initial delay <= maximum delay")
    }
}
impl Error for InvalidRetryPolicy {}

#[derive(Clone, Copy)]
struct Cycle {
    started: Instant,
    failures: u32,
}
impl Cycle {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            failures: 0,
        }
    }
    fn deadline(self, policy: &RetryPolicy) -> Instant {
        self.started
            .checked_add(policy.max_elapsed_time)
            .unwrap_or(self.started)
    }
}
#[derive(Clone, Copy)]
struct Schedule {
    at: Instant,
    restart: bool,
}
enum Wake {
    Ready(Cycle),
    Deferred(Cycle, Option<Schedule>),
}

enum State {
    Waiting {
        cycle: Cycle,
        schedule: Schedule,
    },
    Sending {
        cycle: Cycle,
        token: Arc<()>,
    },
    Saving {
        delivery: Box<VerifiedAppointmentReceipt>,
        cycle: Cycle,
        schedule: Option<Schedule>,
    },
    Exhausted,
    Stopped,
}

/// Scheduling for one explicitly configured tower, driven by the embedding node.
///
/// Use one coordinator per tower. Poll on startup, when jobs arrive, and at
/// [`Self::next_retry_at`]. Drive owned attempts without borrowing storage, then
/// pass completions to [`Self::finish`]. There are no background tasks, registration,
/// cleanup, or LDK acknowledgments. Network and persistence use independent retry
/// policies and cycles. Persistence cooldowns retain receipts and never resend.
///
/// Recovery filters jobs with receipt rows in SQL before cryptographic validation;
/// polling does not audit historical receipts. Use [`ClientStore::appointment_receipt`]
/// for explicit evidence verification. In-flight attempts remain valid if another
/// path records a receipt; finish still checks the original source job.
///
/// Jobs and saved receipts are durable. Retry windows, stopped states, and unsaved
/// receipts are in memory; retain the coordinator between polls. Restarting resets
/// schedules and may resend an unchanged payload whose receipt was not saved.
///
/// ```no_run
/// # use std::time::Instant;
/// # use ldk_watchtower_client::{ClientStore, DeliveryCoordinator};
/// # async fn deliver_due(coordinator: &mut DeliveryCoordinator, store: &mut ClientStore)
/// #     -> Result<(), Box<dyn std::error::Error>> {
/// let (recovery, attempts, events) = coordinator.poll(store, Instant::now())?.into_parts();
/// for failure in recovery.failures() {
///     eprintln!("Pending row {}: {}", failure.row_id(), failure.error());
/// }
/// for event in events { eprintln!("{event:?}"); }
/// // Owned attempts may also be driven concurrently by the caller.
/// for attempt in attempts {
///     let completion = attempt.send().await;
///     let event = coordinator.finish(store, completion, Instant::now())?;
///     eprintln!("{event:?}");
/// }
/// // Poll again when new jobs arrive or next_retry_at() becomes due.
/// # Ok(())
/// # }
/// ```
pub struct DeliveryCoordinator {
    tower: TowerClient,
    network_policy: RetryPolicy,
    persistence_policy: RetryPolicy,
    states: HashMap<JobId, State>,
}
impl DeliveryCoordinator {
    /// Creates a coordinator with independently configurable policies and no I/O.
    pub fn new(
        tower: TowerClient,
        network_policy: RetryPolicy,
        persistence_policy: RetryPolicy,
    ) -> Self {
        Self {
            tower,
            network_policy,
            persistence_policy,
            states: HashMap::new(),
        }
    }
    /// Returns the configured tower identity.
    pub fn tower_id(&self) -> TowerId {
        self.tower.config.tower_id()
    }

    /// Discovers undelivered jobs, retries due saves, and issues due network attempts.
    /// Pass monotonically nondecreasing times from the same clock. Inspect recovery
    /// failures and events. Completed history is not decrypted or audited. SQLite
    /// still scans job metadata for discovery, using indexed receipt lookups.
    /// Dropped attempts/completions are noticed on the next poll as cancellations.
    pub fn poll(
        &mut self,
        store: &mut ClientStore,
        now: Instant,
    ) -> Result<DeliveryBatch, StorageError> {
        let recovery = store.undelivered_appointments(self.tower_id())?;
        let mut attempts = Vec::new();
        let mut events = Vec::new();
        let valid_ids: HashSet<_> = recovery
            .jobs()
            .iter()
            .map(|job| (job.channel_id(), job.commitment_txid()))
            .collect();
        let absent: Vec<_> = self
            .states
            .keys()
            .filter(|id| !valid_ids.contains(id))
            .copied()
            .collect();
        for id in absent {
            let state = self.states.remove(&id).unwrap();
            // Do not invalidate a live completion merely because discovery filtered
            // its job (a receipt was recorded elsewhere, removal, or corruption).
            match &state {
                State::Sending { token, .. } if Arc::strong_count(token) > 1 => {
                    self.states.insert(id, state);
                    continue;
                }
                State::Saving { .. } => {
                    self.advance_save(store, id, state, now, &mut events);
                    continue;
                }
                _ => {}
            }
            match store.delivery_job_status(self.tower_id(), id.0, id.1) {
                Ok(DeliveryJobStatus::Missing) => events.push(DeliveryEvent {
                    id,
                    status: DeliveryStatus::Removed,
                }),
                Ok(DeliveryJobStatus::Recorded) => {} // Prune inactive delivered state; no repeated history events.
                Ok(DeliveryJobStatus::Unrecorded) => {
                    self.states.insert(id, State::Stopped);
                    if !matches!(state, State::Stopped) {
                        events.push(DeliveryEvent {
                            id,
                            status: DeliveryStatus::StorageFailure {
                                error: StorageError::InvalidPendingAppointment,
                                next_attempt_at: None,
                            },
                        });
                    }
                }
                Err(error) => {
                    self.states.insert(id, state);
                    events.push(DeliveryEvent {
                        id,
                        status: DeliveryStatus::StorageFailure {
                            error,
                            next_attempt_at: None,
                        },
                    });
                }
            }
        }
        for job in recovery.jobs() {
            let id = (job.channel_id(), job.commitment_txid());
            let state = self.states.remove(&id).unwrap_or(State::Waiting {
                cycle: Cycle::new(now),
                schedule: Schedule {
                    at: now,
                    restart: false,
                },
            });
            match state {
                State::Waiting { cycle, schedule } if schedule.at <= now => {
                    match self.network_policy.wake(cycle, schedule, now) {
                        Wake::Ready(cycle) => {
                            let token = Arc::new(());
                            self.states.insert(
                                id,
                                State::Sending {
                                    cycle,
                                    token: token.clone(),
                                },
                            );
                            attempts.push(DeliveryAttempt {
                                id,
                                job: job.clone(),
                                tower: self.tower.clone(),
                                token,
                            });
                        }
                        Wake::Deferred(cycle, next) => {
                            self.wait_or_exhaust(id, cycle, next);
                            events.push(DeliveryEvent {
                                id,
                                status: DeliveryStatus::RetryWindowElapsed {
                                    next_attempt_at: next.map(|next| next.at),
                                },
                            });
                        }
                    }
                }
                State::Sending { mut cycle, token } if Arc::strong_count(&token) == 1 => {
                    let next = self.network_policy.failed(&mut cycle, now);
                    self.wait_or_exhaust(id, cycle, next);
                    events.push(DeliveryEvent {
                        id,
                        status: DeliveryStatus::Cancelled {
                            next_attempt_at: next.map(|next| next.at),
                        },
                    });
                }
                state @ State::Saving { .. } => {
                    self.advance_save(store, id, state, now, &mut events)
                }
                other => {
                    self.states.insert(id, other);
                }
            }
        }
        Ok(DeliveryBatch {
            recovery,
            attempts,
            events,
        })
    }
    fn wait_or_exhaust(&mut self, id: JobId, cycle: Cycle, next: Option<Schedule>) {
        self.states.insert(
            id,
            match next {
                Some(schedule) => State::Waiting { cycle, schedule },
                None => State::Exhausted,
            },
        );
    }
    fn advance_save(
        &mut self,
        store: &mut ClientStore,
        id: JobId,
        state: State,
        now: Instant,
        events: &mut Vec<DeliveryEvent>,
    ) {
        match state {
            State::Saving {
                delivery,
                cycle,
                schedule: Some(schedule),
            } if schedule.at <= now => match self.persistence_policy.wake(cycle, schedule, now) {
                Wake::Ready(cycle) => events.push(self.save(store, id, *delivery, cycle, now)),
                Wake::Deferred(cycle, next) => {
                    self.states.insert(
                        id,
                        State::Saving {
                            delivery,
                            cycle,
                            schedule: next,
                        },
                    );
                    events.push(DeliveryEvent {
                        id,
                        status: DeliveryStatus::RetryWindowElapsed {
                            next_attempt_at: next.map(|next| next.at),
                        },
                    });
                }
            },
            other => {
                self.states.insert(id, other);
            }
        }
    }
    /// Saves a completed attempt or schedules its next retry/cooldown. Only the
    /// issuing coordinator accepts a completion. A source job changed or removed
    /// during the request fails saving and retains the verified receipt for inspection.
    pub fn finish(
        &mut self,
        store: &mut ClientStore,
        completion: DeliveryCompletion,
        now: Instant,
    ) -> Result<DeliveryEvent, InvalidDeliveryCompletion> {
        let DeliveryCompletion { id, token, result } = completion;
        let mut cycle = match self.states.get(&id) {
            Some(State::Sending {
                cycle,
                token: expected,
            }) if Arc::ptr_eq(&token, expected) => *cycle,
            _ => return Err(InvalidDeliveryCompletion),
        };
        match result {
            Ok(delivery) => Ok(self.save(store, id, delivery, Cycle::new(now), now)),
            Err(error) => {
                let status = if retryable(&error) {
                    let next = self.network_policy.failed(&mut cycle, now);
                    self.wait_or_exhaust(id, cycle, next);
                    match next {
                        Some(next) if next.restart => DeliveryStatus::CoolingDown {
                            next_attempt_at: next.at,
                            error,
                        },
                        Some(next) => DeliveryStatus::RetryScheduled {
                            next_attempt_at: next.at,
                            error,
                        },
                        None => DeliveryStatus::Exhausted { error },
                    }
                } else {
                    self.states.insert(id, State::Stopped);
                    DeliveryStatus::Stopped { error }
                };
                Ok(DeliveryEvent { id, status })
            }
        }
    }
    fn save(
        &mut self,
        store: &mut ClientStore,
        id: JobId,
        delivery: VerifiedAppointmentReceipt,
        mut cycle: Cycle,
        now: Instant,
    ) -> DeliveryEvent {
        match store.save_appointment_receipt(&delivery) {
            Ok(()) => {
                self.states.remove(&id);
                DeliveryEvent {
                    id,
                    status: DeliveryStatus::Delivered,
                }
            }
            Err(error) => {
                let next = if matches!(error, StorageError::Sqlite(_)) {
                    self.persistence_policy.failed(&mut cycle, now)
                } else {
                    None
                };
                self.states.insert(
                    id,
                    State::Saving {
                        delivery: Box::new(delivery),
                        cycle,
                        schedule: next,
                    },
                );
                DeliveryEvent {
                    id,
                    status: DeliveryStatus::StorageFailure {
                        error,
                        next_attempt_at: next.map(|next| next.at),
                    },
                }
            }
        }
    }
    /// Returns the earliest retry or cooldown deadline. Permanent/manual stops and
    /// live attempts have no deadline. Poll again after dropping/cancelling an attempt.
    pub fn next_retry_at(&self) -> Option<Instant> {
        self.states
            .values()
            .filter_map(|state| match state {
                State::Waiting { schedule, .. } => Some(schedule.at),
                State::Saving { schedule, .. } => schedule.map(|schedule| schedule.at),
                _ => None,
            })
            .min()
    }
    /// Explicitly rearms permanent/manual stops. Save retries retain their verified
    /// receipt and never become network sends. Returns false for unknown/active jobs.
    pub fn retry_job(
        &mut self,
        channel_id: ChannelId,
        commitment_txid: Txid,
        now: Instant,
    ) -> bool {
        let cycle = Cycle::new(now);
        let schedule = Schedule {
            at: now,
            restart: false,
        };
        match self.states.get_mut(&(channel_id, commitment_txid)) {
            Some(state @ (State::Stopped | State::Exhausted)) => {
                *state = State::Waiting { cycle, schedule };
                true
            }
            Some(State::Saving {
                cycle: saved_cycle,
                schedule: next,
                ..
            }) if next.is_none() => {
                *saved_cycle = cycle;
                *next = Some(schedule);
                true
            }
            _ => false,
        }
    }
    /// Returns verified receipts retained after save failures, including during
    /// cooldown or manual stops. They remain in memory until saved or dropped.
    pub fn unsaved_receipts(&self) -> impl Iterator<Item = &VerifiedAppointmentReceipt> {
        self.states.values().filter_map(|state| match state {
            State::Saving { delivery, .. } => Some(delivery.as_ref()),
            _ => None,
        })
    }
}
fn retryable(error: &SubmissionError) -> bool {
    match error {
        SubmissionError::Request(error) => {
            !error.is_builder() && !error.is_decode() && !error.is_redirect()
        }
        SubmissionError::ResponseRead { .. } => true,
        SubmissionError::Rejected {
            error_code: Some(code),
            ..
        } => {
            *code == u32::from(errors::SERVICE_UNAVAILABLE)
                || *code == u32::from(errors::UNEXPECTED_ERROR)
        }
        SubmissionError::Rejected {
            status,
            error_code: None,
            ..
        } => status.is_server_error() || status.as_u16() == 429,
        _ => false,
    }
}

/// A recovery snapshot, owned network attempts, and per-job scheduling results.
/// Always inspect recovery failures and events even when some attempts are available.
pub struct DeliveryBatch {
    recovery: PendingAppointmentRecovery,
    attempts: Vec<DeliveryAttempt>,
    events: Vec<DeliveryEvent>,
}
impl DeliveryBatch {
    /// Returns the verified jobs and isolated corrupt-row failures.
    pub fn recovery(&self) -> &PendingAppointmentRecovery {
        &self.recovery
    }
    /// Returns the due network attempts, without consuming them.
    pub fn attempts(&self) -> &[DeliveryAttempt] {
        &self.attempts
    }
    /// Returns scheduling and persistence results.
    pub fn events(&self) -> &[DeliveryEvent] {
        &self.events
    }
    /// Transfers ownership so the caller can drive each attempt and inspect all diagnostics.
    pub fn into_parts(
        self,
    ) -> (
        PendingAppointmentRecovery,
        Vec<DeliveryAttempt>,
        Vec<DeliveryEvent>,
    ) {
        (self.recovery, self.attempts, self.events)
    }
}

/// One owned send; dropping it or cancelling its future allows retry on the next poll.
/// The coordinator prevents another attempt for the same job while this token is live.
pub struct DeliveryAttempt {
    id: JobId,
    job: PendingAppointment,
    tower: TowerClient,
    token: Arc<()>,
}
impl DeliveryAttempt {
    /// Returns the exact saved payload this attempt will send.
    pub fn job(&self) -> &PendingAppointment {
        &self.job
    }
    /// Sends and verifies without any client-store borrow. Pass the returned
    /// completion to [`DeliveryCoordinator::finish`]; no receipt is saved here.
    pub async fn send(self) -> DeliveryCompletion {
        let result = self.tower.send_appointment(&self.job).await;
        DeliveryCompletion {
            id: self.id,
            token: self.token,
            result,
        }
    }
}

/// A network result bound to its issuing coordinator and attempt.
/// Dropping it without finishing leaves no durable receipt and permits a later retry.
pub struct DeliveryCompletion {
    id: JobId,
    token: Arc<()>,
    result: Result<VerifiedAppointmentReceipt, SubmissionError>,
}
/// A completion was passed to a coordinator which did not issue its active attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDeliveryCompletion;
impl fmt::Display for InvalidDeliveryCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Delivery completion does not match an active attempt")
    }
}
impl Error for InvalidDeliveryCompletion {}

/// An observable result for one tower/job. Delivery only covers the saved payload;
/// none of these statuses authorizes acknowledging the whole commitment to LDK.
#[derive(Debug)]
pub struct DeliveryEvent {
    id: JobId,
    status: DeliveryStatus,
}
impl DeliveryEvent {
    /// Returns the originating channel.
    pub fn channel_id(&self) -> ChannelId {
        self.id.0
    }
    /// Returns the full revoked commitment ID.
    pub fn commitment_txid(&self) -> Txid {
        self.id.1
    }
    /// Returns the result, including any original rejection or storage error.
    pub fn status(&self) -> &DeliveryStatus {
        &self.status
    }
}
/// Per-job scheduling and delivery outcomes.
#[derive(Debug)]
pub enum DeliveryStatus {
    /// A verified receipt was committed to SQLite.
    Delivered,
    /// An eligible network failure will be retried at the given deadline.
    RetryScheduled {
        next_attempt_at: Instant,
        error: SubmissionError,
    },
    /// Retryable failures exhausted the active window; a new cycle starts after cooldown.
    CoolingDown {
        next_attempt_at: Instant,
        error: SubmissionError,
    },
    /// Retryable failures exhausted the window and automatic rearming is disabled.
    Exhausted { error: SubmissionError },
    /// Polling resumed after a window expired; the deadline is its cooldown, if enabled.
    RetryWindowElapsed { next_attempt_at: Option<Instant> },
    /// The source job was removed. Its inactive scheduling state has been pruned.
    Removed,
    /// A non-retryable error requires explicit intervention.
    Stopped { error: SubmissionError },
    /// Receipt loading or saving failed. Saved network results stay in memory on
    /// save failures; no deadline means automatic retries are stopped.
    StorageFailure {
        error: StorageError,
        next_attempt_at: Option<Instant>,
    },
    /// An owned attempt/completion was dropped without being finished.
    Cancelled { next_attempt_at: Option<Instant> },
}
