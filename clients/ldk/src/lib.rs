//! An embedded watchtower client for LDK-based Lightning nodes using The Eye of Satoshi.
//!
//! This crate provides tower connection configuration, persistent client identity,
//! explicit tower registration, claim classification with unclassified-claim diagnostics,
//! durable appointment preparation, explicit submission with verified tower receipts,
//! network submission independent of storage access, caller-driven delivery retries,
//! an LDK persistence adapter with explicit protection scope, explicit completed-job
//! cleanup preserving replay evidence, and TEOS locator derivation.
//! Prepared appointments cover revoked counterparty commitment
//! `to_local` outputs. Preparation does not submit to a tower or acknowledge LDK
//! delivery; HTLC outputs remain outside its scope.

use lightning::chain::channelmonitor::JusticeTransactions;
use teos_common::appointment::Locator;

mod appointments;
mod claims;
mod cleanup;
mod config;
mod coverage;
mod dbm;
mod delivery;
mod identity;
mod ldk_adapter;
mod registration;
mod replay;
mod schema;
mod submission;

pub use appointments::{AppointmentPreparation, PendingAppointment, PreparationError};
pub use claims::{
    classify_claims, ClaimClassification, ClaimClassificationError, ToLocalClaim,
    UnclassifiedClaim, UnclassifiedClaimReason,
};
pub use cleanup::CleanupOutcome;
pub use config::{TowerConfig, TowerConfigError};
pub use coverage::{CoverageOutcome, CoverageRecord, ProtectionScope};
pub use dbm::{ClientStore, PendingAppointmentFailure, PendingAppointmentRecovery, StorageError};
pub use delivery::{
    DeliveryAttempt, DeliveryBatch, DeliveryCompletion, DeliveryCoordinator, DeliveryEvent,
    DeliveryStatus, InvalidDeliveryCompletion, InvalidRetryPolicy, RetryPolicy,
};
pub use identity::ClientIdentity;
pub use ldk_adapter::{
    ClaimCoverage, LdkAdapterConfigError, LdkAdapterEvent, LdkDeliveryBatch, LdkWatchtowerAdapter,
    LdkWatchtowerWorker,
};
pub use registration::{RegistrationError, TowerClient};
pub use replay::ReofferBlockedReason;
pub use submission::{SubmissionError, VerifiedAppointmentReceipt};

/// Derives the TEOS appointment locator for a revoked counterparty commitment.
///
/// The locator identifies the commitment that triggers protection, rather than any
/// of the justice transactions spending its outputs. This does not select a claim
/// or imply that the commitment has been protected.
pub fn appointment_locator(justice: &JusticeTransactions) -> Locator {
    Locator::new(justice.revoked_commitment_txid)
}
