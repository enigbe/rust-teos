//! An embedded watchtower client for LDK-based Lightning nodes using The Eye of Satoshi.
//!
//! This crate provides tower connection configuration, persistent client identity,
//! explicit tower registration, claim classification with unclassified-claim diagnostics,
//! durable appointment preparation, explicit submission with verified tower receipts,
//! and TEOS locator derivation.
//! Prepared appointments cover revoked counterparty commitment
//! `to_local` outputs. Preparation does not submit to a tower or acknowledge LDK
//! delivery; HTLC outputs remain outside its scope.

use lightning::chain::channelmonitor::JusticeTransactions;
use teos_common::appointment::Locator;

mod appointments;
mod claims;
mod config;
mod dbm;
mod identity;
mod registration;
mod submission;

pub use appointments::{AppointmentPreparation, PendingAppointment, PreparationError};
pub use claims::{
    classify_claims, ClaimClassification, ClaimClassificationError, ToLocalClaim,
    UnclassifiedClaim, UnclassifiedClaimReason,
};
pub use config::{TowerConfig, TowerConfigError};
pub use dbm::{ClientStore, PendingAppointmentFailure, PendingAppointmentRecovery, StorageError};
pub use identity::ClientIdentity;
pub use registration::{RegistrationError, TowerClient};
pub use submission::SubmissionError;

/// Derives the TEOS appointment locator for a revoked counterparty commitment.
///
/// The locator identifies the commitment that triggers protection, rather than any
/// of the justice transactions spending its outputs. This does not select a claim
/// or imply that the commitment has been protected.
pub fn appointment_locator(justice: &JusticeTransactions) -> Locator {
    Locator::new(justice.revoked_commitment_txid)
}
