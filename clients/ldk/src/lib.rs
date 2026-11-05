//! An embedded watchtower client for LDK-based Lightning nodes using The Eye of Satoshi.
//!
//! This crate provides tower connection configuration and connects LDK justice
//! transaction types to TEOS locators.
//! The initial implementation is planned to protect revoked counterparty commitment
//! `to_local` outputs; HTLC outputs are outside its initial scope.

use lightning::chain::channelmonitor::JusticeTransactions;
use teos_common::appointment::Locator;

mod config;

pub use config::{TowerConfig, TowerConfigError};

/// Derives the TEOS appointment locator for a revoked counterparty commitment.
///
/// The locator identifies the commitment that triggers protection, rather than any
/// of the justice transactions spending its outputs. This does not select a claim
/// or imply that the commitment has been protected.
pub fn appointment_locator(justice: &JusticeTransactions) -> Locator {
    Locator::new(justice.revoked_commitment_txid)
}
