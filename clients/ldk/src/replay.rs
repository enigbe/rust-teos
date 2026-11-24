use lightning::bitcoin::{
    consensus,
    hashes::{sha256, Hash},
    Transaction,
};
use teos_common::TowerId;

use crate::{ClaimCoverage, CoverageRecord, UnclassifiedClaim};

/// Why a previously prepared commitment cannot safely be acknowledged after its
/// pending payload is gone. Restore evidence/configuration and re-offer explicitly;
/// none of these outcomes authorizes encrypting a replacement transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReofferBlockedReason {
    MissingDeliveryRecord,
    IncompleteDelivery,
    ClaimChanged,
    UnclassifiedClaims(Vec<UnclassifiedClaim>),
    MissingReceipt(TowerId),
    InvalidReceipt(TowerId),
}

pub(crate) enum ReplayResult {
    Unrecorded,
    Replayed {
        record: CoverageRecord,
        coverage: ClaimCoverage,
    },
    Blocked(ReofferBlockedReason),
}

// Match the pending-payload policy: outpoint, revocation script, delay.
// The domain tag keeps this format distinct from future fingerprint formats.
pub(crate) fn claim_fingerprint(transaction: &Transaction, delay: u32) -> Option<[u8; 32]> {
    let [input] = transaction.input.as_slice() else {
        return None;
    };
    let script = input.witness.last()?;
    let mut bytes = b"teos/claim/v1\0".to_vec();
    bytes.extend(consensus::serialize(&input.previous_output));
    bytes.extend(consensus::serialize(&script.to_vec()));
    bytes.extend_from_slice(&delay.to_le_bytes());
    Some(sha256::Hash::hash(&bytes).to_byte_array())
}
