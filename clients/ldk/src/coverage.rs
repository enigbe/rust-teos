use lightning::bitcoin::Txid;
use lightning::ln::types::ChannelId;
use teos_common::TowerId;

use crate::{ClaimCoverage, StorageError};

/// Explicit protection promised by the client. There is deliberately no default.
/// Acknowledgment releases LDK's whole watchtower-retention entry; outputs excluded
/// by this scope are not backed up and cannot be recovered from that retained entry later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionScope {
    /// Back up only recognized to_local claims. Recognized HTLC claims are reported
    /// as excluded. Unknown/malformed claims and mismatched saved payloads block ack.
    /// Claims omitted by LDK at the configured fee rate do not block acknowledgment.
    /// After acknowledgment, lowering the fee cannot recover them from LDK retention.
    ToLocalOnly,
}
impl ProtectionScope {
    pub(crate) fn id(self) -> i64 {
        match self {
            Self::ToLocalOnly => 1,
        }
    }
    pub(crate) fn from_id(id: i64) -> Option<Self> {
        match id {
            1 => Some(Self::ToLocalOnly),
            _ => None,
        }
    }
}

/// Why a complete LDK snapshot does or does not require an appointment in this scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageOutcome {
    /// A recognized to_local claim requires receipts from every required tower.
    ToLocalAppointment,
    /// Only recognized HTLC claims were generated at the configured fee rate.
    /// A to_local output may be absent or uneconomical; this result cannot distinguish them.
    NoToLocalClaimAtFeeRate,
    /// LDK generated no claims at the configured fee rate; outputs may still exist.
    NoClaimsAtFeeRate,
    /// Unknown claims or a mismatched saved claim prevent scope fulfillment.
    Blocked,
}

pub(crate) fn outcome(
    to_local: bool,
    htlcs: usize,
    unknown: usize,
    matches: bool,
) -> CoverageOutcome {
    if unknown != 0 || (to_local && !matches) {
        CoverageOutcome::Blocked
    } else if to_local {
        CoverageOutcome::ToLocalAppointment
    } else if htlcs != 0 {
        CoverageOutcome::NoToLocalClaimAtFeeRate
    } else {
        CoverageOutcome::NoClaimsAtFeeRate
    }
}

/// An immutable coverage observation, with a monotonic local completion marker.
///
/// Records retain the selected scope, excluded/unknown claim counts, fee rate,
/// frozen payload signature, and required tower set across restarts. Unknown claim
/// indices/reasons remain available in the immediate ClaimCoverage diagnostic.
/// `completion_ready` means the client durably checked this scope's obligations;
/// it does not prove that LDK consumed the queued acknowledgment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageRecord {
    pub(crate) id: i64,
    pub(crate) channel_id: ChannelId,
    pub(crate) commitment_txid: Txid,
    pub(crate) scope: ProtectionScope,
    pub(crate) feerate_per_kw: u64,
    pub(crate) to_local: bool,
    pub(crate) excluded_htlc_claims: usize,
    pub(crate) unclassified_claims: usize,
    pub(crate) stored_claim_matches: bool,
    pub(crate) client_signature: Option<String>,
    pub(crate) required_towers: Vec<TowerId>,
    pub(crate) completion_ready: bool,
}
impl CoverageRecord {
    pub(crate) fn observation(
        id: (ChannelId, Txid),
        scope: ProtectionScope,
        feerate_per_kw: u64,
        coverage: &ClaimCoverage,
        signature: Option<&str>,
        mut required_towers: Vec<TowerId>,
    ) -> Self {
        required_towers.sort_unstable_by_key(TowerId::to_vec);
        Self {
            id: 0,
            channel_id: id.0,
            commitment_txid: id.1,
            scope,
            feerate_per_kw,
            to_local: coverage.to_local(),
            excluded_htlc_claims: coverage.recognized_htlc_claims(),
            unclassified_claims: coverage.unclassified().len(),
            stored_claim_matches: coverage.stored_claim_matches(),
            client_signature: signature.map(str::to_owned),
            required_towers,
            completion_ready: false,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        if self.feerate_per_kw == 0
            || self.required_towers.is_empty()
            || self
                .required_towers
                .windows(2)
                .any(|pair| pair[0].to_vec() >= pair[1].to_vec())
            || self.to_local
                != self
                    .client_signature
                    .as_ref()
                    .is_some_and(|signature| !signature.is_empty())
            || (!self.to_local && self.stored_claim_matches)
            || (self.completion_ready && self.outcome() == CoverageOutcome::Blocked)
        {
            return Err(StorageError::InvalidCoverage);
        }
        Ok(())
    }
    pub(crate) fn same_observation(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.completion_ready = false;
        b.completion_ready = false;
        a == b
    }
    /// Stable local observation identifier.
    pub fn id(&self) -> i64 {
        self.id
    }
    /// The originating channel.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }
    /// The full revoked commitment ID.
    pub fn commitment_txid(&self) -> Txid {
        self.commitment_txid
    }
    /// The explicitly selected protection scope.
    pub fn scope(&self) -> ProtectionScope {
        self.scope
    }
    /// Fee rate used to generate the offered claims, including empty snapshots.
    pub fn feerate_per_kw(&self) -> u64 {
        self.feerate_per_kw
    }
    /// Recognized HTLC claims deliberately excluded from this scope.
    pub fn excluded_htlc_claims(&self) -> usize {
        self.excluded_htlc_claims
    }
    /// Unknown supplied claims, which prevent acknowledgment.
    pub fn unclassified_claims(&self) -> usize {
        self.unclassified_claims
    }
    /// Signature binding an applicable observation to the frozen appointment payload.
    pub fn client_signature(&self) -> Option<&str> {
        self.client_signature.as_deref()
    }
    /// Required towers, in canonical public-key order. No-applicable-claim outcomes
    /// record the configured set but do not require tower receipts.
    pub fn required_towers(&self) -> &[TowerId] {
        &self.required_towers
    }
    /// Why an appointment is required, unnecessary, or blocked in this scope.
    pub fn outcome(&self) -> CoverageOutcome {
        match self.scope {
            ProtectionScope::ToLocalOnly => outcome(
                self.to_local,
                self.excluded_htlc_claims,
                self.unclassified_claims,
                self.stored_claim_matches,
            ),
        }
    }
    /// Scope obligations were durably checked before queueing a completion. This is
    /// not a claim that HTLCs are protected or that LDK received the acknowledgment.
    pub fn completion_ready(&self) -> bool {
        self.completion_ready
    }
}
