use std::error::Error;
use std::fmt;

use lightning::bitcoin::ecdsa::Signature;
use lightning::bitcoin::hashes::Hash;
use lightning::bitcoin::opcodes::all::*;
use lightning::bitcoin::script::Instruction::{Op, PushBytes};
use lightning::bitcoin::secp256k1::PublicKey;
use lightning::bitcoin::sighash::EcdsaSighashType;
use lightning::bitcoin::{PubkeyHash, Script, Transaction};
use lightning::chain::channelmonitor::JusticeTransactions;
use lightning::ln::chan_utils::get_revokeable_redeemscript;
use lightning::ln::channel_keys::{DelayedPaymentKey, RevocationKey};

/// A borrowed `to_local` justice transaction and its commitment output's CSV delay.
#[derive(Debug)]
pub struct ToLocalClaim<'a> {
    transaction: &'a Transaction,
    to_self_delay: u16,
}

impl<'a> ToLocalClaim<'a> {
    /// Returns the original signed transaction without rebuilding or modifying it.
    pub fn transaction(&self) -> &'a Transaction {
        self.transaction
    }

    /// Returns the delay encoded in the spent `to_local` witness script.
    pub fn to_self_delay(&self) -> u16 {
        self.to_self_delay
    }
}

/// Classification of the claims supplied for one revoked commitment.
///
/// This describes recognition, not successful delivery or complete protection.
#[derive(Debug)]
pub struct ClaimClassification<'a> {
    to_local: Option<ToLocalClaim<'a>>,
    recognized_htlc_claims: usize,
    unclassified: Vec<UnclassifiedClaim>,
}

impl<'a> ClaimClassification<'a> {
    /// Returns the recognized `to_local` claim, if one was supplied.
    pub fn to_local(&self) -> Option<&ToLocalClaim<'a>> {
        self.to_local.as_ref()
    }

    /// Counts supplied claims with recognized HTLC revocation witnesses.
    ///
    /// This is neither a count of all channel HTLC outputs nor protected HTLCs:
    /// LDK may omit uneconomical claims, and this client only selects `to_local`.
    pub fn recognized_htlc_claims(&self) -> usize {
        self.recognized_htlc_claims
    }

    /// Returns the indices and reasons for claims this version cannot classify.
    pub fn unclassified(&self) -> &[UnclassifiedClaim] {
        &self.unclassified
    }
}

/// A supplied claim that this client version could not classify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnclassifiedClaim {
    transaction_index: usize,
    reason: UnclassifiedClaimReason,
}

impl UnclassifiedClaim {
    /// Returns the index into the original [`JusticeTransactions::txs`] vector.
    pub fn transaction_index(&self) -> usize {
        self.transaction_index
    }

    /// Returns the unsupported part of the transaction's shape or witness.
    pub fn reason(&self) -> UnclassifiedClaimReason {
        self.reason
    }
}

/// Why a claim's role is unknown to this client version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnclassifiedClaimReason {
    /// This version expects exactly one input per justice transaction.
    UnsupportedInputCount,
    /// This version expects native SegWit inputs with an empty scriptSig.
    UnsupportedScriptSig,
    /// The signature encoding or sighash type is unsupported.
    UnsupportedSignature,
    /// The witness shape, selector, or script does not match a recognized format.
    UnsupportedWitness,
}

/// Classifies the pinned LDK justice API's output, identifying its `to_local` claim.
///
/// Call this only with entries returned by `ChannelMonitor::get_pending_justice_txs`.
/// It recognizes LDK's revocation witnesses and standard `to_local` script rather
/// than relying on vector order. This does not verify signatures against spent
/// outputs, transaction fees, or consensus validity.
///
/// Unknown formats are reported individually without discarding a recognized
/// `to_local` claim. An absent `to_local` claim can mean an empty entry, HTLC-only claims,
/// or unclassified claims; inspect the report to distinguish these cases.
///
/// Every input is checked against the entry's commitment, including inputs of
/// otherwise unsupported transactions. A mismatched commitment or multiple
/// recognized `to_local` candidates makes the whole entry an error.
///
/// A successful report does not imply complete channel protection or authorize
/// acknowledging the commitment's justice transactions to LDK. Delivery and
/// acknowledgment policy must account separately for partial coverage.
pub fn classify_claims(
    justice: &JusticeTransactions,
) -> Result<ClaimClassification<'_>, ClaimClassificationError> {
    if justice
        .txs
        .iter()
        .flat_map(|transaction| &transaction.input)
        .any(|input| input.previous_output.txid != justice.revoked_commitment_txid)
    {
        return Err(ClaimClassificationError::UnexpectedCommitment);
    }

    let mut classification = ClaimClassification {
        to_local: None,
        recognized_htlc_claims: 0,
        unclassified: Vec::new(),
    };
    for (transaction_index, transaction) in justice.txs.iter().enumerate() {
        match classify_claim(transaction) {
            Ok(ClassifiedClaim::ToLocal(claim)) => {
                if classification.to_local.is_some() {
                    return Err(ClaimClassificationError::AmbiguousToLocal);
                }
                classification.to_local = Some(claim);
            }
            Ok(ClassifiedClaim::Htlc) => classification.recognized_htlc_claims += 1,
            Err(reason) => classification.unclassified.push(UnclassifiedClaim {
                transaction_index,
                reason,
            }),
        }
    }
    Ok(classification)
}

enum ClassifiedClaim<'a> {
    ToLocal(ToLocalClaim<'a>),
    Htlc,
}

fn classify_claim(
    transaction: &Transaction,
) -> Result<ClassifiedClaim<'_>, UnclassifiedClaimReason> {
    let [input] = transaction.input.as_slice() else {
        return Err(UnclassifiedClaimReason::UnsupportedInputCount);
    };
    if !input.script_sig.is_empty() {
        return Err(UnclassifiedClaimReason::UnsupportedScriptSig);
    }
    let witness: Vec<_> = input.witness.iter().collect();
    let [signature, selector, script] = witness.as_slice() else {
        return Err(UnclassifiedClaimReason::UnsupportedWitness);
    };
    if !matches!(Signature::from_slice(signature), Ok(signature) if signature.sighash_type == EcdsaSighashType::All)
    {
        return Err(UnclassifiedClaimReason::UnsupportedSignature);
    }
    let script = Script::from_bytes(script);
    if *selector == [1].as_slice() {
        let delay = to_local_delay(script).ok_or(UnclassifiedClaimReason::UnsupportedWitness)?;
        Ok(ClassifiedClaim::ToLocal(ToLocalClaim {
            transaction,
            to_self_delay: delay,
        }))
    } else if is_htlc_revocation(script, selector) {
        Ok(ClassifiedClaim::Htlc)
    } else {
        Err(UnclassifiedClaimReason::UnsupportedWitness)
    }
}

fn to_local_delay(script: &Script) -> Option<u16> {
    let instructions = script
        .instructions_minimal()
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let [Op(OP_IF), PushBytes(revocation), Op(OP_ELSE), delay, Op(OP_CSV), Op(OP_DROP), PushBytes(delayed), Op(OP_ENDIF), Op(OP_CHECKSIG)] =
        instructions.as_slice()
    else {
        return None;
    };
    let delay = u16::try_from(delay.script_num()?).ok()?;
    let revocation = RevocationKey(PublicKey::from_slice(revocation.as_bytes()).ok()?);
    let delayed = DelayedPaymentKey(PublicKey::from_slice(delayed.as_bytes()).ok()?);
    // Rebuilding with LDK rejects noncanonical encodings and unexpected script changes.
    let expected = get_revokeable_redeemscript(&revocation, delay, &delayed);
    (expected.as_script() == script).then_some(delay)
}

fn is_htlc_revocation(script: &Script, selector: &[u8]) -> bool {
    if selector.len() != 33 || PublicKey::from_slice(selector).is_err() {
        return false;
    }
    let Ok(instructions) = script.instructions_minimal().collect::<Result<Vec<_>, _>>() else {
        return false;
    };
    // Both offered and received HTLCs use this revocation branch, including anchors.
    // Only recognize the branch needed to distinguish them, not the full HTLC script.
    matches!(
        instructions.as_slice(),
        [Op(OP_DUP), Op(OP_HASH160), PushBytes(hash), Op(OP_EQUAL), Op(OP_IF), Op(OP_CHECKSIG), Op(OP_ELSE), ..]
            if hash.as_bytes() == PubkeyHash::hash(selector).as_byte_array()
    )
}

/// A justice entry mixes commitments or has ambiguous recognized `to_local` claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimClassificationError {
    /// A claim spends a transaction other than the entry's revoked commitment.
    UnexpectedCommitment,
    /// More than one claim has a `to_local` revocation witness.
    AmbiguousToLocal,
}

impl fmt::Display for ClaimClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedCommitment => write!(f, "Justice claim spends a different commitment"),
            Self::AmbiguousToLocal => write!(f, "Multiple to_local justice claims were supplied"),
        }
    }
}

impl Error for ClaimClassificationError {}
