use std::{error::Error, fmt};

use lightning::bitcoin::Txid;
use lightning::chain::channelmonitor::JusticeTransactions;
use lightning::ln::types::ChannelId;
use teos_common::{
    appointment::{Appointment, Locator},
    cryptography, UserId,
};

use crate::{
    classify_claims, ClaimClassification, ClaimClassificationError, ClientStore, StorageError,
};

/// A signed appointment saved for later delivery, independent of any target tower.
///
/// The first saved payload is immutable: later offers for the same channel and
/// commitment reuse it, even if LDK changes the fee or stops offering the claim.
/// This also avoids encrypting changed plaintext with TEOS's fixed nonce and
/// commitment-derived key. Successful storage is not evidence of tower protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAppointment {
    channel_id: ChannelId,
    commitment_txid: Txid,
    user_id: UserId,
    appointment: Appointment,
    signature: String,
}

impl PendingAppointment {
    /// Identifies the originating LDK channel.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }
    /// Returns the full triggering commitment ID, rather than its truncated locator.
    pub fn commitment_txid(&self) -> Txid {
        self.commitment_txid
    }
    /// Returns the persisted signing identity.
    pub fn user_id(&self) -> UserId {
        self.user_id
    }
    /// Returns the exact payload to submit to a tower.
    pub fn appointment(&self) -> &Appointment {
        &self.appointment
    }
    /// Returns the signature over the serialized appointment.
    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub(crate) fn restore(
        channel_id: ChannelId,
        commitment_txid: Txid,
        user_id: UserId,
        appointment: Appointment,
        signature: String,
        expected_user: Option<UserId>,
    ) -> Result<Self, StorageError> {
        if expected_user != Some(user_id)
            || appointment.locator != Locator::new(commitment_txid)
            || !cryptography::verify(&appointment.to_vec(), &signature, &user_id.0)
        {
            return Err(StorageError::InvalidPendingAppointment);
        }
        cryptography::decrypt(&appointment.encrypted_blob, &commitment_txid)
            .map_err(|_| StorageError::InvalidPendingAppointment)?;
        Ok(Self {
            channel_id,
            commitment_txid,
            user_id,
            appointment,
            signature,
        })
    }
}

/// The current coverage report together with an optional durably saved job.
///
/// Neither a saved job nor absence of a selectable claim authorizes acknowledging
/// delivery to LDK. In particular, HTLC and unclassified claims remain unprotected.
#[derive(Debug)]
pub struct AppointmentPreparation<'a> {
    classification: ClaimClassification<'a>,
    pending: Option<PendingAppointment>,
}

impl<'a> AppointmentPreparation<'a> {
    /// Classifies the current offer, which may differ from the saved payload.
    pub fn classification(&self) -> &ClaimClassification<'a> {
        &self.classification
    }
    /// Returns the newly saved or previously persisted job, if one exists.
    pub fn pending_appointment(&self) -> Option<&PendingAppointment> {
        self.pending.as_ref()
    }
}

impl ClientStore {
    /// Classifies an LDK offer and durably prepares its selected `to_local` claim.
    ///
    /// Identity creation and job insertion commit together. Repeated offers reuse
    /// the original job; no eligible claim creates no new job or identity. Invalid
    /// classification and corrupt stored data are errors, never replacements.
    /// No network request or LDK acknowledgment is performed.
    pub fn prepare_appointment<'a>(
        &mut self,
        channel_id: ChannelId,
        justice: &'a JusticeTransactions,
    ) -> Result<AppointmentPreparation<'a>, PreparationError> {
        let classification = classify_claims(justice).map_err(PreparationError::Classification)?;
        let pending = match self.pending_appointment(channel_id, justice.revoked_commitment_txid)? {
            Some(job) => Some(job),
            None => match classification.to_local() {
                Some(claim) => Some(self.insert_pending_appointment(
                    channel_id,
                    justice.revoked_commitment_txid,
                    |identity| {
                        let blob = cryptography::encrypt(
                            claim.transaction(),
                            &justice.revoked_commitment_txid,
                        )
                        .map_err(|_| PreparationError::Encryption)?;
                        let appointment = Appointment::new(
                            Locator::new(justice.revoked_commitment_txid),
                            blob,
                            claim.to_self_delay().into(),
                        );
                        Ok(PendingAppointment {
                            channel_id,
                            commitment_txid: justice.revoked_commitment_txid,
                            user_id: identity.user_id(),
                            signature: identity.sign(&appointment.to_vec()),
                            appointment,
                        })
                    },
                )?),
                None => None,
            },
        };
        Ok(AppointmentPreparation {
            classification,
            pending,
        })
    }
}

/// A failure to classify, encrypt, or durably save a pending appointment.
#[derive(Debug)]
pub enum PreparationError {
    /// The offer contains inconsistent commitment IDs or ambiguous `to_local` claims.
    Classification(ClaimClassificationError),
    /// SQLite or validation of stored data failed.
    Storage(StorageError),
    /// The selected transaction could not be encrypted.
    Encryption,
}
impl From<StorageError> for PreparationError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}
impl fmt::Display for PreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Classification(error) => write!(f, "Cannot prepare appointment: {error}"),
            Self::Storage(error) => write!(f, "Cannot save appointment: {error}"),
            Self::Encryption => write!(f, "Cannot encrypt appointment transaction"),
        }
    }
}
impl Error for PreparationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Classification(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Encryption => None,
        }
    }
}
