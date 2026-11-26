use std::{error::Error, fmt};

use lightning::bitcoin::Txid;
use lightning::ln::types::ChannelId;
use reqwest::StatusCode;
use teos_common::{
    protos::{AddAppointmentRequest, AddAppointmentResponse},
    receipts::AppointmentReceipt,
    TowerId,
};

use crate::{ClientStore, PendingAppointment, StorageError, TowerClient};

use crate::tower_response::{read_success, ResponseError, MAX_RESPONSE_BYTES};

/// A tower receipt verified against the exact submitted job, not yet necessarily saved.
///
/// Obtain this from [`TowerClient::send_appointment`], then save it with
/// [`ClientStore::save_appointment_receipt`]. Retain it if saving fails so the save
/// can be retried without another tower request. This does not authorize LDK acknowledgment.
#[derive(Clone, Debug)]
pub struct VerifiedAppointmentReceipt {
    tower_id: TowerId,
    job: PendingAppointment,
    receipt: AppointmentReceipt,
}

impl VerifiedAppointmentReceipt {
    /// Returns the configured tower whose signature was verified.
    pub fn tower_id(&self) -> TowerId {
        self.tower_id
    }
    /// Returns the exact saved job that was sent to the tower.
    pub fn job(&self) -> &PendingAppointment {
        &self.job
    }
    /// Returns the verified receipt. Verification alone does not imply persistence.
    pub fn receipt(&self) -> &AppointmentReceipt {
        &self.receipt
    }
}

impl TowerClient {
    /// Explicitly submits a saved appointment to the configured tower.
    ///
    /// This convenience method borrows the store throughout the request. For
    /// concurrent delivery, load the job, call [`Self::send_appointment`], and
    /// save the result with [`ClientStore::save_appointment_receipt`] instead.
    /// If saving fails, this convenience method returns a storage error without
    /// the verified receipt. Use the split API to retain it and retry saving
    /// without another tower request.
    ///
    /// Loads and validates the pending job before sending its exact payload. Checks
    /// the response locator and tower signature, then persists the receipt before
    /// returning success. The unsigned slot count and subscription expiry in the
    /// response do not replace the signed registration receipt.
    ///
    /// No automatic retries, pending-job removal, or LDK acknowledgment occur.
    /// A transport error or receipt-save failure can occur after tower acceptance;
    /// callers may explicitly resubmit the same saved payload. An accepted receipt
    /// only covers that payload, not HTLC or unclassified claims in the commitment.
    /// Rejection codes are preserved without choosing a recovery or retry policy;
    /// in particular, an already-triggered appointment is not treated as delivered.
    /// HTTP 200 bodies are limited to 16 KiB; oversized responses fail. Rejection
    /// bodies and messages are limited to 4 KiB, with messages marked when truncated.
    pub async fn submit_appointment(
        &self,
        store: &mut ClientStore,
        channel_id: ChannelId,
        commitment_txid: Txid,
    ) -> Result<AppointmentReceipt, SubmissionError> {
        let job = store
            .pending_appointment(channel_id, commitment_txid)?
            .ok_or(SubmissionError::MissingAppointment)?;
        let delivery = self.send_appointment(&job).await?;
        store.save_appointment_receipt(&delivery)?;
        Ok(delivery.receipt)
    }

    /// Sends a saved job's exact payload and verifies the tower's response without storage access.
    ///
    /// First load the job with [`ClientStore::pending_appointment`]. The returned
    /// receipt is verified but not persisted: explicitly call
    /// [`ClientStore::save_appointment_receipt`] before treating delivery as durable.
    /// Multiple sends can run concurrently without borrowing the client store.
    /// The result retains the original job and configured tower ID for saving.
    ///
    /// Uses the same response limits and validation as [`Self::submit_appointment`].
    /// No automatic retries, pending-job removal, or LDK acknowledgment occur.
    pub async fn send_appointment(
        &self,
        job: &PendingAppointment,
    ) -> Result<VerifiedAppointmentReceipt, SubmissionError> {
        let response = self
            .http
            .post(self.endpoint("add_appointment"))
            .json(&AddAppointmentRequest {
                appointment: Some(job.appointment().clone().into()),
                signature: job.signature().to_owned(),
            })
            .send()
            .await?;
        let body = read_success(response, MAX_RESPONSE_BYTES).await?;
        let response: AddAppointmentResponse =
            serde_json::from_slice(&body).map_err(SubmissionError::InvalidResponse)?;
        if response.locator != job.appointment().locator.to_vec() {
            return Err(SubmissionError::UnexpectedLocator);
        }
        let receipt = AppointmentReceipt::with_signature(
            job.signature().to_owned(),
            response.start_block,
            response.signature,
        );
        if !receipt.verify(&self.config.tower_id()) {
            // TODO: With tower status/misbehavior handling, retain the received
            // receipt and context, distinguishing malformed signatures from
            // valid signatures made by an unexpected key.
            return Err(SubmissionError::InvalidSignature);
        }
        Ok(VerifiedAppointmentReceipt {
            tower_id: self.config.tower_id(),
            job: job.clone(),
            receipt,
        })
    }
}

/// A failure to submit a pending appointment or save the verified tower receipt.
#[derive(Debug)]
pub enum SubmissionError {
    /// No saved appointment exists for the channel and commitment ID.
    MissingAppointment,
    /// Request setup, transport, or timeout failed before receiving response headers.
    Request(reqwest::Error),
    /// Reading a response body failed after receiving its HTTP status.
    ResponseRead {
        /// The HTTP status received before the body read failed.
        status: StatusCode,
        /// The underlying transfer or timeout failure.
        source: reqwest::Error,
    },
    /// An HTTP 200 response exceeded the 16 KiB body limit.
    ResponseTooLarge {
        /// The received HTTP status.
        status: StatusCode,
        /// The maximum number of body bytes retained.
        limit: usize,
    },
    /// A complete HTTP 200 response could not be decoded as the expected payload.
    InvalidResponse(serde_json::Error),
    /// An HTTP response other than 200 OK, including any supplied rejection details.
    Rejected {
        /// The received HTTP status, including errors returned by proxies.
        status: StatusCode,
        /// The tower's numeric code, if present and representable as a u32.
        /// Unknown codes are preserved; known codes are in `teos_common::errors`.
        error_code: Option<u32>,
        /// The JSON error message, or the response body decoded as lossy UTF-8.
        /// At most 4 KiB, with a marker if the body or message was truncated.
        message: String,
    },
    /// The response locator does not match the submitted appointment.
    UnexpectedLocator,
    /// The receipt lacks a valid configured-tower signature over the submitted client signature.
    InvalidSignature,
    /// Loading the saved job or persisting the receipt failed.
    Storage(StorageError),
}
impl From<ResponseError> for SubmissionError {
    fn from(error: ResponseError) -> Self {
        match error {
            ResponseError::Read { status, source } => Self::ResponseRead { status, source },
            ResponseError::TooLarge { status, limit } => Self::ResponseTooLarge { status, limit },
            ResponseError::Rejected {
                status,
                error_code,
                message,
            } => Self::Rejected {
                status,
                error_code,
                message,
            },
        }
    }
}

impl From<reqwest::Error> for SubmissionError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}
impl From<StorageError> for SubmissionError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}
impl fmt::Display for SubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAppointment => {
                write!(f, "No pending appointment exists for this commitment")
            }
            Self::Request(error) => write!(f, "Tower submission request failed: {error}"),
            Self::ResponseRead { status, source } => write!(
                f,
                "Cannot read tower submission response (HTTP {status}): {source}"
            ),
            Self::ResponseTooLarge { status, limit } => write!(
                f,
                "Tower submission response (HTTP {status}) exceeds {limit} bytes"
            ),
            Self::InvalidResponse(error) => write!(f, "Invalid tower submission response: {error}"),
            Self::Rejected {
                status,
                error_code,
                message,
            } => {
                write!(f, "Tower submission rejected with HTTP {status}")?;
                if let Some(code) = error_code {
                    write!(f, " (error code {code})")?;
                }
                write!(f, ": {message}")
            }
            Self::UnexpectedLocator => {
                write!(f, "Tower response identifies a different appointment")
            }
            Self::InvalidSignature => write!(f, "Tower appointment signature is invalid"),
            Self::Storage(error) => write!(f, "{error}"),
        }
    }
}
impl Error for SubmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::ResponseRead { source, .. } => Some(source),
            Self::InvalidResponse(error) => Some(error),
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}
