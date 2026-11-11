use std::{error::Error, fmt};

use lightning::bitcoin::Txid;
use lightning::ln::types::ChannelId;
use reqwest::StatusCode;
use teos_common::{
    protos::{AddAppointmentRequest, AddAppointmentResponse},
    receipts::AppointmentReceipt,
};

use crate::{ClientStore, StorageError, TowerClient};

const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_REJECTION_MESSAGE_BYTES: usize = 4 * 1024;
const TRUNCATION_MARKER: &str = " [truncated]";

// TODO: Add an ignored live integration test using an explicitly configured tower
// URL and ID: register -> prepare -> submit -> reopen -> verify the saved receipt.
// Document that it consumes tower resources; keep it separate from the mock tests.

impl TowerClient {
    /// Explicitly submits a saved appointment to the configured tower.
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
    /// Response bodies are limited to 16 KiB. Oversized HTTP 200 responses fail;
    /// rejection messages are limited to 4 KiB and marked when truncated.
    pub async fn submit_appointment(
        &self,
        store: &mut ClientStore,
        channel_id: ChannelId,
        commitment_txid: Txid,
    ) -> Result<AppointmentReceipt, SubmissionError> {
        // TODO: Before concurrent multi-tower delivery, separate loading, sending,
        // and saving so the mutable store borrow does not span the HTTP await.
        let job = store
            .pending_appointment(channel_id, commitment_txid)?
            .ok_or(SubmissionError::MissingAppointment)?;
        let response = self
            .http
            .post(self.endpoint("add_appointment"))
            .json(&AddAppointmentRequest {
                appointment: Some(job.appointment().clone().into()),
                signature: job.signature().to_owned(),
            })
            .send()
            .await?;
        let status = response.status();
        // Read failures remain transport errors; decoding a complete body is a
        // separate response error. Error responses may come from a proxy as well.
        let (body, truncated) = read_response(response).await?;
        if status != StatusCode::OK {
            let details = serde_json::from_slice::<serde_json::Value>(&body).ok();
            let error_code = details
                .as_ref()
                .and_then(|value| value.get("error_code"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|code| u32::try_from(code).ok());
            let message = details
                .as_ref()
                .and_then(|value| value.get("error"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
            let message = bounded_message(message, truncated);
            return Err(SubmissionError::Rejected {
                status,
                error_code,
                message,
            });
        }
        if truncated {
            return Err(SubmissionError::ResponseTooLarge {
                status,
                limit: MAX_RESPONSE_BYTES,
            });
        }
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
        store.store_appointment_receipt(self.config.tower_id(), &job, &receipt)?;
        Ok(receipt)
    }
}

async fn read_response(
    mut response: reqwest::Response,
) -> Result<(Vec<u8>, bool), SubmissionError> {
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| SubmissionError::ResponseRead { status, source })?
    {
        let remaining = MAX_RESPONSE_BYTES - body.len();
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, false))
}

fn bounded_message(mut message: String, body_truncated: bool) -> String {
    if body_truncated || message.len() > MAX_REJECTION_MESSAGE_BYTES {
        let mut end = message
            .len()
            .min(MAX_REJECTION_MESSAGE_BYTES - TRUNCATION_MARKER.len());
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push_str(TRUNCATION_MARKER);
    }
    message
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
