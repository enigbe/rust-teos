use std::{error::Error, fmt, num::NonZeroUsize};

use reqwest::StatusCode;
use teos_common::{
    appointment::Locator,
    protos::{GetSubscriptionInfoRequest, GetSubscriptionInfoResponse},
};

use crate::tower_response::{read_success, ResponseError};
use crate::{ClientIdentity, TowerClient};

// Subscription replies can contain thousands of locators, unlike signed receipts.
const DEFAULT_SUBSCRIPTION_BYTES: usize = 1024 * 1024;

/// The tower's unsigned report of the user's current subscription and locators.
///
/// This is an observation, not a registration receipt or proof of appointment
/// delivery. It does not authorize LDK acknowledgment or replace saved evidence.
#[derive(Clone, Debug)]
pub struct SubscriptionInfo {
    available_slots: u32,
    subscription_expiry: u32,
    locators: Vec<Locator>,
}

impl SubscriptionInfo {
    /// Remaining appointment slots reported by the tower.
    pub fn available_slots(&self) -> u32 {
        self.available_slots
    }
    /// Expiry block height reported by the tower. The protocol supplies no start height.
    pub fn subscription_expiry(&self) -> u32 {
        self.subscription_expiry
    }
    /// Appointment locators reported by the tower, with no ordering guarantee.
    pub fn locators(&self) -> &[Locator] {
        &self.locators
    }
}

impl TowerClient {
    /// Queries subscription state using the supplied persistent client's identity.
    ///
    /// Obtain the identity from [`crate::ClientStore::load_or_create_identity`].
    /// Signs the protocol's `get subscription info` message without borrowing
    /// storage during the request. This method does not register, renew, retry,
    /// save the response, or rearm delivery. A rejection is returned to the caller.
    ///
    /// The response is unsigned. Its slots, expiry, and locator list do not replace
    /// registration or appointment receipts. HTTP 200 bodies are limited to 1 MiB;
    /// larger reports fail explicitly instead of returning an incomplete list.
    /// Use [`Self::subscription_info_with_limit`] for a larger report.
    /// Rejection bodies and messages use the same 4 KiB limit as registration
    /// and submission.
    pub async fn subscription_info(
        &self,
        identity: &ClientIdentity,
    ) -> Result<SubscriptionInfo, SubscriptionError> {
        self.subscription_info_with_limit(
            identity,
            NonZeroUsize::new(DEFAULT_SUBSCRIPTION_BYTES).unwrap(),
        )
        .await
    }

    /// Queries unsigned subscription state with an HTTP 200 body byte limit.
    ///
    /// Uses the same authentication and read-only semantics as
    /// [`Self::subscription_info`]. Oversized HTTP 200 responses return
    /// [`SubscriptionError::ResponseTooLarge`] instead of a partial locator list.
    ///
    /// TEOS encodes each locator as 32 hexadecimal characters, costing about 35
    /// bytes in JSON including quotes and a comma. Allow roughly 35 bytes per
    /// expected locator plus headroom for the remaining fields. The default
    /// 1 MiB covers about 30,000 locators. Registration's remaining slot count
    /// does not establish how many appointments the tower currently holds.
    /// Non-200 bodies and rejection messages remain capped at 4 KiB regardless
    /// of the success limit. Error codes are extracted when the retained body
    /// contains a complete JSON error response.
    pub async fn subscription_info_with_limit(
        &self,
        identity: &ClientIdentity,
        limit: NonZeroUsize,
    ) -> Result<SubscriptionInfo, SubscriptionError> {
        let response = self
            .http
            .post(self.endpoint("get_subscription_info"))
            .json(&GetSubscriptionInfoRequest {
                signature: identity.sign(b"get subscription info"),
            })
            .send()
            .await?;
        let body = read_success(response, limit.get()).await?;
        let response: GetSubscriptionInfoResponse =
            serde_json::from_slice(&body).map_err(SubscriptionError::InvalidResponse)?;
        let locators = response
            .locators
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                Locator::from_slice(bytes).map_err(|_| SubscriptionError::InvalidLocator { index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SubscriptionInfo {
            available_slots: response.available_slots,
            subscription_expiry: response.subscription_expiry,
            locators,
        })
    }
}

/// A failure to query or decode the tower's unsigned subscription report.
#[derive(Debug)]
pub enum SubscriptionError {
    /// Request setup, transport, or timeout failed before response headers arrived.
    Request(reqwest::Error),
    /// Body transfer failed after receiving the response status.
    ResponseRead {
        status: StatusCode,
        source: reqwest::Error,
    },
    /// An HTTP 200 response exceeded the selected body limit (1 MiB by default).
    ResponseTooLarge { status: StatusCode, limit: usize },
    /// A complete HTTP 200 body could not be decoded as a subscription response.
    InvalidResponse(serde_json::Error),
    /// The zero-based locator entry does not contain exactly 16 bytes.
    InvalidLocator { index: usize },
    /// An HTTP rejection, preserving any tower code and a bounded message.
    Rejected {
        status: StatusCode,
        error_code: Option<u32>,
        message: String,
    },
}

impl From<reqwest::Error> for SubscriptionError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}
impl From<ResponseError> for SubscriptionError {
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
impl fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => write!(f, "Tower subscription query failed: {error}"),
            Self::ResponseRead { status, source } => write!(
                f,
                "Cannot read tower subscription response (HTTP {status}): {source}"
            ),
            Self::ResponseTooLarge { status, limit } => write!(
                f,
                "Tower subscription response (HTTP {status}) exceeds {limit} bytes"
            ),
            Self::InvalidResponse(error) => {
                write!(f, "Invalid tower subscription response: {error}")
            }
            Self::InvalidLocator { index } => {
                write!(f, "Invalid locator at subscription entry {index}")
            }
            Self::Rejected {
                status,
                error_code,
                message,
            } => {
                write!(f, "Tower subscription query rejected with HTTP {status}")?;
                if let Some(code) = error_code {
                    write!(f, " (error code {code})")?;
                }
                write!(f, ": {message}")
            }
        }
    }
}
impl Error for SubscriptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::ResponseRead { source, .. } => Some(source),
            Self::InvalidResponse(error) => Some(error),
            _ => None,
        }
    }
}
