use std::error::Error;
use std::fmt;

use reqwest::{redirect::Policy, Client, StatusCode};
use teos_common::protos::{RegisterRequest, RegisterResponse};
use teos_common::receipts::RegistrationReceipt;

use crate::{ClientStore, StorageError, TowerConfig};

use crate::tower_response::{read_success, ResponseError, MAX_RESPONSE_BYTES};

/// An HTTP client for a single TEOS tower.
///
/// Constructing this does not contact the tower. Requests require a Tokio runtime.
#[derive(Clone)]
pub struct TowerClient {
    pub(crate) config: TowerConfig,
    pub(crate) http: Client,
}

impl TowerClient {
    /// Constructs a client using the configured timeout, with redirects disabled.
    pub fn new(config: TowerConfig) -> Result<Self, RegistrationError> {
        let http = Client::builder()
            .timeout(config.request_timeout())
            .redirect(Policy::none())
            .build()?;
        Ok(Self { config, http })
    }

    pub(crate) fn endpoint(&self, method: &str) -> url::Url {
        let mut endpoint = self.config.endpoint().clone();
        // Preserve an optional reverse-proxy path prefix.
        endpoint.set_path(&format!(
            "{}/{}",
            endpoint.path().trim_end_matches('/'),
            method
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
    }

    /// Explicitly registers or tops up the persisted identity with the tower.
    ///
    /// Verifies the returned user, subscription range, and tower signature before
    /// storing the signed receipt. Success means local persistence also succeeded.
    /// This does not retry: the tower may already have changed the subscription if
    /// the response is lost or local storage fails. Callers must not blindly retry.
    /// HTTP 200 bodies are limited to 16 KiB; rejection bodies and messages to
    /// 4 KiB. Tower codes from complete JSON errors are preserved. Malformed replies
    /// and body-transfer failures are separate; neither triggers re-registration.
    pub async fn register(
        &self,
        store: &mut ClientStore,
    ) -> Result<RegistrationReceipt, RegistrationError> {
        let identity = store.load_or_create_identity()?;
        let user_id = identity.user_id();

        let response = self
            .http
            .post(self.endpoint("register"))
            .json(&RegisterRequest {
                user_id: user_id.to_vec(),
            })
            .send()
            .await?;
        let body = read_success(response, MAX_RESPONSE_BYTES).await?;
        let response: RegisterResponse =
            serde_json::from_slice(&body).map_err(RegistrationError::InvalidResponse)?;
        if response.user_id != user_id.to_vec() {
            return Err(RegistrationError::UnexpectedUser);
        }
        if response.subscription_expiry <= response.subscription_start {
            return Err(RegistrationError::InvalidSubscription);
        }
        let receipt = RegistrationReceipt::with_signature(
            user_id,
            response.available_slots,
            response.subscription_start,
            response.subscription_expiry,
            response.subscription_signature,
        );
        if !receipt.verify(&self.config.tower_id()) {
            return Err(RegistrationError::InvalidSignature);
        }

        store.store_registration(self.config.tower_id(), &receipt)?;
        Ok(receipt)
    }
}

/// A failure to register with a tower or save its verified receipt.
#[derive(Debug)]
pub enum RegistrationError {
    /// Request setup, transport, or timeout failed before receiving response headers.
    Request(reqwest::Error),
    /// Reading the body failed after receiving its HTTP status.
    ResponseRead {
        status: StatusCode,
        source: reqwest::Error,
    },
    /// An HTTP 200 body exceeded the 16 KiB response limit.
    ResponseTooLarge { status: StatusCode, limit: usize },
    /// A complete HTTP 200 body could not be decoded as a registration response.
    InvalidResponse(serde_json::Error),
    /// An HTTP status other than 200, with any tower code and bounded message.
    Rejected {
        status: StatusCode,
        error_code: Option<u32>,
        message: String,
    },
    /// The tower's response identifies a different client.
    UnexpectedUser,
    /// Subscription expiry is not later than its start.
    InvalidSubscription,
    /// The receipt does not carry a valid signature from the configured tower.
    InvalidSignature,
    /// The client identity or registration could not be persisted or loaded.
    Storage(StorageError),
}

impl From<ResponseError> for RegistrationError {
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

impl From<reqwest::Error> for RegistrationError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error)
    }
}

impl From<StorageError> for RegistrationError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => write!(f, "Tower registration request failed: {error}"),
            Self::ResponseRead { status, source } => write!(
                f,
                "Cannot read tower registration response (HTTP {status}): {source}"
            ),
            Self::ResponseTooLarge { status, limit } => write!(
                f,
                "Tower registration response (HTTP {status}) exceeds {limit} bytes"
            ),
            Self::InvalidResponse(error) => {
                write!(f, "Invalid tower registration response: {error}")
            }
            Self::Rejected {
                status,
                error_code,
                message,
            } => {
                write!(f, "Tower registration rejected with HTTP {status}")?;
                if let Some(code) = error_code {
                    write!(f, " (error code {code})")?;
                }
                write!(f, ": {message}")
            }
            Self::UnexpectedUser => write!(f, "Tower registration identifies a different client"),
            Self::InvalidSubscription => {
                write!(f, "Tower registration has an invalid subscription range")
            }
            Self::InvalidSignature => write!(f, "Tower registration signature is invalid"),
            Self::Storage(error) => write!(f, "{error}"),
        }
    }
}

impl Error for RegistrationError {
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
