use std::error::Error;
use std::fmt;

use reqwest::{redirect::Policy, Client, StatusCode};
use teos_common::protos::{RegisterRequest, RegisterResponse};
use teos_common::receipts::RegistrationReceipt;

use crate::{ClientStore, StorageError, TowerConfig};

// TODO: Share bounded response reading and rejection parsing with submission in a
// follow-up, preserving registration error codes and separating malformed replies
// from transport failures. Registration must keep its explicit no-retry behavior.

/// An HTTP client for a single TEOS tower.
///
/// Constructing this does not contact the tower. Requests require a Tokio runtime.
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
        if response.status() != StatusCode::OK {
            return Err(RegistrationError::HttpStatus(response.status()));
        }

        let response: RegisterResponse = response.json().await?;
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
    /// Request setup, transport, timeout, or JSON decoding failed.
    Request(reqwest::Error),
    /// The tower returned an HTTP status other than 200 OK.
    HttpStatus(StatusCode),
    /// The tower's response identifies a different client.
    UnexpectedUser,
    /// Subscription expiry is not later than its start.
    InvalidSubscription,
    /// The receipt does not carry a valid signature from the configured tower.
    InvalidSignature,
    /// The client identity or registration could not be persisted or loaded.
    Storage(StorageError),
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
            Self::HttpStatus(status) => write!(f, "Tower registration returned HTTP {status}"),
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
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}
