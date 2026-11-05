use std::error::Error;
use std::fmt;
use std::time::Duration;

use teos_common::TowerId;
use url::{ParseError, Url};

/// Validated connection settings for a single TEOS tower.
///
/// Construction only validates settings. It does not contact the tower, open
/// storage, or start background tasks.
#[derive(Clone, Debug)]
pub struct TowerConfig {
    tower_id: TowerId,
    endpoint: Url,
    request_timeout: Duration,
}

impl TowerConfig {
    /// Validates an HTTP or HTTPS endpoint and a nonzero request timeout.
    ///
    /// The tower identity is already validated by its public-key type.
    pub fn new(
        tower_id: TowerId,
        endpoint: &str,
        request_timeout: Duration,
    ) -> Result<Self, TowerConfigError> {
        let endpoint = Url::parse(endpoint).map_err(|error| match error {
            ParseError::EmptyHost => TowerConfigError::MissingHost,
            other => TowerConfigError::InvalidEndpoint(other),
        })?;

        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(TowerConfigError::UnsupportedScheme(
                endpoint.scheme().to_owned(),
            ));
        }
        if endpoint.host().is_none() {
            return Err(TowerConfigError::MissingHost);
        }
        if request_timeout.is_zero() {
            return Err(TowerConfigError::ZeroTimeout);
        }

        Ok(Self {
            tower_id,
            endpoint,
            request_timeout,
        })
    }

    /// Returns the public identity used to verify the tower's signed responses.
    pub fn tower_id(&self) -> TowerId {
        self.tower_id
    }

    /// Returns the tower's parsed HTTP or HTTPS endpoint.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Returns the nonzero timeout to use for tower requests.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }
}

/// An invalid tower connection setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TowerConfigError {
    /// The endpoint could not be parsed as an absolute URL.
    InvalidEndpoint(ParseError),
    /// The endpoint uses a scheme other than HTTP or HTTPS.
    UnsupportedScheme(String),
    /// The endpoint has no host.
    MissingHost,
    /// The request timeout is zero.
    ZeroTimeout,
}

impl fmt::Display for TowerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(error) => write!(f, "Invalid tower endpoint: {error}"),
            Self::UnsupportedScheme(scheme) => {
                write!(f, "Unsupported tower endpoint scheme: {scheme}")
            }
            Self::MissingHost => write!(f, "Tower endpoint must include a host"),
            Self::ZeroTimeout => write!(f, "Tower request timeout must be nonzero"),
        }
    }
}

impl Error for TowerConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEndpoint(error) => Some(error),
            _ => None,
        }
    }
}
