use std::error::Error;
use std::fmt;
use std::path::Path;

use lightning::bitcoin::secp256k1::SecretKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use teos_common::cryptography;

use crate::ClientIdentity;

/// SQLite storage for the LDK watchtower client.
///
/// Use a dedicated database in the application's private data directory: it
/// contains the unencrypted client signing key. This does not open the tower's
/// or the CLN plugin's database.
pub struct ClientStore {
    connection: Connection,
}

impl ClientStore {
    /// Opens or creates a client database and initializes its identity table.
    ///
    /// The parent directory must already exist. No identity is generated until
    /// [`Self::load_or_create_identity`] is called.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS client_identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                secret_key BLOB NOT NULL CHECK (length(secret_key) = 32)
            );",
        )?;
        Ok(Self { connection })
    }

    /// Loads the existing identity, creating and persisting one only if absent.
    ///
    /// Initialization is serialized across database connections so concurrent
    /// callers share one identity. Invalid stored keys return an error and are
    /// never silently replaced. A new identity is returned only after commit.
    pub fn load_or_create_identity(&mut self) -> Result<ClientIdentity, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored_key: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT secret_key FROM client_identity WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let secret_key = match stored_key {
            Some(bytes) => {
                SecretKey::from_slice(&bytes).map_err(|_| StorageError::InvalidIdentity)?
            }
            None => {
                let (secret_key, _) = cryptography::get_random_keypair();
                transaction.execute(
                    "INSERT INTO client_identity (id, secret_key) VALUES (1, ?1)",
                    params![&secret_key.secret_bytes()[..]],
                )?;
                secret_key
            }
        };
        transaction.commit()?;
        Ok(ClientIdentity::new(secret_key))
    }
}

/// A failure to open client storage or load and persist its identity.
#[derive(Debug)]
pub enum StorageError {
    /// SQLite could not complete a storage operation.
    Sqlite(rusqlite::Error),
    /// The stored signing key has an invalid length or scalar value.
    InvalidIdentity,
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "Client storage error: {error}"),
            Self::InvalidIdentity => write!(f, "Stored client signing key is invalid"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::InvalidIdentity => None,
        }
    }
}
