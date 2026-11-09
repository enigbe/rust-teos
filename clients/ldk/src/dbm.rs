use std::error::Error;
use std::fmt;
use std::path::Path;

use lightning::bitcoin::secp256k1::SecretKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use teos_common::cryptography;
use teos_common::receipts::RegistrationReceipt;
use teos_common::{TowerId, UserId};

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
            );
            CREATE TABLE IF NOT EXISTS registrations (
                tower_id BLOB NOT NULL,
                user_id BLOB NOT NULL,
                available_slots INTEGER NOT NULL,
                subscription_start INTEGER NOT NULL,
                subscription_expiry INTEGER NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY (tower_id, user_id, subscription_expiry)
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

    /// Loads the registration receipt with the greatest expiry for this tower and user.
    ///
    /// The stored signature is verified again before the receipt is returned.
    /// Earlier receipts are retained as subscription evidence.
    pub fn registration(
        &self,
        tower_id: TowerId,
        user_id: UserId,
    ) -> Result<Option<RegistrationReceipt>, StorageError> {
        let receipt = self
            .connection
            .query_row(
                "SELECT available_slots, subscription_start, subscription_expiry, signature
                 FROM registrations WHERE tower_id=?1 AND user_id=?2
                 ORDER BY subscription_expiry DESC LIMIT 1",
                params![tower_id.to_vec(), user_id.to_vec()],
                |row| {
                    Ok(RegistrationReceipt::with_signature(
                        user_id,
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some(receipt) = &receipt {
            if !receipt.verify(&tower_id)
                || receipt.subscription_expiry() <= receipt.subscription_start()
            {
                return Err(StorageError::InvalidRegistration);
            }
        }
        Ok(receipt)
    }

    pub(crate) fn store_registration(
        &self,
        tower_id: TowerId,
        receipt: &RegistrationReceipt,
    ) -> Result<(), StorageError> {
        let signature = receipt
            .signature()
            .ok_or(StorageError::InvalidRegistration)?;
        self.connection.execute(
            "INSERT INTO registrations
                (tower_id, user_id, available_slots, subscription_start, subscription_expiry, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (tower_id, user_id, subscription_expiry) DO UPDATE SET
                available_slots=excluded.available_slots,
                subscription_start=excluded.subscription_start,
                signature=excluded.signature",
            params![
                tower_id.to_vec(),
                receipt.user_id().to_vec(),
                receipt.available_slots(),
                receipt.subscription_start(),
                receipt.subscription_expiry(),
                signature,
            ],
        )?;
        Ok(())
    }
}

/// A failure to open client storage or load and persist its identity.
#[derive(Debug)]
pub enum StorageError {
    /// SQLite could not complete a storage operation.
    Sqlite(rusqlite::Error),
    /// The stored signing key has an invalid length or scalar value.
    InvalidIdentity,
    /// A stored registration receipt has invalid subscription data or a bad signature.
    InvalidRegistration,
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
            Self::InvalidRegistration => write!(f, "Stored tower registration is invalid"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::InvalidIdentity | Self::InvalidRegistration => None,
        }
    }
}
