use std::error::Error;
use std::fmt;
use std::path::Path;

use lightning::bitcoin::{hashes::Hash, secp256k1::SecretKey, Txid};
use lightning::ln::types::ChannelId;
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{
    appointment::{Appointment, Locator},
    cryptography,
};
use teos_common::{TowerId, UserId};

use crate::{ClientIdentity, PendingAppointment, PreparationError};

// TODO: Before the LDK client's first release, add schema versioning and
// transactional migrations in a separate follow-up. CREATE TABLE IF NOT EXISTS
// does not upgrade existing table definitions.
const CREATE_TABLES: &str = "CREATE TABLE IF NOT EXISTS client_identity (
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
);
CREATE TABLE IF NOT EXISTS pending_appointments (
    channel_id BLOB NOT NULL CHECK (length(channel_id) = 32),
    commitment_txid BLOB NOT NULL CHECK (length(commitment_txid) = 32),
    user_id BLOB NOT NULL CHECK (length(user_id) = 33),
    locator BLOB NOT NULL CHECK (length(locator) = 16),
    encrypted_blob BLOB NOT NULL,
    to_self_delay INTEGER NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (channel_id, commitment_txid)
);
CREATE TABLE IF NOT EXISTS appointment_receipts (
    tower_id BLOB NOT NULL,
    channel_id BLOB NOT NULL,
    commitment_txid BLOB NOT NULL,
    user_signature TEXT NOT NULL,
    start_block INTEGER NOT NULL,
    tower_signature TEXT NOT NULL,
    PRIMARY KEY (tower_id, channel_id, commitment_txid, start_block)
);";

const SELECT_REGISTRATION: &str =
    "SELECT available_slots, subscription_start, subscription_expiry, signature
FROM registrations WHERE tower_id=?1 AND user_id=?2
ORDER BY subscription_expiry DESC LIMIT 1";

const UPSERT_REGISTRATION: &str = "INSERT INTO registrations
   (tower_id, user_id, available_slots, subscription_start, subscription_expiry, signature)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT (tower_id, user_id, subscription_expiry) DO UPDATE SET
   available_slots=excluded.available_slots,
   subscription_start=excluded.subscription_start,
   signature=excluded.signature";

const SELECT_PENDING_APPOINTMENTS: &str = "SELECT rowid, channel_id, commitment_txid, user_id, locator, encrypted_blob, to_self_delay, signature
FROM pending_appointments ORDER BY channel_id, commitment_txid";

const INSERT_PENDING_APPOINTMENT: &str = "INSERT INTO pending_appointments (channel_id, commitment_txid, user_id, locator, encrypted_blob, to_self_delay, signature)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

const SELECT_PENDING_APPOINTMENT: &str = "SELECT rowid, channel_id, commitment_txid, user_id, locator, encrypted_blob, to_self_delay, signature
FROM pending_appointments WHERE channel_id=?1 AND commitment_txid=?2";

const SELECT_IDENTITY: &str = "SELECT secret_key FROM client_identity WHERE id = 1";

const INSERT_IDENTITY: &str = "INSERT INTO client_identity (id, secret_key) VALUES (1, ?1)";

const UPSERT_APPOINTMENT_RECEIPT: &str = "INSERT INTO appointment_receipts
    (tower_id, channel_id, commitment_txid, user_signature, start_block, tower_signature)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT (tower_id, channel_id, commitment_txid, start_block) DO UPDATE SET
    user_signature=excluded.user_signature,
    tower_signature=excluded.tower_signature";

const SELECT_APPOINTMENT_RECEIPT: &str = "SELECT user_signature, start_block, tower_signature
FROM appointment_receipts WHERE tower_id=?1 AND channel_id=?2 AND commitment_txid=?3
ORDER BY start_block DESC LIMIT 1";

/// SQLite storage for the LDK watchtower client.
///
/// Use a dedicated database in the application's private data directory: it
/// contains the unencrypted client signing key. This does not open the tower's
/// or the CLN plugin's database.
pub struct ClientStore {
    connection: Connection,
}

impl ClientStore {
    /// Opens or creates a client database and initializes its tables.
    ///
    /// The parent directory must already exist. No identity is generated until
    /// an operation needs to sign a registration or appointment.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(CREATE_TABLES)?;
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
        let identity = load_or_create_identity(&transaction)?;
        transaction.commit()?;
        Ok(identity)
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
                SELECT_REGISTRATION,
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
            UPSERT_REGISTRATION,
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

/// Pending jobs recovered from storage, together with failures isolated to individual rows.
///
/// Callers must inspect failures as well as jobs: omitted rows are not delivered or
/// safe to acknowledge to LDK. Recovery never deletes or replaces failed rows.
#[derive(Debug, Default)]
pub struct PendingAppointmentRecovery {
    jobs: Vec<PendingAppointment>,
    failures: Vec<PendingAppointmentFailure>,
}

impl PendingAppointmentRecovery {
    /// Returns verified jobs available for delivery, ordered by channel and commitment ID.
    pub fn jobs(&self) -> &[PendingAppointment] {
        &self.jobs
    }
    /// Returns rows that could not be decoded or validated.
    pub fn failures(&self) -> &[PendingAppointmentFailure] {
        &self.failures
    }
}

/// A pending row that could not be recovered. Its stored contents are left untouched.
#[derive(Debug)]
pub struct PendingAppointmentFailure {
    row_id: i64,
    error: StorageError,
}

impl PendingAppointmentFailure {
    /// Returns SQLite's rowid for diagnosis in this database snapshot.
    /// This is not a durable job identifier: database maintenance may change rowids.
    pub fn row_id(&self) -> i64 {
        self.row_id
    }
    /// Returns the decoding or validation failure for this row.
    pub fn error(&self) -> &StorageError {
        &self.error
    }
}

impl ClientStore {
    /// Loads the latest-starting receipt for this tower and pending job.
    ///
    /// Verifies the tower signature and its binding to the saved appointment's
    /// client signature. Earlier receipts are retained as service evidence.
    // TODO: Before pending-job cleanup, preserve the appointment association
    // needed to load and verify receipts after their source jobs are removed.
    pub fn appointment_receipt(
        &self,
        tower_id: TowerId,
        channel_id: ChannelId,
        commitment_txid: Txid,
    ) -> Result<Option<AppointmentReceipt>, StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        let receipt = transaction
            .query_row(
                SELECT_APPOINTMENT_RECEIPT,
                params![
                    tower_id.to_vec(),
                    &channel_id.0[..],
                    &commitment_txid.to_byte_array()[..]
                ],
                |row| {
                    Ok(AppointmentReceipt::with_signature(
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some(receipt) = &receipt {
            let job = find_pending(&transaction, channel_id, commitment_txid)?
                .ok_or(StorageError::InvalidAppointmentReceipt)?;
            if receipt.user_signature() != job.signature() || !receipt.verify(&tower_id) {
                return Err(StorageError::InvalidAppointmentReceipt);
            }
        }
        transaction.commit()?;
        Ok(receipt)
    }

    pub(crate) fn store_appointment_receipt(
        &mut self,
        tower_id: TowerId,
        job: &PendingAppointment,
        receipt: &AppointmentReceipt,
    ) -> Result<(), StorageError> {
        if receipt.user_signature() != job.signature() || !receipt.verify(&tower_id) {
            return Err(StorageError::InvalidAppointmentReceipt);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Do not record delivery against a job changed or removed during the request.
        if find_pending(&transaction, job.channel_id(), job.commitment_txid())?.as_ref()
            != Some(job)
        {
            return Err(StorageError::InvalidPendingAppointment);
        }
        transaction.execute(
            UPSERT_APPOINTMENT_RECEIPT,
            params![
                tower_id.to_vec(),
                &job.channel_id().0[..],
                &job.commitment_txid().to_byte_array()[..],
                receipt.user_signature(),
                receipt.start_block(),
                receipt
                    .signature()
                    .ok_or(StorageError::InvalidAppointmentReceipt)?,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Loads and verifies a saved job for the channel and full commitment ID.
    /// A corrupt job is an error, never treated as absent or replaced automatically.
    pub fn pending_appointment(
        &self,
        channel_id: ChannelId,
        commitment_txid: Txid,
    ) -> Result<Option<PendingAppointment>, StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        let pending = find_pending(&transaction, channel_id, commitment_txid)?;
        transaction.commit()?;
        Ok(pending)
    }

    /// Recovers valid jobs and reports individual invalid rows without stopping recovery.
    ///
    /// The signing identity is loaded once, in the same read snapshot as the jobs.
    /// Query failures or an invalid stored identity fail the operation; row decoding
    /// and appointment validation failures are collected in the report instead.
    pub fn pending_appointments(&self) -> Result<PendingAppointmentRecovery, StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        let expected_user = read_identity(&transaction)?.map(|identity| identity.user_id());
        let mut report = PendingAppointmentRecovery::default();
        {
            let mut statement = transaction.prepare(SELECT_PENDING_APPOINTMENTS)?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let row_id = row.get(0)?;
                match StoredAppointment::read(row)
                    .map_err(StorageError::from)
                    .and_then(|stored| stored.validate(expected_user))
                {
                    Ok(job) => report.jobs.push(job),
                    Err(error) => report
                        .failures
                        .push(PendingAppointmentFailure { row_id, error }),
                }
            }
        }
        transaction.commit()?;
        Ok(report)
    }

    // Recheck after acquiring the write lock: another connection may have saved
    // this job since the caller's initial read. Build/encrypt only if still absent.
    pub(crate) fn insert_pending_appointment(
        &mut self,
        channel_id: ChannelId,
        commitment_txid: Txid,
        build: impl FnOnce(&ClientIdentity) -> Result<PendingAppointment, PreparationError>,
    ) -> Result<PendingAppointment, PreparationError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StorageError::from)?;
        let pending = match find_pending(&transaction, channel_id, commitment_txid)? {
            Some(pending) => pending,
            None => {
                let identity = load_or_create_identity(&transaction)?;
                let job = build(&identity)?;
                transaction
                    .execute(
                        INSERT_PENDING_APPOINTMENT,
                        params![
                            &job.channel_id().0[..],
                            &job.commitment_txid().to_byte_array()[..],
                            job.user_id().to_vec(),
                            job.appointment().locator.to_vec(),
                            &job.appointment().encrypted_blob,
                            job.appointment().to_self_delay,
                            job.signature()
                        ],
                    )
                    .map_err(StorageError::from)?;
                job
            }
        };
        transaction.commit().map_err(StorageError::from)?;
        Ok(pending)
    }
}

fn find_pending(
    connection: &Connection,
    channel_id: ChannelId,
    txid: Txid,
) -> Result<Option<PendingAppointment>, StorageError> {
    let stored = connection
        .query_row(
            SELECT_PENDING_APPOINTMENT,
            params![&channel_id.0[..], &txid.to_byte_array()[..]],
            StoredAppointment::read,
        )
        .optional()?;
    stored
        .map(|row| {
            let expected_user = read_identity(connection)?.map(|identity| identity.user_id());
            row.validate(expected_user)
        })
        .transpose()
}

struct StoredAppointment {
    channel_id: Vec<u8>,
    commitment_txid: Vec<u8>,
    user_id: Vec<u8>,
    locator: Vec<u8>,
    encrypted_blob: Vec<u8>,
    to_self_delay: u32,
    signature: String,
}

impl StoredAppointment {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            channel_id: row.get(1)?,
            commitment_txid: row.get(2)?,
            user_id: row.get(3)?,
            locator: row.get(4)?,
            encrypted_blob: row.get(5)?,
            to_self_delay: row.get(6)?,
            signature: row.get(7)?,
        })
    }

    fn validate(self, expected_user: Option<UserId>) -> Result<PendingAppointment, StorageError> {
        let invalid = || StorageError::InvalidPendingAppointment;
        let channel_id = ChannelId(self.channel_id.try_into().map_err(|_| invalid())?);
        let commitment_txid = Txid::from_slice(&self.commitment_txid).map_err(|_| invalid())?;
        let user_id = UserId::from_slice(&self.user_id).map_err(|_| invalid())?;
        let locator = Locator::from_slice(&self.locator).map_err(|_| invalid())?;
        PendingAppointment::restore(
            channel_id,
            commitment_txid,
            user_id,
            Appointment::new(locator, self.encrypted_blob, self.to_self_delay),
            self.signature,
            expected_user,
        )
    }
}

fn read_identity(connection: &Connection) -> Result<Option<ClientIdentity>, StorageError> {
    let stored_key: Option<Vec<u8>> = connection
        .query_row(SELECT_IDENTITY, [], |row| row.get(0))
        .optional()?;
    stored_key
        .map(|bytes| {
            SecretKey::from_slice(&bytes)
                .map(ClientIdentity::new)
                .map_err(|_| StorageError::InvalidIdentity)
        })
        .transpose()
}

fn load_or_create_identity(connection: &Connection) -> Result<ClientIdentity, StorageError> {
    if let Some(identity) = read_identity(connection)? {
        return Ok(identity);
    }
    let (secret_key, _) = cryptography::get_random_keypair();
    connection.execute(INSERT_IDENTITY, params![&secret_key.secret_bytes()[..]])?;
    Ok(ClientIdentity::new(secret_key))
}

/// A failure to open, read, or write client storage.
#[derive(Debug)]
pub enum StorageError {
    /// SQLite could not complete a storage operation.
    Sqlite(rusqlite::Error),
    /// The stored signing key has an invalid length or scalar value.
    InvalidIdentity,
    /// A stored registration receipt has invalid subscription data or a bad signature.
    InvalidRegistration,
    /// A saved appointment is corrupt or belongs to another signing identity.
    InvalidPendingAppointment,
    /// A stored tower receipt is invalid or does not match its pending job.
    InvalidAppointmentReceipt,
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
            Self::InvalidPendingAppointment => write!(f, "Stored pending appointment is invalid"),
            Self::InvalidAppointmentReceipt => write!(f, "Stored appointment receipt is invalid"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::InvalidIdentity
            | Self::InvalidRegistration
            | Self::InvalidPendingAppointment
            | Self::InvalidAppointmentReceipt => None,
        }
    }
}
