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

use crate::{
    ClientIdentity, CoverageOutcome, CoverageRecord, PendingAppointment, PreparationError,
    ProtectionScope, VerifiedAppointmentReceipt,
};

/// Identifies receipt failures without repeating verification outside the transaction.
pub(crate) enum CoverageCompletionError {
    Storage(StorageError),
    Receipt {
        tower_id: TowerId,
        error: StorageError,
    },
}
impl From<StorageError> for CoverageCompletionError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}
impl From<rusqlite::Error> for CoverageCompletionError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(StorageError::from(error))
    }
}

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
);
CREATE TABLE IF NOT EXISTS coverage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id BLOB NOT NULL CHECK (length(channel_id) = 32),
    commitment_txid BLOB NOT NULL CHECK (length(commitment_txid) = 32),
    scope INTEGER NOT NULL,
    feerate_per_kw INTEGER NOT NULL CHECK (feerate_per_kw > 0),
    to_local INTEGER NOT NULL CHECK (to_local IN (0, 1)),
    excluded_htlc_claims INTEGER NOT NULL CHECK (excluded_htlc_claims >= 0),
    unclassified_claims INTEGER NOT NULL CHECK (unclassified_claims >= 0),
    stored_claim_matches INTEGER NOT NULL CHECK (stored_claim_matches IN (0, 1)),
    client_signature TEXT NOT NULL,
    required_towers BLOB NOT NULL,
    completion_ready INTEGER NOT NULL DEFAULT 0 CHECK (completion_ready IN (0, 1)),
    UNIQUE (channel_id, commitment_txid, scope, feerate_per_kw, to_local,
        excluded_htlc_claims, unclassified_claims, stored_claim_matches, client_signature, required_towers)
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

const SELECT_UNDELIVERED_APPOINTMENTS: &str = "SELECT p.rowid, p.channel_id, p.commitment_txid, p.user_id, p.locator, p.encrypted_blob, p.to_self_delay, p.signature
FROM pending_appointments AS p
WHERE NOT EXISTS (
    SELECT 1 FROM appointment_receipts AS r
    WHERE r.tower_id=?1 AND r.channel_id=p.channel_id AND r.commitment_txid=p.commitment_txid
)
ORDER BY p.channel_id, p.commitment_txid";

const SELECT_DELIVERY_JOB_STATUS: &str = "SELECT EXISTS (
    SELECT 1 FROM appointment_receipts WHERE tower_id=?1 AND channel_id=?2 AND commitment_txid=?3
) FROM pending_appointments WHERE channel_id=?2 AND commitment_txid=?3";

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

const INSERT_COVERAGE: &str = "INSERT INTO coverage_records
    (channel_id, commitment_txid, scope, feerate_per_kw, to_local, excluded_htlc_claims,
     unclassified_claims, stored_claim_matches, client_signature, required_towers)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";

const SELECT_COVERAGE_OBSERVATION: &str = "SELECT id, channel_id, commitment_txid, scope,
    feerate_per_kw, to_local, excluded_htlc_claims, unclassified_claims,
    stored_claim_matches, client_signature, required_towers, completion_ready
FROM coverage_records WHERE channel_id=?1 AND commitment_txid=?2 AND scope=?3
    AND feerate_per_kw=?4 AND to_local=?5 AND excluded_htlc_claims=?6
    AND unclassified_claims=?7 AND stored_claim_matches=?8 AND client_signature=?9 AND required_towers=?10";

const SELECT_COVERAGE_BY_ID: &str = "SELECT id, channel_id, commitment_txid, scope,
    feerate_per_kw, to_local, excluded_htlc_claims, unclassified_claims,
    stored_claim_matches, client_signature, required_towers, completion_ready
FROM coverage_records WHERE id=?1";

const SELECT_COVERAGE_FOR_COMMITMENT: &str = "SELECT id, channel_id, commitment_txid, scope,
    feerate_per_kw, to_local, excluded_htlc_claims, unclassified_claims,
    stored_claim_matches, client_signature, required_towers, completion_ready
FROM coverage_records WHERE channel_id=?1 AND commitment_txid=?2 ORDER BY id";

const COMPLETE_COVERAGE: &str = "UPDATE coverage_records SET completion_ready=1 WHERE id=?1";

pub(crate) enum DeliveryJobStatus {
    Missing,
    Recorded,
    Unrecorded,
}

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
    /// Loads the latest-starting historical receipt for this tower and commitment.
    ///
    /// Verifies the tower signature over the stored client signature and start
    /// block, without loading a pending job or the client signing identity.
    /// Earlier receipts are retained as service evidence.
    ///
    /// The channel and commitment IDs are local associations established when
    /// saving against an unchanged job; the tower does not sign these IDs directly.
    /// The client signature identifies the submitted payload, whose bytes are not
    /// included in the receipt. A valid historical receipt does not establish that
    /// a current job matches it or authorize an LDK acknowledgment. Those paths
    /// must separately check the expected job and protection scope.
    pub fn appointment_receipt(
        &self,
        tower_id: TowerId,
        channel_id: ChannelId,
        commitment_txid: Txid,
    ) -> Result<Option<AppointmentReceipt>, StorageError> {
        let receipt = find_receipt(&self.connection, tower_id, channel_id, commitment_txid)?;
        if let Some(receipt) = &receipt {
            if !receipt.verify(&tower_id) {
                return Err(StorageError::InvalidAppointmentReceipt);
            }
        }
        Ok(receipt)
    }

    /// Persists a verified network result after rechecking its pending job.
    ///
    /// The job must still exist unchanged. Saving re-verifies the tower signature
    /// and commits before returning success. If saving fails, the caller retains
    /// the result and can retry the save without resubmitting to the tower.
    /// Pending jobs are not removed and LDK delivery is not acknowledged.
    pub fn save_appointment_receipt(
        &mut self,
        delivery: &VerifiedAppointmentReceipt,
    ) -> Result<(), StorageError> {
        let tower_id = delivery.tower_id();
        let job = delivery.job();
        let receipt = delivery.receipt();
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
        self.recover_pending(SELECT_PENDING_APPOINTMENTS, [])
    }

    /// Recovers only jobs with no receipt row for this tower, filtering in SQLite
    /// before cryptographic validation. Receipt presence suppresses resending even
    /// if the receipt is corrupt. Use [`Self::appointment_receipt`] to verify stored
    /// evidence explicitly, or [`Self::pending_appointments`] to audit all source jobs.
    pub fn undelivered_appointments(
        &self,
        tower_id: TowerId,
    ) -> Result<PendingAppointmentRecovery, StorageError> {
        self.recover_pending(SELECT_UNDELIVERED_APPOINTMENTS, params![tower_id.to_vec()])
    }

    pub(crate) fn delivery_job_status(
        &self,
        tower_id: TowerId,
        channel_id: ChannelId,
        commitment_txid: Txid,
    ) -> Result<DeliveryJobStatus, StorageError> {
        let recorded: Option<bool> = self
            .connection
            .query_row(
                SELECT_DELIVERY_JOB_STATUS,
                params![
                    tower_id.to_vec(),
                    &channel_id.0[..],
                    &commitment_txid.to_byte_array()[..]
                ],
                |row| row.get(0),
            )
            .optional()?;
        Ok(match recorded {
            None => DeliveryJobStatus::Missing,
            Some(true) => DeliveryJobStatus::Recorded,
            Some(false) => DeliveryJobStatus::Unrecorded,
        })
    }

    fn recover_pending(
        &self,
        query: &str,
        params: impl rusqlite::Params,
    ) -> Result<PendingAppointmentRecovery, StorageError> {
        let transaction = self.connection.unchecked_transaction()?;
        let expected_user = read_identity(&transaction)?.map(|identity| identity.user_id());
        let mut report = PendingAppointmentRecovery::default();
        {
            let mut statement = transaction.prepare(query)?;
            let mut rows = statement.query(params)?;
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

    // TODO: Before cleanup, recover the frozen payload or reject re-offers for
    // previously delivered commitments. A historical receipt cannot reconstruct
    // that payload; encrypting changed plaintext would reuse TEOS's key/nonce.
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

impl ClientStore {
    /// Loads immutable coverage observations for a commitment, including excluded
    /// claim counts. These records remain readable independently of source jobs.
    pub fn coverage_records(
        &self,
        channel_id: ChannelId,
        commitment_txid: Txid,
    ) -> Result<Vec<CoverageRecord>, StorageError> {
        let mut statement = self.connection.prepare(SELECT_COVERAGE_FOR_COMMITMENT)?;
        let rows = statement.query_map(
            params![&channel_id.0[..], &commitment_txid.to_byte_array()[..]],
            RawCoverage::read,
        )?;
        rows.map(|row| row.map_err(StorageError::from)?.validate())
            .collect()
    }
    /// Loads one observation by its stable identifier and validates stored metadata.
    pub fn coverage_record(&self, id: i64) -> Result<Option<CoverageRecord>, StorageError> {
        read_coverage(&self.connection, id)
    }
    pub(crate) fn record_coverage(
        &mut self,
        observation: CoverageRecord,
    ) -> Result<CoverageRecord, StorageError> {
        observation.validate()?;
        if let Some(record) = find_coverage(&self.connection, &observation)? {
            return Ok(record);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = match find_coverage(&transaction, &observation)? {
            Some(record) => record,
            None => {
                transaction.execute(
                    INSERT_COVERAGE,
                    params![
                        &observation.channel_id.0[..],
                        &observation.commitment_txid.to_byte_array()[..],
                        observation.scope.id(),
                        observation.feerate_per_kw,
                        observation.to_local,
                        observation.excluded_htlc_claims,
                        observation.unclassified_claims,
                        observation.stored_claim_matches,
                        observation.client_signature.as_deref().unwrap_or(""),
                        tower_bytes(&observation.required_towers),
                    ],
                )?;
                read_coverage(&transaction, transaction.last_insert_rowid())?
                    .ok_or(StorageError::InvalidCoverage)?
            }
        };
        transaction.commit()?;
        Ok(record)
    }
    // Receipt checks and the durable readiness marker share a transaction. A
    // missing receipt is ordinary pending work; corrupt evidence is an error.
    pub(crate) fn complete_coverage(
        &mut self,
        expected: &CoverageRecord,
    ) -> Result<bool, CoverageCompletionError> {
        let transaction = self.connection.transaction()?;
        let record =
            read_coverage(&transaction, expected.id)?.ok_or(StorageError::InvalidCoverage)?;
        if !record.same_observation(expected) || record.outcome() == CoverageOutcome::Blocked {
            return Err(StorageError::InvalidCoverage.into());
        }
        if record.outcome() == CoverageOutcome::ToLocalAppointment {
            let job = find_pending(&transaction, record.channel_id, record.commitment_txid)?
                .ok_or(StorageError::InvalidPendingAppointment)?;
            if Some(job.signature()) != record.client_signature() {
                return Err(StorageError::InvalidPendingAppointment.into());
            }
            for tower in &record.required_towers {
                let receipt = find_receipt(
                    &transaction,
                    *tower,
                    record.channel_id,
                    record.commitment_txid,
                )
                .map_err(|error| CoverageCompletionError::Receipt {
                    tower_id: *tower,
                    error,
                })?;
                let Some(receipt) = receipt else {
                    return Ok(false);
                };
                if receipt.user_signature() != job.signature() || !receipt.verify(tower) {
                    return Err(CoverageCompletionError::Receipt {
                        tower_id: *tower,
                        error: StorageError::InvalidAppointmentReceipt,
                    });
                }
            }
        }
        if !record.completion_ready {
            transaction.execute(COMPLETE_COVERAGE, [record.id])?;
        }
        transaction.commit()?;
        Ok(true)
    }
}

// Decode only. Callers verify the tower signature; acknowledgment additionally
// checks its binding to the expected job within the completion transaction.
fn find_receipt(
    connection: &Connection,
    tower_id: TowerId,
    channel_id: ChannelId,
    commitment_txid: Txid,
) -> Result<Option<AppointmentReceipt>, StorageError> {
    Ok(connection
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
        .optional()?)
}

fn tower_bytes(towers: &[TowerId]) -> Vec<u8> {
    towers.iter().flat_map(TowerId::to_vec).collect()
}

fn read_coverage(connection: &Connection, id: i64) -> Result<Option<CoverageRecord>, StorageError> {
    connection
        .query_row(SELECT_COVERAGE_BY_ID, [id], RawCoverage::read)
        .optional()?
        .map(RawCoverage::validate)
        .transpose()
}
fn find_coverage(
    connection: &Connection,
    record: &CoverageRecord,
) -> Result<Option<CoverageRecord>, StorageError> {
    connection
        .query_row(
            SELECT_COVERAGE_OBSERVATION,
            params![
                &record.channel_id.0[..],
                &record.commitment_txid.to_byte_array()[..],
                record.scope.id(),
                record.feerate_per_kw,
                record.to_local,
                record.excluded_htlc_claims,
                record.unclassified_claims,
                record.stored_claim_matches,
                record.client_signature.as_deref().unwrap_or(""),
                tower_bytes(&record.required_towers)
            ],
            RawCoverage::read,
        )
        .optional()?
        .map(RawCoverage::validate)
        .transpose()
}

struct RawCoverage {
    id: i64,
    channel: Vec<u8>,
    txid: Vec<u8>,
    scope: i64,
    fee: u64,
    to_local: i64,
    htlcs: usize,
    unknown: usize,
    matches: i64,
    signature: String,
    towers: Vec<u8>,
    ready: i64,
}
impl RawCoverage {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            channel: row.get(1)?,
            txid: row.get(2)?,
            scope: row.get(3)?,
            fee: row.get(4)?,
            to_local: row.get(5)?,
            htlcs: row.get(6)?,
            unknown: row.get(7)?,
            matches: row.get(8)?,
            signature: row.get(9)?,
            towers: row.get(10)?,
            ready: row.get(11)?,
        })
    }
    fn validate(self) -> Result<CoverageRecord, StorageError> {
        let invalid = || StorageError::InvalidCoverage;
        fn flag(value: i64) -> Result<bool, StorageError> {
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(StorageError::InvalidCoverage),
            }
        }
        if self.id <= 0 || self.towers.is_empty() || self.towers.len() % 33 != 0 {
            return Err(invalid());
        }
        let record = CoverageRecord {
            id: self.id,
            channel_id: ChannelId(self.channel.try_into().map_err(|_| invalid())?),
            commitment_txid: Txid::from_slice(&self.txid).map_err(|_| invalid())?,
            scope: ProtectionScope::from_id(self.scope).ok_or_else(invalid)?,
            feerate_per_kw: self.fee,
            to_local: flag(self.to_local)?,
            excluded_htlc_claims: self.htlcs,
            unclassified_claims: self.unknown,
            stored_claim_matches: flag(self.matches)?,
            client_signature: if self.signature.is_empty() {
                None
            } else {
                Some(self.signature)
            },
            required_towers: self
                .towers
                .chunks_exact(33)
                .map(|bytes| TowerId::from_slice(bytes).map_err(|_| invalid()))
                .collect::<Result<_, _>>()?,
            completion_ready: flag(self.ready)?,
        };
        record.validate()?;
        Ok(record)
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
    /// A tower receipt is invalid or does not match the expected submitted payload.
    InvalidAppointmentReceipt,
    /// A coverage observation is corrupt, changed, or incompatible with its policy.
    InvalidCoverage,
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
            Self::InvalidCoverage => write!(f, "Stored coverage record is invalid"),
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
            | Self::InvalidAppointmentReceipt
            | Self::InvalidCoverage => None,
        }
    }
}
