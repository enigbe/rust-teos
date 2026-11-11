use ldk_watchtower_client::{ClientStore, PreparationError, StorageError};
use lightning::bitcoin::hashes::Hash;
use lightning::bitcoin::Txid;
use lightning::ln::types::ChannelId;
use rusqlite::Connection;
use teos_common::{appointment::Locator, cryptography};

mod common;
use common::{htlc, justice, to_local, to_local_with_fee};

#[test]
fn prepares_signed_encrypted_to_local_and_preserves_coverage() {
    let mut store = ClientStore::open(":memory:").unwrap();
    let claim = to_local(144, 0);
    let entry = justice(vec![htlc(true, false), claim.clone()]);
    let prepared = store
        .prepare_appointment(ChannelId([1; 32]), &entry)
        .unwrap();
    assert_eq!(prepared.classification().recognized_htlc_claims(), 1);
    let pending = prepared.pending_appointment().unwrap();
    assert_eq!(pending.channel_id(), ChannelId([1; 32]));
    assert_eq!(pending.commitment_txid(), entry.revoked_commitment_txid);
    assert_eq!(
        pending.appointment().locator,
        Locator::new(entry.revoked_commitment_txid)
    );
    assert_eq!(pending.appointment().to_self_delay, 144);
    assert_eq!(
        cryptography::decrypt(
            &pending.appointment().encrypted_blob,
            &entry.revoked_commitment_txid
        )
        .unwrap(),
        claim
    );
    assert!(cryptography::verify(
        &pending.appointment().to_vec(),
        pending.signature(),
        &pending.user_id().0
    ));
    assert_eq!(
        store.pending_appointments().unwrap().jobs(),
        &[pending.clone()]
    );
}

#[test]
fn reopening_and_changed_fee_reuse_the_exact_saved_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let entry = justice(vec![to_local(144, 0)]);
    let channel = ChannelId([1; 32]);
    let original = {
        let mut store = ClientStore::open(&path).unwrap();
        store
            .prepare_appointment(channel, &entry)
            .unwrap()
            .pending_appointment()
            .unwrap()
            .clone()
    };
    let mut store = ClientStore::open(&path).unwrap();
    assert_eq!(
        store
            .pending_appointment(channel, entry.revoked_commitment_txid)
            .unwrap(),
        Some(original.clone())
    );
    let changed = justice(vec![to_local_with_fee(
        entry.revoked_commitment_txid,
        144,
        0,
        2000,
    )]);
    assert_eq!(
        store
            .prepare_appointment(channel, &changed)
            .unwrap()
            .pending_appointment(),
        Some(&original)
    );
    let empty = justice(vec![]);
    let recovered = store.prepare_appointment(channel, &empty).unwrap();
    assert!(recovered.classification().to_local().is_none());
    assert_eq!(recovered.pending_appointment(), Some(&original));
    assert_eq!(store.pending_appointments().unwrap().jobs().len(), 1);
}

#[test]
fn no_eligible_claim_creates_neither_job_nor_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let mut unknown = to_local(144, 0);
    unknown.input[0].witness.clear();
    for entry in [
        justice(vec![]),
        justice(vec![htlc(false, true)]),
        justice(vec![unknown]),
    ] {
        assert!(store
            .prepare_appointment(ChannelId([1; 32]), &entry)
            .unwrap()
            .pending_appointment()
            .is_none());
    }
    assert!(store.pending_appointments().unwrap().jobs().is_empty());
    let db = Connection::open(path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM client_identity", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn failed_insert_rolls_back_identity_and_can_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_job BEFORE INSERT ON pending_appointments BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let entry = justice(vec![to_local(144, 0)]);
    assert!(matches!(
        store.prepare_appointment(ChannelId([1; 32]), &entry),
        Err(PreparationError::Storage(StorageError::Sqlite(_)))
    ));
    assert!(store.pending_appointments().unwrap().jobs().is_empty());
    assert_eq!(
        db.query_row("SELECT count(*) FROM client_identity", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER fail_job").unwrap();
    assert!(store
        .prepare_appointment(ChannelId([1; 32]), &entry)
        .unwrap()
        .pending_appointment()
        .is_some());
}

#[test]
fn rejects_invalid_classification_without_persisting() {
    let mut store = ClientStore::open(":memory:").unwrap();
    let entry = justice(vec![to_local(144, 0), to_local(144, 1)]);
    assert!(matches!(
        store.prepare_appointment(ChannelId([1; 32]), &entry),
        Err(PreparationError::Classification(_))
    ));
    assert!(store.pending_appointments().unwrap().jobs().is_empty());
}

#[test]
fn stores_distinct_channels_and_full_commitment_ids() {
    let mut store = ClientStore::open(":memory:").unwrap();
    let entry = justice(vec![to_local(144, 0)]);
    for channel in [ChannelId([1; 32]), ChannelId([2; 32])] {
        store.prepare_appointment(channel, &entry).unwrap();
    }
    let mut bytes = entry.revoked_commitment_txid.to_byte_array();
    bytes[31] ^= 1; // Same locator, different full commitment id.
    let txid = Txid::from_byte_array(bytes);
    let mut other = justice(vec![to_local_with_fee(txid, 144, 0, 1000)]);
    other.revoked_commitment_txid = txid;
    store
        .prepare_appointment(ChannelId([1; 32]), &other)
        .unwrap();
    assert_eq!(store.pending_appointments().unwrap().jobs().len(), 3);
}

#[test]
fn corrupted_payload_is_rejected_instead_of_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let entry = justice(vec![to_local(144, 0)]);
    store
        .prepare_appointment(ChannelId([1; 32]), &entry)
        .unwrap();
    let db = Connection::open(path).unwrap();
    db.execute("UPDATE pending_appointments SET encrypted_blob = X'00'", [])
        .unwrap();
    let report = store.pending_appointments().unwrap();
    assert!(report.jobs().is_empty());
    assert!(matches!(
        report.failures()[0].error(),
        StorageError::InvalidPendingAppointment
    ));
    assert!(matches!(
        store.prepare_appointment(ChannelId([1; 32]), &entry),
        Err(PreparationError::Storage(
            StorageError::InvalidPendingAppointment
        ))
    ));
}

#[test]
fn concurrent_offers_preserve_one_identity_and_one_payload() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    ClientStore::open(&path).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [1000, 2000]
        .into_iter()
        .map(|fee| {
            let path = path.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut store = ClientStore::open(path).unwrap();
                let mut entry = justice(vec![]);
                entry.txs.push(to_local_with_fee(
                    entry.revoked_commitment_txid,
                    144,
                    0,
                    fee,
                ));
                barrier.wait();
                store
                    .prepare_appointment(ChannelId([1; 32]), &entry)
                    .unwrap()
                    .pending_appointment()
                    .unwrap()
                    .clone()
            })
        })
        .collect();
    let jobs: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(jobs[0], jobs[1]);
    assert_eq!(
        ClientStore::open(path)
            .unwrap()
            .pending_appointments()
            .unwrap()
            .jobs(),
        &jobs[..1]
    );
}

#[test]
fn saved_jobs_cannot_be_loaded_under_a_replaced_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    store
        .prepare_appointment(ChannelId([1; 32]), &justice(vec![to_local(144, 0)]))
        .unwrap();
    let db = Connection::open(path).unwrap();
    db.execute("UPDATE client_identity SET secret_key=?1", [&[2u8; 32][..]])
        .unwrap();
    let report = store.pending_appointments().unwrap();
    assert!(report.jobs().is_empty());
    assert!(matches!(
        report.failures()[0].error(),
        StorageError::InvalidPendingAppointment
    ));
}

#[test]
fn preparing_a_known_claim_keeps_unknown_claims_visible() {
    let mut store = ClientStore::open(":memory:").unwrap();
    let mut unknown = to_local(144, 1);
    unknown.input[0].witness.clear();
    let entry = justice(vec![unknown, to_local(144, 0)]);
    let prepared = store
        .prepare_appointment(ChannelId([1; 32]), &entry)
        .unwrap();
    assert!(prepared.pending_appointment().is_some());
    assert_eq!(prepared.classification().unclassified().len(), 1);
    assert_eq!(
        prepared.classification().unclassified()[0].transaction_index(),
        0
    );
}

#[test]
fn recovery_returns_valid_jobs_and_identifies_each_failed_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let entry = justice(vec![to_local(144, 0)]);
    for value in 1..=3 {
        store
            .prepare_appointment(ChannelId([value; 32]), &entry)
            .unwrap();
    }
    let valid = store
        .pending_appointment(ChannelId([2; 32]), entry.revoked_commitment_txid)
        .unwrap()
        .unwrap();
    let db = Connection::open(&path).unwrap();
    let first_row: i64 = db
        .query_row(
            "SELECT rowid FROM pending_appointments WHERE channel_id=?1",
            [&[1u8; 32][..]],
            |row| row.get(0),
        )
        .unwrap();
    let last_row: i64 = db
        .query_row(
            "SELECT rowid FROM pending_appointments WHERE channel_id=?1",
            [&[3u8; 32][..]],
            |row| row.get(0),
        )
        .unwrap();
    db.execute(
        "UPDATE pending_appointments SET signature='invalid' WHERE rowid=?1",
        [first_row],
    )
    .unwrap();
    // SQLite's dynamic typing can produce a row decoding error, not just a bad signature.
    db.execute(
        "UPDATE pending_appointments SET to_self_delay='invalid' WHERE rowid=?1",
        [last_row],
    )
    .unwrap();
    drop(store);
    let store = ClientStore::open(path).unwrap();
    let report = store.pending_appointments().unwrap();
    assert_eq!(report.jobs(), &[valid]);
    assert_eq!(report.failures().len(), 2);
    assert_eq!(report.failures()[0].row_id(), first_row);
    assert!(matches!(
        report.failures()[0].error(),
        StorageError::InvalidPendingAppointment
    ));
    assert_eq!(report.failures()[1].row_id(), last_row);
    assert!(matches!(
        report.failures()[1].error(),
        StorageError::Sqlite(_)
    ));
    assert_eq!(
        db.query_row("SELECT count(*) FROM pending_appointments", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        3
    );
}

#[test]
fn read_only_offers_work_while_another_connection_holds_the_write_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let entry = justice(vec![to_local(144, 0)]);
    let original = store
        .prepare_appointment(ChannelId([1; 32]), &entry)
        .unwrap()
        .pending_appointment()
        .unwrap()
        .clone();
    let db = Connection::open(path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        store
            .prepare_appointment(ChannelId([1; 32]), &entry)
            .unwrap()
            .pending_appointment(),
        Some(&original)
    );
    let empty = justice(vec![]);
    assert!(store
        .prepare_appointment(ChannelId([2; 32]), &empty)
        .unwrap()
        .pending_appointment()
        .is_none());
    db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn recovery_reports_query_failures_as_operation_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let store = ClientStore::open(&path).unwrap();
    Connection::open(path)
        .unwrap()
        .execute_batch("DROP TABLE pending_appointments")
        .unwrap();
    assert!(matches!(
        store.pending_appointments(),
        Err(StorageError::Sqlite(_))
    ));
}
