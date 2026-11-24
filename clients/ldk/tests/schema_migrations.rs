use std::fs;

use ldk_watchtower_client::{ClientStore, StorageError};
use rusqlite::{params, types::Value, Connection};

const UNVERSIONED: &str = include_str!("fixtures/unversioned.sql");
const TABLES: &[&str] = &[
    "client_identity",
    "registrations",
    "pending_appointments",
    "appointment_receipts",
    "delivered_appointments",
    "coverage_records",
    "latest_coverage",
    "sqlite_sequence",
];

fn version(db: &Connection) -> i64 {
    db.query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

fn snapshot(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    TABLES
        .iter()
        .map(|table| {
            let mut statement = db
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<Value>>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .collect()
}

fn seed(db: &Connection) {
    let channel = [1u8; 32];
    let commitment = [2u8; 32];
    let user = [3u8; 33];
    let tower = [6u8; 33];
    db.execute(
        "INSERT INTO client_identity VALUES (1, ?1)",
        [&[1u8; 32][..]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO registrations VALUES (?1,?2,100,10,1000,'registration signature')",
        params![&tower[..], &user[..]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO pending_appointments VALUES (?1,?2,?3,?4,?5,144,'client signature')",
        params![
            &channel[..],
            &commitment[..],
            &user[..],
            &[4u8; 16][..],
            &[5u8, 6, 7][..]
        ],
    )
    .unwrap();
    db.execute("INSERT INTO appointment_receipts VALUES (?1,?2,?3,'client signature',123,'tower signature')",
        params![&tower[..], &channel[..], &commitment[..]]).unwrap();
    db.execute(
        "INSERT INTO delivered_appointments VALUES (?1,?2,'client signature',?3)",
        params![&channel[..], &commitment[..], &[7u8; 32][..]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO coverage_records VALUES (42,?1,?2,1,1000,1,2,0,1,'client signature',?3,1)",
        params![&channel[..], &commitment[..], &tower[..]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO latest_coverage VALUES (?1,?2,42)",
        params![&channel[..], &commitment[..]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO latest_coverage VALUES (?1,?2,NULL)",
        params![&[8u8; 32][..], &[9u8; 32][..]],
    )
    .unwrap();
}

#[test]
fn fresh_databases_are_versioned_without_creating_an_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let _store = ClientStore::open(&path).unwrap();
    let db = Connection::open(&path).unwrap();
    assert_eq!(version(&db), 2);
    assert_eq!(
        db.query_row("SELECT count(*) FROM client_identity", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(_store);
    ClientStore::open(&path).unwrap();
    assert_eq!(version(&db), 2);
}

#[test]
fn adopting_the_unversioned_layout_preserves_every_record_and_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(UNVERSIONED).unwrap();
    seed(&db);
    let before = snapshot(&db);
    assert_eq!(version(&db), 0);
    let mut store = ClientStore::open(&path).unwrap();
    assert_eq!(version(&db), 2);
    assert_eq!(snapshot(&db), before);
    assert_eq!(
        store.load_or_create_identity().unwrap().user_id(),
        ClientStore::open(&path)
            .unwrap()
            .load_or_create_identity()
            .unwrap()
            .user_id()
    );
    assert_eq!(
        snapshot(&db),
        before,
        "reopening must not rewrite signed data or coverage IDs"
    );
}

#[test]
fn unsupported_versions_are_rejected_without_modifying_the_file() {
    for unsupported in [-1, 3, 999] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE sentinel (value BLOB); INSERT INTO sentinel VALUES (X'010203');",
        )
        .unwrap();
        db.pragma_update(None, "user_version", unsupported).unwrap();
        drop(db);
        let before = fs::read(&path).unwrap();
        assert!(
            matches!(ClientStore::open(&path), Err(StorageError::UnsupportedSchemaVersion { found, supported: 2 }) if found == unsupported),
            "version {unsupported}"
        );
        assert_eq!(fs::read(&path).unwrap(), before, "version {unsupported}");
    }
}

#[test]
fn unknown_and_partial_unversioned_layouts_are_not_repaired_or_versioned() {
    for sql in [
        "CREATE TABLE unrelated (value TEXT); INSERT INTO unrelated VALUES ('keep me');",
        "CREATE TABLE sqliteX_data (value TEXT); INSERT INTO sqliteX_data VALUES ('not an internal table');",
        "CREATE TABLE client_identity (id INTEGER PRIMARY KEY CHECK (id=1), secret_key BLOB NOT NULL CHECK (length(secret_key)=32));",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(sql).unwrap();
        drop(db);
        let before = fs::read(&path).unwrap();
        assert!(matches!(ClientStore::open(&path), Err(StorageError::InvalidSchema)));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn a_damaged_versioned_layout_is_rejected_instead_of_recreated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    drop(ClientStore::open(&path).unwrap());
    let db = Connection::open(&path).unwrap();
    db.execute("DROP TABLE delivered_appointments", []).unwrap();
    drop(db);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        ClientStore::open(&path),
        Err(StorageError::InvalidSchema)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn concurrent_openers_initialize_or_adopt_once_without_losing_data() {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };
    for legacy in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sqlite");
        let before = if legacy {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(UNVERSIONED).unwrap();
            seed(&db);
            Some(snapshot(&db))
        } else {
            None
        };
        let barrier = Arc::new(Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    drop(ClientStore::open(path).unwrap());
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let db = Connection::open(&path).unwrap();
        assert_eq!(version(&db), 2);
        if let Some(before) = before {
            assert_eq!(snapshot(&db), before);
        }
    }
}

#[test]
fn owned_auxiliary_indexes_and_triggers_survive_adoption_and_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(UNVERSIONED).unwrap();
    db.execute_batch("CREATE INDEX diagnostic_index ON pending_appointments(signature);
        CREATE TRIGGER reject_test_insert BEFORE INSERT ON pending_appointments BEGIN SELECT RAISE(ABORT, 'test'); END;").unwrap();
    drop(ClientStore::open(&path).unwrap());
    drop(ClientStore::open(&path).unwrap());
    assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('diagnostic_index', 'reject_test_insert')", [], |r| r.get::<_,i64>(0)).unwrap(), 2);
}

#[test]
fn full_unversioned_layouts_with_changed_constraints_or_required_indexes_are_rejected() {
    for change_index in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sqlite");
        let db = Connection::open(&path).unwrap();
        if change_index {
            db.execute_batch(UNVERSIONED).unwrap();
            db.execute_batch("DROP INDEX appointment_receipts_by_commitment;
                CREATE INDEX appointment_receipts_by_commitment ON appointment_receipts(user_signature);").unwrap();
        } else {
            db.execute_batch(&UNVERSIONED.replace("CHECK (length(secret_key) = 32)", ""))
                .unwrap();
        }
        drop(db);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            ClientStore::open(&path),
            Err(StorageError::InvalidSchema)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn upgrading_version_one_preserves_all_records_and_starts_with_an_empty_registry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(UNVERSIONED).unwrap();
    db.pragma_update(None, "user_version", 1).unwrap();
    seed(&db);
    let before = snapshot(&db);
    let store = ClientStore::open(&path).unwrap();
    assert_eq!(version(&db), 2);
    assert_eq!(snapshot(&db), before);
    assert!(store.towers().unwrap().is_empty());
    drop(store);
    assert!(ClientStore::open(&path)
        .unwrap()
        .towers()
        .unwrap()
        .is_empty());
    assert_eq!(snapshot(&db), before);
}
