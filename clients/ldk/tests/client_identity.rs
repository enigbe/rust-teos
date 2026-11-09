use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use ldk_watchtower_client::{ClientStore, StorageError};
use rusqlite::{params, Connection};
use tempfile::TempDir;
use teos_common::cryptography;

#[test]
fn creates_a_signing_identity_on_first_use() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("client.sqlite3");
    let mut store = ClientStore::open(&path).unwrap();
    let identity = store.load_or_create_identity().unwrap();
    let message = b"watchtower client identity";

    assert!(cryptography::verify(
        message,
        &identity.sign(message),
        &identity.user_id().0,
    ));

    let connection = Connection::open(path).unwrap();
    let count: u32 = connection
        .query_row("SELECT COUNT(*) FROM client_identity", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn preserves_identity_after_reopening() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("client.sqlite3");
    let identity = {
        let mut store = ClientStore::open(&path).unwrap();
        store.load_or_create_identity().unwrap()
    };

    let mut reopened = ClientStore::open(&path).unwrap();
    let restored = reopened.load_or_create_identity().unwrap();
    assert_eq!(restored.user_id(), identity.user_id());
    assert_eq!(
        restored.sign(b"after restart"),
        identity.sign(b"after restart"),
    );
    assert_eq!(
        reopened.load_or_create_identity().unwrap().user_id(),
        identity.user_id(),
    );
}

#[test]
fn rejects_corrupt_keys_without_replacing_them() {
    for key in [vec![0; 32], vec![255; 32], vec![1; 31]] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("client.sqlite3");
        {
            let mut store = ClientStore::open(&path).unwrap();
            store.load_or_create_identity().unwrap();
        }
        let connection = Connection::open(&path).unwrap();
        // Simulate malformed data that bypassed the schema's length constraint.
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        connection
            .execute(
                "UPDATE client_identity SET secret_key=?1 WHERE id=1",
                params![&key],
            )
            .unwrap();

        let mut store = ClientStore::open(&path).unwrap();
        assert!(matches!(
            store.load_or_create_identity(),
            Err(StorageError::InvalidIdentity)
        ));
        let persisted: Vec<u8> = connection
            .query_row(
                "SELECT secret_key FROM client_identity WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, key);
    }
}

#[test]
fn failed_writes_do_not_return_or_persist_an_identity() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("client.sqlite3");
    let mut store = ClientStore::open(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_identity_write BEFORE INSERT ON client_identity
             BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END;",
        )
        .unwrap();

    assert!(matches!(
        store.load_or_create_identity(),
        Err(StorageError::Sqlite(_))
    ));
    let count: u32 = connection
        .query_row("SELECT COUNT(*) FROM client_identity", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    connection
        .execute_batch("DROP TRIGGER fail_identity_write;")
        .unwrap();
    let identity = store.load_or_create_identity().unwrap();
    drop(store);
    let mut reopened = ClientStore::open(&path).unwrap();
    assert_eq!(
        reopened.load_or_create_identity().unwrap().user_id(),
        identity.user_id(),
    );
}

#[test]
fn returns_storage_errors_for_unavailable_paths() {
    let directory = TempDir::new().unwrap();
    for path in [
        directory.path().to_path_buf(),
        directory.path().join("missing-parent/client.sqlite3"),
    ] {
        assert!(matches!(
            ClientStore::open(path),
            Err(StorageError::Sqlite(_))
        ));
    }
}

#[test]
fn rejects_non_database_files() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("client.sqlite3");
    fs::write(&path, b"not a SQLite database").unwrap();

    assert!(matches!(
        ClientStore::open(path),
        Err(StorageError::Sqlite(_))
    ));
}

#[test]
fn separate_databases_have_separate_identities() {
    let directory = TempDir::new().unwrap();
    let mut first = ClientStore::open(directory.path().join("first.sqlite3")).unwrap();
    let mut second = ClientStore::open(directory.path().join("second.sqlite3")).unwrap();

    assert_ne!(
        first.load_or_create_identity().unwrap().user_id(),
        second.load_or_create_identity().unwrap().user_id(),
    );
}

#[test]
fn concurrent_initializers_share_one_identity() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("client.sqlite3");
    let first = ClientStore::open(&path).unwrap();
    let second = ClientStore::open(&path).unwrap();
    let barrier = Arc::new(Barrier::new(2));

    let handles: Vec<_> = [first, second]
        .into_iter()
        .map(|mut store| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                store.load_or_create_identity().unwrap().user_id()
            })
        })
        .collect();
    let identities: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    assert_eq!(identities[0], identities[1]);
}
