use std::time::Duration;

use ldk_watchtower_client::{ClientStore, StorageError, TowerConfig};
use rusqlite::{params, Connection};
use teos_common::cryptography;

fn config(timeout: Duration) -> TowerConfig {
    let (_, public_key) = cryptography::get_random_keypair();
    TowerConfig::new(
        teos_common::UserId(public_key),
        "https://tower.example:9814/api/",
        timeout,
    )
    .unwrap()
}

fn assert_config(actual: &TowerConfig, expected: &TowerConfig) {
    assert_eq!(actual.tower_id(), expected.tower_id());
    assert_eq!(actual.endpoint(), expected.endpoint());
    assert_eq!(actual.request_timeout(), expected.request_timeout());
}

#[test]
fn saves_and_restores_towers_without_creating_an_identity_or_registration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let first = config(Duration::new(5, 123));
    let second = config(Duration::from_secs(30));
    assert!(store.towers().unwrap().is_empty());
    assert!(store.tower(first.tower_id()).unwrap().is_none());
    store.save_tower(&first).unwrap();
    store.save_tower(&second).unwrap();
    drop(store);

    let store = ClientStore::open(&path).unwrap();
    assert_config(&store.tower(first.tower_id()).unwrap().unwrap(), &first);
    assert_config(&store.tower(second.tower_id()).unwrap().unwrap(), &second);
    let towers = store.towers().unwrap();
    assert_eq!(towers.len(), 2);
    let mut expected = [first.tower_id(), second.tower_id()];
    expected.sort_by_key(|id| id.to_vec());
    assert_eq!(
        towers.iter().map(TowerConfig::tower_id).collect::<Vec<_>>(),
        expected
    );
    let db = Connection::open(path).unwrap();
    for table in ["client_identity", "registrations", "pending_appointments"] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "saving a tower must not populate {table}");
    }
}

#[test]
fn updating_one_tower_replaces_only_its_connection_settings() {
    let mut store = ClientStore::open(":memory:").unwrap();
    let first = config(Duration::from_secs(5));
    let second = config(Duration::from_secs(10));
    store.save_tower(&first).unwrap();
    store.save_tower(&second).unwrap();
    let updated = TowerConfig::new(
        first.tower_id(),
        "http://127.0.0.1:9814/",
        Duration::new(1, 42),
    )
    .unwrap();
    store.save_tower(&updated).unwrap();
    store.save_tower(&updated).unwrap();
    assert_eq!(store.towers().unwrap().len(), 2);
    assert_config(&store.tower(first.tower_id()).unwrap().unwrap(), &updated);
    assert_config(&store.tower(second.tower_id()).unwrap().unwrap(), &second);
}

#[test]
fn preserves_subsecond_precision_and_the_maximum_supported_timeout_as_integers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    for timeout in [
        Duration::from_nanos(1),
        Duration::new(i64::MAX as u64, 999_999_999),
    ] {
        let tower = config(timeout);
        let mut store = ClientStore::open(&path).unwrap();
        store.save_tower(&tower).unwrap();
        drop(store);
        let store = ClientStore::open(&path).unwrap();
        assert_config(&store.tower(tower.tower_id()).unwrap().unwrap(), &tower);
        let db = Connection::open(&path).unwrap();
        let saved: (i64, i64) = db
            .query_row(
                "SELECT timeout_seconds, timeout_nanoseconds FROM tower_registry WHERE tower_id=?1",
                params![tower.tower_id().to_vec()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            saved,
            (timeout.as_secs() as i64, timeout.subsec_nanos() as i64)
        );
    }
}

#[test]
fn invalid_stored_settings_are_reported_without_replacing_or_skipping_them() {
    for column_and_value in [
        "endpoint='ftp://tower.example/'",
        "timeout_seconds=0, timeout_nanoseconds=0",
        "tower_id=zeroblob(33)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.sqlite");
        let mut store = ClientStore::open(&path).unwrap();
        let tower = config(Duration::from_secs(5));
        store.save_tower(&tower).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute(&format!("UPDATE tower_registry SET {column_and_value}"), [])
            .unwrap();
        drop(store);
        let before = std::fs::read(&path).unwrap();
        let store = ClientStore::open(&path).unwrap();
        assert!(matches!(
            store.towers(),
            Err(StorageError::InvalidTowerConfig)
        ));
        // A corrupt primary key cannot be supplied through the typed lookup API.
        if !column_and_value.starts_with("tower_id") {
            assert!(matches!(
                store.tower(tower.tower_id()),
                Err(StorageError::InvalidTowerConfig)
            ));
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn a_failed_update_leaves_the_original_configuration_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let tower = config(Duration::from_secs(5));
    store.save_tower(&tower).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_tower_update AFTER UPDATE ON tower_registry
        BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .unwrap();
    let changed = TowerConfig::new(
        tower.tower_id(),
        "https://new.example/",
        Duration::from_secs(9),
    )
    .unwrap();
    assert!(matches!(
        store.save_tower(&changed),
        Err(StorageError::Sqlite(_))
    ));
    assert_config(&store.tower(tower.tower_id()).unwrap().unwrap(), &tower);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM tower_registry WHERE tower_id=?1",
            params![tower.tower_id().to_vec()],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn removal_is_explicit_idempotent_and_leaves_other_towers_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let first = config(Duration::from_secs(5));
    let second = config(Duration::from_secs(10));
    store.save_tower(&first).unwrap();
    store.save_tower(&second).unwrap();
    assert!(store.remove_tower(first.tower_id()).unwrap());
    assert!(!store.remove_tower(first.tower_id()).unwrap());
    drop(store);
    let store = ClientStore::open(&path).unwrap();
    assert!(store.tower(first.tower_id()).unwrap().is_none());
    assert_eq!(store.towers().unwrap().len(), 1);
    assert_config(&store.tower(second.tower_id()).unwrap().unwrap(), &second);
}

#[test]
fn a_failed_removal_preserves_the_saved_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let tower = config(Duration::from_secs(5));
    store.save_tower(&tower).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_tower_removal AFTER DELETE ON tower_registry
        BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .unwrap();
    assert!(matches!(
        store.remove_tower(tower.tower_id()),
        Err(StorageError::Sqlite(_))
    ));
    assert_config(&store.tower(tower.tower_id()).unwrap().unwrap(), &tower);
}
