use std::path::Path;
use std::time::Duration;

use ldk_watchtower_client::{
    ClientStore, LdkAdapterConfigError, ProtectionScope, StorageError, TowerConfig,
};
use lightning::bitcoin::{secp256k1::SecretKey, ScriptBuf};
use mockito::{Matcher, Server};
use rusqlite::{params, Connection};
use serde_json::json;
use teos_common::{cryptography, receipts::RegistrationReceipt, TowerId};

#[path = "../examples/embedding.rs"]
pub mod embedding;

fn tower() -> (SecretKey, TowerId) {
    let (key, public) = cryptography::get_random_keypair();
    (key, teos_common::UserId(public))
}

fn save(store: &mut ClientStore, id: TowerId, endpoint: &str) {
    store
        .save_tower(&TowerConfig::new(id, endpoint, Duration::from_secs(2)).unwrap())
        .unwrap();
}

fn settings(
    path: &Path,
    towers: Vec<TowerId>,
    registration: embedding::RegistrationAction,
) -> embedding::Settings {
    embedding::Settings {
        database: path.to_owned(),
        required_towers: towers,
        registration,
        scope: ProtectionScope::ToLocalOnly,
        feerate_per_kw: 1000,
        destination: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn assert_no_identity(path: &Path) {
    let db = Connection::open(path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM client_identity", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM registrations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn loads_selected_towers_and_reopens_without_registering_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut server = Server::new_async().await;
    let mut store = ClientStore::open(&path).unwrap();
    let (key, id) = tower();
    save(&mut store, id, &format!("{}/proxy", server.url()));
    let (_, unselected) = tower();
    save(&mut store, unselected, "https://unused.example/");
    // An invalid unselected entry must not affect this explicit selection.
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE tower_registry SET endpoint='ftp://unused.example/' WHERE tower_id=?1",
        params![unselected.to_vec()],
    )
    .unwrap();
    let user_id = store.load_or_create_identity().unwrap().user_id();
    let mut receipt = RegistrationReceipt::new(user_id, 10000, 100, 4420);
    receipt.sign(&key);
    let register = server
        .mock("POST", "/proxy/register")
        .match_body(Matcher::Json(json!({"user_id": user_id.to_string()})))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    drop(store);
    let worker = embedding::open_watchtower(settings(
        &path,
        vec![id],
        embedding::RegistrationAction::RegisterOrRenew,
    ))
    .await
    .unwrap();
    assert_eq!(
        worker.store().registration(id, user_id).unwrap(),
        Some(receipt.clone())
    );
    drop(worker);
    let worker = embedding::open_watchtower(settings(
        &path,
        vec![id],
        embedding::RegistrationAction::UseSavedReceipts,
    ))
    .await
    .unwrap();
    assert_eq!(
        worker.store().registration(id, user_id).unwrap(),
        Some(receipt)
    );
    register.assert_async().await;
}

#[tokio::test]
async fn restart_uses_updated_settings_but_renewal_remains_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut original = Server::new_async().await;
    let mut updated = Server::new_async().await;
    let (key, id) = tower();
    let mut store = ClientStore::open(&path).unwrap();
    save(&mut store, id, &original.url());
    let user_id = store.load_or_create_identity().unwrap().user_id();
    let mut first_receipt = RegistrationReceipt::new(user_id, 10000, 100, 4420);
    first_receipt.sign(&key);
    let first = original
        .mock("POST", "/register")
        .with_status(200)
        .with_body(serde_json::to_string(&first_receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    drop(
        embedding::open_watchtower(settings(
            &path,
            vec![id],
            embedding::RegistrationAction::RegisterOrRenew,
        ))
        .await
        .unwrap(),
    );
    save(&mut store, id, &updated.url());
    let worker = embedding::open_watchtower(settings(
        &path,
        vec![id],
        embedding::RegistrationAction::UseSavedReceipts,
    ))
    .await
    .unwrap();
    assert_eq!(
        worker.store().registration(id, user_id).unwrap(),
        Some(first_receipt)
    );
    drop(worker);
    let mut renewed_receipt = RegistrationReceipt::new(user_id, 20000, 100, 8740);
    renewed_receipt.sign(&key);
    let renewal = updated
        .mock("POST", "/register")
        .match_body(Matcher::Json(json!({"user_id": user_id.to_string()})))
        .with_status(200)
        .with_body(serde_json::to_string(&renewed_receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    let mut worker = embedding::open_watchtower(settings(
        &path,
        vec![id],
        embedding::RegistrationAction::RegisterOrRenew,
    ))
    .await
    .unwrap();
    assert_eq!(
        worker
            .store_mut()
            .load_or_create_identity()
            .unwrap()
            .user_id(),
        user_id
    );
    assert_eq!(
        worker.store().registration(id, user_id).unwrap(),
        Some(renewed_receipt)
    );
    first.assert_async().await;
    renewal.assert_async().await;
}

#[tokio::test]
async fn a_missing_selected_tower_fails_before_registering_any_tower() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut server = Server::new_async().await;
    let (_, first) = tower();
    let (_, missing) = tower();
    save(&mut ClientStore::open(&path).unwrap(), first, &server.url());
    let register = server
        .mock("POST", "/register")
        .expect(0)
        .create_async()
        .await;
    let error = embedding::open_watchtower(settings(
        &path,
        vec![first, missing],
        embedding::RegistrationAction::RegisterOrRenew,
    ))
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains(&missing.to_string()), "{error}");
    assert_no_identity(&path);
    register.assert_async().await;
}

#[tokio::test]
async fn a_corrupt_selected_tower_fails_before_registering_any_tower() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut server = Server::new_async().await;
    let (_, first) = tower();
    let (_, corrupt) = tower();
    let mut store = ClientStore::open(&path).unwrap();
    save(&mut store, first, &server.url());
    save(&mut store, corrupt, "https://unused.example/");
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE tower_registry SET endpoint='ftp://unused.example/' WHERE tower_id=?1",
        params![corrupt.to_vec()],
    )
    .unwrap();
    let register = server
        .mock("POST", "/register")
        .expect(0)
        .create_async()
        .await;
    let error = embedding::open_watchtower(settings(
        &path,
        vec![first, corrupt],
        embedding::RegistrationAction::RegisterOrRenew,
    ))
    .await
    .err()
    .unwrap();
    assert!(matches!(
        error.downcast_ref::<StorageError>(),
        Some(StorageError::InvalidTowerConfig)
    ));
    assert_no_identity(&path);
    register.assert_async().await;
}

#[tokio::test]
async fn invalid_worker_settings_fail_before_identity_creation_or_registration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut server = Server::new_async().await;
    let (_, id) = tower();
    save(&mut ClientStore::open(&path).unwrap(), id, &server.url());
    let register = server
        .mock("POST", "/register")
        .expect(0)
        .create_async()
        .await;
    for case in 0..4 {
        let mut settings = settings(
            &path,
            vec![id],
            embedding::RegistrationAction::RegisterOrRenew,
        );
        match case {
            0 => settings.required_towers.clear(),
            1 => settings.required_towers.push(id),
            2 => settings.feerate_per_kw = 0,
            3 => settings.destination = ScriptBuf::new(),
            _ => unreachable!(),
        }
        let error = embedding::open_watchtower(settings).await.err().unwrap();
        assert!(
            error.downcast_ref::<LdkAdapterConfigError>().is_some(),
            "{error}"
        );
        assert_no_identity(&path);
    }
    register.assert_async().await;
}
