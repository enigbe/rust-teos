use std::time::Duration;

use ldk_watchtower_client::{
    ClientIdentity, ClientStore, RegistrationError, StorageError, TowerClient, TowerConfig,
};
use lightning::bitcoin::secp256k1::SecretKey;
use mockito::{Matcher, Server};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;
use teos_common::receipts::RegistrationReceipt;
use teos_common::{cryptography, TowerId};

struct Fixture {
    directory: TempDir,
    store: ClientStore,
    identity: ClientIdentity,
    tower_key: SecretKey,
    tower_id: TowerId,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let mut store = ClientStore::open(directory.path().join("client.sqlite3")).unwrap();
        let identity = store.load_or_create_identity().unwrap();
        let (tower_key, tower_public_key) = cryptography::get_random_keypair();
        Self {
            directory,
            store,
            identity,
            tower_key,
            tower_id: teos_common::UserId(tower_public_key),
        }
    }

    fn client(&self, endpoint: &str, timeout: Duration) -> TowerClient {
        TowerClient::new(TowerConfig::new(self.tower_id, endpoint, timeout).unwrap()).unwrap()
    }

    fn receipt(&self, slots: u32, expiry: u32) -> RegistrationReceipt {
        let mut receipt = RegistrationReceipt::new(self.identity.user_id(), slots, 100, expiry);
        receipt.sign(&self.tower_key);
        receipt
    }

    fn saved(&self) -> Option<RegistrationReceipt> {
        self.store
            .registration(self.tower_id, self.identity.user_id())
            .unwrap()
    }
}

#[tokio::test]
async fn registers_the_persisted_identity_and_restores_its_receipt() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let receipt = fixture.receipt(10000, 4420);
    let mock = server
        .mock("POST", "/register")
        .match_header("content-type", "application/json")
        .match_body(Matcher::Json(
            json!({"user_id": fixture.identity.user_id().to_string()}),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));

    assert_eq!(client.register(&mut fixture.store).await.unwrap(), receipt);
    assert_eq!(fixture.saved(), Some(receipt.clone()));
    drop(fixture.store);
    let reopened = ClientStore::open(fixture.directory.path().join("client.sqlite3")).unwrap();
    assert_eq!(
        reopened
            .registration(fixture.tower_id, fixture.identity.user_id())
            .unwrap(),
        Some(receipt),
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn construction_and_reopening_do_not_register() {
    let mut server = Server::new_async().await;
    let fixture = Fixture::new();
    let mock = server
        .mock("POST", "/register")
        .expect(0)
        .create_async()
        .await;
    let _client = fixture.client(&server.url(), Duration::from_secs(5));
    assert!(fixture.saved().is_none());
    drop(fixture.store);
    let reopened = ClientStore::open(fixture.directory.path().join("client.sqlite3")).unwrap();
    assert!(reopened
        .registration(fixture.tower_id, fixture.identity.user_id())
        .unwrap()
        .is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn rejects_a_response_for_another_user() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let (_, other_user) = cryptography::get_random_keypair();
    let mut receipt = RegistrationReceipt::new(teos_common::UserId(other_user), 10000, 100, 4420);
    receipt.sign(&fixture.tower_key);
    let mock = server
        .mock("POST", "/register")
        .with_status(200)
        .with_body(serde_json::to_string(&receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));

    assert!(matches!(
        client.register(&mut fixture.store).await,
        Err(RegistrationError::UnexpectedUser)
    ));
    assert!(fixture.saved().is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn rejects_wrong_tower_and_malformed_signatures() {
    for malformed in [false, true] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let (other_key, _) = cryptography::get_random_keypair();
        let mut receipt = fixture.receipt(10000, 4420);
        receipt.sign(&other_key);
        if malformed {
            receipt = RegistrationReceipt::with_signature(
                fixture.identity.user_id(),
                10000,
                100,
                4420,
                "not a signature".to_owned(),
            );
        }
        let mock = server
            .mock("POST", "/register")
            .with_status(200)
            .with_body(serde_json::to_string(&receipt).unwrap())
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));

        assert!(matches!(
            client.register(&mut fixture.store).await,
            Err(RegistrationError::InvalidSignature)
        ));
        assert!(fixture.saved().is_none());
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn rejects_malformed_responses() {
    for body in ["not JSON", "{}", r#"{"user_id":"zz"}"#] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let mock = server
            .mock("POST", "/register")
            .with_status(200)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));

        assert!(
            matches!(client.register(&mut fixture.store).await, Err(RegistrationError::Request(error)) if error.is_decode())
        );
        assert!(fixture.saved().is_none());
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn rejects_invalid_subscription_ranges() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let receipt = fixture.receipt(10000, 100);
    let mock = server
        .mock("POST", "/register")
        .with_status(200)
        .with_body(serde_json::to_string(&receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));

    assert!(matches!(
        client.register(&mut fixture.store).await,
        Err(RegistrationError::InvalidSubscription)
    ));
    assert!(fixture.saved().is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn reports_http_errors_without_retrying() {
    for status in [400, 401, 503] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let mock = server
            .mock("POST", "/register")
            .with_status(status)
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));

        assert!(
            matches!(client.register(&mut fixture.store).await, Err(RegistrationError::HttpStatus(code)) if code.as_u16() == status as u16)
        );
        assert!(fixture.saved().is_none());
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn does_not_follow_registration_redirects() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let redirected = server
        .mock("GET", "/redirected")
        .expect(0)
        .create_async()
        .await;
    let mock = server
        .mock("POST", "/register")
        .with_status(303)
        .with_header("location", &format!("{}/redirected", server.url()))
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));

    assert!(
        matches!(client.register(&mut fixture.store).await, Err(RegistrationError::HttpStatus(code)) if code.as_u16() == 303)
    );
    assert!(fixture.saved().is_none());
    mock.assert_async().await;
    redirected.assert_async().await;
}

#[tokio::test]
async fn applies_the_request_timeout() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let body = serde_json::to_string(&fixture.receipt(10000, 4420)).unwrap();
    let mock = server
        .mock("POST", "/register")
        .with_status(200)
        .with_body_from_fn(move |writer| {
            std::thread::sleep(Duration::from_millis(500));
            writer.write_all(body.as_bytes())
        })
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_millis(100));

    assert!(
        matches!(client.register(&mut fixture.store).await, Err(RegistrationError::Request(error)) if error.is_timeout())
    );
    assert!(fixture.saved().is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn reports_connection_failures() {
    let mut fixture = Fixture::new();
    let client = fixture.client("http://127.0.0.1:0", Duration::from_secs(1));

    assert!(
        matches!(client.register(&mut fixture.store).await, Err(RegistrationError::Request(error)) if error.is_connect())
    );
    assert!(fixture.saved().is_none());
}

#[tokio::test]
async fn explicit_renewal_preserves_previous_receipts() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    for (slots, expiry) in [(10000, 4420), (20000, 8740)] {
        let receipt = fixture.receipt(slots, expiry);
        let mock = server
            .mock("POST", "/register")
            .with_status(200)
            .with_body(serde_json::to_string(&receipt).unwrap())
            .expect(1)
            .create_async()
            .await;
        assert_eq!(client.register(&mut fixture.store).await.unwrap(), receipt);
        assert_eq!(fixture.saved(), Some(receipt));
        mock.assert_async().await;
    }
    let connection = Connection::open(fixture.directory.path().join("client.sqlite3")).unwrap();
    let count: u32 = connection
        .query_row("SELECT COUNT(*) FROM registrations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn failed_persistence_keeps_the_previous_registration() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    let previous = fixture.receipt(10000, 4420);
    let mock = server
        .mock("POST", "/register")
        .with_status(200)
        .with_body(serde_json::to_string(&previous).unwrap())
        .expect(1)
        .create_async()
        .await;
    client.register(&mut fixture.store).await.unwrap();
    mock.assert_async().await;
    drop(mock);

    let connection = Connection::open(fixture.directory.path().join("client.sqlite3")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_registration BEFORE INSERT ON registrations
         BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END;",
        )
        .unwrap();
    let renewed = fixture.receipt(20000, 8740);
    let mock = server
        .mock("POST", "/register")
        .with_status(200)
        .with_body(serde_json::to_string(&renewed).unwrap())
        .expect(1)
        .create_async()
        .await;

    assert!(matches!(
        client.register(&mut fixture.store).await,
        Err(RegistrationError::Storage(_))
    ));
    assert_eq!(fixture.saved(), Some(previous));
    mock.assert_async().await;
}

#[tokio::test]
async fn registers_through_an_endpoint_path_prefix() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let receipt = fixture.receipt(10000, 4420);
    let mock = server
        .mock("POST", "/teos/register")
        .with_status(200)
        .with_body(serde_json::to_string(&receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&format!("{}/teos", server.url()), Duration::from_secs(5));

    assert_eq!(client.register(&mut fixture.store).await.unwrap(), receipt);
    mock.assert_async().await;
}

#[tokio::test]
async fn rejects_a_tampered_stored_receipt() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let mock = server
        .mock("POST", "/register")
        .with_status(200)
        .with_body(serde_json::to_string(&fixture.receipt(10000, 4420)).unwrap())
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    client.register(&mut fixture.store).await.unwrap();
    let connection = Connection::open(fixture.directory.path().join("client.sqlite3")).unwrap();
    connection
        .execute("UPDATE registrations SET available_slots=99999", [])
        .unwrap();

    assert!(matches!(
        fixture
            .store
            .registration(fixture.tower_id, fixture.identity.user_id()),
        Err(StorageError::InvalidRegistration)
    ));
    mock.assert_async().await;
}
