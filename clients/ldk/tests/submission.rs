use std::time::Duration;

use ldk_watchtower_client::{
    ClientStore, PendingAppointment, StorageError, SubmissionError, TowerClient, TowerConfig,
};
use lightning::bitcoin::secp256k1::SecretKey;
use lightning::ln::types::ChannelId;
use mockito::{Matcher, Server};
use rusqlite::Connection;
use teos_common::{
    cryptography,
    protos::{AddAppointmentRequest, AddAppointmentResponse},
    receipts::AppointmentReceipt,
    TowerId,
};

mod common;

struct Fixture {
    directory: tempfile::TempDir,
    store: ClientStore,
    job: PendingAppointment,
    tower_key: SecretKey,
    tower_id: TowerId,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ClientStore::open(directory.path().join("client.sqlite")).unwrap();
        let entry = common::justice(vec![common::htlc(true, false), common::to_local(144, 0)]);
        let job = store
            .prepare_appointment(ChannelId([1; 32]), &entry)
            .unwrap()
            .pending_appointment()
            .unwrap()
            .clone();
        let (tower_key, public_key) = cryptography::get_random_keypair();
        Self {
            directory,
            store,
            job,
            tower_key,
            tower_id: teos_common::UserId(public_key),
        }
    }
    fn client(&self, endpoint: &str, timeout: Duration) -> TowerClient {
        TowerClient::new(TowerConfig::new(self.tower_id, endpoint, timeout).unwrap()).unwrap()
    }
    fn receipt(&self, start_block: u32) -> AppointmentReceipt {
        let mut receipt = AppointmentReceipt::new(self.job.signature().to_owned(), start_block);
        receipt.sign(&self.tower_key);
        receipt
    }
    fn response(&self, receipt: &AppointmentReceipt) -> String {
        serde_json::to_string(&AddAppointmentResponse {
            locator: self.job.appointment().locator.to_vec(),
            start_block: receipt.start_block(),
            signature: receipt.signature().unwrap(),
            available_slots: 99,
            subscription_expiry: 1000,
        })
        .unwrap()
    }
    fn saved(&self) -> Option<AppointmentReceipt> {
        self.store
            .appointment_receipt(
                self.tower_id,
                self.job.channel_id(),
                self.job.commitment_txid(),
            )
            .unwrap()
    }
    fn assert_pending(&self) {
        assert_eq!(
            self.store
                .pending_appointment(self.job.channel_id(), self.job.commitment_txid())
                .unwrap(),
            Some(self.job.clone())
        );
    }
}

#[tokio::test]
async fn submits_the_exact_saved_payload_and_restores_the_verified_receipt() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let receipt = fixture.receipt(100);
    let request = AddAppointmentRequest {
        appointment: Some(fixture.job.appointment().clone().into()),
        signature: fixture.job.signature().to_owned(),
    };
    let mock = server
        .mock("POST", "/proxy/add_appointment")
        .match_header("content-type", "application/json")
        .match_body(Matcher::Json(serde_json::to_value(request).unwrap()))
        .with_status(200)
        .with_body(fixture.response(&receipt))
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(
        &format!("{}/proxy/?ignored=true#fragment", server.url()),
        Duration::from_secs(5),
    );
    assert_eq!(
        client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid()
            )
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(fixture.saved(), Some(receipt.clone()));
    fixture.assert_pending();
    drop(fixture.store);
    let reopened = ClientStore::open(fixture.directory.path().join("client.sqlite")).unwrap();
    assert_eq!(
        reopened
            .appointment_receipt(
                fixture.tower_id,
                fixture.job.channel_id(),
                fixture.job.commitment_txid()
            )
            .unwrap(),
        Some(receipt)
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn rejects_wrong_tower_malformed_and_unbound_signatures() {
    for kind in 0..3 {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let mut receipt = fixture.receipt(100);
        match kind {
            0 => receipt.sign(&cryptography::get_random_keypair().0),
            1 => {
                receipt = AppointmentReceipt::with_signature(
                    fixture.job.signature().to_owned(),
                    100,
                    "bad signature".into(),
                )
            }
            _ => {
                receipt = AppointmentReceipt::new("another client signature".into(), 100);
                receipt.sign(&fixture.tower_key);
            }
        }
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(200)
            .with_body(fixture.response(&receipt))
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));
        assert!(matches!(
            client
                .submit_appointment(
                    &mut fixture.store,
                    fixture.job.channel_id(),
                    fixture.job.commitment_txid()
                )
                .await,
            Err(SubmissionError::InvalidSignature)
        ));
        assert!(fixture.saved().is_none());
        fixture.assert_pending();
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn rejects_a_response_for_another_locator() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let mut body: serde_json::Value =
        serde_json::from_str(&fixture.response(&fixture.receipt(100))).unwrap();
    body["locator"] = serde_json::json!("00".repeat(16));
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(body.to_string())
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    assert!(matches!(
        client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid()
            )
            .await,
        Err(SubmissionError::UnexpectedLocator)
    ));
    assert!(fixture.saved().is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn reports_http_errors_without_retrying_or_following_redirects() {
    for status in [400, 401, 503, 307] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(status)
            .with_header("location", &format!("{}/redirected", server.url()))
            .with_body("tower rejected request")
            .expect(1)
            .create_async()
            .await;
        let redirected = server
            .mock("POST", "/redirected")
            .expect(0)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));
        assert!(
            matches!(client.submit_appointment(&mut fixture.store, fixture.job.channel_id(), fixture.job.commitment_txid()).await, Err(SubmissionError::Rejected { status: code, error_code: None, message }) if code.as_u16() == status as u16 && message == "tower rejected request")
        );
        assert!(fixture.saved().is_none());
        fixture.assert_pending();
        mock.assert_async().await;
        redirected.assert_async().await;
    }
}

#[tokio::test]
async fn rejects_malformed_responses() {
    for body in ["not json", "{}", r#"{"locator":"not hex"}"#] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(200)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));
        assert!(matches!(
            client
                .submit_appointment(
                    &mut fixture.store,
                    fixture.job.channel_id(),
                    fixture.job.commitment_txid()
                )
                .await,
            Err(SubmissionError::InvalidResponse(_))
        ));
        assert!(fixture.saved().is_none());
        fixture.assert_pending();
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn applies_the_request_timeout() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let body = fixture.response(&fixture.receipt(100));
    let mock = server
        .mock("POST", "/add_appointment")
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
        matches!(client.submit_appointment(&mut fixture.store, fixture.job.channel_id(), fixture.job.commitment_txid()).await, Err(SubmissionError::Request(error)) if error.is_timeout())
    );
    assert!(fixture.saved().is_none());
    fixture.assert_pending();
    mock.assert_async().await;
}

#[tokio::test]
async fn reports_connection_failures_and_keeps_the_job() {
    let mut fixture = Fixture::new();
    let client = fixture.client("http://127.0.0.1:0", Duration::from_secs(1));
    assert!(
        matches!(client.submit_appointment(&mut fixture.store, fixture.job.channel_id(), fixture.job.commitment_txid()).await, Err(SubmissionError::Request(error)) if error.is_connect())
    );
    fixture.assert_pending();
    assert!(fixture.saved().is_none());
}

#[tokio::test]
async fn missing_and_corrupt_jobs_fail_before_contacting_the_tower() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .expect(0)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    assert!(matches!(
        client
            .submit_appointment(
                &mut fixture.store,
                ChannelId([2; 32]),
                fixture.job.commitment_txid()
            )
            .await,
        Err(SubmissionError::MissingAppointment)
    ));
    Connection::open(fixture.directory.path().join("client.sqlite"))
        .unwrap()
        .execute("UPDATE pending_appointments SET signature='bad'", [])
        .unwrap();
    assert!(matches!(
        client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid()
            )
            .await,
        Err(SubmissionError::Storage(
            StorageError::InvalidPendingAppointment
        ))
    ));
    mock.assert_async().await;
}

#[tokio::test]
async fn failed_receipt_persistence_keeps_the_previous_receipt_and_pending_job() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    let original = fixture.receipt(100);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(fixture.response(&original))
        .expect(1)
        .create_async()
        .await;
    client
        .submit_appointment(
            &mut fixture.store,
            fixture.job.channel_id(),
            fixture.job.commitment_txid(),
        )
        .await
        .unwrap();
    mock.assert_async().await;
    drop(mock);
    let db = Connection::open(fixture.directory.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON appointment_receipts BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(fixture.response(&fixture.receipt(101)))
        .expect(1)
        .create_async()
        .await;
    assert!(matches!(
        client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid()
            )
            .await,
        Err(SubmissionError::Storage(StorageError::Sqlite(_)))
    ));
    assert_eq!(fixture.saved(), Some(original));
    fixture.assert_pending();
    mock.assert_async().await;
}

#[tokio::test]
async fn explicit_resubmission_preserves_receipts_and_separates_towers() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    for block in [100, 100, 101] {
        let receipt = fixture.receipt(block);
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(200)
            .with_body(fixture.response(&receipt))
            .expect(1)
            .create_async()
            .await;
        client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid(),
            )
            .await
            .unwrap();
        mock.assert_async().await;
        drop(mock);
    }
    assert_eq!(fixture.saved(), Some(fixture.receipt(101)));
    let other_tower = teos_common::UserId(cryptography::get_random_keypair().1);
    assert!(fixture
        .store
        .appointment_receipt(
            other_tower,
            fixture.job.channel_id(),
            fixture.job.commitment_txid()
        )
        .unwrap()
        .is_none());
    let db = Connection::open(fixture.directory.path().join("client.sqlite")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM appointment_receipts", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        2
    );
    fixture.assert_pending();
}

#[tokio::test]
async fn rejects_tampered_stored_receipts() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(fixture.response(&fixture.receipt(100)))
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    client
        .submit_appointment(
            &mut fixture.store,
            fixture.job.channel_id(),
            fixture.job.commitment_txid(),
        )
        .await
        .unwrap();
    Connection::open(fixture.directory.path().join("client.sqlite"))
        .unwrap()
        .execute("UPDATE appointment_receipts SET start_block=999", [])
        .unwrap();
    assert!(matches!(
        fixture.store.appointment_receipt(
            fixture.tower_id,
            fixture.job.channel_id(),
            fixture.job.commitment_txid()
        ),
        Err(StorageError::InvalidAppointmentReceipt)
    ));
    mock.assert_async().await;
}

#[tokio::test]
async fn persists_independent_receipts_for_two_towers() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let first_id = fixture.tower_id;
    let first_receipt = fixture.receipt(100);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(fixture.response(&first_receipt))
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    client
        .submit_appointment(
            &mut fixture.store,
            fixture.job.channel_id(),
            fixture.job.commitment_txid(),
        )
        .await
        .unwrap();
    mock.assert_async().await;
    drop(mock);
    let (key, public_key) = cryptography::get_random_keypair();
    fixture.tower_key = key;
    fixture.tower_id = teos_common::UserId(public_key);
    let second_receipt = fixture.receipt(100);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(fixture.response(&second_receipt))
        .expect(1)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    client
        .submit_appointment(
            &mut fixture.store,
            fixture.job.channel_id(),
            fixture.job.commitment_txid(),
        )
        .await
        .unwrap();
    assert_eq!(fixture.saved(), Some(second_receipt));
    assert_eq!(
        fixture
            .store
            .appointment_receipt(
                first_id,
                fixture.job.channel_id(),
                fixture.job.commitment_txid()
            )
            .unwrap(),
        Some(first_receipt)
    );
    fixture.assert_pending();
    mock.assert_async().await;
}

#[tokio::test]
async fn resubmission_can_restore_a_corrupt_receipt_from_a_verified_response() {
    let mut server = Server::new_async().await;
    let mut fixture = Fixture::new();
    let receipt = fixture.receipt(100);
    let mock = server
        .mock("POST", "/add_appointment")
        .with_status(200)
        .with_body(fixture.response(&receipt))
        .expect(2)
        .create_async()
        .await;
    let client = fixture.client(&server.url(), Duration::from_secs(5));
    client
        .submit_appointment(
            &mut fixture.store,
            fixture.job.channel_id(),
            fixture.job.commitment_txid(),
        )
        .await
        .unwrap();
    let db = Connection::open(fixture.directory.path().join("client.sqlite")).unwrap();
    db.execute(
        "UPDATE appointment_receipts SET tower_signature='invalid'",
        [],
    )
    .unwrap();
    assert!(matches!(
        fixture.store.appointment_receipt(
            fixture.tower_id,
            fixture.job.channel_id(),
            fixture.job.commitment_txid()
        ),
        Err(StorageError::InvalidAppointmentReceipt)
    ));
    assert_eq!(
        client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid()
            )
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(fixture.saved(), Some(receipt));
    fixture.assert_pending();
    mock.assert_async().await;
}

#[tokio::test]
async fn preserves_tower_rejection_codes_and_messages_without_choosing_a_retry_policy() {
    for code in [7, 32, 33, 34, 35, 999] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let message = format!("tower rejection {code}");
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(401)
            .with_body(serde_json::json!({"error": message, "error_code": code}).to_string())
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));
        match client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid(),
            )
            .await
        {
            Err(SubmissionError::Rejected {
                status,
                error_code,
                message: returned,
            }) => {
                assert_eq!(status.as_u16(), 401);
                assert_eq!(error_code, Some(code));
                assert_eq!(returned, message);
            }
            other => panic!("Expected tower rejection, got {other:?}"),
        }
        assert!(fixture.saved().is_none());
        fixture.assert_pending();
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn preserves_rejection_details_when_the_error_body_is_not_a_standard_teos_error() {
    for (body, expected_message, expected_code) in [
        ("<html>bad gateway</html>", "<html>bad gateway</html>", None),
        ("", "", None),
        ("{invalid json", "{invalid json", None),
        (r#"{"error":"unavailable"}"#, "unavailable", None),
        (
            r#"{"error":"unavailable","error_code":"32"}"#,
            "unavailable",
            None,
        ),
        (r#"{"error_code":999}"#, r#"{"error_code":999}"#, Some(999)),
    ] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(502)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));
        match client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid(),
            )
            .await
        {
            Err(SubmissionError::Rejected {
                status,
                error_code,
                message,
            }) => {
                assert_eq!(status.as_u16(), 502);
                assert_eq!(error_code, expected_code);
                assert_eq!(message, expected_message);
            }
            other => panic!("Expected tower rejection, got {other:?}"),
        }
        assert!(fixture.saved().is_none());
        fixture.assert_pending();
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn bounds_success_responses_including_chunked_bodies() {
    for oversized in [false, true] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let receipt = fixture.receipt(100);
        let mut body = fixture.response(&receipt);
        body.extend(std::iter::repeat(' ').take(16 * 1024 - body.len()));
        if oversized {
            body.push(' ');
        }
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(200)
            .with_body_from_fn(move |writer| {
                for chunk in body.as_bytes().chunks(1024) {
                    writer.write_all(chunk)?;
                }
                Ok(())
            })
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));
        let result = client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid(),
            )
            .await;
        if oversized {
            assert!(
                matches!(result, Err(SubmissionError::ResponseTooLarge { status, limit: 16384 }) if status.as_u16() == 200)
            );
            assert!(fixture.saved().is_none());
        } else {
            assert_eq!(result.unwrap(), receipt);
        }
        fixture.assert_pending();
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn bounds_rejection_messages_and_marks_truncation() {
    for body in [
        "x".repeat(32 * 1024),
        serde_json::json!({"error": "€".repeat(3000), "error_code": 32}).to_string(),
    ] {
        let mut server = Server::new_async().await;
        let mut fixture = Fixture::new();
        let mock = server
            .mock("POST", "/add_appointment")
            .with_status(502)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let client = fixture.client(&server.url(), Duration::from_secs(5));
        match client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid(),
            )
            .await
        {
            Err(SubmissionError::Rejected {
                status, message, ..
            }) => {
                assert_eq!(status.as_u16(), 502);
                assert!(message.len() <= 4096);
                assert!(message.ends_with("[truncated]"));
            }
            other => panic!("Expected bounded rejection, got {other:?}"),
        }
        assert!(fixture.saved().is_none());
        fixture.assert_pending();
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn body_read_failures_preserve_status_and_transport_error() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    for status in [200, 401] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            // Drain the request before closing the response connection, so an
            // unread request cannot cause a reset before headers reach the client.
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            stream.read_exact(&mut vec![0; length]).unwrap();
            // Declare a longer body, send one byte, then disconnect.
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx"
            )
            .unwrap();
            stream.flush().unwrap();
        });
        let mut fixture = Fixture::new();
        let client = fixture.client(&endpoint, Duration::from_secs(5));
        match client
            .submit_appointment(
                &mut fixture.store,
                fixture.job.channel_id(),
                fixture.job.commitment_txid(),
            )
            .await
        {
            Err(SubmissionError::ResponseRead {
                status: received,
                source,
            }) => {
                assert_eq!(received.as_u16(), status);
                assert!(source.is_body());
            }
            other => panic!("Expected response read failure, got {other:?}"),
        }
        server.join().unwrap();
        assert!(fixture.saved().is_none());
        fixture.assert_pending();
    }
}
