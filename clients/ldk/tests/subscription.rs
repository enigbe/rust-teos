use std::{num::NonZeroUsize, time::Duration};

use ldk_watchtower_client::{
    ClientIdentity, ClientStore, SubscriptionError, TowerClient, TowerConfig,
};
use mockito::{Matcher, Server};
use serde_json::json;
use tempfile::TempDir;
use teos_common::{
    cryptography, protos::GetSubscriptionInfoResponse, receipts::RegistrationReceipt,
};

fn fixture(endpoint: &str) -> (TempDir, ClientStore, ClientIdentity, TowerClient) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = ClientStore::open(dir.path().join("client.sqlite")).unwrap();
    let identity = store.load_or_create_identity().unwrap();
    let (_, key) = cryptography::get_random_keypair();
    let client = TowerClient::new(
        TowerConfig::new(teos_common::UserId(key), endpoint, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    (dir, store, identity, client)
}

#[tokio::test]
async fn signs_the_subscription_query_and_preserves_the_signed_registration() {
    let mut server = Server::new_async().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path).unwrap();
    let identity = store.load_or_create_identity().unwrap();
    let (key, public) = cryptography::get_random_keypair();
    let tower_id = teos_common::UserId(public);
    let config = TowerConfig::new(
        tower_id,
        &format!("{}/proxy/?ignored=true#fragment", server.url()),
        Duration::from_secs(2),
    )
    .unwrap();
    store.save_tower(&config).unwrap();
    let client = TowerClient::new(config).unwrap();
    let mut receipt = RegistrationReceipt::new(identity.user_id(), 100, 10, 1000);
    receipt.sign(&key);
    let registration = server
        .mock("POST", "/proxy/register")
        .with_status(200)
        .with_body(serde_json::to_string(&receipt).unwrap())
        .expect(1)
        .create_async()
        .await;
    client.register(&mut store).await.unwrap();
    let response = GetSubscriptionInfoResponse {
        available_slots: 3,
        subscription_expiry: 900,
        locators: vec![vec![1; 16], vec![2; 16]],
    };
    let query = server
        .mock("POST", "/proxy/get_subscription_info")
        .match_header("content-type", "application/json")
        .match_body(Matcher::Json(
            json!({"signature": identity.sign(b"get subscription info")}),
        ))
        .with_status(200)
        .with_body(serde_json::to_string(&response).unwrap())
        .expect(1)
        .create_async()
        .await;
    let before = std::fs::read(&path).unwrap();
    let info = client.subscription_info(&identity).await.unwrap();
    assert_eq!(info.available_slots(), 3);
    assert_eq!(info.subscription_expiry(), 900);
    assert_eq!(
        info.locators()
            .iter()
            .map(|l| l.to_vec())
            .collect::<Vec<_>>(),
        response.locators
    );
    assert_eq!(
        store.registration(tower_id, identity.user_id()).unwrap(),
        Some(receipt)
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "querying must not update stored evidence"
    );
    registration.assert_async().await;
    query.assert_async().await;
}

#[tokio::test]
async fn preserves_subscription_rejections_without_registering_or_retrying() {
    for (status, body, expected_code) in [
        (
            401,
            json!({"error":"not registered", "error_code":7}).to_string(),
            Some(7),
        ),
        (
            503,
            json!({"error":"unavailable", "error_code":32}).to_string(),
            Some(32),
        ),
        (429, "proxy throttled".into(), None),
    ] {
        let mut server = Server::new_async().await;
        let (_, _, identity, client) = fixture(&server.url());
        let register = server
            .mock("POST", "/register")
            .expect(0)
            .create_async()
            .await;
        let mock = server
            .mock("POST", "/get_subscription_info")
            .with_status(status)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(client.subscription_info(&identity).await,
            Err(SubscriptionError::Rejected { status: found, error_code, .. })
                if found.as_u16() == status as u16 && error_code == expected_code));
        register.assert_async().await;
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn rejects_malformed_subscription_responses_and_locators() {
    for body in [
        "not JSON".into(),
        "{}".into(),
        json!({"available_slots":1,"subscription_expiry":900,"locators":["zz"]}).to_string(),
    ] {
        let mut server = Server::new_async().await;
        let (_, _, identity, client) = fixture(&server.url());
        let mock = server
            .mock("POST", "/get_subscription_info")
            .with_status(200)
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(
            client.subscription_info(&identity).await,
            Err(SubscriptionError::InvalidResponse(_))
        ));
        mock.assert_async().await;
    }
    for length in [0, 15, 17] {
        let mut server = Server::new_async().await;
        let (_, _, identity, client) = fixture(&server.url());
        let response = GetSubscriptionInfoResponse {
            available_slots: 1,
            subscription_expiry: 900,
            locators: vec![vec![0; 16], vec![0; length]],
        };
        let mock = server
            .mock("POST", "/get_subscription_info")
            .with_status(200)
            .with_body(serde_json::to_string(&response).unwrap())
            .expect(1)
            .create_async()
            .await;
        assert!(matches!(
            client.subscription_info(&identity).await,
            Err(SubscriptionError::InvalidLocator { index: 1 })
        ));
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn supports_large_locator_lists_but_bounds_subscription_bodies() {
    let mut server = Server::new_async().await;
    let (_, _, identity, client) = fixture(&server.url());
    let response = GetSubscriptionInfoResponse {
        available_slots: 0,
        subscription_expiry: 900,
        locators: vec![vec![0; 16]; 1500],
    };
    let mock = server
        .mock("POST", "/get_subscription_info")
        .with_status(200)
        .with_body(serde_json::to_string(&response).unwrap())
        .expect(1)
        .create_async()
        .await;
    assert_eq!(
        client
            .subscription_info(&identity)
            .await
            .unwrap()
            .locators()
            .len(),
        1500
    );
    mock.assert_async().await;
    let oversized = server
        .mock("POST", "/get_subscription_info")
        .with_status(200)
        .with_body(" ".repeat(1024 * 1024 + 1))
        .expect(1)
        .create_async()
        .await;
    assert!(matches!(
        client.subscription_info(&identity).await,
        Err(SubscriptionError::ResponseTooLarge { limit: 1048576, .. })
    ));
    oversized.assert_async().await;
}

#[tokio::test]
async fn subscription_transport_failures_are_not_registration_attempts() {
    let (_, _, identity, client) = fixture("http://127.0.0.1:0");
    assert!(
        matches!(client.subscription_info(&identity).await, Err(SubscriptionError::Request(error)) if error.is_connect())
    );
}

#[tokio::test]
async fn an_explicit_limit_returns_all_fifty_thousand_locators_intact() {
    let mut server = Server::new_async().await;
    let (_, _, identity, client) = fixture(&server.url());
    let response = GetSubscriptionInfoResponse {
        available_slots: 17,
        subscription_expiry: 900,
        locators: (0u128..50_000)
            .map(|index| index.to_be_bytes().to_vec())
            .collect(),
    };
    let body = serde_json::to_string(&response).unwrap();
    assert!(body.len() > 1024 * 1024);
    let mock = server
        .mock("POST", "/get_subscription_info")
        .with_status(200)
        .with_body(body)
        .expect(2)
        .create_async()
        .await;
    assert!(matches!(
        client.subscription_info(&identity).await,
        Err(SubscriptionError::ResponseTooLarge { limit: 1048576, .. })
    ));
    let info = client
        .subscription_info_with_limit(&identity, NonZeroUsize::new(2 * 1024 * 1024).unwrap())
        .await
        .unwrap();
    assert_eq!(info.available_slots(), response.available_slots);
    assert_eq!(info.subscription_expiry(), response.subscription_expiry);
    assert_eq!(info.locators().len(), 50_000);
    assert_eq!(
        info.locators()
            .iter()
            .map(|locator| locator.to_vec())
            .collect::<Vec<_>>(),
        response.locators
    );
    mock.assert_async().await;
}

#[tokio::test]
async fn explicit_limits_accept_the_exact_body_size_and_reject_one_byte_less() {
    let mut server = Server::new_async().await;
    let (_, _, identity, client) = fixture(&server.url());
    let response = GetSubscriptionInfoResponse {
        available_slots: 0,
        subscription_expiry: 900,
        locators: Vec::new(),
    };
    let body = serde_json::to_string(&response).unwrap();
    let length = body.len();
    let mock = server
        .mock("POST", "/get_subscription_info")
        .with_status(200)
        .with_body(body)
        .expect(2)
        .create_async()
        .await;
    assert!(
        matches!(client.subscription_info_with_limit(&identity, NonZeroUsize::new(length - 1).unwrap()).await,
        Err(SubscriptionError::ResponseTooLarge { limit, .. }) if limit == length - 1)
    );
    let info = client
        .subscription_info_with_limit(&identity, NonZeroUsize::new(length).unwrap())
        .await
        .unwrap();
    assert!(info.locators().is_empty());
    assert_eq!(info.subscription_expiry(), 900);
    mock.assert_async().await;
}

#[tokio::test]
async fn a_large_success_limit_does_not_make_rejections_read_a_large_body() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
        }
        let length: usize = String::from_utf8(headers)
            .unwrap()
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        stream.read_exact(&mut vec![0; length]).unwrap();
        // Advertise 64 MiB, send just over the rejection cap, then close. A
        // reader following the success limit would fail with an incomplete body.
        write!(
            stream,
            "HTTP/1.1 502 Test\r\nContent-Length: 67108864\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        stream.write_all(&[b'x'; 4097]).unwrap();
        stream.flush().unwrap();
    });
    let (_, _, identity, client) = fixture(&endpoint);
    let result = client
        .subscription_info_with_limit(&identity, NonZeroUsize::new(64 * 1024 * 1024).unwrap())
        .await;
    server.join().unwrap();
    assert!(
        matches!(result, Err(SubscriptionError::Rejected { status, error_code: None, message })
        if status.as_u16() == 502 && message.len() <= 4096 && message.ends_with(" [truncated]"))
    );
}

#[tokio::test]
async fn a_tiny_success_limit_still_preserves_normal_rejection_details() {
    let mut server = Server::new_async().await;
    let (_, _, identity, client) = fixture(&server.url());
    let mock = server
        .mock("POST", "/get_subscription_info")
        .with_status(401)
        .with_body(json!({"error":"not registered", "error_code":7}).to_string())
        .expect(1)
        .create_async()
        .await;
    assert!(
        matches!(client.subscription_info_with_limit(&identity, NonZeroUsize::new(1).unwrap()).await,
        Err(SubscriptionError::Rejected { status, error_code: Some(7), message })
            if status.as_u16() == 401 && message == "not registered")
    );
    mock.assert_async().await;
}
