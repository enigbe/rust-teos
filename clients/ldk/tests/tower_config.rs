use std::time::Duration;

use ldk_watchtower_client::{TowerConfig, TowerConfigError};
use teos_common::TowerId;

fn tower_id() -> TowerId {
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        .parse()
        .unwrap()
}

#[test]
fn accepts_http_and_https_endpoints() {
    for endpoint in [
        "http://tower.example:9814/",
        "https://tower.example/",
        "http://127.0.0.1:9814/",
        "http://[::1]:9814/",
    ] {
        let config = TowerConfig::new(tower_id(), endpoint, Duration::from_secs(10)).unwrap();

        assert_eq!(config.tower_id(), tower_id());
        assert_eq!(config.endpoint().as_str(), endpoint);
        assert_eq!(config.request_timeout(), Duration::from_secs(10));
    }
}

#[test]
fn rejects_invalid_endpoints() {
    let error = TowerConfig::new(tower_id(), "not a URL", Duration::from_secs(10)).unwrap_err();

    assert!(matches!(error, TowerConfigError::InvalidEndpoint(_)));
}

#[test]
fn rejects_unsupported_schemes() {
    for (endpoint, scheme) in [
        ("ftp://tower.example/", "ftp"),
        ("file:///tmp/tower", "file"),
        ("mailto:tower@example.com", "mailto"),
    ] {
        let error = TowerConfig::new(tower_id(), endpoint, Duration::from_secs(10)).unwrap_err();

        assert_eq!(
            error,
            TowerConfigError::UnsupportedScheme(scheme.to_owned())
        );
    }
}

#[test]
fn rejects_missing_hosts() {
    for endpoint in ["http://", "https://", "http://:9814"] {
        let error = TowerConfig::new(tower_id(), endpoint, Duration::from_secs(10)).unwrap_err();

        assert_eq!(error, TowerConfigError::MissingHost);
    }
}

#[test]
fn rejects_zero_timeout() {
    let error = TowerConfig::new(tower_id(), "http://tower.example/", Duration::ZERO).unwrap_err();

    assert_eq!(error, TowerConfigError::ZeroTimeout);
}

#[test]
fn accepts_a_one_nanosecond_timeout() {
    let timeout = Duration::from_nanos(1);
    let config = TowerConfig::new(tower_id(), "http://tower.example/", timeout).unwrap();

    assert_eq!(config.request_timeout(), timeout);
}

#[test]
fn accepts_the_maximum_supported_timeout_without_losing_precision() {
    let timeout = Duration::new(i64::MAX as u64, 999_999_999);
    let config = TowerConfig::new(tower_id(), "https://tower.example/", timeout).unwrap();

    assert_eq!(config.request_timeout(), timeout);
}

#[test]
fn rejects_timeouts_whose_seconds_exceed_sqlites_integer_range() {
    for timeout in [Duration::from_secs(i64::MAX as u64 + 1), Duration::MAX] {
        let error = TowerConfig::new(tower_id(), "https://tower.example/", timeout).unwrap_err();

        assert_eq!(error, TowerConfigError::TimeoutTooLarge);
    }
}
