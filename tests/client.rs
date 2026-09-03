// The Rust-specific API surface, as distinct from the shared conformance corpus
// in conformance.rs.

mod support;

use std::time::{Duration, Instant};

use support::{Route, Stub};
use vpndetection::{BatchOptions, Client, ErrorKind, Format, LookupOptions};

fn many_addrs() -> Vec<String> {
    (1..=12).map(|i| format!("9.9.9.{i}")).collect()
}

fn many_routes() -> Vec<(String, Route)> {
    let addrs = many_addrs();
    Stub::ok_routes(&addrs.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Peak in-flight is the only measurement that tells a real limit from an option
/// that was accepted and ignored.
#[tokio::test]
async fn batch_concurrency_is_configurable_per_call() {
    let stub = Stub::start_with_delay(many_routes(), Duration::from_millis(20)).await;
    let client = stub.client().no_cache().build().expect("build");

    client.lookup_batch(many_addrs(), BatchOptions::new().concurrency(3)).await;

    assert_eq!(stub.count(), many_addrs().len());
    assert!(
        stub.peak_in_flight() <= 3,
        "peak in flight was {}, want at most 3",
        stub.peak_in_flight()
    );
    assert!(stub.peak_in_flight() > 1, "requests never overlapped");
}

#[tokio::test]
async fn a_per_call_concurrency_overrides_the_client_default() {
    let stub = Stub::start_with_delay(many_routes(), Duration::from_millis(20)).await;
    let client = stub.client().no_cache().concurrency(2).build().expect("build");

    client.lookup_batch(many_addrs(), BatchOptions::new().concurrency(6)).await;

    let peak = stub.peak_in_flight();
    assert!(peak > 2, "override ignored: peak in flight was {peak}, want above 2");
    assert!(peak <= 6, "peak in flight was {peak}, want at most 6");
}

#[tokio::test]
async fn without_an_override_the_client_concurrency_still_applies() {
    let stub = Stub::start_with_delay(many_routes(), Duration::from_millis(20)).await;
    let client = stub.client().no_cache().concurrency(2).build().expect("build");

    client.lookup_batch(many_addrs(), BatchOptions::new()).await;

    assert!(stub.peak_in_flight() <= 2, "peak in flight was {}", stub.peak_in_flight());
}

#[tokio::test]
async fn retries_are_configurable_per_call() {
    let stub =
        Stub::start([("/9.9.9.9".to_owned(), Route::json(500, r#"{"error":"lookup failed"}"#))])
            .await;
    let client = stub.client().no_cache().retries(0).build().expect("build");

    client
        .lookup_with("9.9.9.9", LookupOptions::new().retries(2))
        .await
        .expect_err("a 500 should have failed the lookup");

    // One initial attempt plus two retries, rather than the client's zero.
    assert_eq!(stub.count(), 3);
}

/// A 429 with no Retry-After is a spent allowance, and retrying it is hammering
/// a quota that will not recover until its window rolls over.
#[tokio::test]
async fn a_spent_quota_is_never_retried() {
    let stub = Stub::start([(
        "/9.9.9.9".to_owned(),
        Route::json(429, r#"{"error":"request allowance exceeded"}"#),
    )])
    .await;
    let client = stub.client().no_cache().retries(5).build().expect("build");

    let err = client.lookup("9.9.9.9").await.expect_err("a 429 should fail");

    assert_eq!(err.kind(), ErrorKind::QuotaExceeded);
    assert_eq!(stub.count(), 1);
}

#[tokio::test]
async fn a_rate_limit_is_retried_after_the_server_supplied_wait() {
    let stub = Stub::start([(
        "/9.9.9.9".to_owned(),
        Route::json(429, r#"{"error":"rate limit exceeded"}"#).header("Retry-After", "1"),
    )])
    .await;
    let client = stub.client().no_cache().retries(1).build().expect("build");

    let start = Instant::now();
    client.lookup("9.9.9.9").await.expect_err("the lookup should still have failed");

    assert_eq!(stub.count(), 2);
    // The header, not the backoff schedule, decides the wait.
    assert!(start.elapsed() >= Duration::from_secs(1), "waited {:?}", start.elapsed());
}

#[tokio::test]
async fn is_bogon_is_on_the_client_and_agrees_with_the_standalone_function() {
    let stub = Stub::start([]).await;
    let client = stub.client().build().expect("build");
    for case in support::corpus::load().is_bogon {
        assert_eq!(client.is_bogon(&case.ip), case.expect, "{} ({})", case.ip, case.why);
        assert_eq!(client.is_bogon(&case.ip), vpndetection::is_bogon(&case.ip), "{}", case.ip);
    }
}

/// The single most important semantic in the library, asserted natively rather
/// than through the corpus's JSON view: a plan that omits a field leaves `None`,
/// and a plan that includes it answers `Some(false)`.
#[tokio::test]
async fn absent_and_false_are_different_values() {
    let stub = Stub::start([
        ("/1.1.1.1".to_owned(), Route::ok(r#"{"ip":"1.1.1.1","is_vpn":false}"#)),
        ("/8.8.4.4".to_owned(), Route::ok(r#"{"ip":"8.8.4.4","is_vpn":false,"is_hosting":false}"#)),
    ])
    .await;
    let client = stub.client().build().expect("build");

    let free = client.lookup("1.1.1.1").await.expect("lookup");
    assert_eq!(free.is_hosting, None, "a field the plan omits must be None");
    assert!(!free.is_hosting_or_false());

    let served = client.lookup("8.8.4.4").await.expect("lookup");
    assert_eq!(served.is_hosting, Some(false), "a checked-and-no answer must be Some(false)");
    assert!(!served.is_hosting_or_false());
}

#[tokio::test]
async fn or_false_readers_coalesce_an_absent_flag() {
    let stub = Stub::start([(
        "/45.83.91.1".to_owned(),
        Route::ok(r#"{"ip":"45.83.91.1","is_vpn":true,"is_hosting":true,"is_tor":false}"#),
    )])
    .await;
    let client = stub.client().build().expect("build");

    let result = client.lookup("45.83.91.1").await.expect("lookup");

    assert!(result.is_vpn, "the wire answer reads straight off the result");
    assert!(result.is_hosting_or_false());
    assert!(!result.is_tor_or_false(), "a present false flag reads as false");
    assert!(!result.is_dcproxy_or_false(), "an absent flag reads as false");
    assert_eq!(result.is_dcproxy, None, "the reader must not populate what it reads");
}

/// The download endpoint answers 302 to object storage, and the dataset behind
/// it runs to gigabytes. The origin here PROMISES 8 GiB, so a client that
/// follows the redirect is caught by the request count rather than by the wait.
#[tokio::test]
async fn download_url_returns_the_redirect_rather_than_following_it() {
    let stub = Stub::start([]).await;
    let location = format!("{}/huge.mmdb", stub.base_url);
    stub.route("/api/v1/database/download", Route::json(302, "").header("Location", &location));
    stub.route("/huge.mmdb", Route::ok("").promising(8 * 1024 * 1024 * 1024));
    let client = stub.client().api_key("key").build().expect("build");

    let url = client
        .database()
        .download_url("vpn_ip_extended_v1", Format::Mmdb)
        .await
        .expect("download_url");

    assert_eq!(url, location);
    assert_eq!(
        stub.calls(),
        vec!["/api/v1/database/download"],
        "the redirect must not be followed"
    );
}

/// reqwest follows redirects by DEFAULT and the policy is a client-level setting
/// with no per-request override, so a caller-supplied client is the one way this
/// can still go wrong. It is refused rather than silently downloaded.
#[tokio::test]
async fn a_redirect_following_http_client_is_refused_not_obeyed() {
    let stub = Stub::start([]).await;
    let location = format!("{}/huge.mmdb", stub.base_url);
    stub.route("/api/v1/database/download", Route::json(302, "").header("Location", &location));
    stub.route("/huge.mmdb", Route::ok("").promising(8 * 1024 * 1024 * 1024));
    let client =
        stub.client().api_key("key").http_client(reqwest::Client::new()).build().expect("build");

    let err = client
        .database()
        .download_url("vpn_ip_extended_v1", Format::Mmdb)
        .await
        .expect_err("a followed redirect has no Location left to return");

    assert!(err.message().contains("redirect::Policy::none"), "{}", err.message());
}

/// Which digests a dataset publishes is the API's choice, so the whole set comes
/// back. They nest under `checksums`, and reading a top-level `sha256` is how the
/// Node SDK shipped this broken in 1.0.x.
#[tokio::test]
async fn checksums_returns_the_whole_digest_set_from_under_its_key() {
    let stub = Stub::start([(
        "/api/v1/database/checksum".to_owned(),
        Route::ok(
            r#"{"id":"vpn_ip_extended_v1","format":"mmdb","checksums":{"md5":"m","sha1":"s1","sha256":"s256","sha512":"s512"}}"#,
        ),
    )])
    .await;
    let client = stub.client().api_key("key").build().expect("build");

    let sums =
        client.database().checksums("vpn_ip_extended_v1", Format::Mmdb).await.expect("checksums");

    assert_eq!(sums.md5.as_deref(), Some("m"));
    assert_eq!(sums.sha1.as_deref(), Some("s1"));
    assert_eq!(sums.sha256.as_deref(), Some("s256"));
    assert_eq!(sums.sha512.as_deref(), Some("s512"));
}

#[tokio::test]
async fn the_database_list_unwraps_one_level_down() {
    let stub = Stub::start([(
        "/api/v1/database/list".to_owned(),
        Route::ok(
            r#"{"datasets":[{"id":"vpn_ip_extended_v1","name":"VPN IP Extended","redistribution":"internal","in_term":true,"formats":[{"format":"mmdb","bytes":1234}]}]}"#,
        ),
    )])
    .await;
    let client = stub.client().api_key("key").build().expect("build");

    let datasets = client.database().list().await.expect("list");

    assert_eq!(datasets.len(), 1);
    assert_eq!(datasets[0].id, "vpn_ip_extended_v1");
    assert_eq!(datasets[0].formats[0].format, Format::Mmdb);
}

/// A 404 from a bad dataset id is a CLIENT error. Letting it fall through to the
/// retryable server_error default is the mistake both the Node and Go SDKs
/// shipped with.
#[tokio::test]
async fn an_unknown_dataset_is_not_retried() {
    let stub = Stub::start([(
        "/api/v1/database/metadata".to_owned(),
        Route::json(404, r#"{"rc":"NOT_FOUND"}"#),
    )])
    .await;
    let client = stub.client().api_key("key").retries(3).build().expect("build");

    let err = client.database().metadata("no_such_dataset").await.expect_err("404");

    assert_eq!(err.kind(), ErrorKind::BadRequest);
    assert!(!err.retryable());
    assert_eq!(err.message(), "NOT_FOUND");
    assert_eq!(stub.count(), 1);
}

#[test]
fn the_builder_rejects_unusable_options() {
    assert!(Client::builder().concurrency(0).build().is_err());
    assert!(Client::builder().cache(0, Duration::from_secs(60)).build().is_err());
    assert!(Client::builder().cache(10, Duration::ZERO).build().is_err());
    assert!(Client::builder().base_url("not a url").build().is_err());
    assert!(Client::builder().base_url("/relative").build().is_err());
}

#[tokio::test]
async fn an_ipv6_address_survives_the_path_template() {
    let stub = Stub::start([(
        "/2606:4700:4700::1111".to_owned(),
        Route::ok(r#"{"ip":"2606:4700:4700::1111","is_vpn":false}"#),
    )])
    .await;
    let client = stub.client().build().expect("build");

    let result = client.lookup("2606:4700:4700::1111").await.expect("lookup");

    assert_eq!(result.ip, "2606:4700:4700::1111");
}
