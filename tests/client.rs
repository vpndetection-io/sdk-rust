// The Rust-specific API surface, as distinct from the shared conformance corpus
// in conformance.rs.

mod support;

use std::time::{Duration, Instant};

use support::{Route, Stub};
use vpndetection::{
    BatchOptions, Client, DatabaseFormat, Error, ErrorKind, LookupOptions, Standing,
};

/// An origin that holds every request this long before answering, so only a
/// timeout ends the wait, and how long a call took says WHICH timeout fired.
const STALL: Duration = Duration::from_secs(60);
/// Far above the per-call value, so a per-call timeout that was accepted and
/// ignored shows up as a call that ran long.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_millis(150);
/// Short enough to wait for, long above `CALL_TIMEOUT`, and far below the
/// client's 30 second read timeout, so only the whole-attempt deadline fits.
const BODY_CLIENT_TIMEOUT: Duration = Duration::from_secs(1);

/// Enough addresses for seven chunks of the batch endpoint's 1000, so a
/// concurrency bound has something to bound: one request per chunk, and only
/// the chunks overlap.
fn many_addrs() -> Vec<String> {
    (0..6001).map(|i| format!("9.{}.{}.{}", 1 + i / 65536, (i / 256) % 256, i % 256)).collect()
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

    assert_eq!(stub.count(), 7, "one request per chunk of 1000");
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

/// Zero would leave nothing to run the chunks, so the whole batch is refused as a
/// bad request, every address answered with that refusal, before any request.
#[tokio::test]
async fn a_per_call_concurrency_below_one_is_refused_before_any_request() {
    let stub = Stub::start(Stub::ok_routes(&["1.1.1.1", "9.9.9.9"])).await;
    let client = stub.client().no_cache().build().expect("build");

    // Bounded: a limit of zero handed to the stream never polls a chunk at all,
    // so without the refusal this call would wait forever.
    let got = tokio::time::timeout(
        Duration::from_secs(10),
        client.lookup_batch(["1.1.1.1", "10.0.0.1", "9.9.9.9"], BatchOptions::new().concurrency(0)),
    )
    .await
    .expect("a batch at concurrency 0 never settled");

    assert_eq!(stub.count(), 0, "a refused batch still sent a request");
    assert_eq!(got.keys().collect::<Vec<_>>(), ["1.1.1.1", "10.0.0.1", "9.9.9.9"]);
    for (ip, answer) in &got {
        let err = answer.as_ref().expect_err("a refused batch answered an address");
        assert_eq!(err.kind(), ErrorKind::BadRequest, "{ip}: {err}");
        assert!(!err.retryable(), "{ip}: retrying cannot fix the option");
    }
}

/// Chunking is the SDK's job, so a batch has no size limit of its own: 2,500
/// addresses are three requests of at most 1000, never a refusal and never a
/// request per address.
#[tokio::test]
async fn a_batch_of_any_size_is_chunked_rather_than_refused() {
    let addrs: Vec<String> = many_addrs().into_iter().take(2500).collect();
    let stub =
        Stub::start(Stub::ok_routes(&addrs.iter().map(String::as_str).collect::<Vec<_>>())).await;
    let client = stub.client().no_cache().build().expect("build");

    let got = client.lookup_batch(&addrs, BatchOptions::new()).await;

    let requests = stub.requests();
    assert_eq!(requests.len(), 3, "2500 addresses are three chunks of up to 1000");
    for call in &requests {
        assert_eq!(call.path, "/batch");
        let body: serde_json::Value = serde_json::from_str(&call.body).expect("a JSON body");
        let sent = body["ips"].as_array().expect("an ips array").len();
        assert!(sent <= 1000, "a chunk carried {sent} addresses");
    }
    assert_eq!(got.len(), 2500);
    for ip in &addrs {
        let answer = got[ip].as_ref().unwrap_or_else(|e| panic!("{ip}: {e}"));
        assert_eq!(&answer.ip, ip, "{ip} should be answered for itself");
    }
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

/// Every call that takes `LookupOptions` is held to it, because each one reads
/// the option separately and a call that forgot would still compile.
#[tokio::test]
async fn a_per_call_timeout_below_the_clients_is_the_one_that_fires() {
    let stub = Stub::start_with_delay(Stub::ok_routes(&["9.9.9.9"]), STALL).await;
    let client =
        stub.client().no_cache().retries(0).timeout(CLIENT_TIMEOUT).build().expect("build");
    let opts = || LookupOptions::new().timeout(CALL_TIMEOUT);

    for (call, (err, took)) in [
        ("lookup_with", stalled(client.lookup_with("9.9.9.9", opts())).await),
        ("my_ip_with", stalled(client.my_ip_with(opts())).await),
        ("my_entitlement_with", stalled(client.my_entitlement_with(opts())).await),
    ] {
        assert!(
            took < CLIENT_TIMEOUT / 2,
            "{call} waited {took:?}: the call's timeout was ignored"
        );
        assert_timed_out(call, &err);
    }
}

/// Per attempt at each chunk. A chunk that runs out of time marks every address
/// in it, the same as any other chunk that fails as a whole.
#[tokio::test]
async fn a_per_call_timeout_bounds_each_chunk_of_a_batch() {
    let stub = Stub::start_with_delay(Stub::ok_routes(&["1.1.1.1", "9.9.9.9"]), STALL).await;
    let client =
        stub.client().no_cache().retries(0).timeout(CLIENT_TIMEOUT).build().expect("build");

    let start = Instant::now();
    let got = client
        .lookup_batch(["1.1.1.1", "9.9.9.9"], BatchOptions::new().timeout(CALL_TIMEOUT))
        .await;

    let took = start.elapsed();
    assert!(took < CLIENT_TIMEOUT / 2, "the batch waited {took:?}: its timeout was ignored");
    assert_eq!(got.len(), 2);
    for (ip, answer) in &got {
        assert_timed_out(ip, answer.as_ref().expect_err("a stalled chunk cannot have answered"));
    }
}

/// A deadline that stopped at the response head would never end a body stalled
/// after it, nor one trickled a byte at a time so that no single read stalls.
/// The call's own value fires first, then a call without one is held to the
/// client's.
#[tokio::test]
async fn the_timeout_covers_a_body_that_stalls_or_trickles() {
    let answer = format!(r#"{{"ip":"9.9.9.9","is_vpn":false,"pad":"{}"}}"#, "x".repeat(400));
    for (shape, route) in [
        ("stalled", Route::ok(answer.clone()).stalling_after(8)),
        ("trickled", Route::ok(answer.clone()).trickling(Duration::from_millis(20))),
    ] {
        let stub = Stub::start([("/9.9.9.9".to_owned(), route)]).await;
        let client = stub
            .client()
            .no_cache()
            .retries(0)
            .timeout(BODY_CLIENT_TIMEOUT)
            .build()
            .expect("build");

        let opts = LookupOptions::new().timeout(CALL_TIMEOUT);
        let (err, took) = stalled(client.lookup_with("9.9.9.9", opts)).await;
        assert_timed_out(shape, &err);
        assert!(
            took >= CALL_TIMEOUT && took < BODY_CLIENT_TIMEOUT,
            "{shape}: the call's timeout fired after {took:?}"
        );

        let (err, took) = stalled(client.lookup("9.9.9.9")).await;
        assert_timed_out(shape, &err);
        assert!(
            took >= BODY_CLIENT_TIMEOUT && took < BODY_CLIENT_TIMEOUT * 3,
            "{shape}: the client's timeout fired after {took:?}"
        );
    }
}

/// The database calls take no per-call options, so the client's timeout is the
/// one that has to reach them. Asking for a download link is one of them; the
/// transfer that follows is not (`tests/download.rs`).
#[tokio::test]
async fn the_client_timeout_bounds_the_database_calls() {
    let stub = Stub::start_with_delay(
        [
            ("/api/v1/database/list".to_owned(), Route::ok(r#"{"databases":[]}"#)),
            ("/api/v1/database/download".to_owned(), Route::json(302, "")),
        ],
        STALL,
    )
    .await;
    let client =
        stub.client().api_key("key").retries(0).timeout(CALL_TIMEOUT).build().expect("build");
    let database = client.database();

    for (call, (err, took)) in [
        ("list", stalled(database.list()).await),
        ("download_url", stalled(database.download_url("cdn_ip_v1", DatabaseFormat::Csvgz)).await),
    ] {
        assert!(
            took < CLIENT_TIMEOUT / 2,
            "{call} waited {took:?}: the client timeout never fired"
        );
        assert_timed_out(call, &err);
    }
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
        .download_url("vpn_ip_extended_v1", DatabaseFormat::Mmdb)
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
        .download_url("vpn_ip_extended_v1", DatabaseFormat::Mmdb)
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

    let sums = client
        .database()
        .checksums("vpn_ip_extended_v1", DatabaseFormat::Mmdb)
        .await
        .expect("checksums");

    assert_eq!(sums.md5.as_str(), "m");
    assert_eq!(sums.sha1.as_str(), "s1");
    assert_eq!(sums.sha256.as_str(), "s256");
    assert_eq!(sums.sha512.as_str(), "s512");
}

/// A licence is held against a FAMILY, and the ids a download takes are one
/// level further down still. The spec used to claim `{id, formats}` here, which
/// decoded into a family whose every field was empty, so list -> download was
/// broken in every SDK; the depth is pinned so it cannot silently go back.
#[tokio::test]
async fn the_database_list_unwraps_a_family_and_its_versions() {
    let stub = Stub::start([(
        "/api/v1/database/list".to_owned(),
        Route::ok(
            r#"{"databases":[{"base":"vpn_ip","name":"VPN IP","summary":"vpn_ip rows","starts":"2026-01-01T00:00:00.000Z","expires":null,"renews_at":null,"notice_due_at":null,"license_type":"standard","in_term":true,"standing":"licensed","versions":[{"id":"vpn_ip_extended_v1","version":1,"formats":[{"format":"mmdb","bytes":1234}],"sample_formats":["csvgz"]}]}]}"#,
        ),
    )])
    .await;
    let client = stub.client().api_key("key").build().expect("build");

    let databases = client.database().list().await.expect("list");

    assert_eq!(databases.len(), 1);
    assert_eq!(databases[0].base, "vpn_ip");
    assert_eq!(databases[0].standing, Standing::Licensed);
    let version = &databases[0].versions[0];
    assert_eq!(version.id, "vpn_ip_extended_v1", "the id a download takes lives on the VERSION");
    assert_eq!(version.version, 1);
    assert_eq!(version.formats[0].format, DatabaseFormat::Mmdb);
    assert_eq!(version.sample_formats.as_deref(), Some([DatabaseFormat::Csvgz].as_slice()));
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
    assert!(Client::builder().timeout(Duration::ZERO).build().is_err());
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

const ENTITLEMENT_BODY: &str = r#"{
  "org_id": "85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61",
  "apikey": {
    "id": "0ab424cc-7619-4dad-b027-afacdc2cedb0",
    "expires": null,
    "allowed_cidrs": []
  },
  "plan": {"key": "max", "tier": "max"},
  "usage": {
    "requests": 580,
    "quota": 5000000,
    "hard_limit": null,
    "window_start": "2026-09-04T07:00:00Z",
    "window_end": "2026-10-04T07:00:00Z"
  }
}"#;

#[tokio::test]
async fn my_ip_classifies_the_calling_address() {
    let stub =
        Stub::start([("/myip".to_string(), Route::ok(r#"{"ip":"45.83.91.1","is_vpn":true}"#))])
            .await;
    let client = stub.client().build().expect("build");

    let answer = client.my_ip().await.expect("my_ip");

    assert_eq!(answer.ip, "45.83.91.1");
    assert!(answer.is_vpn);
}

/// The cache is keyed by address, and which address this is IS the question.
#[tokio::test]
async fn my_ip_is_not_cached() {
    let stub =
        Stub::start([("/myip".to_string(), Route::ok(r#"{"ip":"45.83.91.1","is_vpn":true}"#))])
            .await;
    let client = stub.client().build().expect("build");

    client.my_ip().await.expect("my_ip");
    client.my_ip().await.expect("my_ip");

    assert_eq!(stub.count(), 2);
}

#[tokio::test]
async fn my_entitlement_reports_the_plan_and_the_usage() {
    let stub =
        Stub::start([("/api/v1/entitlement".to_string(), Route::ok(ENTITLEMENT_BODY))]).await;
    let client = stub.client().build().expect("build");

    let ent = client.my_entitlement().await.expect("my_entitlement");

    assert_eq!(ent.plan.key, "max");
    assert_eq!(ent.plan.tier, "max");
    assert_eq!(ent.usage.requests, 580);
    assert_eq!(ent.usage.quota, 5_000_000);
    // None means NEVER stop, which is not the same as a limit of zero.
    assert_eq!(ent.usage.hard_limit, None);
    assert!(ent.apikey.allowed_cidrs.is_empty());
    assert_eq!(ent.apikey.expires, None);
}

/// The whole point is what has been spent.
#[tokio::test]
async fn my_entitlement_is_not_cached() {
    let stub =
        Stub::start([("/api/v1/entitlement".to_string(), Route::ok(ENTITLEMENT_BODY))]).await;
    let client = stub.client().build().expect("build");

    client.my_entitlement().await.expect("my_entitlement");
    client.my_entitlement().await.expect("my_entitlement");

    assert_eq!(stub.count(), 2);
}

#[tokio::test]
async fn my_entitlement_surfaces_an_unauthorized_key() {
    let stub = Stub::start([(
        "/api/v1/entitlement".to_string(),
        Route::json(401, r#"{"error":"invalid API key"}"#),
    )])
    .await;
    let client = stub.client().retries(0).build().expect("build");

    let err = client.my_entitlement().await.expect_err("expected an error");
    assert_eq!(err.kind(), ErrorKind::Unauthorized);
}

/// Awaits a call that must fail, and how long it took to.
async fn stalled<T: std::fmt::Debug>(
    call: impl Future<Output = Result<T, Error>>,
) -> (Error, Duration) {
    let start = Instant::now();
    let err = call.await.expect_err("a stalled origin cannot have answered");
    (err, start.elapsed())
}

/// A timeout is the crate's own retryable transport error, and says it timed out.
fn assert_timed_out(call: &str, err: &Error) {
    assert_eq!(err.kind(), ErrorKind::Network, "{call}: {err}");
    assert!(err.retryable(), "{call}: a timeout is worth another attempt");
    assert!(err.message().contains("timed out"), "{call}: {}", err.message());
}
