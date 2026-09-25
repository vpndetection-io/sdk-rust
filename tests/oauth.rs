// The `oauth` accessor against the shared corpus: what leaves the client, how
// answers decode, how failures classify, and which calls retry. The poll's
// timing cases need its clock replaced, so they are unit tests in
// src/oauth/tests.rs; this file only proves the real clock is wired in.

mod support;

use std::time::{Duration, Instant};

use serde_json::Value;
use support::corpus::{self, OauthArgs};
use support::oauth::{
    assert_failure, assert_members, device_member, form, metadata_member, route, token_member,
};
use support::{Call, Route, Stub};
use vpndetection::{
    Client, DeviceAuthorization, DeviceAuthorizationOptions, ErrorKind, OauthError, OauthOptions,
};

const CLIENT_ID: &str = "vpndetection-cli";
/// Satisfies every operation's required members at once.
const EVERY_REQUIRED_MEMBER: &str = r#"{"issuer":"https://api.example.test",
    "authorization_endpoint":"https://api.example.test/oauth/authorize",
    "token_endpoint":"https://api.example.test/oauth/token","device_code":"mo_dc_x",
    "user_code":"BCDF-GHJK","verification_uri":"https://app.example.test/device",
    "expires_in":900,"interval":1,"access_token":"mo_at_x","token_type":"Bearer"}"#;
const STALL: Duration = Duration::from_secs(60);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_millis(150);

#[tokio::test]
async fn no_oauth_request_carries_the_api_key() {
    let data = corpus::load().oauth;
    let stub = Stub::start(every_path(Route::ok(EVERY_REQUIRED_MEMBER))).await;
    let client = stub.client().api_key(&data.no_credential.api_key).build().expect("build");
    let oauth = client.oauth();

    oauth.metadata().await.expect("metadata");
    let device = oauth
        .device_authorization_with(
            CLIENT_ID,
            DeviceAuthorizationOptions::new().scope("account.read").resource("https://x.test/"),
        )
        .await
        .expect("device authorization");
    oauth.exchange_device_code(CLIENT_ID, "mo_dc_x").await.expect("exchange device code");
    oauth.exchange_refresh_token(CLIENT_ID, "mo_rt_x").await.expect("exchange refresh token");
    oauth.revoke(CLIENT_ID, "mo_rt_x").await.expect("revoke");
    oauth.poll_device_token(CLIENT_ID, &device).await.expect("poll");

    let requests = stub.requests();
    assert_eq!(requests.len(), 6, "every operation reached the stub once");
    for call in &requests {
        for name in &data.no_credential.forbidden_headers {
            assert_eq!(call.header(name), None, "{}: carried {name}", call.path);
        }
        let target = call.header("x-stub-target").expect("the stub records the target");
        let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
        for pair in query.split('&') {
            let key = pair.split('=').next().unwrap_or_default();
            assert!(!data.no_credential.forbidden_query.iter().any(|q| q == key), "{target}");
        }
        let key = &data.no_credential.api_key;
        assert!(!call.body.contains(key.as_str()), "{}: the key is in the body", call.path);
        for (name, value) in &call.headers {
            assert!(!value.contains(key.as_str()), "{}: the key is in {name}", call.path);
        }
    }
}

/// Asserted on what the client REQUESTED, and on a client built with no key,
/// which is how these calls are meant to be made.
#[tokio::test]
async fn each_form_goes_to_its_endpoint_with_exactly_its_fields() {
    let data = corpus::load().oauth;
    for case in &data.forms.cases {
        let stub = Stub::start(every_path(Route::ok(EVERY_REQUIRED_MEMBER))).await;
        let client = stub.client().build().expect("build");

        call(&client, &case.operation, &case.args).await.unwrap_or_else(|e| panic!("{e}"));

        let requests = stub.requests();
        assert_eq!(requests.len(), 1, "{}: one request", case.name);
        let endpoint = &data.endpoints[&case.endpoint];
        assert_sent_to(&case.name, &requests[0], &endpoint.method, &endpoint.path);
        let content_type = requests[0].header("content-type").unwrap_or_default();
        assert!(
            content_type.starts_with(&data.forms.content_type),
            "{}: {content_type}",
            case.name
        );
        assert_eq!(form(&requests[0]), case.fields, "{}: fields", case.name);
    }

    let stub = Stub::start(every_path(Route::ok(EVERY_REQUIRED_MEMBER))).await;
    let client = stub.client().build().expect("build");
    client.oauth().metadata().await.expect("metadata");
    let endpoint = &data.endpoints["metadata"];
    assert_sent_to("metadata", &stub.requests()[0], &endpoint.method, &endpoint.path);
}

#[tokio::test]
async fn answers_decode_with_absent_members_absent() {
    let data = corpus::load().oauth;
    for case in &data.responses.metadata {
        let client = serving(&case.served).await;
        let got = client.oauth().metadata().await.unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let member = |name: &str| metadata_member(&got, name);
        assert_members(&case.name, member, &case.expect.present, &case.expect.absent);
    }
    for case in &data.responses.device_authorization {
        let client = serving(&case.served).await;
        let got = client.oauth().device_authorization(CLIENT_ID).await;
        let got = got.unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let member = |name: &str| device_member(&got, name);
        assert_members(&case.name, member, &case.expect.present, &case.expect.absent);
    }
    for case in &data.responses.token {
        let client = serving(&case.served).await;
        let got = client.oauth().exchange_device_code(CLIENT_ID, "mo_dc_x").await;
        let got = got.unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let member = |name: &str| token_member(&got, name);
        assert_members(&case.name, member, &case.expect.present, &case.expect.absent);
    }
    for served in &data.responses.revoke {
        let client = serving(served).await;
        client.oauth().revoke(CLIENT_ID, "mo_rt_x").await.unwrap_or_else(|e| panic!("{e}"));
    }
}

#[tokio::test]
async fn failures_are_classified_as_the_corpus_says() {
    for case in corpus::load().oauth.errors.cases {
        let client = serving(&case.served).await;
        let err =
            client.oauth().exchange_device_code(CLIENT_ID, "mo_dc_x").await.expect_err(&case.name);
        assert_failure(&case.name, &err, &case.expect);
    }
}

/// With the client at its default retries. The count is asserted before the
/// outcome, so an extra attempt fails here rather than on what it was answered.
#[tokio::test]
async fn only_the_calls_that_consume_nothing_are_retried() {
    let data = corpus::load().oauth;
    for case in &data.retries.cases {
        let stub = Stub::start([]).await;
        let path = &data.endpoints[endpoint_of(&case.operation)].path;
        stub.sequence(path.as_str(), case.responses.iter().map(route));
        let client = stub.client().build().expect("build");

        let outcome = call(&client, &case.operation, &case.args).await;

        assert_eq!(Some(stub.count()), case.expect.requests, "{}: requests", case.name);
        match outcome {
            Ok(()) => assert_eq!(case.expect.outcome, "ok", "{}: succeeded", case.name),
            Err(err) => assert_failure(&case.name, &err, &case.expect),
        }
    }
}

/// Each required member left out on its own, then a body that is not JSON: every
/// one is the crate's ordinary server error carrying the status, never a value
/// with a hole in it.
#[tokio::test]
async fn a_2xx_without_a_required_member_is_an_ordinary_error() {
    let required = [
        ("metadata", &["issuer", "authorization_endpoint", "token_endpoint"][..]),
        (
            "deviceAuthorization",
            &["device_code", "user_code", "verification_uri", "expires_in", "interval"][..],
        ),
        ("exchangeDeviceCode", &["access_token", "token_type", "expires_in"][..]),
        ("exchangeRefreshToken", &["access_token", "token_type", "expires_in"][..]),
    ];
    let complete: serde_json::Map<String, Value> =
        serde_json::from_str(EVERY_REQUIRED_MEMBER).expect("a JSON object");
    let mut cases: Vec<(&str, String)> = vec![("metadata", "<html>not json</html>".to_owned())];
    for (operation, members) in required {
        for member in members {
            let mut body = complete.clone();
            body.remove(*member);
            cases.push((operation, Value::Object(body).to_string()));
        }
    }
    for (operation, body) in cases {
        let stub = Stub::start(every_path(Route::ok(body.as_str()))).await;
        let client = stub.client().retries(0).build().expect("build");
        let args = OauthArgs {
            device_code: Some("x".into()),
            refresh_token: Some("x".into()),
            ..OauthArgs::default()
        };

        let err = call(&client, operation, &args).await.expect_err(&format!("{operation} {body}"));

        assert!(matches!(err, OauthError::Client(_)), "{operation} {body}: {err:?}");
        assert_eq!(err.kind(), ErrorKind::ServerError, "{operation} {body}");
        assert_eq!(err.status(), Some(200), "{operation} {body}");
        assert_eq!(err.error_code(), None, "{operation} {body}");
    }
}

/// Every network method takes the per-call timeout, and it is the one that
/// fires when it is the shorter. The poll's includes its one-second wait.
#[tokio::test]
async fn every_oauth_call_takes_a_per_call_timeout() {
    let stub = Stub::start_with_delay(every_path(Route::ok(EVERY_REQUIRED_MEMBER)), STALL).await;
    let client = stub.client().retries(0).timeout(CLIENT_TIMEOUT).build().expect("build");
    let oauth = client.oauth();
    let opts = || OauthOptions::new().timeout(CALL_TIMEOUT);
    let device_opts = DeviceAuthorizationOptions::new().timeout(CALL_TIMEOUT);
    let device = device(1);

    let calls = [
        ("metadata", timed(oauth.metadata_with(opts())).await, CALL_TIMEOUT),
        (
            "device_authorization",
            timed(oauth.device_authorization_with(CLIENT_ID, device_opts)).await,
            CALL_TIMEOUT,
        ),
        (
            "exchange_device_code",
            timed(oauth.exchange_device_code_with(CLIENT_ID, "x", opts())).await,
            CALL_TIMEOUT,
        ),
        (
            "exchange_refresh_token",
            timed(oauth.exchange_refresh_token_with(CLIENT_ID, "x", opts())).await,
            CALL_TIMEOUT,
        ),
        ("revoke", timed(oauth.revoke_with(CLIENT_ID, "x", opts())).await, CALL_TIMEOUT),
        (
            "poll_device_token",
            timed(oauth.poll_device_token_with(CLIENT_ID, &device, opts())).await,
            Duration::from_secs(1) + CALL_TIMEOUT,
        ),
    ];
    for (name, (err, took), bound) in calls {
        assert!(took >= bound, "{name} failed after {took:?}, before its {bound:?}");
        assert!(took < bound + Duration::from_secs(2), "{name} waited {took:?}: ignored");
        assert!(matches!(err, OauthError::Client(_)), "{name}: {err:?}");
        assert_eq!(err.kind(), ErrorKind::Network, "{name}: {err}");
        assert!(err.retryable(), "{name}: a timeout is worth another attempt");
        assert!(err.message().contains("timed out"), "{name}: {}", err.message());
    }
}

/// Dropping the future is Rust's cancellation: the wait ends, and no request
/// goes out afterwards.
#[tokio::test]
async fn dropping_a_poll_during_its_wait_sends_nothing() {
    let stub =
        Stub::start(every_path(Route::json(400, r#"{"error":"authorization_pending"}"#))).await;
    let client = stub.client().build().expect("build");
    let device = device(1);

    let start = Instant::now();
    let dropped = tokio::time::timeout(
        Duration::from_millis(200),
        client.oauth().poll_device_token(CLIENT_ID, &device),
    )
    .await;

    assert!(dropped.is_err(), "the poll settled before it was dropped: {dropped:?}");
    assert!(start.elapsed() < Duration::from_secs(1), "settled after {:?}", start.elapsed());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(stub.count(), 0, "a dropped poll still sent a request");
}

/// The corpus's pending-then-token case on the real clock, within its
/// tolerance, so the clock the unit tests replace is known to be the one used.
#[tokio::test]
async fn the_poll_waits_on_the_real_clock() {
    let data = corpus::load().oauth;
    let case = data.poll.cases.iter().find(|c| c.name == "pending-then-token").expect("case");
    let stub = Stub::start([]).await;
    stub.sequence("/oauth/token", case.responses.iter().map(route));
    let client = stub.client().build().expect("build");
    let device: DeviceAuthorization = serde_json::from_value(case.device.clone()).expect("device");

    let start = Instant::now();
    let token = client.oauth().poll_device_token(&case.client_id, &device).await.expect("poll");
    let settled = start.elapsed();

    let requests = stub.requests();
    assert_eq!(Some(requests.len()), case.expect.requests, "requests");
    let mut previous = start;
    for (call, wait) in requests.iter().zip(&case.expect.waits) {
        let gap = call.at.duration_since(previous);
        let wait = Duration::from_secs(*wait);
        assert!(gap + Duration::from_millis(50) >= wait, "waited {gap:?}, want {wait:?}");
        assert!(gap < wait + Duration::from_secs(1), "waited {gap:?}, want {wait:?}");
        previous = call.at;
    }
    let total: u64 = case.expect.waits.iter().sum();
    assert!(settled + Duration::from_millis(50) >= Duration::from_secs(total), "{settled:?}");
    assert_eq!(token.access_token, "mo_at_poll");
}

async fn call(client: &Client, operation: &str, args: &OauthArgs) -> Result<(), OauthError> {
    let oauth = client.oauth();
    let client_id = args.client_id.as_deref().unwrap_or(CLIENT_ID);
    let arg = |value: &Option<String>| value.clone().unwrap_or_default();
    match operation {
        "metadata" => oauth.metadata().await.map(drop),
        "deviceAuthorization" => {
            let mut opts = DeviceAuthorizationOptions::new();
            if let Some(scope) = &args.scope {
                opts = opts.scope(scope);
            }
            if let Some(resource) = &args.resource {
                opts = opts.resource(resource);
            }
            oauth.device_authorization_with(client_id, opts).await.map(drop)
        }
        "exchangeDeviceCode" => {
            oauth.exchange_device_code(client_id, &arg(&args.device_code)).await.map(drop)
        }
        "exchangeRefreshToken" => {
            oauth.exchange_refresh_token(client_id, &arg(&args.refresh_token)).await.map(drop)
        }
        "revoke" => oauth.revoke(client_id, &arg(&args.token)).await,
        other => panic!("the corpus names an operation this release lacks: {other}"),
    }
}

fn endpoint_of(operation: &str) -> &'static str {
    match operation {
        "metadata" => "metadata",
        "deviceAuthorization" => "deviceAuthorization",
        "exchangeDeviceCode" | "exchangeRefreshToken" => "token",
        "revoke" => "revoke",
        other => panic!("no endpoint for {other}"),
    }
}

fn assert_sent_to(case: &str, call: &Call, method: &str, path: &str) {
    assert_eq!((call.method.as_str(), call.path.as_str()), (method, path), "{case}: endpoint");
}

async fn serving(served: &corpus::Served) -> Client {
    let stub = Stub::start(every_path(route(served))).await;
    stub.client().retries(0).build().expect("build")
}

/// Awaits a call that must fail, and how long it took to.
async fn timed<T: std::fmt::Debug>(
    call: impl Future<Output = Result<T, OauthError>>,
) -> (OauthError, Duration) {
    let start = Instant::now();
    let err = call.await.expect_err("a stalled origin cannot have answered");
    (err, start.elapsed())
}

fn every_path(route: Route) -> Vec<(String, Route)> {
    [
        "/.well-known/oauth-authorization-server",
        "/oauth/device_authorization",
        "/oauth/token",
        "/oauth/revoke",
    ]
    .into_iter()
    .map(|path| (path.to_owned(), route.clone()))
    .collect()
}

fn device(interval: i64) -> DeviceAuthorization {
    let value: Value = serde_json::json!({
        "device_code": "mo_dc_x", "user_code": "BCDF-GHJK",
        "verification_uri": "https://app.example.test/device", "expires_in": 900,
        "interval": interval,
    });
    serde_json::from_value(value).expect("a device authorization")
}

/// The time left is rarely whole seconds here, so a sleep dropping the fraction
/// polls again short of the deadline; only such a poll reaches the approval.
#[tokio::test]
async fn the_poll_sleeps_the_fraction_left_before_its_deadline() {
    let stub = Stub::start([]).await;
    stub.sequence(
        "/oauth/token",
        [
            Route::json(400, r#"{"error":"authorization_pending"}"#),
            Route::ok(EVERY_REQUIRED_MEMBER),
        ],
    );
    let client = stub.client().build().expect("build");
    let device: DeviceAuthorization = serde_json::from_value(serde_json::json!({
        "device_code": "mo_dc_x", "user_code": "BCDF-GHJK",
        "verification_uri": "https://app.example.test/device", "expires_in": 2, "interval": 1,
    }))
    .expect("device");

    let start = Instant::now();
    let err = client.oauth().poll_device_token(CLIENT_ID, &device).await.expect_err("expired");
    let settled = start.elapsed();

    assert_eq!(stub.count(), 1, "polled again before the deadline");
    assert!(matches!(err, OauthError::ExpiredToken(ref e) if e.status.is_none()), "{err:?}");
    assert!(settled >= Duration::from_millis(1950), "expired before its deadline: {settled:?}");
    assert!(settled < Duration::from_millis(3500), "{settled:?}");
}

/// A zero timeout is refused on every OAuth call, the poll's before its first
/// wait rather than an interval later.
#[tokio::test]
async fn a_zero_oauth_timeout_is_refused_before_any_request() {
    let stub = Stub::start(every_path(Route::ok(EVERY_REQUIRED_MEMBER))).await;
    let client = stub.client().build().expect("build");
    let oauth = client.oauth();
    let zero = || OauthOptions::new().timeout(Duration::ZERO);
    let device: DeviceAuthorization = serde_json::from_value(serde_json::json!({
        "device_code": "mo_dc_x", "user_code": "BCDF-GHJK",
        "verification_uri": "https://app.example.test/device", "expires_in": 900, "interval": 5,
    }))
    .expect("device");

    let start = Instant::now();
    for (call, answer) in [
        ("metadata", oauth.metadata_with(zero()).await.map(|_| ())),
        (
            "device_authorization",
            oauth
                .device_authorization_with(
                    CLIENT_ID,
                    DeviceAuthorizationOptions::new().timeout(Duration::ZERO),
                )
                .await
                .map(|_| ()),
        ),
        (
            "exchange",
            oauth.exchange_device_code_with(CLIENT_ID, "mo_dc_x", zero()).await.map(|_| ()),
        ),
        ("revoke", oauth.revoke_with(CLIENT_ID, "mo_rt_x", zero()).await),
        ("poll", oauth.poll_device_token_with(CLIENT_ID, &device, zero()).await.map(|_| ())),
    ] {
        match answer {
            Err(OauthError::Client(err)) => assert_eq!(err.kind(), ErrorKind::BadRequest, "{call}"),
            other => panic!("{call}: {other:?}"),
        }
    }
    assert!(start.elapsed() < Duration::from_secs(1), "the poll waited before refusing");
    assert_eq!(stub.count(), 0);
}
