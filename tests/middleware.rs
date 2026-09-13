// The middleware half of the shared conformance corpus, which every framework
// middleware in every language asserts, plus the Rust-specific parts of it.
//
// The framework-shaped half - extractors, a tower Layer - is asserted in the
// adapter crate against a real server. What is here is everything a framework
// cannot change.

mod support;

use std::sync::{Arc, Mutex};

use serde_json::json;
use support::{Route, Stub, corpus};
use vpndetection::middleware::{
    Bound, Condition, ConditionError, Core, IpSelector, OnMissingField, Options, RequestView,
    from_json, header, xff,
};

const PUBLIC_IP: &str = "45.83.91.1";

/// The least a framework can offer, so the core is exercised without one.
struct Req {
    ip: Option<String>,
    headers: Vec<(String, String)>,
}

impl Req {
    fn from(ip: &str) -> Self {
        Self { ip: Some(ip.to_owned()), headers: Vec::new() }
    }

    fn nowhere() -> Self {
        Self { ip: None, headers: Vec::new() }
    }

    fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }

    fn view<T>(&self, body: impl FnOnce(&RequestView<'_>) -> T) -> T {
        let header = |name: &str| {
            let wanted = name.to_ascii_lowercase();
            self.headers.iter().find(|(k, _)| *k == wanted).map(|(_, v)| v.clone())
        };
        let framework_ip = || self.ip.clone();
        body(&RequestView { header: &header, framework_ip: &framework_ip })
    }

    // A view borrows this request, so the future has to be awaited while the
    // view is still alive - which a closure returning one cannot express.
    async fn evaluate(
        &self,
        core: &Core,
    ) -> Result<vpndetection::middleware::Lookup, ConditionError> {
        let header = |name: &str| {
            let wanted = name.to_ascii_lowercase();
            self.headers.iter().find(|(k, _)| *k == wanted).map(|(_, v)| v.clone())
        };
        let framework_ip = || self.ip.clone();
        core.evaluate(&RequestView { header: &header, framework_ip: &framework_ip }).await
    }
}

fn warnings() -> (Arc<Mutex<Vec<String>>>, vpndetection::middleware::Warn) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    (seen, Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_owned())))
}

async fn serving(stub: &Stub, options: Options) -> Core {
    Core::new(options.client(stub.client().no_cache().retries(0).build().expect("build")))
        .expect("core")
}

fn answer(ip: &str, body: serde_json::Value) -> (String, Route) {
    let mut merged = json!({ "ip": ip });
    for (k, v) in body.as_object().expect("an object") {
        merged[k] = v.clone();
    }
    (format!("/{ip}"), Route::ok(merged.to_string()))
}

#[tokio::test]
async fn corpus_conditions() {
    for case in corpus::load().middleware.conditions {
        let ip = case.bogon.clone().unwrap_or_else(|| {
            case.body.as_ref().expect("a body")["ip"].as_str().expect("an ip").to_owned()
        });
        let routes = match (&case.bogon, &case.body) {
            // Answered locally, so this needs no route and pins the synthesized
            // shape rather than a fixture's idea of it.
            (Some(_), _) => vec![],
            (None, body) => {
                let mut served = body.clone().expect("a body");
                served.as_object_mut().expect("an object").remove("ip");
                vec![answer(&ip, served)]
            }
        };
        let stub = Stub::start(routes).await;
        let (seen, warn) = warnings();
        let core = serving(
            &stub,
            Options::new()
                .block_condition(from_json(&case.condition).expect("a readable condition"))
                .ip_selector({
                    let ip = ip.clone();
                    Arc::new(move |_: &RequestView<'_>| Some(ip.clone())) as IpSelector
                })
                .on_warn(warn),
        )
        .await;

        let found = Req::nowhere().evaluate(&core).await.expect("evaluate");

        assert_eq!(found.blocked, case.expect.blocked, "{}: {}", case.name, case.why);
        let reported: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.contains("does not include"))
            .cloned()
            .collect();
        assert_eq!(
            reported.len(),
            usize::from(!case.expect.missing.is_empty()),
            "{}: {}",
            case.name,
            case.why
        );
        for member in &case.expect.missing {
            assert!(reported[0].contains(member), "{}: {}", case.name, case.why);
        }
    }
}

#[test]
fn corpus_refuses_a_condition_that_constrains_nothing() {
    for case in corpus::load().middleware.invalid_conditions {
        let condition = from_json(&case.condition).expect("a readable condition");
        let Err(error) = Core::new(Options::new().block_condition(condition)) else {
            panic!("{}: accepted a condition that constrains nothing ({})", case.name, case.why);
        };
        assert!(error.to_string().contains("constrains nothing"), "{}", case.why);
    }
}

#[tokio::test]
async fn enriches_without_blocking_when_no_condition_is_configured() {
    let stub = Stub::start([answer(PUBLIC_IP, json!({ "is_vpn": true }))]).await;
    let core = serving(&stub, Options::new()).await;

    let found = Req::from(PUBLIC_IP).evaluate(&core).await.expect("evaluate");

    assert!(!found.blocked);
    assert!(found.result.expect("a result").is_vpn);
    assert_eq!(found.ip.as_deref(), Some(PUBLIC_IP));
}

#[tokio::test]
async fn a_condition_reaches_the_evidence_fields() {
    let stub = Stub::start([answer(
        PUBLIC_IP,
        json!({ "is_vpn": true, "vpn": { "provider": "MULLVAD" } }),
    )])
    .await;
    let other = serving(
        &stub,
        Options::new().block_condition(vec![Condition::from([(
            "vpn",
            Condition::from([("provider", "nordvpn")]),
        )])]),
    )
    .await;
    assert!(
        !Req::from(PUBLIC_IP).evaluate(&other).await.expect("evaluate").blocked,
        "a different provider must not match"
    );

    let cased = serving(
        &stub,
        Options::new().block_condition(vec![Condition::from([(
            "vpn",
            Condition::from([("provider", "mullvad")]),
        )])]),
    )
    .await;
    assert!(
        Req::from(PUBLIC_IP).evaluate(&cased).await.expect("evaluate").blocked,
        "a provider must compare without case"
    );
}

#[tokio::test]
async fn a_bound_reaches_the_numeric_evidence() {
    let stub =
        Stub::start([answer(PUBLIC_IP, json!({ "is_vpn": false, "resproxy": { "hits": 7 } }))])
            .await;
    for (bound, want) in [(Bound::gte(5.0), true), (Bound::gte(5.0).and_lt(7.0), false)] {
        let core = serving(
            &stub,
            Options::new().block_condition(vec![Condition::from([(
                "resproxy",
                Condition::from([("hits", bound)]),
            )])]),
        )
        .await;
        assert_eq!(
            Req::from(PUBLIC_IP).evaluate(&core).await.expect("evaluate").blocked,
            want,
            "every bound given must hold"
        );
    }
}

#[tokio::test]
async fn fails_open_on_a_lookup_error_and_closed_only_when_asked() {
    let stub =
        Stub::start([(format!("/{PUBLIC_IP}"), Route::json(500, r#"{"error":"boom"}"#))]).await;

    let opened =
        serving(&stub, Options::new().block_condition(vec![Condition::from([("is_vpn", true)])]))
            .await;
    let found = Req::from(PUBLIC_IP).evaluate(&opened).await.expect("evaluate");
    assert!(!found.blocked);
    assert!(found.error.is_some());
    assert!(found.result.is_none());

    let closed = serving(
        &stub,
        Options::new().block_condition(vec![Condition::from([("is_vpn", true)])]).fail_closed(true),
    )
    .await;
    assert!(Req::from(PUBLIC_IP).evaluate(&closed).await.expect("evaluate").blocked);
}

#[tokio::test]
async fn a_private_client_address_warns_once_and_never_reaches_the_network() {
    let stub = Stub::start([]).await;
    let (seen, warn) = warnings();
    let core = serving(
        &stub,
        Options::new().block_condition(vec![Condition::from([("is_vpn", true)])]).on_warn(warn),
    )
    .await;

    for _ in 0..2 {
        let found = Req::from("10.0.0.7").evaluate(&core).await.expect("evaluate");
        assert!(!found.blocked, "local development must not lock you out of your own app");
        assert!(found.result.expect("a result").is_bogon);
    }

    assert_eq!(stub.count(), 0, "a bogon is answered locally");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "a misconfiguration is the same on every request");
    assert!(seen[0].contains("not a public address"));
}

#[tokio::test]
async fn a_missing_member_warns_once_or_fails_on_request() {
    let stub = Stub::start([answer(PUBLIC_IP, json!({ "is_vpn": true }))]).await;
    let (seen, warn) = warnings();
    let warned = serving(
        &stub,
        Options::new().block_condition(vec![Condition::from([("is_hosting", true)])]).on_warn(warn),
    )
    .await;

    for _ in 0..2 {
        Req::from(PUBLIC_IP).evaluate(&warned).await.expect("evaluate");
    }
    let reported = seen.lock().unwrap().clone();
    assert_eq!(reported.len(), 1);
    assert!(reported[0].contains("is_hosting"));

    let strict = serving(
        &stub,
        Options::new()
            .block_condition(vec![Condition::from([("is_hosting", true)])])
            .on_missing_field(OnMissingField::Fail),
    )
    .await;
    assert!(Req::from(PUBLIC_IP).evaluate(&strict).await.is_err());
}

#[tokio::test]
async fn an_unresolvable_address_warns_and_does_not_block() {
    let stub = Stub::start([]).await;
    let (seen, warn) = warnings();
    let core = serving(
        &stub,
        Options::new().block_condition(vec![Condition::from([("is_vpn", true)])]).on_warn(warn),
    )
    .await;

    let found = Req::nowhere().evaluate(&core).await.expect("evaluate");

    assert!(!found.blocked);
    assert!(found.error.is_some());
    assert!(seen.lock().unwrap()[0].contains("could not resolve a client address"));
}

#[test]
fn selectors_read_what_they_say_they_read() {
    let chained =
        Req::from("10.0.0.1").with("X-Forwarded-For", "203.0.113.9, 70.41.3.18, 150.172.238.178");

    chained.view(|v| {
        assert_eq!(vpndetection::middleware::framework_ip()(v).as_deref(), Some("10.0.0.1"));
        assert_eq!(xff(0)(v).as_deref(), Some("203.0.113.9"));
        assert_eq!(xff(1)(v).as_deref(), Some("150.172.238.178"));
        assert_eq!(xff(2)(v).as_deref(), Some("70.41.3.18"));
        // Past the chain's length the depth is meaningless, so this falls back
        // to the left-most rather than indexing off the end.
        assert_eq!(xff(9)(v).as_deref(), Some("203.0.113.9"));
        assert_eq!(header("CF-Connecting-IP")(v).as_deref(), Some("10.0.0.1"));
    });

    Req::from("10.0.0.1").with("CF-Connecting-IP", "198.51.100.4").view(|v| {
        assert_eq!(header("CF-Connecting-IP")(v).as_deref(), Some("198.51.100.4"));
    });
    Req::from("10.0.0.1").view(|v| assert_eq!(xff(0)(v).as_deref(), Some("10.0.0.1")));
}

#[test]
fn a_condition_read_from_json_is_the_one_written_in_rust() {
    let written = vec![
        Condition::new()
            .with("is_vpn", true)
            .with("vpn", Condition::from([("confidence", vec!["high", "medium"])])),
        Condition::from([("resproxy", Condition::from([("hits", Bound::gte(5.0).and_lt(100.0))]))]),
    ];
    let read = from_json(&json!([
        { "is_vpn": true, "vpn": { "confidence": ["high", "medium"] } },
        { "resproxy": { "hits": { "gte": 5, "lt": 100 } } },
    ]))
    .expect("a readable condition");

    assert_eq!(read, written);
}

#[test]
fn a_condition_that_is_not_an_object_is_refused_rather_than_ignored() {
    assert!(from_json(&json!("is_vpn")).is_err());
    assert!(from_json(&json!([{ "is_vpn": true }, 7])).is_err());
}
