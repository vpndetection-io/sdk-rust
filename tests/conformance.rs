// Asserts the shared conformance corpus that every VPNDetection SDK asserts.
//
// The corpus is generated into testdata/ and is identical across languages, so a
// behavior that drifts here fails here rather than surfacing as two client
// libraries quietly disagreeing about the same address.

mod support;

use std::time::Duration;

use serde_json::{Value, json};
use support::corpus::{self, Corpus};
use support::{Route, Stub};
use vpndetection::{BatchOptions, Lookup, is_bogon};

#[test]
fn is_bogon_matches_the_canonical_ranges() {
    for case in corpus::load().is_bogon {
        assert_eq!(
            is_bogon(&case.ip),
            case.expect,
            "is_bogon({:?}) should be {} ({})",
            case.ip,
            case.expect,
            case.why
        );
    }
}

#[tokio::test]
async fn a_bogon_is_answered_locally_in_the_full_max_shape() {
    let data = corpus::load();
    let stub = Stub::start([]).await;
    let client = stub.client().build().expect("build");

    let result = client.lookup("10.0.0.1").await.expect("lookup");

    assert!(result.is_bogon, "is_bogon should mark a locally computed answer");
    assert_eq!(result.ip, "10.0.0.1");
    let wire = wire(&result);
    for name in &data.bogon_response.flags_false {
        assert_flag(&wire, name, false);
    }
    for name in &data.bogon_response.empty_objects {
        assert_empty_object(&wire, name);
    }
    assert_eq!(stub.count(), 0, "a bogon must not reach the network");
}

#[tokio::test]
async fn a_lookup_preserves_absent_versus_false_across_every_plan_shape() {
    for case in corpus::load().lookup {
        let ip = case.body["ip"].as_str().expect("the fixture body has an ip").to_owned();
        let stub =
            Stub::start([(format!("/{ip}"), Route::json(case.status, case.body.to_string()))])
                .await;
        let client = stub.client().build().expect("build");

        let result = client.lookup(&ip).await.unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let wire = wire(&result);

        assert_eq!(result.ip, case.expect.ip, "{}: ip", case.name);
        assert_eq!(result.is_bogon, case.expect.is_bogon, "{}: is_bogon", case.name);
        for (name, want) in &case.expect.present {
            assert_flag(&wire, name, *want);
        }
        for name in &case.expect.absent {
            assert_absent(&wire, name);
        }
        for name in &case.expect.empty_present {
            assert_empty_object(&wire, name);
        }
        assert_object(&wire, "vpn", case.expect.vpn.as_ref());
        assert_object(&wire, "hosting", case.expect.hosting.as_ref());
        assert_object(&wire, "dcproxy", case.expect.dcproxy.as_ref());
    }
}

#[tokio::test]
async fn a_429_is_classified_by_retry_after_not_by_its_status() {
    for case in corpus::load().errors {
        let mut route = Route::json(case.status, case.body.to_string());
        for (name, value) in &case.headers {
            route = route.header(name, value);
        }
        let stub = Stub::start([("/1.1.1.1".to_owned(), route)]).await;
        // No retries, so a retryable failure surfaces rather than looping.
        let client = stub.client().retries(0).build().expect("build");

        let err = client.lookup("1.1.1.1").await.expect_err(&case.name);

        assert_eq!(err.kind().as_str(), case.expect.kind, "{}: kind", case.name);
        assert_eq!(err.retryable(), case.expect.retryable, "{}: retryable", case.name);
        if let Some(message) = &case.expect.message {
            assert_eq!(&err.message(), message, "{}: message", case.name);
        }
        if let Some(seconds) = case.expect.retry_after_seconds {
            assert_eq!(
                err.retry_after(),
                Some(Duration::from_secs(seconds)),
                "{}: retry_after",
                case.name
            );
        }
    }
}

#[tokio::test]
async fn a_batch_dedupes_short_circuits_bogons_and_keys_by_address() {
    let data = corpus::load();
    let case = data.batch_case("dedup-bogon-and-order-free-keying");
    let stub = Stub::start(Stub::ok_routes(&["1.1.1.1", "8.8.8.8"])).await;
    let client = stub.client().build().expect("build");

    let got = client.lookup_batch(&case.input, BatchOptions::new()).await;

    // Keyed by address, not positional, and in the order each was first seen.
    assert_eq!(got.keys().cloned().collect::<Vec<_>>(), case.expect.keys);
    assert_eq!(stub.count(), case.expect.http_requests.expect("httpRequests"));
    for ip in &case.expect.bogon_keys {
        let answer = got[ip].as_ref().unwrap_or_else(|e| panic!("{ip}: {e}"));
        assert!(answer.is_bogon, "{ip} should be a local answer");
    }
}

#[tokio::test]
async fn one_bad_address_does_not_lose_the_rest_of_the_batch() {
    let data = corpus::load();
    let case = data.batch_case("partial-failure-does-not-fail-the-batch");
    let stub = Stub::start(Stub::ok_routes(&["1.1.1.1"])).await;
    let client = stub.client().retries(0).build().expect("build");

    let got = client.lookup_batch(&case.input, BatchOptions::new()).await;

    assert_eq!(got.keys().cloned().collect::<Vec<_>>(), case.expect.keys);
    for ip in &case.expect.error_keys {
        assert!(got[ip].is_err(), "{ip} should carry its own error");
    }
    let good = got["1.1.1.1"].as_ref().expect("the good address should still have answered");
    assert!(!good.is_vpn);
}

#[tokio::test]
async fn a_cache_hit_issues_no_second_request() {
    let data = corpus::load();
    let case = data.batch_case("cache-hit-issues-no-second-request");
    let stub = Stub::start(Stub::ok_routes(&["1.1.1.1"])).await;
    let client = stub.client().build().expect("build");

    for _ in 0..case.repeat.unwrap_or(1) {
        client.lookup_batch(&case.input, BatchOptions::new()).await;
    }
    assert_eq!(stub.count(), case.expect.http_requests.expect("httpRequests"));
}

#[tokio::test]
async fn two_clients_never_share_a_cached_answer() {
    let stub = Stub::start(Stub::ok_routes(&["1.1.1.1"])).await;
    let a = stub.client().api_key("key-a").build().expect("build");
    let b = stub.client().api_key("key-b").build().expect("build");

    a.lookup("1.1.1.1").await.expect("lookup");
    b.lookup("1.1.1.1").await.expect("lookup");

    // Two keys can be on different plans and so entitled to different fields; a
    // shared cache would serve one of them the other's shape.
    assert_eq!(stub.count(), 2);
}

#[tokio::test]
async fn caching_can_be_turned_off() {
    let stub = Stub::start(Stub::ok_routes(&["1.1.1.1"])).await;
    let client = stub.client().no_cache().build().expect("build");

    client.lookup("1.1.1.1").await.expect("lookup");
    client.lookup("1.1.1.1").await.expect("lookup");

    assert_eq!(stub.count(), 2);
}

/// Every generated range has to be reachable through the predicate, which is the
/// only public surface the table has. The exact table-versus-corpus comparison
/// is a unit test in src/bogon.rs, where the `pub(crate)` table is visible.
#[test]
fn every_generated_range_is_reachable_through_the_predicate() {
    let data: Corpus = corpus::load();
    for cidr in data.bogons.v4.iter().chain(data.bogons.v6.iter()) {
        let host = cidr.split('/').next().expect("a cidr has a network part");
        assert!(is_bogon(host), "{cidr}: the network address should be a bogon");
    }
}

/// Serializing the wire answer is what pins the names the API actually serves:
/// an absent option is missing from the JSON, a present one is there and false.
fn wire(result: &Lookup) -> Value {
    serde_json::to_value(&result.answer).expect("serializing the answer")
}

fn assert_flag(wire: &Value, name: &str, want: bool) {
    let got = wire
        .get(name)
        .unwrap_or_else(|| panic!("{name} must be present and {want}, but is absent"));
    assert_eq!(got, &json!(want), "{name}");
}

fn assert_absent(wire: &Value, name: &str) {
    assert!(wire.get(name).is_none(), "{name} must be ABSENT, not {:?}", wire.get(name));
}

fn assert_empty_object(wire: &Value, name: &str) {
    let got =
        wire.get(name).unwrap_or_else(|| panic!("{name} must be present and empty, but is absent"));
    assert_eq!(got, &json!({}), "{name} must be present and EMPTY");
}

fn assert_object(wire: &Value, name: &str, want: Option<&Value>) {
    let Some(want) = want else {
        return;
    };
    let got = wire.get(name).unwrap_or_else(|| panic!("{name} is absent"));
    assert_eq!(got, want, "{name}");
}
