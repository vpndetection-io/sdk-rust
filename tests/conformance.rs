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
use vpndetection::{BatchOptions, BotDetail, Lookup, is_bogon};

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

// A listener on :: sees an IPv4 visitor as ::ffff:a.b.c.d, which read whole is
// inside ::ffff:0:0/96: through 5.3.0 each was answered as a bogon with no
// request made.
#[tokio::test]
async fn an_ipv4_mapped_address_is_the_ipv4_address_it_carries() {
    for case in corpus::load().ipv4_mapped {
        assert_eq!(is_bogon(&case.ip), case.expect, "is_bogon({:?}) ({})", case.ip, case.why);
        let body = json!({"ip": case.carries, "is_vpn": true}).to_string();
        let routes = || [(format!("/{}", case.carries), Route::json(200, body.clone()))];
        let want_sent: Vec<String> =
            if case.expect { Vec::new() } else { vec![case.carries.clone()] };

        let stub = Stub::start(routes()).await;
        let client = stub.client().build().expect("build");
        let result = client.lookup(&case.ip).await.unwrap_or_else(|e| panic!("{}: {e}", case.ip));
        assert_eq!(result.is_bogon, case.expect, "{}", case.ip);
        assert_eq!(result.ip, case.carries, "{}", case.ip);
        client.lookup(&case.carries).await.expect("a lookup of the carried address");
        let paths: Vec<String> = stub.requests().into_iter().map(|call| call.path).collect();
        let want_paths: Vec<String> = want_sent.iter().map(|ip| format!("/{ip}")).collect();
        assert_eq!(paths, want_paths, "{}: one request, cached as {}", case.ip, case.carries);

        let batch_stub = Stub::start(routes()).await;
        let uncached = batch_stub.client().no_cache().build().expect("build");
        let mut asked = vec![case.ip.clone()];
        if case.carries != case.ip {
            asked.push(case.carries.clone());
        }
        let got = uncached.lookup_batch(&asked, BatchOptions::new()).await;
        assert_eq!(got.keys().cloned().collect::<Vec<_>>(), asked, "{}", case.ip);
        let answer = got[&case.ip].as_ref().unwrap_or_else(|e| panic!("{}: {e}", case.ip));
        assert_eq!(answer.ip, case.carries, "{}", case.ip);
        let sent: Vec<String> = batch_stub
            .requests()
            .into_iter()
            .filter_map(|call| serde_json::from_str::<Value>(&call.body).ok())
            .flat_map(|body| body["ips"].as_array().cloned().unwrap_or_default())
            .filter_map(|ip| ip.as_str().map(str::to_owned))
            .collect();
        assert_eq!(sent, want_sent, "{}", case.ip);
    }
}

#[tokio::test]
async fn a_bogon_is_answered_locally_in_the_widest_shape() {
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
    let bogon = &data.bogon_response;
    for (name, want) in [
        ("location", &bogon.location),
        ("asn", &bogon.asn),
        ("web", &bogon.web),
        ("hostname", &bogon.hostname),
        ("company", &bogon.company),
        ("abuse", &bogon.abuse),
    ] {
        assert_member(&wire, name, Some(want));
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
        let mut wire = wire(&result);
        // The AS's `type` is held a `String` until the next major: an answer
        // without one reads empty, so the comparison below sees it as served.
        if case.body.get("asn").is_some_and(|asn| asn.get("type").is_none()) {
            let held = wire["asn"].as_object_mut().expect("the answer's asn");
            assert_eq!(held.remove("type"), Some(json!("")), "{}: asn.type reads empty", case.name);
        }

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
        let expect = &case.expect;
        for (name, want) in [
            ("vpn", &expect.vpn),
            ("hosting", &expect.hosting),
            ("dcproxy", &expect.dcproxy),
            ("pubproxy", &expect.pubproxy),
            ("bot", &expect.bot),
            ("location", &expect.location),
            ("asn", &expect.asn),
            ("carrier", &expect.carrier),
            ("satellite", &expect.satellite),
            ("ssh", &expect.ssh),
            ("smtp", &expect.smtp),
            ("web", &expect.web),
            ("dns_resolver", &expect.dns_resolver),
            ("bittorrent", &expect.bittorrent),
            ("company", &expect.company),
            ("hostname", &expect.hostname),
            ("abuse", &expect.abuse),
        ] {
            assert_member(&wire, name, want.as_ref());
        }
        if let Some(want) = &expect.bot {
            assert_bot(&case.name, result.bot.as_deref(), want);
        }
    }
}

/// A served `bot` read key by key off the typed detail rather than off a
/// serialization, so a member that decodes from the wrong wire name, or a list
/// read out of order, is caught where it lives.
fn assert_bot(case: &str, got: Option<&BotDetail>, want: &Value) {
    let bot = got.unwrap_or_else(|| panic!("{case}: bot is absent"));
    let want = want.as_object().unwrap_or_else(|| panic!("{case}: expect.bot is no object"));
    for (key, want) in want {
        let got = match key.as_str() {
            "provider" => json!(bot.provider),
            "provider_name" => json!(bot.provider_name),
            "agents" => json!(bot.agents),
            "categories" => json!(bot.categories),
            "verified" => json!(bot.verified),
            "identity" => json!(bot.identity),
            "verified_by" => json!(bot.verified_by),
            "confidence" => json!(bot.confidence),
            "first_seen" => json!(bot.first_seen),
            "last_seen" => json!(bot.last_seen),
            other => panic!("{case}: BotDetail has no member {other}"),
        };
        assert_eq!(&got, want, "{case}: bot.{key}");
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
        let err = got[ip].as_ref().expect_err(&format!("{ip} should carry its own error"));
        assert_eq!(err.kind().as_str(), case.expect.error_kinds[ip], "{ip}");
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

/// Both the boundary and the absence of any cap: a batch of any size is chunks
/// of 1000, never a refusal.
#[tokio::test]
async fn a_large_batch_is_sent_in_chunks_of_a_thousand() {
    let data = corpus::load();
    for name in ["chunks-of-one-thousand", "uncapped-input-is-chunked"] {
        let case = data.batch_case(name);
        let addrs: Vec<&str> = case.input.iter().map(String::as_str).collect();
        let stub = Stub::start(Stub::ok_routes(&addrs)).await;
        let client = stub.client().no_cache().build().expect("build");

        let got = client.lookup_batch(&case.input, BatchOptions::new()).await;

        assert_eq!(got.len(), case.expect.key_count.expect("keyCount"), "{name}");
        assert_eq!(stub.count(), case.expect.http_requests.expect("httpRequests"), "{name}");
        for ip in &case.input {
            let answer = got[ip].as_ref().unwrap_or_else(|e| panic!("{name}: {ip}: {e}"));
            assert_eq!(&answer.ip, ip, "{name}: {ip} should be answered for itself");
        }
    }
}

/// A per-entry failure carries no headers, so its 429 can only be a spent
/// allowance, and a 500 is the server's; neither is retried per entry, because
/// retries belong to the call and the call succeeded.
#[tokio::test]
async fn an_entry_error_is_classified_by_its_status() {
    let data = corpus::load();
    let case = data.batch_case("an-entry-error-is-classified-by-its-status");
    let mut routes = Stub::ok_routes(&["1.1.1.1"]);
    routes.push((
        "/8.8.8.8".to_owned(),
        Route::json(429, r#"{"error":"overage cap reached; raise or remove it in Billing"}"#),
    ));
    routes.push(("/9.9.9.9".to_owned(), Route::json(500, r#"{"error":"lookup failed"}"#)));
    let stub = Stub::start(routes).await;
    let client = stub.client().retries(3).build().expect("build");

    let got = client.lookup_batch(&case.input, BatchOptions::new()).await;

    assert_eq!(got.keys().cloned().collect::<Vec<_>>(), case.expect.keys);
    for (ip, kind) in &case.expect.error_kinds {
        let err = got[ip].as_ref().expect_err(&format!("{ip} should carry its error"));
        assert_eq!(err.kind().as_str(), kind, "{ip}");
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

/// A closed vocabulary in an ANSWER is the API's to extend, so every case's
/// value comes back as served: the plan's name and a tier no published list
/// holds, a database's standing, license type and format, and a download's
/// outcome. Each answer is read through its typed result, rendered back to its
/// wire names, and walked along the case's path.
#[tokio::test]
async fn every_vocabulary_value_comes_back_as_served() {
    let data: Corpus = corpus::load();
    let mut calls = std::collections::BTreeSet::new();
    for case in &data.vocabulary.cases {
        calls.insert(case.call.as_str());
        let path = match case.call.as_str() {
            "myEntitlement" => "/api/v1/entitlement",
            "listDatabases" => "/api/v1/database/list",
            "listDownloads" => "/api/v1/database/downloads",
            other => panic!("{}: no call for {other}", case.name),
        };
        let route = Route::ok(case.answer.to_string());
        let stub = Stub::start([(path.to_string(), route)]).await;
        let client = stub.client().retries(0).build().expect("build");
        let read = match case.call.as_str() {
            "myEntitlement" => client.my_entitlement().await.map(|ent| json!(ent)),
            "listDatabases" => {
                client.database().list().await.map(|list| json!({"databases": list}))
            }
            _ => client.database().downloads(None).await.map(|list| json!({"downloads": list})),
        }
        .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        for (path, want) in &case.expect {
            let got = path.split('.').fold(&read, |value, step| match step.parse::<usize>() {
                Ok(index) => &value[index],
                Err(_) => &value[step],
            });
            assert_eq!(got, want, "{}: {path}", case.name);
        }
    }
    assert_eq!(
        calls.into_iter().collect::<Vec<_>>(),
        ["listDatabases", "listDownloads", "myEntitlement"],
        "the corpus's vocabulary cases moved to a call this suite does not make"
    );
}

/// An AS number is 32 bits unsigned, so the private-use range from 4200000000 is
/// past an `i32`.
#[tokio::test]
async fn an_as_number_past_an_i32_reads() {
    let body = r#"{"ip":"45.83.91.1","is_vpn":false,"asn":{"asn":4200000001,"name":"n","domain":"d","type":"isp","prefix":"45.83.91.0/24","country":"NL","rpki_status":"valid"}}"#;
    let stub = Stub::start([("/45.83.91.1".to_string(), Route::ok(body))]).await;
    let client = stub.client().build().expect("build");

    let answer = client.lookup("45.83.91.1").await.expect("lookup");

    assert_eq!(answer.asn.as_deref().expect("the answer has an asn").asn, 4_200_000_001);
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

/// A member the case names, object, list or string, equal to the corpus's value.
fn assert_member(wire: &Value, name: &str, want: Option<&Value>) {
    let Some(want) = want else {
        return;
    };
    let got = wire.get(name).unwrap_or_else(|| panic!("{name} is absent"));
    assert_eq!(numbers_as_floats(got), numbers_as_floats(want), "{name}");
}

/// A latitude the corpus writes as `0` decodes into an `f64` and renders back
/// as `0.0`, which `serde_json` holds unequal, so every number is compared by
/// its value.
fn numbers_as_floats(value: &Value) -> Value {
    match value {
        Value::Number(n) => json!(n.as_f64().expect("a JSON number")),
        Value::Array(items) => Value::Array(items.iter().map(numbers_as_floats).collect()),
        Value::Object(fields) => {
            Value::Object(fields.iter().map(|(k, v)| (k.clone(), numbers_as_floats(v))).collect())
        }
        other => other.clone(),
    }
}
