// The per-call user agent: what reaches the origin, and what the cache and the
// in-flight sharing key on once an answer depends on it.

mod support;

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{Value, json};
use support::{Call, Route, Stub};
use vpndetection::{BatchOptions, ErrorKind, LookupOptions, Verdict};

const GOOGLEBOT: &str =
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) a&b=c#d%e?f/g;h";

/// The `user_agent` query parameters a request carried, decoded.
fn agents_sent(call: &Call) -> Vec<String> {
    let target = call.header("x-stub-target").expect("target");
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
    serde_urlencoded::from_str::<Vec<(String, String)>>(query)
        .expect("a query string")
        .into_iter()
        .filter(|(name, _)| name == "user_agent")
        .map(|(_, value)| value)
        .collect()
}

fn verdict(ip: &str, verdict: &str) -> (String, Route) {
    let body = json!({
        "ip": ip,
        "is_vpn": false,
        "user_agent": { "agent": "Googlebot", "kind": "bot", "verdict": verdict },
    });
    (format!("/{ip}"), Route::ok(body.to_string()))
}

fn plain(ip: &str) -> (String, Route) {
    (format!("/{ip}"), Route::ok(json!({ "ip": ip, "is_vpn": false }).to_string()))
}

fn batch_bodies(stub: &Stub) -> Vec<Value> {
    stub.requests()
        .iter()
        .filter(|call| call.path == "/batch")
        .map(|call| serde_json::from_str(&call.body).expect("a JSON body"))
        .collect()
}

#[tokio::test]
async fn a_lookup_sends_its_user_agent_percent_encoded() {
    let stub = Stub::start([verdict("66.249.66.1", "verified")]).await;
    let client = stub.client().build().expect("build");
    let answer = client
        .lookup_with("66.249.66.1", LookupOptions::new().user_agent(GOOGLEBOT))
        .await
        .expect("lookup");

    let calls = stub.requests();
    assert_eq!(calls.len(), 1);
    assert_eq!(agents_sent(&calls[0]), [GOOGLEBOT]);
    let target = calls[0].header("x-stub-target").expect("target");
    assert!(target.contains("%2Bhttp"), "a + reached the origin raw: {target}");
    for raw in ["&b", "=c", "#d", "%e", "?f", ";h"] {
        assert!(!target.contains(raw), "{raw:?} reached the origin raw: {target}");
    }
    let ua = answer.user_agent.as_ref().expect("the verdict");
    assert_eq!((ua.agent.as_str(), ua.kind.as_str()), ("Googlebot", "bot"));
    assert_eq!(ua.verdict, Verdict::Verified);
    assert_eq!(ua.verdict.to_string(), "verified");
}

#[tokio::test]
async fn an_answer_without_a_verdict_has_none() {
    let stub = Stub::start([plain("9.9.9.9")]).await;
    let client = stub.client().build().expect("build");
    let answer = client.lookup("9.9.9.9").await.expect("lookup");
    assert!(answer.user_agent.is_none());
    assert_eq!(agents_sent(&stub.requests()[0]), Vec::<String>::new());
}

#[tokio::test]
async fn my_ip_sends_its_user_agent_and_stays_uncached() {
    let stub = Stub::start([("/myip".to_owned(), verdict("66.249.66.1", "spoofed").1)]).await;
    let client = stub.client().build().expect("build");
    for _ in 0..2 {
        let answer =
            client.my_ip_with(LookupOptions::new().user_agent(GOOGLEBOT)).await.expect("my_ip");
        assert_eq!(answer.user_agent.as_ref().expect("verdict").verdict, Verdict::Spoofed);
    }
    let calls = stub.requests();
    assert_eq!(calls.len(), 2, "my_ip is never cached");
    for call in &calls {
        assert_eq!(agents_sent(call), [GOOGLEBOT]);
    }
}

#[tokio::test]
async fn the_cache_keys_on_the_address_and_its_agent() {
    let stub = Stub::start([plain("8.8.8.8")]).await;
    let client = stub.client().build().expect("build");
    let with = |agent: &str| LookupOptions::new().user_agent(agent);
    client.lookup_with("8.8.8.8", with("agent-a")).await.expect("a");
    client.lookup_with("8.8.8.8", with("agent-b")).await.expect("b");
    client.lookup_with("8.8.8.8", with("agent-a")).await.expect("a again");
    client.lookup("8.8.8.8").await.expect("none");
    // An empty agent is none, so it shares the plain answer.
    client.lookup_with("8.8.8.8", with("")).await.expect("empty");
    client.lookup("8.8.8.8").await.expect("none again");

    let sent: Vec<Vec<String>> = stub.requests().iter().map(agents_sent).collect();
    assert_eq!(sent, [vec!["agent-a".to_owned()], vec!["agent-b".to_owned()], vec![]]);
}

#[tokio::test]
async fn concurrent_misses_for_one_pair_share_one_request() {
    let stub = Stub::start_with_delay([plain("8.8.8.8")], Duration::from_millis(300)).await;
    let client = stub.client().build().expect("build");
    let with = |agent: &str| LookupOptions::new().user_agent(agent);
    let (a, b, other, none) = tokio::join!(
        client.lookup_with("8.8.8.8", with("agent-a")),
        client.lookup_with("8.8.8.8", with("agent-a")),
        client.lookup_with("8.8.8.8", with("agent-b")),
        client.lookup("8.8.8.8"),
    );
    for answer in [a, b, other, none] {
        answer.expect("answered");
    }
    let mut sent: Vec<Vec<String>> = stub.requests().iter().map(agents_sent).collect();
    sent.sort();
    assert_eq!(sent, [vec![], vec!["agent-a".to_owned()], vec!["agent-b".to_owned()]]);
}

#[tokio::test]
async fn a_long_agent_is_sent_whole() {
    let long = format!("Mozilla/5.0 {}", "x".repeat(2000));
    let stub = Stub::start([plain("9.9.9.9")]).await;
    let client = stub.client().build().expect("build");
    client.lookup_with("9.9.9.9", LookupOptions::new().user_agent(&long)).await.expect("lookup");
    assert_eq!(agents_sent(&stub.requests()[0]), [long]);
}

#[tokio::test]
async fn a_bogon_stays_local_and_carries_no_verdict() {
    let stub = Stub::start([]).await;
    let client = stub.client().build().expect("build");
    for ip in ["10.0.0.1", "::ffff:192.168.1.1"] {
        let answer =
            client.lookup_with(ip, LookupOptions::new().user_agent(GOOGLEBOT)).await.expect(ip);
        assert!(answer.is_bogon, "{ip}");
        assert!(answer.user_agent.is_none(), "{ip}");
    }
    let batch = client
        .lookup_batch(["10.0.0.1"], BatchOptions::new().user_agents([("10.0.0.1", GOOGLEBOT)]))
        .await;
    assert!(batch["10.0.0.1"].as_ref().expect("bogon").user_agent.is_none());
    assert_eq!(stub.count(), 0);
}

#[tokio::test]
async fn my_entitlement_refuses_a_user_agent() {
    let stub = Stub::start([]).await;
    let client = stub.client().api_key("key").build().expect("build");
    let err = client
        .my_entitlement_with(LookupOptions::new().user_agent(GOOGLEBOT))
        .await
        .expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::BadRequest);
    assert_eq!(stub.count(), 0);
}

/// `user_agents` is keyed by each address exactly as `ips` sends it, and goes
/// only for the addresses that carry one.
#[tokio::test]
async fn a_batch_sends_user_agents_keyed_by_the_address_as_sent() {
    const LONG_V6: &str = "2001:4860:4801:0010:0000:0000:0000:0001";
    let stub = Stub::start([plain(LONG_V6), plain("8.8.8.8"), plain("1.1.1.1")]).await;
    let client = stub.client().api_key("key").build().expect("build");
    let agents = [(LONG_V6, GOOGLEBOT), ("::ffff:8.8.8.8", "curl/8.0"), ("1.1.1.1", "")];
    let answers = client
        .lookup_batch(
            [LONG_V6, "::ffff:8.8.8.8", "1.1.1.1"],
            BatchOptions::new().user_agents(agents),
        )
        .await;
    for (ip, answer) in &answers {
        answer.as_ref().unwrap_or_else(|err| panic!("{ip}: {err}"));
    }

    let bodies = batch_bodies(&stub);
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["ips"], json!([LONG_V6, "8.8.8.8", "1.1.1.1"]));
    assert_eq!(bodies[0]["user_agents"], json!({ LONG_V6: GOOGLEBOT, "8.8.8.8": "curl/8.0" }));
}

#[tokio::test]
async fn a_batch_with_no_agent_sends_no_user_agents() {
    let stub = Stub::start([plain("8.8.8.8"), plain("1.1.1.1")]).await;
    let client = stub.client().api_key("key").no_cache().build().expect("build");
    client.lookup_batch(["8.8.8.8", "1.1.1.1"], BatchOptions::new()).await;
    client
        .lookup_batch(["8.8.8.8", "1.1.1.1"], BatchOptions::new().user_agents([("1.1.1.1", "")]))
        .await;
    let bodies = batch_bodies(&stub);
    assert_eq!(bodies.len(), 2);
    for body in bodies {
        assert!(body.get("user_agents").is_none(), "sent {body}");
    }
}

#[tokio::test]
async fn user_agents_goes_only_with_a_chunk_whose_addresses_carry_one() {
    let ips: Vec<String> = (0..1001).map(|i| format!("9.9.{}.{}", i / 250, i % 250 + 1)).collect();
    let last = ips.last().expect("an address").clone();
    let stub = Stub::start([]).await;
    let client = stub.client().api_key("key").build().expect("build");
    client
        .lookup_batch(&ips, BatchOptions::new().concurrency(1).user_agents([(&*last, GOOGLEBOT)]))
        .await;
    let bodies = batch_bodies(&stub);
    assert_eq!(bodies.len(), 2);
    let (first, second) = (&bodies[0], &bodies[1]);
    assert!(first.get("user_agents").is_none(), "the first chunk carries none");
    assert_eq!(second["user_agents"], json!({ last: GOOGLEBOT }));
}

/// A request keys `user_agents` by address, so one address with two agents
/// takes two requests, each sending it once with its own.
#[tokio::test]
async fn one_address_with_two_agents_goes_in_two_requests() {
    let stub = Stub::start([plain("8.8.8.8"), plain("1.1.1.1")]).await;
    let client = stub.client().api_key("key").build().expect("build");
    let agents = [("8.8.8.8", "agent-a"), ("::ffff:8.8.8.8", "agent-b")];
    let answers = client
        .lookup_batch(
            ["8.8.8.8", "::ffff:8.8.8.8", "1.1.1.1"],
            BatchOptions::new().user_agents(agents),
        )
        .await;
    assert_eq!(answers.len(), 3);
    for (ip, answer) in &answers {
        answer.as_ref().unwrap_or_else(|err| panic!("{ip}: {err}"));
    }
    let mut sent: Vec<(Value, Value)> = batch_bodies(&stub)
        .into_iter()
        .map(|b| (b["ips"].clone(), b["user_agents"].clone()))
        .collect();
    sent.sort_by_key(|(ips, _)| ips.to_string());
    assert_eq!(
        sent,
        [
            (json!(["8.8.8.8", "1.1.1.1"]), json!({ "8.8.8.8": "agent-a" })),
            (json!(["8.8.8.8"]), json!({ "8.8.8.8": "agent-b" })),
        ]
    );
}

/// A batch entry's answer is cached on its pair, so a lookup for the same pair
/// is a hit and the address's plain lookup is not.
#[tokio::test]
async fn a_batch_caches_each_answer_on_its_pair() {
    let stub = Stub::start([plain("8.8.8.8"), plain("1.1.1.1")]).await;
    let client = stub.client().api_key("key").build().expect("build");
    let agents: HashMap<String, String> = [("8.8.8.8".to_owned(), "agent-a".to_owned())].into();
    client.lookup_batch(["8.8.8.8", "1.1.1.1"], BatchOptions::new().user_agents(agents)).await;
    assert_eq!(stub.count(), 1);
    client.lookup_with("8.8.8.8", LookupOptions::new().user_agent("agent-a")).await.expect("hit");
    client.lookup("1.1.1.1").await.expect("hit");
    assert_eq!(stub.count(), 1, "both pairs were cached by the batch");
    client.lookup("8.8.8.8").await.expect("the plain answer");
    client.lookup_with("8.8.8.8", LookupOptions::new().user_agent("agent-b")).await.expect("b");
    assert_eq!(stub.count(), 3);
}
