// `allow_bots`: the request's own User-Agent sent with its lookup, and a
// verified crawler never refused. Every peer is a PUBLIC address, since a bogon
// is answered locally and would pass every assertion here vacuously.

mod support;

use std::sync::{Arc, Mutex};

use serde_json::json;
use support::{Call, Route, Stub};
use vpndetection::middleware::{
    Condition, ConditionError, Core, Lookup, OnMissingField, Options, RequestView, Warn,
};

const PEER: &str = "66.249.66.1";
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

fn answer(verdict: Option<&str>) -> (String, Route) {
    let mut body = json!({ "ip": PEER, "is_vpn": false, "is_hosting": true });
    if let Some(verdict) = verdict {
        body["user_agent"] = json!({ "agent": "Googlebot", "kind": "bot", "verdict": verdict });
    }
    (format!("/{PEER}"), Route::ok(body.to_string()))
}

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

fn warnings() -> (Arc<Mutex<Vec<String>>>, Warn) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    (seen, Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_owned())))
}

/// A core over the stub, refusing a hosting address, as an app refusing
/// datacenter traffic would.
fn core(stub: &Stub, options: Options) -> Core {
    let client = stub.client().api_key("key").no_cache().retries(0).build().expect("build");
    let refuse_hosting = vec![Condition::new().with("is_hosting", true)];
    Core::new(options.client(client).block_condition(refuse_hosting)).expect("core")
}

async fn evaluate(core: &Core, user_agent: Option<&str>) -> Result<Lookup, ConditionError> {
    let header = |name: &str| match name.eq_ignore_ascii_case("user-agent") {
        true => user_agent.map(str::to_owned),
        false => None,
    };
    let framework_ip = || Some(PEER.to_owned());
    core.evaluate(&RequestView { header: &header, framework_ip: &framework_ip }).await
}

#[tokio::test]
async fn a_verified_crawler_passes_a_condition_it_otherwise_meets() {
    let stub = Stub::start([answer(Some("verified"))]).await;
    let found = evaluate(&core(&stub, Options::new().allow_bots(true)), Some(GOOGLEBOT))
        .await
        .expect("evaluated");
    assert!(!found.blocked, "a verified crawler was refused");
    let result = found.result.expect("the answer is still attached");
    assert_eq!(result.is_hosting, Some(true));
    assert_eq!(
        result.user_agent.as_ref().expect("verdict").verdict,
        vpndetection::Verdict::Verified
    );
    let calls = stub.requests();
    assert_eq!(calls.len(), 1);
    assert_eq!(agents_sent(&calls[0]), [GOOGLEBOT], "the request's own agent reached the origin");
}

#[tokio::test]
async fn a_spoofed_or_not_bot_verdict_is_refused() {
    for verdict in ["spoofed", "not_bot", "unverifiable"] {
        let stub = Stub::start([answer(Some(verdict))]).await;
        let found = evaluate(&core(&stub, Options::new().allow_bots(true)), Some(GOOGLEBOT))
            .await
            .expect("evaluated");
        assert!(found.blocked, "{verdict}: let through");
        assert_eq!(agents_sent(&stub.requests()[0]), [GOOGLEBOT], "{verdict}");
    }
}

#[tokio::test]
async fn off_sends_no_agent_and_lets_no_crawler_through() {
    let stub = Stub::start([answer(Some("verified"))]).await;
    let found = evaluate(&core(&stub, Options::new()), Some(GOOGLEBOT)).await.expect("evaluated");
    assert!(found.blocked, "a verdict the client never asked for let a request through");
    assert_eq!(agents_sent(&stub.requests()[0]), Vec::<String>::new());
}

#[tokio::test]
async fn an_absent_or_empty_header_sends_none() {
    for header in [None, Some(""), Some("   ")] {
        let stub = Stub::start([answer(None)]).await;
        let (seen, warn) = warnings();
        let core = core(&stub, Options::new().allow_bots(true).on_warn(warn));
        let found = evaluate(&core, header).await.expect("evaluated");
        assert!(found.blocked, "{header:?}");
        assert_eq!(agents_sent(&stub.requests()[0]), Vec::<String>::new(), "{header:?}");
        assert!(seen.lock().unwrap().is_empty(), "{header:?}: warned with no agent sent");
    }
}

/// A keyless client or a free key past its trial is never answered a verdict,
/// so nothing is let through, and `on_missing_field` says so once.
#[tokio::test]
async fn a_served_answer_without_a_verdict_is_reported_once() {
    let stub = Stub::start([answer(None)]).await;
    let (seen, warn) = warnings();
    let core = core(&stub, Options::new().allow_bots(true).on_warn(warn));
    for _ in 0..3 {
        let found = evaluate(&core, Some(GOOGLEBOT)).await.expect("evaluated");
        assert!(found.blocked);
    }
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].contains("user_agent"), "{}", seen[0]);
    }

    let failing = Stub::start([answer(None)]).await;
    let core = self::core(
        &failing,
        Options::new().allow_bots(true).on_missing_field(OnMissingField::Fail),
    );
    assert!(evaluate(&core, Some(GOOGLEBOT)).await.is_err(), "Fail let the request through");

    let ignoring = Stub::start([answer(None)]).await;
    let (quiet, warn) = warnings();
    let options =
        Options::new().allow_bots(true).on_missing_field(OnMissingField::Ignore).on_warn(warn);
    evaluate(&self::core(&ignoring, options), Some(GOOGLEBOT)).await.expect("evaluated");
    assert!(quiet.lock().unwrap().is_empty());
}
