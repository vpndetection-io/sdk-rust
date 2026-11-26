// `allow_bots`: a crawler's User-Agent sent with its lookup, at most four an
// address, and a verified crawler never refused. Every peer is a PUBLIC address,
// since a bogon is answered locally and would pass every assertion here
// vacuously.

mod support;

use std::sync::{Arc, Mutex};

use serde_json::json;
use support::{Call, Route, Stub, corpus};
use vpndetection::middleware::{
    Condition, ConditionError, Core, Lookup, MAX_AGENTS_PER_ADDRESS, OnMissingField, Options,
    RequestView, Warn, names_crawler,
};

const PEER: &str = "66.249.66.1";
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

fn crawler(n: u32) -> String {
    format!("Mozilla/5.0 (compatible; Examplebot/{n}.0)")
}

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
    evaluate_from(core, PEER, user_agent).await
}

async fn evaluate_from(
    core: &Core,
    peer: &str,
    user_agent: Option<&str>,
) -> Result<Lookup, ConditionError> {
    let header = |name: &str| match name.eq_ignore_ascii_case("user-agent") {
        true => user_agent.map(str::to_owned),
        false => None,
    };
    let framework_ip = || Some(peer.to_owned());
    core.evaluate(&RequestView { header: &header, framework_ip: &framework_ip }).await
}

/// A bot's address as the API answers it: `user_agent` says `verified` for an
/// agent that arrived and is absent for a lookup without one, as the real answer
/// is, and `bot` is the operator's own record where given. The stub answers a
/// path's sequence in order, so `with_agent` lists whether each request is
/// expected to carry an agent, and a request the test did not count fails.
fn bot_answers(peer: &str, bot: Option<serde_json::Value>, with_agent: &[bool]) -> Vec<Route> {
    with_agent
        .iter()
        .map(|sent| {
            let mut body = json!({ "ip": peer, "is_vpn": false, "is_bot": true });
            if let Some(bot) = &bot {
                body["bot"] = bot.clone();
            }
            if *sent {
                body["user_agent"] =
                    json!({ "agent": "Examplebot", "kind": "bot", "verdict": "verified" });
            }
            Route::ok(body.to_string())
        })
        .collect()
}

/// A core over the stub, refusing a bot, as an app refusing automation would.
fn bot_core(stub: &Stub) -> Core {
    let client = stub.client().api_key("key").no_cache().retries(0).build().expect("build");
    let refuse_bots = vec![Condition::new().with("is_bot", true)];
    Core::new(Options::new().client(client).allow_bots(true).block_condition(refuse_bots))
        .expect("core")
}

/// What each lookup carried as its `user_agent`, in order, `None` for a bare one.
fn agents_in_order(stub: &Stub) -> Vec<Option<String>> {
    stub.requests().iter().map(|call| agents_sent(call).into_iter().next()).collect()
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

#[tokio::test]
async fn only_an_agent_naming_a_crawler_is_sent_as_the_corpus_says() {
    let agents = corpus::load().crawler_agents;
    assert!(!agents.crawlers.is_empty() && !agents.others.is_empty());
    for agent in &agents.crawlers {
        assert!(names_crawler(agent), "{agent}");
    }
    for agent in &agents.others {
        assert!(!names_crawler(agent), "{agent}");
    }
    for term in &agents.terms {
        assert!(names_crawler(&format!("x {} y", term.to_uppercase())), "{term}");
    }
    // Only A-Z fold: the Kelvin sign lowercases to k in Unicode, and is no k here.
    assert!(names_crawler("Mozilla/5.0 (compatible; Keenable-User)"));
    assert!(!names_crawler("Mozilla/5.0 (compatible; \u{212A}eenable-User)"));

    let stub = Stub::start([]).await;
    stub.sequence(format!("/{PEER}"), bot_answers(PEER, None, &[false]));
    let found = evaluate(&bot_core(&stub), Some(CHROME)).await.expect("evaluated");
    assert_eq!(agents_in_order(&stub), [None], "a browser's agent stays off the lookup");
    assert!(found.blocked);
}

#[tokio::test]
async fn one_address_is_looked_up_with_at_most_four_crawler_agents_and_none_passes_past_them() {
    assert_eq!(MAX_AGENTS_PER_ADDRESS, 4);
    let other = "66.249.66.2";
    let stub = Stub::start([]).await;
    stub.sequence(
        format!("/{PEER}"),
        bot_answers(PEER, None, &[true, true, true, true, false, true]),
    );
    stub.sequence(format!("/{other}"), bot_answers(other, None, &[true]));
    let core = bot_core(&stub);

    for n in 1..=4 {
        let found = evaluate(&core, Some(&crawler(n))).await.expect("evaluated");
        assert!(!found.blocked, "agent {n}");
    }
    let past = evaluate(&core, Some(&crawler(5))).await.expect("evaluated");
    assert!(past.blocked, "an agent past the bound was let through as verified");
    assert!(past.result.expect("answered").user_agent.is_none());
    let known = evaluate(&core, Some(&crawler(1))).await.expect("evaluated");
    assert!(!known.blocked, "a known agent is still sent");
    let sent: Vec<Option<String>> =
        [Some(1), Some(2), Some(3), Some(4), None, Some(1)].map(|n| n.map(crawler)).into();
    assert_eq!(agents_in_order(&stub), sent);

    let elsewhere = evaluate_from(&core, other, Some(&crawler(5))).await.expect("evaluated");
    assert!(!elsewhere.blocked, "each address has its own bound");
    assert_eq!(agents_in_order(&stub).last(), Some(&Some(crawler(5))));
}

#[tokio::test]
async fn past_the_bound_an_address_its_operator_vouches_for_still_passes() {
    let stub = Stub::start([]).await;
    let bot = json!({ "provider": "example", "verified": true });
    stub.sequence(
        format!("/{PEER}"),
        bot_answers(PEER, Some(bot.clone()), &[true, true, true, true, false, false]),
    );
    let core = bot_core(&stub);

    for n in 1..=5 {
        let found = evaluate(&core, Some(&crawler(n))).await.expect("evaluated");
        assert!(!found.blocked, "agent {n}");
    }
    assert_eq!(agents_in_order(&stub).last(), Some(&None));
    let browser = evaluate(&core, Some(CHROME)).await.expect("evaluated");
    assert!(browser.blocked, "a browser on that address is judged as the condition says");
}

/// A core refusing a forged crawler, as an app that only distrusts a spoofed
/// agent would, over the stub's bot address.
fn forged_core(stub: &Stub, options: Options) -> Core {
    let client = stub.client().api_key("key").no_cache().retries(0).build().expect("build");
    let forged =
        vec![Condition::new().with("user_agent", Condition::new().with("verdict", "spoofed"))];
    Core::new(options.client(client).block_condition(forged)).expect("core")
}

/// The bot's answers in order: `user_agent` says `spoofed` for a request that
/// carried an agent and is absent for one that carried none.
fn spoofed_answers(with_agent: &[bool]) -> Vec<Route> {
    with_agent
        .iter()
        .map(|sent| {
            let mut body = json!({ "ip": PEER, "is_vpn": false, "is_bot": true });
            if *sent {
                body["user_agent"] =
                    json!({ "agent": "Examplebot", "kind": "bot", "verdict": "spoofed" });
            }
            Route::ok(body.to_string())
        })
        .collect()
}

#[tokio::test]
async fn a_condition_on_the_verdict_is_no_plan_gap_for_a_request_that_sent_no_agent() {
    for header in [Some(CHROME), None] {
        let stub = Stub::start([]).await;
        stub.sequence(format!("/{PEER}"), spoofed_answers(&[false]));
        let (seen, warn) = warnings();
        let options =
            Options::new().allow_bots(true).on_missing_field(OnMissingField::Fail).on_warn(warn);
        let found = evaluate(&forged_core(&stub, options), header).await.expect("evaluated");
        assert!(!found.blocked, "{header:?}");
        assert_eq!(agents_in_order(&stub), [None], "{header:?}");
        assert!(seen.lock().unwrap().is_empty(), "{header:?}: warned with no agent sent");
    }

    let stub = Stub::start([]).await;
    stub.sequence(format!("/{PEER}"), spoofed_answers(&[true, true, true, true, false]));
    let options = Options::new().allow_bots(true).on_missing_field(OnMissingField::Fail);
    let core = forged_core(&stub, options);
    for n in 1..=4 {
        let found = evaluate(&core, Some(&crawler(n))).await.expect("evaluated");
        assert!(found.blocked, "agent {n}: a spoofed crawler");
    }
    let past = evaluate(&core, Some(&crawler(5))).await.expect("past the bound, no gap either");
    assert!(!past.blocked, "past the bound there is no verdict to match");
    assert_eq!(agents_in_order(&stub).last(), Some(&None));

    // Off, no agent is ever sent, so the condition can never match, and says so.
    let off = Stub::start([answer(None)]).await;
    let (seen, warn) = warnings();
    let core = forged_core(&off, Options::new().on_warn(warn));
    for _ in 0..2 {
        let found = evaluate(&core, Some(GOOGLEBOT)).await.expect("evaluated");
        assert!(!found.blocked);
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].contains("user_agent"), "{}", seen[0]);
}
