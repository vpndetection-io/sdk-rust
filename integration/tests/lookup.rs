// The published crate looking addresses up against the staging API.
//
// Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each
// one serving a superset of the tier below it, so a pricing change stays a
// pricing change instead of arriving as a red SDK build. What a served answer
// must satisfy on every tier: ip and is_vpn always; a present flag is a real
// boolean; a field a higher tier serves is ABSENT on a lower one rather than
// false; a populated detail object carries its documented keys; an empty one
// means its flag is false.

use std::collections::BTreeSet;

use vpndetection::{BatchOptions, ErrorKind};
use vpndetection_integration::{
    MEMBERS, PROBE, RUNGS, STAGING, answer_for, assert_served_by_tier, client_fields, client_for,
    ladder_skip, observable, skip_unless,
};

#[tokio::test]
async fn a_lookup_without_a_key_answers_ip_and_is_vpn_at_the_least() {
    let answer = answer_for(&RUNGS[0]).await;

    assert_eq!(answer.wire.get("ip").and_then(|v| v.as_str()), Some(PROBE));
    assert!(answer.wire.get("is_vpn").is_some_and(|v| v.is_boolean()), "is_vpn is not a boolean");
    assert_served_by_tier(answer);
    println!("testing against {STAGING}");
}

#[tokio::test]
async fn a_key_reaches_the_wire_and_its_answer_keeps_its_shape() {
    for rung in RUNGS.iter().filter(|rung| rung.secret.is_some()) {
        // Per tier rather than for the whole test: a missing starter key must
        // not take the scale and max tiers down with it.
        if let Some(reason) = rung.skip_reason() {
            println!("SKIPPED: {reason}");
            continue;
        }
        // answer_for asserts the key reached the wire before handing anything
        // back, so a tier that silently ran unauthenticated fails here rather
        // than passing every comparison below vacuously.
        assert_served_by_tier(answer_for(rung).await);
    }
}

#[tokio::test]
async fn each_tier_serves_a_superset_of_the_tier_below() {
    skip_unless!(ladder_skip());

    let mut below: Option<&BTreeSet<String>> = None;
    let mut sets = Vec::new();
    for rung in observable() {
        let answer = answer_for(rung).await;
        // trial_expired marks a trial key's answers, and no other: it is not a
        // field a tier serves.
        let fields: BTreeSet<String> =
            answer.wire.keys().filter(|field| *field != "trial_expired").cloned().collect();
        println!("{}: {} fields", answer.tier, fields.len());
        sets.push((answer.tier, answer.widens, fields));
    }

    for (tier, widens, fields) in &sets {
        if let Some(lower) = below {
            for field in lower {
                assert!(
                    fields.contains(field),
                    "{tier} drops {field}, which the tier below serves"
                );
            }
            // Without this a run in which every key resolved to the same plan
            // would pass: identical sets satisfy containment in both directions.
            if *widens {
                assert!(
                    fields.len() > lower.len(),
                    "{tier} answers {} field(s) and the tier below answers {}, so it is no wider",
                    fields.len(),
                    lower.len()
                );
            }
        }
        if *tier != "trial" {
            below = Some(fields);
        }
    }
}

#[tokio::test]
async fn a_trial_keys_answer_is_a_paid_one_or_unlimiteds_and_says_which() {
    skip_unless!(RUNGS[1].skip_reason());
    let wire = &answer_for(&RUNGS[1]).await.wire;

    let expired = wire
        .get("trial_expired")
        .and_then(|value| value.as_bool())
        .expect("a trial key answers trial_expired");
    // The organization's first 100 lookups of the UTC day are answered in full,
    // and the rest as Unlimited's: which half a run sees depends on the day.
    assert_eq!(
        wire.contains_key("is_hosting"),
        !expired,
        "is_hosting is served exactly while the day lasts"
    );
}

#[tokio::test]
async fn a_trial_keys_batch_of_two_is_refused_as_a_bad_request_once() {
    skip_unless!(RUNGS[1].skip_reason());
    let (client, recorder) = client_for(&RUNGS[1]).await;

    let answers = client.lookup_batch([PROBE, "8.8.8.8"], BatchOptions::new()).await;

    for ip in [PROBE, "8.8.8.8"] {
        let refused = answers[ip].as_ref().expect_err("a trial key's batch of two must fail");
        assert_eq!(refused.kind(), ErrorKind::BadRequest);
        assert_eq!(refused.status(), Some(402));
        assert!(!refused.retryable());
    }
    let paths: Vec<String> = recorder.facts().iter().map(|fact| fact.path.clone()).collect();
    assert_eq!(paths, ["/batch"], "one request, never retried");
}

#[tokio::test]
async fn a_trial_keys_batch_of_one_is_answered() {
    skip_unless!(RUNGS[1].skip_reason());
    let (client, recorder) = client_for(&RUNGS[1]).await;

    let answers = client.lookup_batch([PROBE], BatchOptions::new()).await;

    assert!(
        answers[PROBE].is_ok(),
        "a trial key's batch of one failed: {:?}",
        answers[PROBE].as_ref().err()
    );
    // Read off the wire, since the crate this suite resolves may predate the member.
    let served = recorder.json_body("/batch").expect("the batch's answer was captured");
    assert!(
        served["results"][PROBE]["trial_expired"].is_boolean(),
        "the answer carries trial_expired"
    );
}

#[tokio::test]
async fn a_field_a_higher_tier_serves_is_absent_on_a_lower_one_never_false() {
    skip_unless!(ladder_skip());

    let mut answers = Vec::new();
    for rung in observable() {
        answers.push(answer_for(rung).await);
    }

    // The positive half: a field the wire carried must have reached the result,
    // which is what makes a served `false` survive. A field the client does not
    // model at all is the API moving ahead of the pinned spec, not a drop, and
    // is reported as such.
    for answer in &answers {
        let held = client_fields(&answer.result);
        // trial_expired has its own test, read off the wire, since the crate this
        // suite resolves may predate the member.
        for field in answer.wire.keys().filter(|field| *field != "trial_expired") {
            assert!(
                held.contains(field),
                "{}: the wire served {field} and the client dropped it (or the pinned spec does \
                 not model it yet)",
                answer.tier
            );
        }
    }

    for (i, lower) in answers.iter().enumerate() {
        let higher: BTreeSet<&String> =
            answers[i + 1..].iter().flat_map(|answer| answer.wire.keys()).collect();
        let held = client_fields(&lower.result);
        for field in higher {
            if lower.wire.contains_key(field) {
                continue;
            }
            assert!(
                !held.contains(field),
                "{field} is not in the {} plan, so the result must hold nothing for it",
                lower.tier
            );
        }
    }
}

#[tokio::test]
async fn a_bogon_is_answered_without_touching_the_network() {
    let (client, recorder) = client_for(&RUNGS[0]).await;

    let result = client.lookup("10.0.0.1").await.expect("a private address");

    assert!(result.is_bogon, "a private address must be answered locally");
    assert!(!result.is_vpn, "a private address cannot be VPN infrastructure");
    assert!(vpndetection::is_bogon("10.0.0.1"), "the standalone function must agree");
    assert!(recorder.facts().is_empty(), "the bogon path reached the network");

    // Computed rather than served, so it carries every field whatever the plan.
    let wire = serde_json::to_value(&result.answer).expect("re-encoding the answer");
    for (name, _) in &MEMBERS {
        let flag = format!("is_{name}");
        assert_eq!(wire.get(&flag), Some(&serde_json::json!(false)), "{flag} on a bogon");
        let detail = wire.get(*name).unwrap_or_else(|| panic!("{name} must be present on a bogon"));
        let fields = detail.as_object().expect("a detail object");
        assert!(fields.is_empty(), "{name} must be present and EMPTY on a bogon: {detail}");
    }
}

#[tokio::test]
async fn a_batch_without_a_key_is_refused_once_and_its_bogon_still_answered() {
    let (client, recorder) = client_for(&RUNGS[0]).await;

    let answers = client.lookup_batch([PROBE, "10.0.0.1"], BatchOptions::new()).await;

    let bogon = answers["10.0.0.1"].as_ref().expect("10.0.0.1 was not answered locally");
    assert!(bogon.is_bogon);
    let refused = answers[PROBE].as_ref().expect_err("a batch without a key must fail");
    assert_eq!(refused.kind(), ErrorKind::Unauthorized);
    assert_eq!(refused.status(), Some(401));
    assert!(!refused.retryable());
    let paths: Vec<String> = recorder.facts().iter().map(|fact| fact.path.clone()).collect();
    assert_eq!(paths, ["/batch"], "one request, never retried");
}

#[tokio::test]
async fn a_batch_collapses_duplicates_and_keeps_bogons_off_the_wire() {
    // A batch needs a paid plan, and starter is the cheapest.
    skip_unless!(RUNGS[2].skip_reason());
    let (client, recorder) = client_for(&RUNGS[2]).await;

    let answers = client
        .lookup_batch([PROBE, "8.8.8.8", PROBE, "10.0.0.1", "8.8.8.8"], BatchOptions::new())
        .await;

    // Rust keeps the map insertion-ordered, so the exact order is assertable
    // here where Go could only assert the set.
    let keys: Vec<&str> = answers.keys().map(String::as_str).collect();
    assert_eq!(keys, [PROBE, "8.8.8.8", "10.0.0.1"], "duplicates collapse, first-seen order holds");

    // One route, POST /batch, and the addresses read off the bodies it carried
    // rather than a request count, so a retry against a wobbling staging cannot
    // read as a failure to deduplicate.
    let facts = recorder.facts();
    let routes: BTreeSet<(&str, &str)> =
        facts.iter().map(|fact| (fact.method.as_str(), fact.path.as_str())).collect();
    assert_eq!(
        routes,
        BTreeSet::from([("POST", "/batch")]),
        "a batch is sent to POST /batch alone"
    );
    for fact in &facts {
        assert!(fact.carried_key, "the paid key never reached the wire");
        let distinct: BTreeSet<&String> = fact.ips.iter().collect();
        assert_eq!(distinct.len(), fact.ips.len(), "a chunk repeated an address: {:?}", fact.ips);
    }
    let sent: BTreeSet<&str> =
        facts.iter().flat_map(|fact| fact.ips.iter().map(String::as_str)).collect();
    assert_eq!(
        sent,
        BTreeSet::from([PROBE, "8.8.8.8"]),
        "the batch sent the wrong set of addresses"
    );

    let bogon = answers["10.0.0.1"].as_ref().expect("10.0.0.1 was not answered locally");
    assert!(bogon.is_bogon);
    for ip in [PROBE, "8.8.8.8"] {
        assert!(answers[ip].is_ok(), "{ip} failed: {:?}", answers[ip].as_ref().err());
    }
}
