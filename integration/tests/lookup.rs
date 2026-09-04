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

use vpndetection::BatchOptions;
use vpndetection_integration::{
    MEMBERS, PROBE, RUNGS, STAGING, answer_for, assert_served_by_tier, client_fields, client_for,
    ladder_skip, observable, skip_unless,
};

#[tokio::test]
async fn an_unauthenticated_lookup_answers_ip_and_is_vpn() {
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
        let fields: BTreeSet<String> = answer.wire.keys().cloned().collect();
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
        below = Some(fields);
    }
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
        for field in answer.wire.keys() {
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
async fn a_batch_collapses_duplicates_and_keeps_bogons_off_the_wire() {
    let (client, recorder) = client_for(&RUNGS[0]).await;

    let answers = client
        .lookup_batch([PROBE, "8.8.8.8", PROBE, "10.0.0.1", "8.8.8.8"], BatchOptions::new())
        .await;

    // Rust keeps the map insertion-ordered, so the exact order is assertable
    // here where Go could only assert the set.
    let keys: Vec<&str> = answers.keys().map(String::as_str).collect();
    assert_eq!(keys, [PROBE, "8.8.8.8", "10.0.0.1"], "duplicates collapse, first-seen order holds");

    // Distinct paths rather than a request count, so a retry against a wobbling
    // staging cannot read as a failure to deduplicate.
    let asked: BTreeSet<String> = recorder.facts().iter().map(|fact| fact.path.clone()).collect();
    let want: BTreeSet<String> = [format!("/{PROBE}"), "/8.8.8.8".to_owned()].into();
    assert_eq!(asked, want, "the batch asked for the wrong set of addresses");

    let bogon = answers["10.0.0.1"].as_ref().expect("10.0.0.1 was not answered locally");
    assert!(bogon.is_bogon);
    for ip in [PROBE, "8.8.8.8"] {
        assert!(answers[ip].is_ok(), "{ip} failed: {:?}", answers[ip].as_ref().err());
    }
}
