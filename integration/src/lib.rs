//! The staging fixtures the test files share: which plan tiers this run can
//! observe, one client and one answer per tier, and the shape rules that hold
//! whatever the plan.
//!
//! Every lookup goes through [`recorder::Recorder`], a recording reverse proxy
//! in front of staging, because reqwest offers no seam of its own and two of the
//! things that have to be proved here are about the REQUEST rather than the
//! answer: that the key reached the wire, and that it did not travel any
//! further than the API.

pub mod recorder;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use recorder::{Fact, Recorder};
use serde_json::Value;
use vpndetection::{Client, Lookup};

/// The deployment these tests run against, reached through the client's own
/// base-URL option, which is what makes that option worth testing.
pub const STAGING: &str = "https://api-staging.vpndetection.io";

/// A stable VPN address, and the one the README teaches.
pub const PROBE: &str = "45.83.91.1";

const RUNG_COUNT: usize = 5;

/// Ascending, one rung per plan tier. `widens` is what a rung promises against
/// whichever observable rung sits below it: a paid tier serves strictly more
/// than the tier under it, while a free key and no key at all are the same
/// entitlement reached two ways.
///
/// Field COUNTS are deliberately absent. Pinning "starter answers seven fields"
/// turns a pricing change into a red SDK build; the relation between the tiers
/// is what the client actually has to keep.
pub const RUNGS: [Rung; RUNG_COUNT] = [
    Rung { tier: "unauth", secret: None, widens: false },
    Rung { tier: "free", secret: Some("VPNDETECTION_STAGING_KEY_FREE"), widens: false },
    Rung { tier: "starter", secret: Some("VPNDETECTION_STAGING_KEY_STARTER"), widens: true },
    Rung { tier: "scale", secret: Some("VPNDETECTION_STAGING_KEY_SCALE"), widens: true },
    Rung { tier: "max", secret: Some("VPNDETECTION_STAGING_KEY_MAX"), widens: true },
];

pub struct Rung {
    pub tier: &'static str,
    pub secret: Option<&'static str>,
    pub widens: bool,
}

impl Rung {
    /// This rung's key, or `None` when it cannot be exercised.
    ///
    /// Empty counts as absent: Actions interpolates a secret that does not exist
    /// to an EMPTY STRING rather than leaving the variable unset, and a client
    /// built with an empty key sends no authorization header at all, so an empty
    /// key runs as a second unauthenticated client and every comparison against
    /// it is vacuously true.
    pub fn key(&self) -> Option<String> {
        let name = self.secret?;
        std::env::var(name).ok().map(|key| key.trim().to_owned()).filter(|key| !key.is_empty())
    }

    /// A reason, or `None` when this tier can be exercised.
    pub fn skip_reason(&self) -> Option<String> {
        match self.secret {
            Some(name) if self.key().is_none() => {
                Some(format!("{name} is not set, so the {} tier cannot be exercised", self.tier))
            }
            _ => None,
        }
    }
}

/// Rust's test harness has no skip, so a tier without a key says so and passes.
/// Printed rather than silent: a suite that quietly tests nothing is the exact
/// failure this crate exists to prevent, and `run.sh` passes `--nocapture` so
/// the line lands in the log.
#[macro_export]
macro_rules! skip_unless {
    ($reason:expr) => {
        if let Some(reason) = $reason {
            println!("SKIPPED: {reason}");
            return;
        }
    };
}

/// The rungs a run can actually observe, in ascending order.
pub fn observable() -> Vec<&'static Rung> {
    RUNGS.iter().filter(|rung| rung.skip_reason().is_none()).collect()
}

/// The ladder needs two rungs to say anything. The unauthenticated one is always
/// there, so this only fires when no tier secret at all is configured.
pub fn ladder_skip() -> Option<String> {
    match observable().len() {
        0 | 1 => Some("no tier secret is set, so there is no ladder to compare".to_owned()),
        _ => None,
    }
}

pub fn max_rung() -> &'static Rung {
    &RUNGS[RUNG_COUNT - 1]
}

/// One lookup per tier for the whole binary. The client caches, so a second
/// reader of the same tier would cost no request either, but a fixture also
/// carries what the wire said, which the client does not keep.
static ANSWERS: [tokio::sync::OnceCell<Answer>; RUNG_COUNT] =
    [const { tokio::sync::OnceCell::const_new() }; RUNG_COUNT];

pub struct Answer {
    pub tier: &'static str,
    pub widens: bool,
    pub result: Lookup,
    /// The answer as it came off the wire. The client keeps the decoded result;
    /// a field the pinned spec does not model is only visible here.
    pub wire: BTreeMap<String, Value>,
    pub facts: Vec<Fact>,
}

pub async fn answer_for(rung: &'static Rung) -> &'static Answer {
    let index = RUNGS.iter().position(|r| r.tier == rung.tier).expect("an unknown rung");
    ANSWERS[index].get_or_init(|| look_up(rung)).await
}

async fn look_up(rung: &'static Rung) -> Answer {
    let (client, recorder) = client_for(rung).await;
    let result = client
        .lookup(PROBE)
        .await
        .unwrap_or_else(|err| panic!("{}: lookup({PROBE}): {err}", rung.tier));

    let wire = recorder
        .json_body(&format!("/{PROBE}"))
        .unwrap_or_else(|| panic!("{}: no JSON answer was captured for {PROBE}", rung.tier));
    let wire: BTreeMap<String, Value> =
        serde_json::from_value(wire).expect("the answer is a JSON object");

    // Checked HERE rather than in one test, so no comparison anywhere can be made
    // against a tier that silently ran unauthenticated: an unsent key answers the
    // free shape, which satisfies every containment check vacuously.
    if rung.secret.is_some() {
        assert!(recorder.carried_key(), "{}: the key never reached the wire", rung.tier);
    }
    Answer { tier: rung.tier, widens: rung.widens, result, wire, facts: recorder.facts() }
}

/// A client of this tier, and the recorder standing in front of it. A client per
/// caller, so one test's request record cannot be read through another's.
pub async fn client_for(rung: &Rung) -> (Client, Arc<Recorder>) {
    let key = rung.key();
    let recorder = Recorder::start(STAGING, key.clone()).await;
    let mut builder = Client::builder().base_url(&recorder.base_url);
    if let Some(key) = key {
        builder = builder.api_key(key);
    }
    (builder.build().expect("building the client"), recorder)
}

/// One entry per dataset the API answers about. `required` is what a POPULATED
/// detail object carries on every tier; `optional` is the max-only remainder,
/// which is absent rather than empty on a lower plan.
pub const MEMBERS: [(&str, Detail); 8] = [
    ("vpn", Detail { required: &["provider", "last_seen"], optional: &["confidence", "method"] }),
    ("hosting", Detail { required: CLASS_KEYS, optional: &[] }),
    ("relay", Detail { required: CLASS_KEYS, optional: &[] }),
    ("tor", Detail { required: CLASS_KEYS, optional: &[] }),
    ("cdn", Detail { required: CLASS_KEYS, optional: &[] }),
    ("resproxy", Detail { required: PROXY_KEYS, optional: &[] }),
    ("dcproxy", Detail { required: PROXY_KEYS, optional: &[] }),
    ("mobproxy", Detail { required: PROXY_KEYS, optional: &[] }),
];

const CLASS_KEYS: &[&str] = &["provider", "confidence", "last_seen"];
const PROXY_KEYS: &[&str] =
    &["provider", "first_seen", "last_seen", "hits", "hits_days_pct", "providers_num"];

pub struct Detail {
    pub required: &'static [&'static str],
    pub optional: &'static [&'static str],
}

pub fn assert_served_by_tier(answer: &Answer) {
    assert_eq!(answer.result.ip, PROBE, "{}: answered about the wrong address", answer.tier);
    assert!(!answer.result.is_bogon, "{}: a served answer is not a local one", answer.tier);
    assert_shape(answer);
}

/// Holds on every plan: presence is the plan, the value is the answer.
pub fn assert_shape(answer: &Answer) {
    let tier = answer.tier;
    assert!(answer.wire.get("ip").is_some_and(Value::is_string), "{tier}: ip is not a string");
    let served = answer.wire.get("is_vpn").and_then(Value::as_bool);
    let served = served.unwrap_or_else(|| panic!("{tier}: is_vpn is on every plan"));
    assert_eq!(answer.result.is_vpn, served, "{tier}: is_vpn disagrees with the wire");

    for (name, spec) in &MEMBERS {
        let flag = format!("is_{name}");
        if let Some(value) = answer.wire.get(&flag) {
            assert!(value.is_boolean(), "{tier}: {flag} is present, so it must be a real boolean");
        }
        let Some(object) = answer.wire.get(*name) else {
            continue;
        };
        // A detail object without its flag would leave a caller reading the
        // object to find out whether the address is flagged at all.
        assert!(answer.wire.contains_key(&flag), "{tier}: {name} is served without {flag}");
        assert_detail(tier, name, spec, object, answer.wire.get(&flag));
    }
}

fn assert_detail(tier: &str, name: &str, spec: &Detail, object: &Value, flag: Option<&Value>) {
    let fields = object
        .as_object()
        .unwrap_or_else(|| panic!("{tier}: {name} must be an object when present, got {object}"));
    if fields.is_empty() {
        assert_eq!(
            flag,
            Some(&Value::Bool(false)),
            "{tier}: {name} is empty, so is_{name} is false"
        );
        return;
    }
    for key in spec.required {
        assert!(fields.contains_key(*key), "{tier}: {name} is populated but carries no {key}");
    }
    for key in fields.keys() {
        let documented =
            spec.required.contains(&key.as_str()) || spec.optional.contains(&key.as_str());
        assert!(documented, "{tier}: {name}.{key} is not a documented key of this detail object");
    }
}

/// The fields the CLIENT holds, by their wire names, so a test can say "this
/// field is absent" about the name the API serves rather than whatever the
/// generator called it. Every optional member skips serializing when it is
/// `None`, so what comes back is exactly what survived the decode.
pub fn client_fields(result: &Lookup) -> BTreeSet<String> {
    let value = serde_json::to_value(&result.answer).expect("re-encoding the answer");
    value.as_object().expect("the answer is an object").keys().cloned().collect()
}
