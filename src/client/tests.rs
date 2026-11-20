// A spent trial's or a reached cap's answer is cached for a minute at most, or
// for the client's TTL when that is shorter, a batch's entries included. A unit
// test because when an entry expires is private: moka keeps it, and only the
// client's own record of what it set can be read back.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::Client;
use crate::models::LookupResponse;
use crate::support;
use crate::{BatchOptions, Lookup};
use support::{Route, Stub};

const PLAIN: &str = "45.83.91.1";
const UNFLAGGED: &str = "45.83.91.2";
const TRIAL: &str = "45.83.91.3";
const CAP: &str = "45.83.91.4";

const HOUR: Duration = Duration::from_secs(60 * 60);
const MINUTE: Duration = Duration::from_secs(60);
const FIVE_SECONDS: Duration = Duration::from_secs(5);

fn flagged(ip: &str) -> serde_json::Value {
    let mut body = serde_json::json!({"ip": ip, "is_bogon": false, "is_vpn": false});
    let flags = match ip {
        UNFLAGGED => serde_json::json!({"trial_expired": false, "cap_reached": false}),
        TRIAL => serde_json::json!({"trial_expired": true}),
        CAP => serde_json::json!({"cap_reached": true}),
        _ => serde_json::json!({}),
    };
    body.as_object_mut().unwrap().extend(flags.as_object().unwrap().clone());
    body
}

async fn stub() -> Arc<Stub> {
    Stub::start(
        [PLAIN, UNFLAGGED, TRIAL, CAP]
            .map(|ip| (format!("/{ip}"), Route::ok(flagged(ip).to_string()))),
    )
    .await
}

fn expiry(client: &Client, ip: &str) -> Instant {
    client
        .0
        .expiries
        .lock()
        .unwrap()
        .get(ip)
        .copied()
        .unwrap_or_else(|| panic!("{ip} was not cached"))
}

fn served(ip: &str) -> Lookup {
    Lookup::served(serde_json::from_value::<LookupResponse>(flagged(ip)).expect("an answer"))
}

#[tokio::test]
async fn each_answer_is_cached_as_long_as_its_flags_allow() {
    let cases = [
        (PLAIN, HOUR, HOUR),
        (UNFLAGGED, HOUR, HOUR),
        (TRIAL, HOUR, MINUTE),
        (CAP, HOUR, MINUTE),
        (TRIAL, FIVE_SECONDS, FIVE_SECONDS),
        (CAP, FIVE_SECONDS, FIVE_SECONDS),
        (PLAIN, FIVE_SECONDS, FIVE_SECONDS),
    ];
    for how in ["lookup", "lookup_batch"] {
        for (ip, ttl, want) in cases {
            let stub = stub().await;
            let client = stub.client().cache(100, ttl).build().expect("build");

            let before = Instant::now();
            if how == "lookup" {
                client.lookup(ip).await.expect("lookup");
            } else {
                let answers = client.lookup_batch([ip, PLAIN], BatchOptions::new()).await;
                answers[ip].as_ref().expect("a batch entry");
            }
            let after = Instant::now();

            let expires = expiry(&client, ip);
            assert!(
                expires >= before + want && expires <= after + want,
                "{how}: {ip} under a {ttl:?} TTL expires {:?} after the call began, want {want:?}",
                expires - before,
            );
        }
    }
}

#[tokio::test]
async fn a_reduced_answer_is_still_cached_so_a_repeat_sends_nothing() {
    let stub = stub().await;
    let client = stub.client().build().expect("build");

    for ip in [TRIAL, CAP] {
        client.lookup(ip).await.expect("lookup");
        let again = client.lookup(ip).await.expect("lookup");
        assert!(
            again.trial_expired == Some(true) || again.cap_reached == Some(true),
            "{ip}: the cached answer lost its flag"
        );
    }
    assert_eq!(stub.count(), 2, "a repeat of a reduced answer went to the API");
}

#[tokio::test]
async fn a_replaced_answer_lives_as_long_as_the_new_one_may() {
    let stub = stub().await;
    let client = stub.client().build().expect("build");
    let cache = client.0.cache.as_ref().expect("a cache");

    cache.insert(PLAIN.to_owned(), served(PLAIN)).await;
    let before = Instant::now();
    cache.insert(PLAIN.to_owned(), served(TRIAL)).await;
    assert!(expiry(&client, PLAIN) <= Instant::now() + MINUTE, "a reduced answer kept the TTL");

    cache.insert(PLAIN.to_owned(), served(PLAIN)).await;
    assert!(expiry(&client, PLAIN) >= before + HOUR - MINUTE, "a full answer kept a minute");
}
