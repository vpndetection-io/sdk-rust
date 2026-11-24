// The `first_seen` and `last_seen` of the bot, SSH, SMTP, web, DNS resolver and
// BitTorrent details are days, `format: date`: read in that form alone, and
// still handed back as the string the API wrote.

mod support;

use serde_json::{Value, json};
use support::{Route, Stub};
use vpndetection::{Error, ErrorKind, Lookup};

const DETAILS: [&str; 6] = ["bot", "ssh", "smtp", "web", "dns_resolver", "bittorrent"];

/// An answer carrying all six details, each day written as the API writes it.
fn well_formed() -> Value {
    let days = json!({ "first_seen": "2026-09-01", "last_seen": "2026-11-23" });
    let mut answer = json!({
        "ip": "9.9.9.9",
        "is_vpn": false,
        "is_bot": true,
        "bot": days,
        "ssh": days,
        "smtp": days,
        "dns_resolver": days,
        "bittorrent": { "first_seen": "2026-09-01", "last_seen": "2026-11-23", "last_reachable": "" },
        "web": [{
            "port": 443, "tls_ok": true, "session_ok": true, "status_code": 200, "server": "nginx",
            "location": "", "title": "", "cert_subject_cn": "", "cert_subject_o": "",
            "cert_issuer_dn": "", "cert_browser_trusted": true, "tls_version": "TLSv1.3",
            "first_seen": "2026-09-01", "last_seen": "2026-11-23",
        }],
    });
    answer["bot"]["provider"] = json!("google");
    answer
}

fn with(detail: &str, member: &str, value: &str) -> Value {
    let mut answer = well_formed();
    match detail {
        "web" => answer["web"][0][member] = json!(value),
        _ => answer[detail][member] = json!(value),
    }
    answer
}

/// One lookup of `body`, retried once, and how many requests it took.
async fn read(body: &Value) -> (Result<Lookup, Error>, usize) {
    let stub = Stub::start([("/9.9.9.9".to_owned(), Route::ok(body.to_string()))]).await;
    let client = stub.client().api_key("key").no_cache().retries(1).build().expect("build");
    let answer = client.lookup("9.9.9.9").await;
    (answer, stub.count())
}

fn assert_refused(case: &str, read: (Result<Lookup, Error>, usize)) {
    let (answer, count) = read;
    let Err(err) = answer else { panic!("{case}: read as a day") };
    assert_eq!(err.kind(), ErrorKind::ServerError, "{case}: {err}");
    assert_eq!(err.status(), Some(200), "{case}: the status");
    assert_eq!(count, 2, "{case}: retried like an outage");
}

#[tokio::test]
async fn a_bot_last_seen_takes_the_date_probe() {
    let (answer, _) = read(&well_formed()).await;
    let answer = answer.expect("the well-formed answer");
    let bot = answer.bot.as_ref().expect("bot");
    assert_eq!(bot.first_seen.as_deref(), Some("2026-09-01"));
    assert_eq!(bot.last_seen.as_deref(), Some("2026-11-23"));
    let web = &answer.web.as_ref().expect("web")[0];
    assert_eq!((web.first_seen.as_str(), web.last_seen.as_str()), ("2026-09-01", "2026-11-23"));
    assert_eq!(answer.bittorrent.as_ref().expect("bittorrent").last_reachable.as_deref(), Some(""));

    let leap = read(&with("bot", "last_seen", "2028-02-29")).await.0.expect("a leap day");
    assert_eq!(leap.bot.as_ref().and_then(|b| b.last_seen.as_deref()), Some("2028-02-29"));

    let mut checks = tokio::task::JoinSet::new();
    for value in [
        "x",
        "",
        "tomorrow",
        "monday",
        "2026-02-30",
        "2027-02-29",
        "2026-11-31",
        "2026-13-01",
        "2026-10-20T24:00:00Z",
        "2026-10-20T10:00:00Z",
        "2026-10-20T10:00:00",
        "2026-10-20 10:00",
        "2026-10-20+05",
        "2026-10-20+05:00",
        "2026-10-20Z",
        "2026-10-20\n",
        " 2026-10-20",
        "2026-10-2\u{0660}",
        "\u{0662}026-10-20",
        "2026-10-5",
        "20261020",
        "2026-W43-2",
        "+2026-10-20",
    ] {
        checks.spawn(async move {
            assert_refused(
                &format!("bot.last_seen {value:?}"),
                read(&with("bot", "last_seen", value)).await,
            );
        });
    }
    while let Some(check) = checks.join_next().await {
        check.expect("check");
    }
}

#[tokio::test]
async fn each_detail_s_first_and_last_seen_refuses_a_malformed_day() {
    let mut checks = tokio::task::JoinSet::new();
    for detail in DETAILS {
        for member in ["first_seen", "last_seen"] {
            checks.spawn(async move {
                assert_refused(
                    &format!("{detail}.{member}"),
                    read(&with(detail, member, "x")).await,
                );
            });
        }
    }
    while let Some(check) = checks.join_next().await {
        check.expect("check");
    }
}
