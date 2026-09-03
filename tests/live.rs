// A smoke test against the real API, ignored by default so `cargo test` stays
// offline and costs no quota. Set VPNDETECTION_API_KEY to exercise a paid plan's
// fields; without one it runs on the free tier.
//
//     cargo test --test live -- --ignored --nocapture

use vpndetection::Client;

#[tokio::test]
#[ignore = "queries the real API"]
async fn live_lookup() {
    let key = std::env::var("VPNDETECTION_API_KEY").ok().filter(|k| !k.is_empty());
    let mut builder = Client::builder();
    if let Some(key) = &key {
        builder = builder.api_key(key);
    }
    let client = builder.build().expect("build");

    let vpn = client.lookup("45.83.91.1").await.expect("lookup 45.83.91.1");
    println!(
        "45.83.91.1: is_vpn={} is_bogon={} is_hosting={:?} vpn={:?}",
        vpn.is_vpn, vpn.is_bogon, vpn.is_hosting, vpn.vpn
    );
    assert!(vpn.is_vpn, "45.83.91.1 should be VPN infrastructure");

    let clean = client.lookup("1.1.1.1").await.expect("lookup 1.1.1.1");
    println!(
        "1.1.1.1: is_vpn={} is_bogon={} is_hosting={:?}",
        clean.is_vpn, clean.is_bogon, clean.is_hosting
    );
    assert!(!clean.is_vpn, "1.1.1.1 should not be VPN infrastructure");

    if key.is_none() {
        // The one assertion a stub cannot make honestly: the free tier does not
        // include is_hosting, so it is ABSENT rather than false.
        assert_eq!(clean.is_hosting, None, "the free tier does not include is_hosting");
    }
}
