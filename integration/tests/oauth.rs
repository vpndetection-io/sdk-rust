// The published crate's OAuth accessor against staging, on a KEYLESS client.
//
// Only what is safe to repeat: discovery, revoking junk, exchanging a junk
// device code, and at most ONE device authorization per run, because staging
// allows 30 a minute per source address and every SDK built here shares one.
// Never a poll: nobody approves the code. That no request carries a key is
// asserted offline, against a client built with one.

use vpndetection::{Client, DeviceAuthorizationOptions, OauthError};
use vpndetection_integration::STAGING;

/// The one client ID staging accepts, already public in the CLI's source.
const CLIENT_ID: &str = "vpndetection-cli";

#[tokio::test]
async fn staging_publishes_its_authorization_server_metadata() {
    let metadata = keyless().oauth().metadata().await.expect("metadata");

    assert_eq!(metadata.issuer, STAGING);
    assert!(metadata.device_authorization_endpoint.is_some(), "no device authorization endpoint");
    let methods = metadata.code_challenge_methods_supported.unwrap_or_default();
    assert!(methods.iter().any(|method| method == "S256"), "{methods:?}");
}

#[tokio::test]
async fn revoking_a_token_that_does_not_exist_succeeds() {
    keyless().oauth().revoke(CLIENT_ID, "mo_rt_sdk-ci-not-a-token").await.expect("revoke");
}

#[tokio::test]
async fn an_unknown_device_code_is_an_expired_token() {
    let err = keyless()
        .oauth()
        .exchange_device_code(CLIENT_ID, "mo_dc_sdk-ci-not-a-code")
        .await
        .expect_err("a device code nobody issued cannot be exchanged");

    assert!(matches!(err, OauthError::ExpiredToken(_)), "{err:?}");
    assert_eq!(err.status(), Some(400));
}

/// The one device authorization this run spends. `slow_down` passes too: it is
/// the limiter answering for every SDK that ran from this address this minute.
#[tokio::test]
async fn a_device_authorization_starts_or_is_throttled() {
    let opts = DeviceAuthorizationOptions::new().scope("account.read");
    match keyless().oauth().device_authorization_with(CLIENT_ID, opts).await {
        Ok(device) => {
            assert!(!device.device_code.is_empty() && !device.user_code.is_empty());
            assert!(device.verification_uri.ends_with("/device"), "{}", device.verification_uri);
            assert!(device.expires_in > 0 && device.interval > 0, "{device:?}");
        }
        Err(err) => assert_eq!(err.error_code(), Some("slow_down"), "{err}"),
    }
}

fn keyless() -> Client {
    Client::builder().base_url(STAGING).build().expect("build")
}
