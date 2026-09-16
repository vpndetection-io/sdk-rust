// Assertions the OAuth corpus makes, shared by tests/oauth.rs and the poll's
// unit tests in src/oauth/tests.rs.
#![allow(dead_code)]

use std::collections::HashMap;

use serde_json::{Value, json};

use super::corpus::{OauthExpect, Served};
use super::{Call, Route};
use vpndetection::{DeviceAuthorization, OauthError, OauthMetadata, TokenResponse};

pub fn route(served: &Served) -> Route {
    Route::json(served.status, served.text())
}

/// The body decoded as a form, refusing a field that arrives twice so "same
/// fields exactly" cannot pass on the last of two.
pub fn form(call: &Call) -> HashMap<String, String> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(&call.body).expect("the body is not a form");
    let fields: HashMap<String, String> = pairs.iter().cloned().collect();
    assert_eq!(fields.len(), pairs.len(), "a form field was sent twice: {}", call.body);
    fields
}

/// A failure against what the corpus says of it. The OAuth refusals are told
/// apart by variant; `client` is the crate's ordinary error.
pub fn assert_failure(case: &str, err: &OauthError, want: &OauthExpect) {
    // The wildcard is unreachable inside the crate, where the poll's unit tests
    // compile this, and required outside it.
    #[allow(unreachable_patterns)]
    let outcome = match err {
        OauthError::AccessDenied(_) => "accessDenied",
        OauthError::ExpiredToken(_) => "expiredToken",
        OauthError::Rejected(_) => "oauth",
        OauthError::Client(_) => "client",
        _ => "an unknown variant",
    };
    assert_eq!(outcome, want.outcome, "{case}: which error ({err})");
    if let Some(code) = &want.error_code {
        assert_eq!(err.error_code(), Some(code.as_str()), "{case}: error code");
    }
    if let Some(description) = &want.error_description {
        assert_eq!(err.error_description(), description.as_deref(), "{case}: description");
    }
    if let Some(status) = want.status {
        assert_eq!(err.status(), status, "{case}: status");
    }
    if let Some(kind) = &want.kind {
        assert_eq!(err.kind().as_str(), kind, "{case}: kind");
    }
    if let Some(retryable) = want.retryable {
        assert_eq!(err.retryable(), retryable, "{case}: retryable");
    }
    if let Some(message) = &want.message {
        assert_eq!(&err.message(), message, "{case}: message");
    }
    if outcome != "client" {
        assert!(!err.retryable(), "{case}: an OAuth refusal is never retryable");
    }
}

/// Every present member has its value, and every absent one is `None`.
pub fn assert_members(
    case: &str,
    member: impl Fn(&str) -> Option<Value>,
    present: &serde_json::Map<String, Value>,
    absent: &[String],
) {
    for (name, want) in present {
        // Advertised by the corpus's metadata, no longer by the server, and not
        // a member of this release's type (sdk-go 14e52de skips it too).
        if name == "client_id_metadata_document_supported" {
            continue;
        }
        assert_eq!(member(name).as_ref(), Some(want), "{case}: {name}");
    }
    for name in absent {
        assert_eq!(member(name), None, "{case}: {name} must be ABSENT");
    }
}

/// Reads a member off the real field rather than off a serialization, so a
/// field that decodes from the wrong wire name is caught where it lives.
pub fn token_member(token: &TokenResponse, name: &str) -> Option<Value> {
    match name {
        "access_token" => Some(json!(token.access_token)),
        "token_type" => Some(json!(token.token_type)),
        "expires_in" => Some(json!(token.expires_in)),
        "refresh_token" => token.refresh_token.as_ref().map(|v| json!(v)),
        "scope" => token.scope.as_ref().map(|v| json!(v)),
        "apikey_id" => token.apikey_id.as_ref().map(|v| json!(v)),
        "apikey" => token.apikey.as_ref().map(|v| json!(v)),
        other => panic!("TokenResponse has no member {other}"),
    }
}

pub fn device_member(device: &DeviceAuthorization, name: &str) -> Option<Value> {
    match name {
        "device_code" => Some(json!(device.device_code)),
        "user_code" => Some(json!(device.user_code)),
        "verification_uri" => Some(json!(device.verification_uri)),
        "verification_uri_complete" => device.verification_uri_complete.as_ref().map(|v| json!(v)),
        "expires_in" => Some(json!(device.expires_in)),
        "interval" => Some(json!(device.interval)),
        other => panic!("DeviceAuthorization has no member {other}"),
    }
}

pub fn metadata_member(metadata: &OauthMetadata, name: &str) -> Option<Value> {
    let m = metadata;
    match name {
        "issuer" => Some(json!(m.issuer)),
        "authorization_endpoint" => Some(json!(m.authorization_endpoint)),
        "token_endpoint" => Some(json!(m.token_endpoint)),
        "device_authorization_endpoint" => {
            m.device_authorization_endpoint.as_ref().map(|v| json!(v))
        }
        "revocation_endpoint" => m.revocation_endpoint.as_ref().map(|v| json!(v)),
        "scopes_supported" => m.scopes_supported.as_ref().map(|v| json!(v)),
        "response_types_supported" => m.response_types_supported.as_ref().map(|v| json!(v)),
        "grant_types_supported" => m.grant_types_supported.as_ref().map(|v| json!(v)),
        "code_challenge_methods_supported" => {
            m.code_challenge_methods_supported.as_ref().map(|v| json!(v))
        }
        "token_endpoint_auth_methods_supported" => {
            m.token_endpoint_auth_methods_supported.as_ref().map(|v| json!(v))
        }
        "authorization_response_iss_parameter_supported" => {
            m.authorization_response_iss_parameter_supported.map(|v| json!(v))
        }
        "service_documentation" => m.service_documentation.as_ref().map(|v| json!(v)),
        other => panic!("OauthMetadata has no member {other}"),
    }
}
