//! Signing a person in on their own machine with the OAuth device flow, so a
//! program can be handed one of their API keys instead of asking them to paste
//! it.

use std::future::Future;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::client::{Client, with_retry};
use crate::error::{Error, ErrorKind, kind_for_status};
use crate::transport::Answer;

const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
const DEVICE_AUTHORIZATION_PATH: &str = "/oauth/device_authorization";
const TOKEN_PATH: &str = "/oauth/token";
const REVOKE_PATH: &str = "/oauth/revoke";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// RFC 8628's default, for a device authorization whose interval is below 1.
const DEFAULT_POLL_INTERVAL: i64 = 5;
const SLOW_DOWN_STEP: i64 = 5;

/// The OAuth authorization server behind the API: the device flow, token
/// refresh and revocation.
///
/// Every call takes a client ID, which is issued on request from
/// support@vpndetection.io. None of these requests carries the client's API
/// key, and none needs one, so a client built without a key works the same.
///
/// Reached through [`Client::oauth`].
#[derive(Debug, Clone, Copy)]
pub struct OauthApi<'a> {
    client: &'a Client,
}

impl<'a> OauthApi<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// The authorization server's discovery document. Nothing here needs it:
    /// every request is built from the client's base URL.
    pub async fn metadata(&self) -> Result<OauthMetadata, OauthError> {
        self.metadata_with(OauthOptions::new()).await
    }

    /// [`OauthApi::metadata`], with this call's own timeout.
    pub async fn metadata_with(&self, opts: OauthOptions) -> Result<OauthMetadata, OauthError> {
        let timeout = self.timeout(opts.timeout);
        with_retry(self.client.retries(), || async move {
            decode(self.client.transport().get_keyless(METADATA_PATH, timeout).await?)
        })
        .await
    }

    /// Starts a device sign-in. Show the person [`DeviceAuthorization::user_code`]
    /// and [`DeviceAuthorization::verification_uri`], then hand the answer to
    /// [`OauthApi::poll_device_token`].
    ///
    /// It consumes nothing, so it is retried like any read. A refusal, such as
    /// `slow_down` when this address has started too many, is an
    /// [`OauthError::Rejected`].
    pub async fn device_authorization(
        &self,
        client_id: &str,
    ) -> Result<DeviceAuthorization, OauthError> {
        self.device_authorization_with(client_id, DeviceAuthorizationOptions::new()).await
    }

    /// [`OauthApi::device_authorization`], asking for a scope or a resource, or
    /// with this call's own timeout.
    pub async fn device_authorization_with(
        &self,
        client_id: &str,
        opts: DeviceAuthorizationOptions,
    ) -> Result<DeviceAuthorization, OauthError> {
        let mut form = vec![("client_id", client_id)];
        if let Some(scope) = opts.scope.as_deref().filter(|s| !s.is_empty()) {
            form.push(("scope", scope));
        }
        if let Some(resource) = opts.resource.as_deref().filter(|r| !r.is_empty()) {
            form.push(("resource", resource));
        }
        let timeout = self.timeout(opts.timeout);
        let form = &form;
        with_retry(self.client.retries(), || async move {
            let answer =
                self.client.transport().post_form(DEVICE_AUTHORIZATION_PATH, form, timeout).await?;
            decode(answer)
        })
        .await
    }

    /// Exchanges an approved device code for tokens, once.
    ///
    /// Never retried: the server consumes the code on approval, so a retry after
    /// a lost answer loses the tokens. While the person has not decided yet this
    /// is an [`OauthError::Rejected`] with code `authorization_pending`, which
    /// is what [`OauthApi::poll_device_token`] waits through.
    pub async fn exchange_device_code(
        &self,
        client_id: &str,
        device_code: &str,
    ) -> Result<TokenResponse, OauthError> {
        self.exchange_device_code_with(client_id, device_code, OauthOptions::new()).await
    }

    /// [`OauthApi::exchange_device_code`], with this call's own timeout.
    pub async fn exchange_device_code_with(
        &self,
        client_id: &str,
        device_code: &str,
        opts: OauthOptions,
    ) -> Result<TokenResponse, OauthError> {
        let form = [
            ("grant_type", DEVICE_CODE_GRANT),
            ("device_code", device_code),
            ("client_id", client_id),
        ];
        self.exchange(&form, opts).await
    }

    /// Exchanges a refresh token for a new pair, once.
    ///
    /// Never retried: the server consumes the refresh token before it mints the
    /// new one, so keep the [`TokenResponse::refresh_token`] this returns. A
    /// refresh names the key the person picked in
    /// [`TokenResponse::apikey_id`] but never hands the key itself back.
    pub async fn exchange_refresh_token(
        &self,
        client_id: &str,
        refresh_token: &str,
    ) -> Result<TokenResponse, OauthError> {
        self.exchange_refresh_token_with(client_id, refresh_token, OauthOptions::new()).await
    }

    /// [`OauthApi::exchange_refresh_token`], with this call's own timeout.
    pub async fn exchange_refresh_token_with(
        &self,
        client_id: &str,
        refresh_token: &str,
        opts: OauthOptions,
    ) -> Result<TokenResponse, OauthError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ];
        self.exchange(&form, opts).await
    }

    /// Revokes a token. A refresh token ends the whole sign-in and every token
    /// it issued, which is how a machine is signed out; an access token ends
    /// only itself. Revoking twice is revoking once, so it is retried like a
    /// read.
    pub async fn revoke(&self, client_id: &str, token: &str) -> Result<(), OauthError> {
        self.revoke_with(client_id, token, OauthOptions::new()).await
    }

    /// [`OauthApi::revoke`], with this call's own timeout.
    pub async fn revoke_with(
        &self,
        client_id: &str,
        token: &str,
        opts: OauthOptions,
    ) -> Result<(), OauthError> {
        let form = [("token", token), ("client_id", client_id)];
        let timeout = self.timeout(opts.timeout);
        let form = &form;
        with_retry(self.client.retries(), || async move {
            let answer = self.client.transport().post_form(REVOKE_PATH, form, timeout).await?;
            match answer.status {
                200..=299 => Ok(()),
                _ => Err(refusal(answer)),
            }
        })
        .await
    }

    /// Waits for the person to approve a device sign-in, and returns its tokens.
    ///
    /// Before EVERY request, the first included, it sleeps
    /// [`DeviceAuthorization::interval`] seconds, or 5 when that is below one,
    /// and adds 5 more for the rest of the call each time the server answers
    /// `slow_down`. It stops at the
    /// first answer that is neither `authorization_pending` nor `slow_down`: a
    /// refusal is [`OauthError::AccessDenied`], a code that ran out
    /// [`OauthError::ExpiredToken`], and an ordinary failure ends it too.
    /// Running out of [`DeviceAuthorization::expires_in`], counted from this
    /// call, is an [`OauthError::ExpiredToken`] with no status. Calling it again
    /// with the same device authorization is safe until the code expires.
    ///
    /// There is no cancellation handle: dropping the future stops the wait and
    /// any request in flight, and nothing is reported.
    pub async fn poll_device_token(
        &self,
        client_id: &str,
        device: &DeviceAuthorization,
    ) -> Result<TokenResponse, OauthError> {
        self.poll_device_token_with(client_id, device, OauthOptions::new()).await
    }

    /// [`OauthApi::poll_device_token`], with a timeout for each poll request.
    /// It bounds every request, never the poll as a whole.
    pub async fn poll_device_token_with(
        &self,
        client_id: &str,
        device: &DeviceAuthorization,
        opts: OauthOptions,
    ) -> Result<TokenResponse, OauthError> {
        self.poll(client_id, device, opts, &TokioClock::start()).await
    }

    pub(crate) async fn poll<C: PollClock + Sync>(
        &self,
        client_id: &str,
        device: &DeviceAuthorization,
        opts: OauthOptions,
        clock: &C,
    ) -> Result<TokenResponse, OauthError> {
        let mut interval =
            if device.interval >= 1 { device.interval } else { DEFAULT_POLL_INTERVAL };
        let deadline = clock.now() + seconds(device.expires_in);
        loop {
            clock.sleep(seconds(interval)).await;
            if clock.now() >= deadline {
                return Err(OauthError::ExpiredToken(OauthErrorResponse {
                    error_code: "expired_token".to_owned(),
                    error_description: None,
                    status: None,
                }));
            }
            match self.exchange_device_code_with(client_id, &device.device_code, opts.clone()).await
            {
                Err(OauthError::Rejected(refused)) if refused.error_code == "slow_down" => {
                    interval += SLOW_DOWN_STEP;
                }
                Err(OauthError::Rejected(refused))
                    if refused.error_code == "authorization_pending" => {}
                outcome => return outcome,
            }
        }
    }

    async fn exchange(
        &self,
        form: &[(&str, &str)],
        opts: OauthOptions,
    ) -> Result<TokenResponse, OauthError> {
        let timeout = self.timeout(opts.timeout);
        decode(self.client.transport().post_form(TOKEN_PATH, form, timeout).await?)
    }

    fn timeout(&self, per_call: Option<Duration>) -> Duration {
        per_call.unwrap_or(self.client.timeout())
    }
}

/// One call's overrides for an [`OauthApi`] method.
#[derive(Debug, Clone, Default)]
pub struct OauthOptions {
    timeout: Option<Duration>,
}

impl OauthOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides [`crate::ClientBuilder::timeout`] for this call, still per
    /// attempt. On [`OauthApi::poll_device_token_with`] it bounds each poll
    /// request, never the poll as a whole.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// What [`OauthApi::device_authorization_with`] asks for. A value left unset,
/// or set empty, is left out of the request rather than sent empty.
#[derive(Debug, Clone, Default)]
pub struct DeviceAuthorizationOptions {
    scope: Option<String>,
    resource: Option<String>,
    timeout: Option<Duration>,
}

impl DeviceAuthorizationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// The scopes to ask for, space-delimited and sent verbatim, for example
    /// `account.read apikeys.read apikeys.reveal`. The server narrows it to
    /// what the client may ask for without saying so; the granted set comes
    /// back in [`TokenResponse::scope`].
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// The API the tokens are for (RFC 8707).
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Overrides [`crate::ClientBuilder::timeout`] for this call, still per
    /// attempt.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// The authorization server's discovery document (RFC 8414).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OauthMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
}

/// A device sign-in that has started and is waiting for the person.
///
/// Serializable, so a program can keep it while the person is away and poll
/// with it later.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeviceAuthorization {
    /// What [`OauthApi::poll_device_token`] exchanges. Never show it.
    pub device_code: String,
    /// What the person types at [`DeviceAuthorization::verification_uri`].
    pub user_code: String,
    pub verification_uri: String,
    /// The same page with the code already filled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Seconds until both codes expire.
    pub expires_in: i64,
    /// Seconds to wait between polls.
    pub interval: i64,
}

/// What a successful token exchange hands over.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TokenResponse {
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// Seconds until the access token expires.
    pub expires_in: i64,
    /// A refresh consumes the token it presents, so keep the one that comes
    /// back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// What was actually granted, which may be narrower than what was asked
    /// for. `Some("")` when nothing was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The ID of the API key the person picked, while this sign-in may still
    /// read that key back. `None` when no key was picked, or when their role
    /// no longer allows reading keys back.
    #[serde(rename = "mslm:apikey_id", default, skip_serializing_if = "Option::is_none")]
    pub apikey_id: Option<String>,
    /// The API key itself, from the device code grant only and never from a
    /// refresh. `None` without [`TokenResponse::apikey_id`], and also beside
    /// one whose secret cannot be read back, which is the case for a key
    /// created before keys could be shown again in the console.
    #[serde(rename = "mslm:apikey", default, skip_serializing_if = "Option::is_none")]
    pub apikey: Option<String>,
}

/// What every [`OauthApi`] call fails with.
///
/// Separate from [`Error`] because adding variants to that enum would break
/// every caller matching it exhaustively. An ordinary failure - a transport
/// error, a timeout, a 5xx, a 4xx that is not an OAuth refusal - is
/// [`OauthError::Client`], exactly the [`Error`] any other call would give.
/// The OAuth refusals are never retryable.
#[derive(Debug)]
#[non_exhaustive]
pub enum OauthError {
    /// The person refused the sign-in (`access_denied`).
    AccessDenied(OauthErrorResponse),
    /// The device code expired, or was already exchanged or refused
    /// (`expired_token`). A poll that outlived the code locally carries no
    /// status.
    ExpiredToken(OauthErrorResponse),
    /// Any other OAuth refusal, including a code this version has never seen:
    /// `authorization_pending`, `slow_down`, `invalid_grant`, `invalid_client`.
    Rejected(OauthErrorResponse),
    /// Anything that is not an OAuth refusal.
    Client(Error),
}

/// What the authorization server said when it refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct OauthErrorResponse {
    /// The RFC 6749 `error`, for example `invalid_grant`.
    pub error_code: String,
    /// `error_description`, when the server sent one as a string.
    pub error_description: Option<String>,
    /// The HTTP status, or `None` for the expiry a poll decides locally.
    pub status: Option<u16>,
}

impl OauthError {
    /// Follows the status like any response's: 400 is a bad request and 401 an
    /// unregistered client ID, never the API key, which these requests do not
    /// carry. The expiry a poll decides locally is a bad request.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Client(err) => err.kind(),
            Self::AccessDenied(r) | Self::ExpiredToken(r) | Self::Rejected(r) => {
                kind_for_status(r.status.unwrap_or(400), None)
            }
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            Self::Client(err) => err.retryable(),
            Self::AccessDenied(_) | Self::ExpiredToken(_) | Self::Rejected(_) => false,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Client(err) => err.status(),
            Self::AccessDenied(r) | Self::ExpiredToken(r) | Self::Rejected(r) => r.status,
        }
    }

    /// The OAuth `error`, or `None` for an ordinary failure.
    pub fn error_code(&self) -> Option<&str> {
        self.response().map(|r| r.error_code.as_str())
    }

    pub fn error_description(&self) -> Option<&str> {
        self.response().and_then(|r| r.error_description.as_deref())
    }

    /// `<error>` or `<error>: <error_description>` for a refusal, and the
    /// ordinary message otherwise.
    pub fn message(&self) -> String {
        match self {
            Self::Client(err) => err.message(),
            Self::AccessDenied(r) | Self::ExpiredToken(r) | Self::Rejected(r) => {
                match &r.error_description {
                    Some(description) => format!("{}: {description}", r.error_code),
                    None => r.error_code.clone(),
                }
            }
        }
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Client(err) => err.retry_after(),
            Self::AccessDenied(_) | Self::ExpiredToken(_) | Self::Rejected(_) => None,
        }
    }

    fn response(&self) -> Option<&OauthErrorResponse> {
        match self {
            Self::AccessDenied(r) | Self::ExpiredToken(r) | Self::Rejected(r) => Some(r),
            Self::Client(_) => None,
        }
    }
}

impl std::fmt::Display for OauthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self, self.status()) {
            (Self::Client(err), _) => std::fmt::Display::fmt(err, f),
            (_, Some(status)) => {
                write!(f, "vpndetection: oauth (HTTP {status}): {}", self.message())
            }
            (_, None) => write!(f, "vpndetection: oauth: {}", self.message()),
        }
    }
}

impl std::error::Error for OauthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(err) => Some(err),
            Self::AccessDenied(_) | Self::ExpiredToken(_) | Self::Rejected(_) => None,
        }
    }
}

impl From<Error> for OauthError {
    fn from(err: Error) -> Self {
        Self::Client(err)
    }
}

/// The poll's wait and its deadline, replaced together in tests.
pub(crate) trait PollClock {
    /// Monotonic, from any fixed origin.
    fn now(&self) -> Duration;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

struct TokioClock {
    origin: tokio::time::Instant,
}

impl TokioClock {
    fn start() -> Self {
        Self { origin: tokio::time::Instant::now() }
    }
}

impl PollClock for TokioClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}

fn seconds(n: i64) -> Duration {
    Duration::from_secs(u64::try_from(n).unwrap_or(0))
}

/// A 2xx decoded into `T`, where a body that does not parse or lacks a
/// required member is the ordinary server error carrying the status.
fn decode<T: DeserializeOwned>(answer: Answer) -> Result<T, OauthError> {
    if !(200..300).contains(&answer.status) {
        return Err(refusal(answer));
    }
    serde_json::from_str(&answer.body).map_err(|e| {
        OauthError::Client(Error::Api {
            kind: ErrorKind::ServerError,
            message: format!("could not decode the response: {e}"),
            status: answer.status,
            retry_after: None,
        })
    })
}

/// Only a 4xx whose body is a JSON object with a STRING `error` is an OAuth
/// refusal. Every 5xx is the server failing, whatever its body says.
fn refusal(answer: Answer) -> OauthError {
    if (400..500).contains(&answer.status) {
        if let Some(refused) = oauth_error_response(answer.status, &answer.body) {
            return match refused.error_code.as_str() {
                "access_denied" => OauthError::AccessDenied(refused),
                "expired_token" => OauthError::ExpiredToken(refused),
                _ => OauthError::Rejected(refused),
            };
        }
    }
    OauthError::Client(Error::from_response(answer.status, answer.retry_after, &answer.body))
}

fn oauth_error_response(status: u16, body: &str) -> Option<OauthErrorResponse> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error_code = value.get("error")?.as_str()?.to_owned();
    let error_description =
        value.get("error_description").and_then(serde_json::Value::as_str).map(str::to_owned);
    Some(OauthErrorResponse { error_code, error_description, status: Some(status) })
}

#[cfg(test)]
mod tests;
