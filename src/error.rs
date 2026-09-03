use std::time::Duration;

use serde::Deserialize;

/// What every failure from this crate is.
///
/// Match on [`Error::kind`] to branch, or ask [`Error::retryable`] whether
/// retrying this exact request could succeed. The client already retries what
/// is retryable, so an error that reaches you has usually run out of attempts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The API answered, and said no.
    #[error("vpndetection: {kind} (HTTP {status}): {message}")]
    Api {
        kind: ErrorKind,
        /// The API's own explanation.
        message: String,
        status: u16,
        /// How long the server asked us to wait. `None` when it did not ask,
        /// which on a 429 means an allowance is spent rather than throttled.
        retry_after: Option<Duration>,
    },

    /// No response arrived: a refused connection, a timeout, a TLS failure, or
    /// a body that could not be decoded. All are worth another attempt.
    #[error("vpndetection: network: {0}")]
    Network(#[from] reqwest::Error),

    /// The client was asked for something it cannot do, before any request was
    /// sent: an unusable base URL, or a cache sized at zero.
    #[error("vpndetection: {0}")]
    Config(String),
}

/// Why a request failed.
///
/// [`ErrorKind::RateLimited`] and [`ErrorKind::QuotaExceeded`] both arrive as
/// HTTP 429 and are NOT the same thing. A rate limit is the API protecting
/// itself, carries `Retry-After`, and retrying works. A spent quota carries no
/// such header, and retrying will not help until the window rolls over or the
/// limit is raised. The header is the only thing that distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    RateLimited,
    QuotaExceeded,
    ServerError,
    Network,
}

impl ErrorKind {
    /// The wire spelling, which is also the name the shared conformance corpus
    /// uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::RateLimited => "rate_limited",
            Self::QuotaExceeded => "quota_exceeded",
            Self::ServerError => "server_error",
            Self::Network => "network",
        }
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Api { kind, .. } => *kind,
            Self::Network(_) => ErrorKind::Network,
            Self::Config(_) => ErrorKind::BadRequest,
        }
    }

    /// Whether retrying this exact request could succeed.
    pub fn retryable(&self) -> bool {
        matches!(self.kind(), ErrorKind::RateLimited | ErrorKind::ServerError | ErrorKind::Network)
    }

    /// The API's own explanation, or the transport failure's text.
    pub fn message(&self) -> String {
        match self {
            Self::Api { message, .. } => message.clone(),
            Self::Network(e) => e.to_string(),
            Self::Config(m) => m.clone(),
        }
    }

    /// The HTTP status, or `None` when no response was received.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// How long the server asked us to wait before retrying.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub(crate) fn from_response(status: u16, retry_after: Option<Duration>, body: &str) -> Self {
        let message = envelope_message(body)
            .unwrap_or_else(|| format!("request failed with status {status}"));
        let kind = match status {
            // Present means transient, absent means an allowance is spent.
            // Nothing else in the response separates the two.
            429 if retry_after.is_some() => ErrorKind::RateLimited,
            429 => ErrorKind::QuotaExceeded,
            401 => ErrorKind::Unauthorized,
            403 => ErrorKind::Forbidden,
            // Any other 4xx is a CLIENT error. Falling through to the
            // server_error default would make it retryable, so a bad dataset id
            // would be retried twice before failing. Classify on the RANGE, not
            // on an enumerated list.
            400..=499 => ErrorKind::BadRequest,
            _ => ErrorKind::ServerError,
        };
        Self::Api { kind, message, status, retry_after }
    }
}

/// The two APIs behind this host answer with different envelopes: the lookup
/// endpoint uses `error`, the database endpoints use `rc`. Both are read here so
/// a caller never has to know which one they hit.
fn envelope_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Envelope {
        error: Option<String>,
        rc: Option<String>,
    }
    let envelope: Envelope = serde_json::from_str(body).ok()?;
    envelope.error.or(envelope.rc).filter(|m| !m.is_empty())
}
