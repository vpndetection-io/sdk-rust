use std::time::Duration;

use serde::Deserialize;

/// What every failure from this crate is.
///
/// Match on [`Error::kind`] to branch, or ask [`Error::retryable`] whether
/// retrying this exact request could succeed. The client already retries what
/// is retryable, so an error that reaches you has usually run out of attempts.
#[derive(Debug)]
pub enum Error {
    /// The API answered, and said no.
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
    Network(reqwest::Error),

    /// A dataset transfer failed on this side of the socket: the stream ended
    /// before the promised length (`UnexpectedEof`), the disk filled, or the
    /// destination could not be written. The inner
    /// [`std::io::ErrorKind`] is what tells those apart.
    Io(std::io::Error),

    /// The client was asked for something it cannot do, before any request was
    /// sent: an unusable base URL, or a cache sized at zero.
    Config(String),
}

// Written out rather than derived, because one shape needs a conditional: a
// chunk-level failure restated per address (`Error::restated`) is API-shaped
// but never had an HTTP status, and printing `(HTTP 0)` would be a lie.
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api { kind, message, status: 0, .. } => {
                write!(f, "vpndetection: {kind}: {message}")
            }
            Self::Api { kind, message, status, .. } => {
                write!(f, "vpndetection: {kind} (HTTP {status}): {message}")
            }
            Self::Network(_) => write!(f, "vpndetection: network: {}", self.message()),
            Self::Io(e) => write!(f, "vpndetection: io: {e}"),
            Self::Config(m) => write!(f, "vpndetection: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Network(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Api { .. } | Self::Config(_) => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Network(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
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
    Io,
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
            Self::Io => "io",
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
            Self::Io(_) => ErrorKind::Io,
            Self::Config(_) => ErrorKind::BadRequest,
        }
    }

    /// Whether retrying this exact request could succeed.
    ///
    /// A transfer that ended early is worth another attempt and a full disk is
    /// not, and both arrive as [`Error::Io`], so the two are separated by the
    /// inner [`std::io::ErrorKind`] rather than lumped together.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Io(e) => e.kind() == std::io::ErrorKind::UnexpectedEof,
            _ => matches!(
                self.kind(),
                ErrorKind::RateLimited | ErrorKind::ServerError | ErrorKind::Network
            ),
        }
    }

    /// The API's own explanation, or the transport failure's text.
    pub fn message(&self) -> String {
        match self {
            Self::Api { message, .. } => message.clone(),
            // reqwest names a timeout only in its source chain, which a batch
            // entry restating this error does not keep.
            Self::Network(e) if e.is_timeout() => format!("timed out: {e}"),
            Self::Network(e) => e.to_string(),
            Self::Io(e) => e.to_string(),
            Self::Config(m) => m.clone(),
        }
    }

    /// The HTTP status, or `None` when no response was received.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } if *status != 0 => Some(*status),
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
        Self::Api { kind: kind_for_status(status, retry_after), message, status, retry_after }
    }

    /// A per-entry failure inside a successful batch: the status the single
    /// lookup would have answered, and its message, with no headers at all - so
    /// a 429 here is a spent allowance, which is the only kind the API puts in
    /// an entry.
    pub(crate) fn from_entry(status: u16, message: &str) -> Self {
        Self::Api {
            kind: kind_for_status(status, None),
            message: message.to_owned(),
            status,
            retry_after: None,
        }
    }

    /// The same failure again, for every address in a chunk that failed as a
    /// whole. `reqwest::Error` and `std::io::Error` do not clone, so the
    /// failure is restated as an API-shaped error with the same kind, message
    /// and retry advice; a transport failure keeps `status()` at `None`.
    pub(crate) fn restated(&self) -> Self {
        Self::Api {
            kind: self.kind(),
            message: self.message(),
            status: self.status().unwrap_or(0),
            retry_after: self.retry_after(),
        }
    }
}

/// What a status code means for a caller. Object storage answers a spent
/// presigned link with the same codes the API uses, so the mapping is shared
/// rather than written twice.
pub(crate) fn kind_for_status(status: u16, retry_after: Option<Duration>) -> ErrorKind {
    match status {
        // Present means transient, absent means an allowance is spent. Nothing
        // else in the response separates the two.
        429 if retry_after.is_some() => ErrorKind::RateLimited,
        429 => ErrorKind::QuotaExceeded,
        401 => ErrorKind::Unauthorized,
        403 => ErrorKind::Forbidden,
        // Any other 4xx is a CLIENT error. Falling through to the server_error
        // default would make it retryable, so a bad dataset id would be retried
        // twice before failing. Classify on the RANGE, not on an enumerated
        // list.
        400..=499 => ErrorKind::BadRequest,
        _ => ErrorKind::ServerError,
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
