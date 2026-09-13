//! The framework-agnostic half of a web middleware: resolve a client address,
//! classify it, and decide whether the condition matched.
//!
//! An adapter - [`vpndetection-axum`](https://crates.io/crates/vpndetection-axum)
//! is the one we publish - keeps only the parts that are genuinely
//! framework-shaped and shares everything here, so the shared conformance
//! corpus is asserted once for Rust rather than once per framework.
//!
//! Blocking is opt-in. Without a [`Options::block_condition`] this only
//! enriches: every request carries a [`Lookup`] and what it means is the
//! application's decision.

mod condition;
mod selectors;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value as Json;

pub use condition::{Bound, Condition, ConditionError, Conditions, Value, from_json};
pub use selectors::{IpSelector, RequestView, framework_ip, header, xff};

use crate::{Client, Error, is_bogon};

/// Defaults set for a request path rather than for a script: failing open
/// quickly beats holding a visitor while we try again.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2500);
pub const DEFAULT_RETRIES: u32 = 0;

/// What to do when a condition names a member the plan does not serve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnMissingField {
    #[default]
    Warn,
    Fail,
    Ignore,
}

/// Where warnings go. Defaults to `eprintln!`.
pub type Warn = Arc<dyn Fn(&str) + Send + Sync>;

/// How a middleware behaves.
///
/// Everything is optional except that you almost certainly want an
/// [`Options::api_key`]: the free allowance is counted per source address, and
/// a server is one source address.
#[derive(Clone)]
pub struct Options {
    /// An existing client to use. Prefer this if you already hold one: two
    /// clients mean two caches, and a cache is per instance because two keys
    /// can be on different plans and entitled to different fields.
    pub client: Option<Client>,

    pub api_key: Option<String>,

    pub base_url: Option<String>,

    /// How long a lookup may hold the request. Ignored when `client` is set.
    pub timeout: Duration,

    /// Retry attempts for a transient failure. Ignored when `client` is set.
    pub retries: u32,

    /// How the client address is decided. Defaults to the framework's own
    /// accessor.
    pub ip_selector: Option<IpSelector>,

    /// What to block on. Leave it empty to only enrich the request.
    pub block_condition: Option<Conditions>,

    /// Block when the lookup itself fails. Our outage should not become yours.
    pub fail_closed: bool,

    pub on_missing_field: OnMissingField,

    pub on_warn: Option<Warn>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            client: None,
            api_key: None,
            base_url: None,
            timeout: DEFAULT_TIMEOUT,
            retries: DEFAULT_RETRIES,
            ip_selector: None,
            block_condition: None,
            fail_closed: false,
            on_missing_field: OnMissingField::default(),
            on_warn: None,
        }
    }
}

impl Options {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    #[must_use]
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    #[must_use]
    pub fn ip_selector(mut self, selector: IpSelector) -> Self {
        self.ip_selector = Some(selector);
        self
    }

    #[must_use]
    pub fn block_condition(mut self, conditions: impl Into<Conditions>) -> Self {
        self.block_condition = Some(conditions.into());
        self
    }

    #[must_use]
    pub fn fail_closed(mut self, fail_closed: bool) -> Self {
        self.fail_closed = fail_closed;
        self
    }

    #[must_use]
    pub fn on_missing_field(mut self, on: OnMissingField) -> Self {
        self.on_missing_field = on;
        self
    }

    #[must_use]
    pub fn on_warn(mut self, warn: Warn) -> Self {
        self.on_warn = Some(warn);
        self
    }
}

/// What a middleware attached to the request, whether or not it succeeded.
#[derive(Debug, Clone)]
pub struct Lookup {
    /// Whether the condition matched. Always false when none was configured.
    pub blocked: bool,

    /// The address that was classified, as the selector resolved it.
    pub ip: Option<String>,

    /// The answer. `None` when the lookup failed.
    pub result: Option<crate::Lookup>,

    /// Why the lookup failed. `None` when it succeeded.
    pub error: Option<Arc<Error>>,
}

/// Classifies one request and answers what the adapter should do with it.
#[derive(Clone)]
pub struct Core {
    client: Client,
    selector: IpSelector,
    condition: Option<Conditions>,
    fail_closed: bool,
    on_missing_field: OnMissingField,
    on_warn: Option<Warn>,
    warned: Arc<Mutex<HashSet<String>>>,
}

impl Core {
    /// Refuses a condition that constrains nothing, and builds a client when
    /// none was passed.
    pub fn new(options: Options) -> Result<Self, Error> {
        if let Some(condition) = &options.block_condition {
            condition::validate(condition).map_err(|e| Error::Config(e.to_string()))?;
        }
        let client = match options.client {
            Some(client) => client,
            None => {
                // A TOTAL timeout, unlike the SDK's own client, which bounds
                // CONNECT and the next byte so a multi-gigabyte dataset can
                // still be fetched through it. Nothing here downloads a
                // dataset, and what a request path needs bounded is the whole
                // wait.
                let http = reqwest::Client::builder()
                    .timeout(options.timeout)
                    .user_agent(concat!("vpndetection-rust/", env!("CARGO_PKG_VERSION")))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?;
                let mut builder = Client::builder().retries(options.retries).http_client(http);
                if let Some(key) = options.api_key {
                    builder = builder.api_key(key);
                }
                if let Some(url) = options.base_url {
                    builder = builder.base_url(url);
                }
                builder.build()?
            }
        };
        Ok(Self {
            client,
            selector: options.ip_selector.unwrap_or_else(selectors::framework_ip),
            condition: options.block_condition,
            fail_closed: options.fail_closed,
            on_missing_field: options.on_missing_field,
            on_warn: options.on_warn,
            warned: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Whether a condition was configured at all.
    pub fn blocking(&self) -> bool {
        self.condition.is_some()
    }

    /// Classify one request.
    ///
    /// A failed LOOKUP is not an error here: it lands on [`Lookup::error`] and
    /// the request is let through. What CAN fail is a misconfiguration - a
    /// condition naming a member the plan does not serve, with
    /// [`OnMissingField::Fail`].
    pub async fn evaluate(&self, view: &RequestView<'_>) -> Result<Lookup, ConditionError> {
        let ip = (self.selector)(view).unwrap_or_default().trim().to_owned();
        if ip.is_empty() {
            self.warn(
                "could not resolve a client address from this request; pass an ip_selector \
                 that knows where yours comes from",
            );
            return Ok(Lookup {
                blocked: self.fail_closed,
                ip: None,
                result: None,
                error: Some(Arc::new(Error::Config("no client address on the request".to_owned()))),
            });
        }
        if is_bogon(&ip) {
            // Expected in local development. Anywhere else it means a proxy
            // sits in front and its own address is what reached us.
            self.warn(&format!(
                "resolved the client address as {ip}, which is not a public address. If this \
                 application runs behind a proxy or load balancer, configure its trusted-proxy \
                 setting or pass an ip_selector that reads your edge's header."
            ));
        }

        let result = match self.client.lookup(&ip).await {
            Ok(result) => result,
            Err(error) => {
                return Ok(Lookup {
                    blocked: self.fail_closed,
                    ip: Some(ip),
                    result: None,
                    error: Some(Arc::new(error)),
                });
            }
        };

        let blocked = match &self.condition {
            None => false,
            Some(condition) => {
                // Only rendered when a condition exists: matching is by WIRE
                // name, and rendering it for every request that never had a
                // policy would be pure cost.
                let answer = serde_json::to_value(&result.answer).unwrap_or(Json::Null);
                self.report_missing(condition, &answer)?;
                condition::matches(condition, &answer)
            }
        };
        Ok(Lookup { blocked, ip: Some(ip), result: Some(result), error: None })
    }

    fn report_missing(&self, condition: &[Condition], answer: &Json) -> Result<(), ConditionError> {
        if self.on_missing_field == OnMissingField::Ignore {
            return Ok(());
        }
        let missing = condition::missing_members(condition, answer);
        if missing.is_empty() {
            return Ok(());
        }
        let message = format!(
            "block_condition names {}, which your plan does not include, so those terms can \
             never match. An absent member means \"not in your plan\", not \"checked, and no\".",
            missing.join(", ")
        );
        if self.on_missing_field == OnMissingField::Fail {
            return Err(ConditionError::new(message));
        }
        self.warn(&message);
        Ok(())
    }

    // A misconfiguration is the same on every request, so saying so once is a
    // warning and saying so a million times is an outage of its own.
    fn warn(&self, message: &str) {
        let fresh = match self.warned.lock() {
            Ok(mut seen) => seen.insert(message.to_owned()),
            Err(_) => false,
        };
        if !fresh {
            return;
        }
        match &self.on_warn {
            Some(warn) => warn(message),
            None => eprintln!("[vpndetection] {message}"),
        }
    }
}
