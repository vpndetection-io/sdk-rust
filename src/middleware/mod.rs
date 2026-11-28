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
mod crawlers;
mod selectors;

use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::Value as Json;

pub use condition::{Bound, Condition, ConditionError, Conditions, Value, from_json};
pub use selectors::{IpSelector, RequestView, framework_ip, header, xff};

use crate::{Client, Error, LookupOptions, Verdict, is_bogon};

/// Defaults set for a request path rather than for a script: failing open
/// quickly beats holding a visitor while we try again.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2500);
pub const DEFAULT_RETRIES: u32 = 0;

/// The most crawler agents one address is looked up with while it is
/// remembered, which is an hour from its first.
pub const MAX_AGENTS_PER_ADDRESS: usize = 4;

/// How long an address's crawler agents are remembered: the client's default
/// cache TTL.
const AGENTS_TTL: Duration = Duration::from_secs(60 * 60);

/// How many addresses are remembered at once.
const AGENTS_ADDRESSES: u64 = 10_000;

/// Whether a `User-Agent` names a crawler, the only kind of agent whose verdict
/// can be `verified` or `spoofed`. It errs toward a match, which costs a lookup.
pub fn names_crawler(agent: &str) -> bool {
    let lower = agent.to_ascii_lowercase();
    crawlers::CRAWLER_TERMS.iter().any(|term| lower.contains(term))
}

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
/// [`Options::api_key`] on a paid plan: without one a lookup leaves out the
/// hosting, CDN and proxy flags, `is_bot` and the AS's `type`, and a condition
/// on one is reported missing by its path, never matched.
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

    /// Send the request's own `User-Agent` header with its lookup when it
    /// names a crawler, and never refuse a request whose answer's `user_agent`
    /// verdict is `verified`, whatever [`Options::block_condition`] matches; the
    /// answer is still attached. Any other agent, or none, is not sent, since its
    /// verdict could only be `not_bot`. One address is looked up with at most
    /// [`MAX_AGENTS_PER_ADDRESS`] crawler agents an hour: past those its lookup
    /// sends none, and a request passes as a crawler only where the answer's
    /// `bot.verified` is true. A keyless client, or a free key past its trial,
    /// is never answered a verdict, so nothing is let through and
    /// [`Options::on_missing_field`] says so once. Off by default, so the cache
    /// holds one answer per address rather than one per agent.
    pub allow_bots: bool,

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
            allow_bots: false,
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
    pub fn allow_bots(mut self, allow_bots: bool) -> Self {
        self.allow_bots = allow_bots;
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
    agents: Option<Agents>,
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
                // Through the SDK's own option, not a reqwest client built with
                // `.timeout()`: the SDK sets every API request's deadline itself,
                // and a per-request deadline overrides the client's.
                let mut builder =
                    Client::builder().retries(options.retries).timeout(options.timeout);
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
            agents: options.allow_bots.then(Agents::new),
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

        let mut lookup = LookupOptions::new();
        let claim = match &self.agents {
            Some(agents) => agents.claim(&ip, (view.header)("user-agent").as_deref()).await,
            None => None,
        };
        let agent = match &claim {
            Some(Claim::Sent(agent)) => Some(agent),
            _ => None,
        };
        if let Some(agent) = agent {
            lookup = lookup.user_agent(agent.clone());
        }
        let served = match self.client.lookup_served(&ip, lookup).await {
            Ok(served) => served,
            Err(error) => {
                return Ok(Lookup {
                    blocked: self.fail_closed,
                    ip: Some(ip),
                    result: None,
                    error: Some(Arc::new(error)),
                });
            }
        };

        let result = &served.lookup;
        if agent.is_some() && !result.is_bogon && result.user_agent.is_none() {
            self.report(
                "allow_bots sent the request's user agent, and the answer carries no user_agent \
                 verdict, so no crawler is let through: a keyless client, or a free key past its \
                 trial, is never answered one"
                    .to_owned(),
            )?;
        }
        let verified = match &claim {
            Some(Claim::Sent(_)) => {
                result.user_agent.as_ref().is_some_and(|ua| ua.verdict == Verdict::Verified)
            }
            Some(Claim::PastBound) => {
                result.bot.as_ref().is_some_and(|bot| bot.verified == Some(true))
            }
            None => false,
        };

        let blocked = match &self.condition {
            None => false,
            Some(_) if verified => false,
            Some(condition) => {
                // Only rendered when a condition exists: matching is by WIRE
                // name, and rendering it for every request that never had a
                // policy would be pure cost.
                let answer = served.wire();
                // A request that sent no agent has no verdict to lack, whatever the plan serves.
                let unsent: &[&str] =
                    if self.agents.is_some() && agent.is_none() { &["user_agent"] } else { &[] };
                // A bogon is answered locally, with every member but a verdict, which no plan explains.
                if !result.is_bogon {
                    self.report_missing(condition, &answer, unsent)?;
                }
                condition::matches(condition, &answer)
            }
        };
        Ok(Lookup { blocked, ip: Some(ip), result: Some(served.lookup), error: None })
    }

    fn report_missing(
        &self,
        condition: &[Condition],
        answer: &Json,
        unsent: &[&str],
    ) -> Result<(), ConditionError> {
        if self.on_missing_field == OnMissingField::Ignore {
            return Ok(());
        }
        let mut missing = condition::missing_members(condition, answer);
        missing.retain(|member| !unsent.contains(&member.as_str()));
        if missing.is_empty() {
            return Ok(());
        }
        self.report(format!(
            "block_condition names {}, which your plan does not include, so those terms can \
             never match. An absent member means \"not in your plan\", not \"checked, and no\".",
            missing.join(", ")
        ))
    }

    /// Says what the plan does not serve as [`OnMissingField`] asks: an error,
    /// a warning once, or nothing.
    fn report(&self, message: String) -> Result<(), ConditionError> {
        match self.on_missing_field {
            OnMissingField::Ignore => return Ok(()),
            OnMissingField::Fail => return Err(ConditionError::new(message)),
            OnMissingField::Warn => {}
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

/// What a request's crawler agent comes to.
enum Claim {
    /// The agent the lookup sends.
    Sent(String),
    /// The address already has [`MAX_AGENTS_PER_ADDRESS`] other agents, so the
    /// lookup sends none.
    PastBound,
}

/// The crawler agents each address was looked up with. Only a crawler's agent is
/// sent, and an address claiming more than [`MAX_AGENTS_PER_ADDRESS`] of them in
/// an hour sends none past those, so a visitor inventing an agent per request
/// spends at most that many lookups.
///
/// An agent is kept as a hash under a key drawn per process, so a long one costs
/// eight bytes and no agent can be made to collide with another.
#[derive(Clone)]
struct Agents {
    seen: moka::future::Cache<String, Arc<Mutex<Vec<u64>>>>,
    hasher: RandomState,
}

impl Agents {
    fn new() -> Self {
        // An entry is written once, when the address sends its first agent, and
        // later agents go into its list: a rewrite would restart the hour.
        let seen = moka::future::Cache::builder()
            .max_capacity(AGENTS_ADDRESSES)
            .time_to_live(AGENTS_TTL)
            .build();
        Self { seen, hasher: RandomState::new() }
    }

    /// What this request's agent comes to, or `None` when it names no crawler.
    async fn claim(&self, ip: &str, header: Option<&str>) -> Option<Claim> {
        let agent = header.map(str::trim).filter(|agent| names_crawler(agent))?;
        let known = self.seen.get_with(ip.to_owned(), async { Arc::default() }).await;
        let mut known = known.lock().unwrap_or_else(PoisonError::into_inner);
        let hash = self.hasher.hash_one(agent);
        if known.contains(&hash) {
            return Some(Claim::Sent(agent.to_owned()));
        }
        if known.len() >= MAX_AGENTS_PER_ADDRESS {
            return Some(Claim::PastBound);
        }
        known.push(hash);
        Some(Claim::Sent(agent.to_owned()))
    }
}

#[cfg(test)]
mod tests;
