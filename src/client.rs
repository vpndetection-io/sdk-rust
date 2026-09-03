use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use indexmap::IndexMap;
use moka::future::Cache;

use crate::bogon::{bogon_lookup, is_bogon};
use crate::database::Database;
use crate::error::Error;
use crate::lookup::Lookup;
use crate::models::LookupResponse;
use crate::transport::{Transport, encode_path_segment};

/// The production API. Override it with [`ClientBuilder::base_url`].
pub const DEFAULT_BASE_URL: &str = "https://api.vpndetection.io";

const DEFAULT_CACHE_CAPACITY: u64 = 10_000;
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_CONCURRENCY: usize = 8;
const DEFAULT_RETRIES: u32 = 2;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_BASE_DELAY: Duration = Duration::from_millis(250);

/// A client for the VPNDetection API.
///
/// Cloning is cheap and shares everything, including the cache and the
/// connection pool, so a clone per task is the intended way to use it across
/// one.
///
/// The cache is per instance and never global: two clients holding different API
/// keys are on different plans and entitled to different fields, so a shared
/// cache would serve one of them the other's shape.
#[derive(Debug, Clone)]
pub struct Client(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    transport: Transport,
    cache: Option<Cache<String, Lookup>>,
    concurrency: usize,
    retries: u32,
}

impl Client {
    /// A client on the free tier, against production. The free tier answers `ip`
    /// and `is_vpn` and allows 1000 requests per day per source address.
    pub fn new() -> Result<Self, Error> {
        Self::builder().build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Classifies one address.
    ///
    /// A bogon is answered locally and never reaches the network. Everything
    /// else is served, then cached for this client.
    pub async fn lookup(&self, ip: &str) -> Result<Lookup, Error> {
        self.lookup_with(ip, LookupOptions::new()).await
    }

    /// [`Client::lookup`], with this call's own retry budget.
    pub async fn lookup_with(&self, ip: &str, opts: LookupOptions) -> Result<Lookup, Error> {
        if is_bogon(ip) {
            return Ok(bogon_lookup(ip));
        }
        if let Some(cache) = &self.0.cache {
            if let Some(hit) = cache.get(ip).await {
                return Ok(hit);
            }
        }

        let path = format!("/{}", encode_path_segment(ip));
        let answer: LookupResponse = with_retry(opts.retries.unwrap_or(self.0.retries), || {
            self.0.transport.get_json(&path, &[])
        })
        .await?;

        let lookup = Lookup::served(answer);
        if let Some(cache) = &self.0.cache {
            cache.insert(ip.to_owned(), lookup.clone()).await;
        }
        Ok(lookup)
    }

    /// Classifies many addresses concurrently.
    ///
    /// The answers are keyed by address rather than positional, so duplicates in
    /// the input collapse to a single request and the caller never has to line
    /// two lists up. Keys are in the order the addresses were first seen. An
    /// address that fails carries its error as its value, so one bad entry
    /// cannot lose the rest of the answers.
    pub async fn lookup_batch<I, S>(
        &self,
        ips: I,
        opts: BatchOptions,
    ) -> IndexMap<String, Result<Lookup, Error>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let unique = dedupe(ips);
        let lookup_opts = LookupOptions { retries: opts.retries };
        let concurrency = opts.concurrency.unwrap_or(self.0.concurrency);

        // buffer_unordered completes out of order, so the answers are gathered
        // by INPUT index and only then assembled, which is what keeps the map
        // insertion-ordered whatever order the network answers in.
        let mut answers: Vec<Option<Result<Lookup, Error>>> =
            (0..unique.len()).map(|_| None).collect();
        {
            let mut stream = futures_util::stream::iter(unique.iter().enumerate())
                .map(|(i, ip)| {
                    let opts = lookup_opts.clone();
                    async move { (i, self.lookup_with(ip, opts).await) }
                })
                .buffer_unordered(concurrency);
            while let Some((i, answer)) = stream.next().await {
                answers[i] = Some(answer);
            }
        }

        unique
            .into_iter()
            .zip(answers)
            .map(|(ip, answer)| (ip, answer.expect("every address is answered exactly once")))
            .collect()
    }

    /// Whether an address is answered locally rather than served. Exposed here
    /// so the check is reachable from the client you already hold; the free
    /// [`crate::is_bogon`] is the same function.
    pub fn is_bogon(&self, ip: &str) -> bool {
        is_bogon(ip)
    }

    /// The licensed dataset downloads, for keys carrying the `db.download`
    /// scope.
    pub fn database(&self) -> Database<'_> {
        Database::new(self)
    }

    pub(crate) fn transport(&self) -> &Transport {
        &self.0.transport
    }

    pub(crate) fn retries(&self) -> u32 {
        self.0.retries
    }
}

/// Builds a [`Client`]. With nothing set it queries production on the free tier.
#[derive(Debug, Default)]
pub struct ClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    cache_capacity: Option<u64>,
    cache_ttl: Option<Duration>,
    cache_off: bool,
    concurrency: Option<usize>,
    retries: Option<u32>,
    http_client: Option<reqwest::Client>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Authenticates as the key's organization. Which fields a lookup answers
    /// with, and how many requests are allowed, follow the key's plan.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Points the client at a different deployment of the API.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Sizes the per-client answer cache. Defaults are 10000 addresses and a one
    /// hour TTL.
    pub fn cache(mut self, capacity: u64, ttl: Duration) -> Self {
        self.cache_capacity = Some(capacity);
        self.cache_ttl = Some(ttl);
        self.cache_off = false;
        self
    }

    /// Turns caching off, so every lookup of a non-bogon address is served.
    pub fn no_cache(mut self) -> Self {
        self.cache_off = true;
        self
    }

    /// How many requests a batch keeps in flight. Default 8.
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = Some(n);
        self
    }

    /// How many further attempts a transient failure gets. Default 2.
    pub fn retries(mut self, n: u32) -> Self {
        self.retries = Some(n);
        self
    }

    /// The HTTP client to send with, for a custom transport, proxy or timeout.
    /// Without one the SDK builds a client with a 30 second timeout.
    ///
    /// **Build it with [`reqwest::redirect::Policy::none`].** reqwest follows
    /// redirects by default and its policy is a client-level setting with no
    /// per-request override, so a following client would chase the download
    /// endpoint's 302 into object storage instead of handing back the link.
    /// [`Database::download_url`] refuses rather than downloading, but only
    /// after the request has been spent.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    pub fn build(self) -> Result<Client, Error> {
        let base_url = self.base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_owned());
        let parsed = reqwest::Url::parse(&base_url)
            .map_err(|e| Error::Config(format!("base url {base_url:?}: {e}")))?;
        if !parsed.has_host() {
            return Err(Error::Config(format!("base url {base_url:?} needs a scheme and a host")));
        }
        let concurrency = self.concurrency.unwrap_or(DEFAULT_CONCURRENCY);
        if concurrency == 0 {
            return Err(Error::Config("concurrency must be at least 1".to_owned()));
        }
        let capacity = self.cache_capacity.unwrap_or(DEFAULT_CACHE_CAPACITY);
        let ttl = self.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL);
        if capacity == 0 {
            return Err(Error::Config("cache capacity must be at least 1".to_owned()));
        }
        if ttl.is_zero() {
            return Err(Error::Config("cache ttl must be positive".to_owned()));
        }

        let http = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .timeout(DEFAULT_TIMEOUT)
                .user_agent(concat!("vpndetection-rust/", env!("CARGO_PKG_VERSION")))
                // The download endpoint answers 302 to object storage and the
                // dataset behind it runs to gigabytes, so the link is the answer
                // and following it is never what a caller wants.
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        };

        Ok(Client(Arc::new(Inner {
            transport: Transport::new(
                http,
                base_url.trim_end_matches('/').to_owned(),
                self.api_key,
            ),
            cache: (!self.cache_off)
                .then(|| Cache::builder().max_capacity(capacity).time_to_live(ttl).build()),
            concurrency,
            retries: self.retries.unwrap_or(DEFAULT_RETRIES),
        })))
    }
}

/// One call's overrides for [`Client::lookup_with`].
#[derive(Debug, Clone, Default)]
pub struct LookupOptions {
    retries: Option<u32>,
}

impl LookupOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the client's retry count for this call.
    pub fn retries(mut self, n: u32) -> Self {
        self.retries = Some(n);
        self
    }
}

/// One batch's overrides for [`Client::lookup_batch`].
///
/// `concurrency` lives here and not on [`LookupOptions`], so passing it to a
/// single lookup does not compile rather than being accepted and ignored.
#[derive(Debug, Clone, Default)]
pub struct BatchOptions {
    retries: Option<u32>,
    concurrency: Option<usize>,
}

impl BatchOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the client's retry count for every address in this batch.
    pub fn retries(mut self, n: u32) -> Self {
        self.retries = Some(n);
        self
    }

    /// Overrides the client's in-flight request limit for this batch, so one
    /// large batch does not need a second client to widen it.
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = Some(n.max(1));
        self
    }
}

/// Backs off exponentially, except that a server-supplied `Retry-After` wins
/// over the schedule. A 429 WITHOUT that header is a spent allowance rather than
/// a throttle and is not retried at all, which [`Error::retryable`] decides.
pub(crate) async fn with_retry<T, F, Fut>(retries: u32, mut attempt: F) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let mut delay = RETRY_BASE_DELAY;
    let mut remaining = retries;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) if remaining == 0 || !err.retryable() => return Err(err),
            Err(err) => {
                tokio::time::sleep(err.retry_after().unwrap_or(delay)).await;
                delay *= 2;
                remaining -= 1;
            }
        }
    }
}

fn dedupe<I, S>(ips: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = std::collections::HashSet::new();
    ips.into_iter().map(|ip| ip.as_ref().to_owned()).filter(|ip| seen.insert(ip.clone())).collect()
}
