use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use indexmap::IndexMap;
use moka::future::Cache;

use crate::bogon::{bogon_lookup, is_bogon};
use crate::database::DatabaseApi;
use crate::entitlement::Entitlement;
use crate::error::{Error, ErrorKind};
use crate::flight::{Flights, restate};
use crate::lookup::Lookup;
use crate::models::{BatchLookupRequest, BatchLookupResponse, LookupResponse};
use crate::oauth::{OauthApi, OauthError};
use crate::transport::{Transport, encode_path_segment};

/// The production API. Override it with [`ClientBuilder::base_url`].
pub const DEFAULT_BASE_URL: &str = "https://api.vpndetection.io";

const DEFAULT_CACHE_CAPACITY: u64 = 10_000;
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_CONCURRENCY: usize = 8;
const DEFAULT_RETRIES: u32 = 2;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
// The CLIENT bounds how long we wait for CONNECT and for the next BYTE, never the
// whole transfer: a total `.timeout()` on it would also cover a dataset's body, and
// a download that legitimately takes longer aborts however healthy the link is.
// The whole-request bound is set per API request instead (`DEFAULT_TIMEOUT`).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
/// The longest `Retry-After` waited out as given, 2^31 - 1 ms. One past it reads
/// like a header that will not parse, a throttle all the same, so the call waits
/// its own backoff instead: a `Retry-After` of 2147484 held a call for 24.8 days,
/// and 9223372036854775807 or a year-9999 date for good (5.2.2, measured
/// 2026-09-25), with tokio clamping rather than refusing the sleep.
const MAX_RETRY_AFTER: Duration = Duration::from_millis(2_147_483_647);
/// The most addresses `POST /batch` takes in one call; a larger batch is sent
/// in chunks of this size.
const BATCH_MAX: usize = 1000;

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
    /// The addresses with a request in flight, shared by a lookup and a batch.
    /// Only a client that caches shares them: without a cache every lookup is
    /// served, as [`ClientBuilder::no_cache`] promises.
    flights: Flights,
    concurrency: usize,
    retries: u32,
    timeout: Duration,
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
    /// else is served, then cached for this client. Calls that miss the cache
    /// while a request for their address is in flight, a batch's included, await
    /// that request rather than sending their own.
    pub async fn lookup(&self, ip: &str) -> Result<Lookup, Error> {
        self.lookup_with(ip, LookupOptions::new()).await
    }

    /// [`Client::lookup`], with this call's own retry budget and timeout. A call
    /// that joins a request already in flight takes that request's answer, sent
    /// under the options of the call that led it.
    pub async fn lookup_with(&self, ip: &str, opts: LookupOptions) -> Result<Lookup, Error> {
        let timeout = self.call_timeout(opts.timeout)?;
        let retries = opts.retries.unwrap_or(self.0.retries);
        if is_bogon(ip) {
            return Ok(bogon_lookup(ip));
        }
        let Some(cache) = &self.0.cache else {
            return self.serve(ip, retries, timeout).await;
        };

        loop {
            if let Some(hit) = cache.get(ip).await {
                return Ok(hit);
            }
            let (mut pilot, joined) = self.0.flights.board([ip]);
            if let Some((_, flight)) = joined.into_iter().next() {
                match flight.await {
                    Ok(landed) => return restate(&landed),
                    // Its leader was dropped before the answer landed.
                    Err(_) => continue,
                }
            }
            // A request that landed between the miss above and boarding cached
            // its answer before leaving the board, so it is found here.
            let answer = match cache.get(ip).await {
                Some(hit) => Ok(hit),
                None => {
                    let answer = self.serve(ip, retries, timeout).await;
                    if let Ok(lookup) = &answer {
                        cache.insert(ip.to_owned(), lookup.clone()).await;
                    }
                    answer
                }
            };
            pilot.land(ip, &answer);
            return answer;
        }
    }

    async fn serve(&self, ip: &str, retries: u32, timeout: Duration) -> Result<Lookup, Error> {
        let path = format!("/{}", encode_path_segment(ip));
        let answer: LookupResponse =
            with_retry(retries, || self.0.transport.get_json(&path, &[], timeout)).await?;
        Ok(Lookup::served(answer))
    }

    /// Classifies the address this client is calling from.
    ///
    /// The same answer [`Client::lookup`] would give for that address, at the
    /// same cost against your allowance. The address is the one our edge
    /// observed, so a call made through a proxy or a VPN reports the exit it
    /// left through - usually the point of asking.
    ///
    /// Deliberately NOT cached. The cache is keyed by address, and which
    /// address this is IS the question: a machine that moves between networks
    /// would otherwise be told where it used to be.
    pub async fn my_ip(&self) -> Result<Lookup, Error> {
        self.my_ip_with(LookupOptions::new()).await
    }

    /// [`Client::my_ip`], with this call's own retry budget and timeout.
    pub async fn my_ip_with(&self, opts: LookupOptions) -> Result<Lookup, Error> {
        let timeout = self.call_timeout(opts.timeout)?;
        let answer: LookupResponse = with_retry(opts.retries.unwrap_or(self.0.retries), || {
            self.0.transport.get_json("/myip", &[], timeout)
        })
        .await?;
        Ok(Lookup::served(answer))
    }

    /// What this client's key is entitled to, and how much of it has been used.
    ///
    /// Named for what it answers rather than `me`, which sits one letter from
    /// [`Client::my_ip`] and means something quite different: one is which
    /// address you are calling FROM, the other is what the key you are calling
    /// WITH may spend.
    ///
    /// Unlike a lookup there is no useful unauthenticated answer, so a client
    /// built without an API key gets an unauthorized error rather than a
    /// partial one.
    ///
    /// Usage counts against the ALLOWANCE WINDOW - the anniversary of the
    /// subscription, not the calendar month and not the billing period - and it
    /// is the same number a lookup is gated on. It can lag by a few seconds,
    /// because requests are counted in memory and flushed in aggregate.
    ///
    /// Deliberately NOT cached: the whole point is what has been spent, and a
    /// cached answer is a wrong one within seconds of the next request.
    pub async fn my_entitlement(&self) -> Result<Entitlement, Error> {
        self.my_entitlement_with(LookupOptions::new()).await
    }

    /// [`Client::my_entitlement`], with this call's own retry budget and timeout.
    pub async fn my_entitlement_with(&self, opts: LookupOptions) -> Result<Entitlement, Error> {
        let timeout = self.call_timeout(opts.timeout)?;
        with_retry(opts.retries.unwrap_or(self.0.retries), || {
            self.0.transport.get_json("/api/v1/entitlement", &[], timeout)
        })
        .await
    }

    /// Classifies many addresses in as few requests as possible.
    ///
    /// Bogons are answered locally and cached answers are reused, and an address
    /// with a request already in flight, a single lookup's or another batch's,
    /// awaits that request; everything else goes to `POST /batch` in chunks of up
    /// to 1000 addresses, with at most `concurrency` chunks in flight. The answers are keyed by address
    /// rather than positional, so duplicates in the input collapse to a single
    /// entry and the caller never has to line two lists up. Keys are in the
    /// order the addresses were first seen. An address that fails carries its
    /// error as its value, so one bad entry cannot lose the rest of the answers:
    /// the API reports a per-entry failure with the status the single lookup
    /// would have answered, and a chunk that fails as a whole marks every
    /// address in it.
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
        let retries = opts.retries.unwrap_or(self.0.retries);
        let concurrency = opts.concurrency.unwrap_or(self.0.concurrency);
        let refused = match self.call_timeout(opts.timeout) {
            Err(err) => Some(err.message()),
            Ok(_) if concurrency == 0 => Some("concurrency must be at least 1".to_owned()),
            Ok(_) => None,
        };
        if let Some(message) = refused {
            return unique
                .into_iter()
                .map(|ip| (ip, Err(Error::Config(message.clone()))))
                .collect();
        }
        let timeout = opts.timeout.unwrap_or(self.0.timeout);

        let mut answers: HashMap<String, Result<Lookup, Error>> =
            HashMap::with_capacity(unique.len());
        let mut pending: Vec<String> = Vec::new();
        for ip in &unique {
            if is_bogon(ip) {
                answers.insert(ip.clone(), Ok(bogon_lookup(ip)));
                continue;
            }
            if let Some(cache) = &self.0.cache {
                if let Some(hit) = cache.get(ip).await {
                    answers.insert(ip.clone(), Ok(hit));
                    continue;
                }
            }
            pending.push(ip.clone());
        }

        // Each address with a request in flight awaits it, and the rest are
        // boarded before any chunk is built, so a lookup arriving meanwhile
        // awaits this batch's answer in turn. A request that landed since the
        // cache was read above cached its answer first, so a led address is
        // looked up there once more before it is sent.
        let (mut pilot, joined) = match &self.0.cache {
            Some(_) => self.0.flights.board(pending.iter().map(String::as_str)),
            None => self.0.flights.board([]),
        };
        let mut send: Vec<String> = Vec::with_capacity(pending.len());
        for ip in pending {
            if joined.iter().any(|(joined_ip, _)| *joined_ip == ip) {
                continue;
            }
            if let Some(cache) = self.0.cache.as_ref().filter(|_| pilot.leads(&ip)) {
                if let Some(hit) = cache.get(&ip).await {
                    let hit = Ok(hit);
                    pilot.land(&ip, &hit);
                    answers.insert(ip, hit);
                    continue;
                }
            }
            send.push(ip);
        }

        // buffer_unordered completes out of order, so each chunk's answers are
        // gathered as they land and the map is assembled in input order at the
        // end, which is what keeps it insertion-ordered whatever order the
        // network answers in.
        let chunks: Vec<Vec<String>> = send.chunks(BATCH_MAX).map(<[String]>::to_vec).collect();
        {
            let mut stream = futures_util::stream::iter(chunks)
                .map(|chunk| async move { self.lookup_chunk(chunk, retries, timeout).await })
                .buffer_unordered(concurrency);
            while let Some(chunk_answers) = stream.next().await {
                for (ip, answer) in chunk_answers {
                    pilot.land(&ip, &answer);
                    answers.insert(ip, answer);
                }
            }
        }
        drop(pilot);
        for (ip, flight) in joined {
            let answer = match flight.await {
                Ok(landed) => restate(&landed),
                // Its leader was dropped before the answer landed, so this one
                // goes alone, sharing whatever is in flight by then.
                Err(_) => {
                    let opts = LookupOptions { retries: Some(retries), timeout: Some(timeout) };
                    self.lookup_with(&ip, opts).await
                }
            };
            answers.insert(ip, answer);
        }

        unique
            .into_iter()
            .map(|ip| {
                let answer = answers.remove(&ip).expect("every address is answered exactly once");
                (ip, answer)
            })
            .collect()
    }

    /// One `POST /batch`, mapped back onto the addresses it was asked about. A
    /// chunk-level failure - the call refused, the transport failing, the
    /// retries exhausted - becomes every address's error, exactly as it would
    /// have been had each been looked up alone.
    async fn lookup_chunk(
        &self,
        chunk: Vec<String>,
        retries: u32,
        timeout: Duration,
    ) -> Vec<(String, Result<Lookup, Error>)> {
        let request = BatchLookupRequest { ips: chunk.clone() };
        let answered: Result<BatchLookupResponse, Error> =
            with_retry(retries, || self.0.transport.post_json("/batch", &request, timeout)).await;
        let mut body = match answered {
            Ok(body) => body,
            Err(err) => return chunk.into_iter().map(|ip| (ip, Err(err.restated()))).collect(),
        };
        let mut out = Vec::with_capacity(chunk.len());
        for ip in chunk {
            let answer = if let Some(served) = body.results.remove(&ip) {
                let lookup = Lookup::served(served);
                if let Some(cache) = &self.0.cache {
                    cache.insert(ip.clone(), lookup.clone()).await;
                }
                Ok(lookup)
            } else if let Some(failed) = body.errors.remove(&ip) {
                Err(Error::from_entry(u16::try_from(failed.status).unwrap_or(500), &failed.error))
            } else {
                Err(Error::Api {
                    kind: ErrorKind::ServerError,
                    message: format!("the batch answer did not include {ip}"),
                    status: 200,
                    retry_after: None,
                })
            };
            out.push((ip, answer));
        }
        out
    }

    /// Whether an address is answered locally rather than served. Exposed here
    /// so the check is reachable from the client you already hold; the free
    /// [`crate::is_bogon`] is the same function.
    pub fn is_bogon(&self, ip: &str) -> bool {
        is_bogon(ip)
    }

    /// The licensed dataset downloads, for keys carrying the `db.download`
    /// scope.
    pub fn database(&self) -> DatabaseApi<'_> {
        DatabaseApi::new(self)
    }

    /// Signing a person in with the OAuth device flow, so a program on their
    /// own machine can be handed one of their API keys. These requests never
    /// carry this client's API key, so a client built without one works.
    pub fn oauth(&self) -> OauthApi<'_> {
        OauthApi::new(self)
    }

    pub(crate) fn transport(&self) -> &Transport {
        &self.0.transport
    }

    pub(crate) fn retries(&self) -> u32 {
        self.0.retries
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.0.timeout
    }

    /// One call's timeout: its own, else the client's. Zero is refused here, before
    /// a bogon or a cache hit could answer without a request to fail, since no
    /// attempt can meet it: accepted, it failed every call as a retried network
    /// error after ~750 ms of backoff (5.2.2, measured 2026-09-25). `build`
    /// refuses the client's own zero. `Duration::MAX` needs no refusal, since
    /// tokio clamps a deadline past its reach rather than failing.
    pub(crate) fn call_timeout(&self, per_call: Option<Duration>) -> Result<Duration, Error> {
        match per_call {
            Some(timeout) if timeout.is_zero() => {
                Err(Error::Config("timeout must be positive".to_owned()))
            }
            Some(timeout) => Ok(timeout),
            None => Ok(self.0.timeout),
        }
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
    timeout: Option<Duration>,
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

    /// How long one attempt at an API request may take, from connecting to the
    /// last byte of the answer. Default 30 seconds.
    ///
    /// Per ATTEMPT, so a call that is retried can take longer in total. A
    /// dataset transfer is exempt: a download runs for as long as the file
    /// takes, and only a connection that stops moving fails it. A request that
    /// runs out of time is an [`Error::Network`], which is retryable.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The HTTP client to send with, for a custom transport or proxy. Without
    /// one the SDK builds a client that gives up on a connection after 10
    /// seconds and on a read that stalls for 30.
    ///
    /// Each API request's deadline is still [`ClientBuilder::timeout`], which
    /// takes precedence over a total timeout configured on this client. That
    /// one does still apply to a dataset transfer, so leave it unset unless you
    /// mean to cap how large a download can be.
    ///
    /// **Build it with [`reqwest::redirect::Policy::none`].** reqwest follows
    /// redirects by default and its policy is a client-level setting with no
    /// per-request override, so a following client would chase the download
    /// endpoint's 302 into object storage instead of handing back the link.
    /// [`DatabaseApi::download_url`] refuses rather than downloading, but only
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
        let timeout = self.timeout.unwrap_or(DEFAULT_TIMEOUT);
        if timeout.is_zero() {
            return Err(Error::Config("timeout must be positive".to_owned()));
        }

        let http = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .read_timeout(DEFAULT_READ_TIMEOUT)
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
            flights: Flights::default(),
            concurrency,
            retries: self.retries.unwrap_or(DEFAULT_RETRIES),
            timeout,
        })))
    }
}

/// One call's overrides for [`Client::lookup_with`], [`Client::my_ip_with`] and
/// [`Client::my_entitlement_with`].
#[derive(Debug, Clone, Default)]
pub struct LookupOptions {
    retries: Option<u32>,
    timeout: Option<Duration>,
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

    /// Overrides [`ClientBuilder::timeout`] for this call, still per attempt.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
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
    timeout: Option<Duration>,
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
    /// large batch does not need a second client to widen it. Zero refuses the
    /// whole batch as a bad request before any request is sent.
    pub fn concurrency(mut self, n: usize) -> Self {
        self.concurrency = Some(n);
        self
    }

    /// Overrides [`ClientBuilder::timeout`] for each attempt at each chunk of
    /// this batch.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// Backs off exponentially, except that a server-supplied `Retry-After` wins
/// over the schedule, up to [`MAX_RETRY_AFTER`]. A 429 WITHOUT that header is a spent allowance rather than
/// a throttle and is not retried at all, which [`Error::retryable`] decides.
pub(crate) async fn with_retry<T, E, F, Fut>(retries: u32, mut attempt: F) -> Result<T, E>
where
    E: Retry,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut delay = RETRY_BASE_DELAY;
    let mut remaining = retries;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) if remaining == 0 || !err.retryable() => return Err(err),
            Err(err) => {
                let wait = err.retry_after().filter(|wait| *wait <= MAX_RETRY_AFTER);
                tokio::time::sleep(wait.unwrap_or(delay)).await;
                delay = delay.saturating_mul(2);
                remaining -= 1;
            }
        }
    }
}

/// What [`with_retry`] asks of a failure, so the OAuth calls retry by the same
/// rules without folding their refusals into [`Error`].
pub(crate) trait Retry {
    fn retryable(&self) -> bool;
    fn retry_after(&self) -> Option<Duration>;
}

impl Retry for Error {
    fn retryable(&self) -> bool {
        Error::retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        Error::retry_after(self)
    }
}

impl Retry for OauthError {
    fn retryable(&self) -> bool {
        OauthError::retryable(self)
    }

    fn retry_after(&self) -> Option<Duration> {
        OauthError::retry_after(self)
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
