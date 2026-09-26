# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="28"/>](https://vpndetection.io/) VPNDetection Rust Client Library

[![crates.io](https://img.shields.io/crates/v/vpndetection.svg)](https://crates.io/crates/vpndetection)
[![docs.rs](https://img.shields.io/docsrs/vpndetection)](https://docs.rs/vpndetection)
[![license](https://img.shields.io/crates/l/vpndetection.svg)](LICENSE)

The official Rust client library for the [VPNDetection](https://vpndetection.io) API.

The library helps you query VPNDetection's APIs for anonymity detection including VPNs, residential proxies, Tor nodes, hosting servers, CDNs, relays and more.

## Getting Started

```bash
cargo add vpndetection
```

Requires Rust 1.85 or newer. Everything is `async` and runs on tokio.

## Usage

**No API key needed to start.** The free tier answers `ip` and `is_vpn`, and allows 1000 requests per day per source address.

```rust
use vpndetection::Client;

let client = Client::new()?;

let result = client.lookup("45.83.91.1").await?;
println!("{}", result.is_vpn);   // true
```

### With an API key

An API key raises your quota, and raises your features on a paid plan. Create one in the [console](https://app.vpndetection.io), then pass it in:

```rust
let client = Client::builder()
    .api_key(std::env::var("VPNDETECTION_API_KEY")?)
    .build()?;

let result = client.lookup("45.83.91.1").await?;
println!("{}", result.is_vpn);                  // true
println!("{:?}", result.is_hosting);            // Some(true)

if let Some(vpn) = result.vpn.as_deref() {
    println!("{:?}", vpn.provider);             // Some("mullvad")
}
```

Every setting has a default, and `Client::builder()` is where you change one:

```rust
let client = Client::builder().api_key(key).concurrency(32).retries(4).build()?;
```

Each attempt at a request gives up after 30 seconds, and `timeout` changes that. A database download isn't bound by it, since a large one runs for minutes:

```rust
use std::time::Duration;

let client = Client::builder().api_key(key).timeout(Duration::from_secs(5)).build()?;
```

### Your own address

```rust
let result = client.my_ip().await?;
println!("{}", result.ip);   // the address we saw this call come from
```

Same answer `lookup` would give for that address, and the same cost against your allowance. It is deliberately not cached: which address you are is the whole question, and a machine that moves between networks would otherwise be told where it used to be.

### Your plan and usage

```rust
let acct = client.my_entitlement().await?;
println!("{}", acct.plan.key);            // max
println!("{}", acct.usage.requests);      // 580
println!("{}", acct.usage.window_end);    // when the allowance resets
```

Usage counts against the anniversary of your subscription, not the calendar month and not the billing period, and it is the same number a lookup is gated on. `hard_limit` is `None` on an uncapped plan, which is not the same as zero.

`my_ip_with` and `my_entitlement_with` take this call's own retry budget and timeout, the same as `lookup_with`.

### Batch lookup

Look up many addresses at once. Bogons and cached answers are handled locally, and everything else goes to the batch endpoint in chunks of up to 1000 addresses, in parallel:

```rust
use vpndetection::BatchOptions;

let results = client
    .lookup_batch(["45.83.91.1", "8.8.8.8", "1.1.1.1"], BatchOptions::new())
    .await;

for (ip, result) in &results {
    match result {
        Ok(result) => println!("{ip}: {}", result.is_vpn),
        Err(err) => eprintln!("{ip}: {err}"),
    }
}
```

Results are keyed by address and in the order you first listed each one, so duplicates in your list collapse into a single entry and one address failing never loses the rest: it carries its error as its value, with the status the API would have given that address on its own.

There's no limit on how many addresses you pass. How many chunks are in flight at once, how many times a failed chunk is retried, and how long each attempt may take are configurable per call:

```rust
let results = client
    .lookup_batch(
        many_ips,
        BatchOptions::new().concurrency(4).retries(4).timeout(Duration::from_secs(10)),
    )
    .await;
```

### Caching

Answers are cached by default, so repeat lookups of the same address are free:

```rust
let client = Client::new()?;

let result = client.lookup("45.83.91.1").await?;
println!("{}", result.is_vpn);    // true, API request

let result2 = client.lookup("45.83.91.1").await?;
println!("{}", result2.is_vpn);   // true, no API request, result was cached
```

You can change the default cache variables (max size, TTL, etc) on initialization, or even disable it:

```rust
use std::time::Duration;

let client = Client::builder().cache(50_000, Duration::from_secs(6 * 60 * 60)).build()?;
let client_no_cache = Client::builder().no_cache().build()?;
```

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```rust
let result = client.lookup("192.168.1.1").await?;
result.is_bogon;   // true, this answer was computed rather than served
result.is_vpn;     // false
```

Because the answer is computed rather than served, it always carries every field, whatever plan you are on. Do not read your plan's shape off a private address.

The check is available on the client, which is handy when your inputs are addresses anyway:

```rust
client.is_bogon("10.0.0.1");   // true
client.is_bogon("8.8.8.8");    // false
```

It is also callable on its own, if you want it without a client:

```rust
vpndetection::is_bogon("10.0.0.1");   // true
```

### Errors

Failures return a `vpndetection::Error` carrying a `kind()` and a `retryable()` flag:

```rust
use vpndetection::ErrorKind;

match client.lookup("1.1.1.1").await {
    Ok(result) => println!("{}", result.is_vpn),
    Err(err) => println!("{} {}", err.kind(), err.retryable()),
}
```

`kind()` is one of `BadRequest`, `Unauthorized`, `Forbidden`, `RateLimited`, `QuotaExceeded`, `ServerError`, `Network` or `Io`, the last of which is a database transfer that could not be written or that ended early.

Note that `RateLimited` and `QuotaExceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

### Database downloads

If your key carries the `db.download` scope, the licensed databases are available through `client.database()`. A license covers a database FAMILY, so the id you download comes from one of its `versions`:

```rust
use vpndetection::DatabaseFormat;

let families = client.database().list().await?;

let url = client.database().download_url("vpn_ip_extended_v1", DatabaseFormat::Mmdb).await?;
let raw = client.database().download_bytes("cdn_ip_v1", DatabaseFormat::Csvgz).await?;
let written = client.database().download("vpn_ip_extended_v1", DatabaseFormat::Mmdb, "./vpn_ip.mmdb").await?;
```

`download_url` hands back a time-limited link so you can run the transfer yourself. `download` streams to disk through a neighboring `.part` file, so nothing bigger than a chunk is ever held in memory and a transfer that dies half way leaves no truncated file. `download_bytes` holds the whole file in memory, and the catalog runs from `cdn_ip_v1` at 10 KB to `resproxy_ip_90d_v1` at 1.79 GB, so use `download` for anything you have not measured.

### Sign in with OAuth (device flow)

A program running on the person's own machine can let them sign in with a browser and pick one of their API keys, instead of asking them to paste it:

```rust
use vpndetection::{Client, DeviceAuthorizationOptions};

let client = Client::new()?;
let scope = DeviceAuthorizationOptions::new().scope("account.read apikeys.read apikeys.reveal");
let device = client.oauth().device_authorization_with("your-client-id", scope).await?;
println!("Open {} and enter {}", device.verification_uri, device.user_code);

let token = client.oauth().poll_device_token("your-client-id", &device).await?;
let Some(apikey) = token.apikey else {
    return Err("no API key came back: none was picked, or it cannot be shown again".into());
};
let keyed = Client::builder().api_key(apikey).build()?;
```

A denied sign-in fails with `OauthError::AccessDenied` and a code that ran out with `OauthError::ExpiredToken`. Client IDs are issued on request from support@vpndetection.io, and `client.oauth().revoke("your-client-id", &refresh_token)` signs the machine out again.

### TLS backends

`rustls` is the default, so the crate builds with no system libraries at all. If you would rather link the platform's TLS, or you already depend on `reqwest` with its own defaults and want one backend rather than two:

```toml
vpndetection = { version = "5", default-features = false, features = ["native-tls"] }
```

### Calling from synchronous code

There is no blocking facade, on purpose: `reqwest::blocking` builds its own runtime and panics when constructed inside one, so a facade would fail for exactly the callers most likely to reach for it. If you have no runtime, make the cost visible instead:

```rust
let runtime = tokio::runtime::Runtime::new()?;
let client = Client::new()?;
let result = runtime.block_on(client.lookup("45.83.91.1"))?;
```

### Absent is not false

Every field beyond `ip` and `is_vpn` is an `Option`, because your plan decides which of them the API sends. `None` means "not in your plan", which is not the same answer as `Some(false)`, which means "checked, and no".

```rust
result.is_hosting.unwrap_or(false);   // when you only want the flag
result.is_hosting.is_none();          // not in your plan
```

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="64"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
