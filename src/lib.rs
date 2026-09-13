//! The official Rust client library for the [VPNDetection](https://vpndetection.io)
//! API: anonymity detection covering VPNs, residential proxies, Tor nodes,
//! hosting servers, CDNs and relays.
//!
//! Start with [`Client::new`] and [`Client::lookup`]. No API key is needed: the
//! free tier answers `ip` and `is_vpn` and allows 1000 requests per day per
//! source address.
//!
//! ```no_run
//! # async fn run() -> Result<(), vpndetection::Error> {
//! let client = vpndetection::Client::new()?;
//!
//! let result = client.lookup("45.83.91.1").await?;
//! println!("{}", result.is_vpn);
//! # Ok(())
//! # }
//! ```
//!
//! # Absent is not false
//!
//! Every field beyond `ip` and `is_vpn` is an [`Option`], because your plan
//! decides which of them the API sends. `None` means "not in your plan", which
//! is a different answer from `Some(false)`. Read the option itself wherever
//! that matters, or `unwrap_or(false)` when all you want to know is whether an
//! address is flagged.
//!
//! # Async only
//!
//! Everything here is `async` on tokio, and there is no blocking facade.
//! `reqwest::blocking` builds its own runtime and PANICS when constructed inside
//! one, so a facade would fail for exactly the callers most likely to reach for
//! it. A caller with no runtime writes the three lines that make the cost
//! visible:
//!
//! ```no_run
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let runtime = tokio::runtime::Runtime::new()?;
//! let client = vpndetection::Client::new()?;
//! let result = runtime.block_on(client.lookup("45.83.91.1"))?;
//! # let _ = result;
//! # Ok(())
//! # }
//! ```

mod account;
mod bogon;
mod bogons;
mod client;
mod database;
mod error;
mod generated;
mod lookup;
pub mod middleware;
mod transport;

// The generated models refer to themselves as `crate::models`, so this binding
// is what lets scripts/generate.sh drop their output in untouched.
pub(crate) use generated::models;

pub use account::{Account, AccountApikey, AccountPlan, AccountUsage};
pub use bogon::is_bogon;
pub use client::{BatchOptions, Client, ClientBuilder, DEFAULT_BASE_URL, LookupOptions};
pub use database::DatabaseApi;
pub use error::{Error, ErrorKind};
pub use lookup::Lookup;

// The wire shapes, generated from the OpenAPI spec and re-exported so a consumer
// never has to name a private module. The format enum is named ONCE in the spec
// now, so `database.formats[0].format == DatabaseFormat::Mmdb` and the sample
// formats compare against the same type instead of a parallel one.
pub use generated::models::download::Outcome as DownloadOutcome;
pub use generated::models::{
    ClassDetail, Database, DatabaseFormatSize, DatabaseMetadata, DatabaseMetadataColumn,
    DatabaseVersion, DbChecksums, Download, LookupResponse, ProxyDetail, VpnDetail,
};
pub use generated::models::{DatabaseFormat, Standing};
// `license_type` is a NULLABLE enum, and naming one in the spec makes
// openapi-python-client emit three identical enums unioned together - so it
// stays inline, and the generator hangs its type off the model's own module
// rather than emitting a file for it.
pub use generated::models::database::LicenseType;
