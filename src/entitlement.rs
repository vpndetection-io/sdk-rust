//! What an API key is entitled to, and how much of it has been used.
//!
//! Hand-written rather than generated. The entitlement schemas carry `format: uuid`
//! fields, which the generator emits as `uuid::Uuid` - a fourth runtime
//! dependency for two opaque identifiers a client only ever passes through. See
//! the model allowlist in `scripts/generate.sh` for the same reasoning.

use serde::{Deserialize, Serialize};

/// What an API key is entitled to, and what it has spent.
///
/// Everything here describes the key that asked: there is no way to enquire
/// about another organization, because the credential IS the question.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entitlement {
    /// The organization the key belongs to.
    pub org_id: String,
    pub apikey: EntitlementApikey,
    pub plan: EntitlementPlan,
    pub usage: EntitlementUsage,
}

/// The credential itself.
///
/// The key is never echoed back - only its id, which is what the console shows
/// and what you can act on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntitlementApikey {
    pub id: String,
    /// `None` for a key with no end date, which is the normal case.
    #[serde(deserialize_with = "Option::deserialize")]
    pub expires: Option<chrono::DateTime<chrono::FixedOffset>>,
    /// The source addresses this key may be used from. EMPTY means
    /// unrestricted, never "deny all".
    pub allowed_cidrs: Vec<String>,
}

/// The plan behind the key, and the field tier it buys.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntitlementPlan {
    /// The plan the organization is on, e.g. `max`.
    pub key: String,
    /// The field tier, which decides how much of a lookup answer comes back:
    /// `free`, `starter`, `scale` or `max`. What each tier includes is
    /// documented on the lookup endpoint rather than repeated here.
    pub tier: String,
}

/// Consumption against the plan's allowance, in the current window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntitlementUsage {
    /// Requests counted in the current window. The same number a lookup is
    /// gated on, and it can lag by a few seconds.
    pub requests: i64,
    /// What the plan includes. Zero on a plan that includes none.
    pub quota: i64,
    /// Where we stop serving. `None` means NEVER, which is the normal state of
    /// an uncapped paid plan and is not the same as zero. Above the quota and
    /// below this, requests are served and billed as overage.
    #[serde(deserialize_with = "Option::deserialize")]
    pub hard_limit: Option<i64>,
    /// When the current allowance period began.
    pub window_start: chrono::DateTime<chrono::FixedOffset>,
    /// When the allowance next resets.
    pub window_end: chrono::DateTime<chrono::FixedOffset>,
}
