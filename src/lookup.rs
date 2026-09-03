use std::ops::Deref;

use crate::models::LookupResponse;

/// What a lookup answers.
///
/// An `Option` member is one your plan does not include. It never means "we
/// could not check", so `None` and `Some(false)` are genuinely different
/// answers: `None` is "not in your plan", `Some(false)` is "checked, and no".
/// This is the single most important semantic in the library, and it is why
/// every tier-gated flag is an `Option<bool>` rather than a `bool`.
///
/// A detail object that is present but empty means the flag above it is false.
/// A populated one always carries every one of its keys, empty values included.
///
/// The wire answer's fields are reachable straight off a `Lookup` through
/// [`Deref`], so `result.is_vpn` and `result.vpn` read as if they were its own,
/// and [`Lookup::answer`] is the untouched wire object.
#[derive(Debug, Clone, PartialEq)]
pub struct Lookup {
    /// True when this answer was computed locally rather than served, which
    /// happens for a bogon and only for a bogon.
    pub is_bogon: bool,

    /// The answer as it was served, with the wire's own optionality intact.
    pub answer: LookupResponse,
}

impl Lookup {
    pub(crate) fn served(answer: LookupResponse) -> Self {
        Self { is_bogon: false, answer }
    }
}

/// `result.is_vpn` rather than `result.answer.is_vpn`. `Lookup` adds one field
/// to the served answer and hides nothing, so the deref is a widening rather
/// than the inheritance `Deref` is usually cautioned against.
impl Deref for Lookup {
    type Target = LookupResponse;

    fn deref(&self) -> &LookupResponse {
        &self.answer
    }
}

/// Readers that treat "not in your plan" as false, for callers who only want to
/// know whether an address is flagged. Read the `Option` itself wherever absent
/// and false must be told apart, which is the whole reason they are options.
///
/// `result.is_hosting.unwrap_or(false)` says the same thing and is what the
/// README teaches; these exist so a long match arm does not have to.
impl Lookup {
    pub fn is_hosting_or_false(&self) -> bool {
        self.is_hosting.unwrap_or(false)
    }

    pub fn is_relay_or_false(&self) -> bool {
        self.is_relay.unwrap_or(false)
    }

    pub fn is_tor_or_false(&self) -> bool {
        self.is_tor.unwrap_or(false)
    }

    pub fn is_cdn_or_false(&self) -> bool {
        self.is_cdn.unwrap_or(false)
    }

    pub fn is_resproxy_or_false(&self) -> bool {
        self.is_resproxy.unwrap_or(false)
    }

    pub fn is_dcproxy_or_false(&self) -> bool {
        self.is_dcproxy.unwrap_or(false)
    }

    pub fn is_mobproxy_or_false(&self) -> bool {
        self.is_mobproxy.unwrap_or(false)
    }
}
