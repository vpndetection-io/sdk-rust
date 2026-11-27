use std::ops::Deref;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use crate::models::LookupResponse;

/// What a lookup answers.
///
/// An `Option` member is one your plan does not include. It never means "we
/// could not check", so `None` and `Some(false)` are genuinely different
/// answers: `None` is "not in your plan", `Some(false)` is "checked, and no".
/// This is the single most important semantic in the library, and it is why
/// every tier-gated flag is an `Option<bool>` rather than a `bool`.
///
/// One member is the exception, kept a `String` for the type it has always had:
/// the network's `asn.type`. It is a paid plan's or the trial's, and an answer
/// that leaves it out, Unlimited's, reads `""`. The next major makes it an
/// `Option<String>`.
///
/// A detail object that is present but empty means the flag above it is false,
/// as does an empty `web` list.
/// A populated one always carries every one of its keys, empty values included.
///
/// The wire answer's fields are reachable straight off a `Lookup` through
/// [`Deref`], so `result.is_vpn` and `result.vpn` read as if they were its own,
/// and [`Lookup::answer`] is the wire object.
#[derive(Debug, Clone, PartialEq)]
pub struct Lookup {
    /// True for reserved space (private, loopback, documentation and the like),
    /// which this crate answers locally without a request. A served answer
    /// carries the API's own `is_bogon`, and this reads it.
    pub is_bogon: bool,

    /// The answer as it was served, with the wire's own optionality intact but
    /// for `asn.type`, which reads `""` when it left it out.
    pub answer: LookupResponse,
}

impl Lookup {
    pub(crate) fn served(answer: LookupResponse) -> Self {
        Self { is_bogon: answer.is_bogon.unwrap_or(false), answer }
    }
}

/// The members a paid plan or the trial serves and Unlimited does not, held at
/// the type they have always had until the next major, as JSON pointers into
/// the wire answer: the AS's type, which the generator reads as required.
pub(crate) const HELD: [&str; 1] = ["/asn/type"];

/// A [`Lookup`] and which held members its wire answer left out. The public
/// `String` reads those `""`; the middleware reads them as absent, which is
/// what makes a condition on one report the plan gap instead of reading an
/// empty value. It is what the cache and the requests in flight hold, so a
/// cached answer keeps what the wire said.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Served {
    pub(crate) lookup: Lookup,
    pub(crate) absent: Vec<&'static str>,
}

impl Served {
    /// An answer computed here, which carries every member.
    pub(crate) fn whole(lookup: Lookup) -> Self {
        Self { lookup, absent: Vec::new() }
    }

    pub(crate) fn from_value(wire: serde_json::Value) -> Result<Self, serde_json::Error> {
        let absent = HELD.into_iter().filter(|member| wire.pointer(member).is_none()).collect();
        let answer = serde_json::from_value::<LookupResponse>(wire)?;
        Ok(Self { lookup: Lookup::served(answer), absent })
    }

    /// The answer as the wire served it: JSON that leaves out each held member
    /// the wire left out.
    pub(crate) fn wire(&self) -> serde_json::Value {
        let mut wire = serde_json::to_value(&self.lookup.answer).unwrap_or(serde_json::Value::Null);
        for path in &self.absent {
            let Some((parent, member)) = path.rsplit_once('/') else { continue };
            if let Some(members) = wire.pointer_mut(parent).and_then(|at| at.as_object_mut()) {
                members.remove(member);
            }
        }
        wire
    }
}

impl<'de> Deserialize<'de> for Served {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = serde_json::Value::deserialize(deserializer)?;
        Self::from_value(wire).map_err(D::Error::custom)
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

    pub fn is_pubproxy_or_false(&self) -> bool {
        self.is_pubproxy.unwrap_or(false)
    }

    pub fn is_bot_or_false(&self) -> bool {
        self.is_bot.unwrap_or(false)
    }

    pub fn is_anycast_or_false(&self) -> bool {
        self.is_anycast.unwrap_or(false)
    }

    pub fn is_carrier_or_false(&self) -> bool {
        self.is_carrier.unwrap_or(false)
    }

    pub fn is_satellite_or_false(&self) -> bool {
        self.is_satellite.unwrap_or(false)
    }

    pub fn is_ssh_or_false(&self) -> bool {
        self.is_ssh.unwrap_or(false)
    }

    pub fn is_smtp_or_false(&self) -> bool {
        self.is_smtp.unwrap_or(false)
    }

    pub fn is_web_or_false(&self) -> bool {
        self.is_web.unwrap_or(false)
    }

    pub fn is_dns_resolver_or_false(&self) -> bool {
        self.is_dns_resolver.unwrap_or(false)
    }

    pub fn is_bittorrent_or_false(&self) -> bool {
        self.is_bittorrent.unwrap_or(false)
    }
}
