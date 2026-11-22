use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

use ipnet::IpNet;

use crate::bogons::{BOGON_V4, BOGON_V6};
use crate::lookup::Lookup;
use crate::models::{AbuseContact, Asn, Company, Location, LookupResponse};

/// Whether an address is private, loopback, link-local, documentation,
/// multicast or otherwise not routable on the public internet, including the
/// IPv6 equivalents and the 6to4 and Teredo ranges that wrap them.
///
/// These can never be VPN or proxy infrastructure, so the client answers them
/// itself and they never cost a request. [`Client::is_bogon`] is the same
/// check, for code that already holds a client.
///
/// [`Client::is_bogon`]: crate::Client::is_bogon
pub fn is_bogon(ip: &str) -> bool {
    let Ok(addr) = IpAddr::from_str(ip) else {
        return false;
    };
    // An IPv4-mapped address is judged as the IPv4 address it carries: read
    // whole it is inside ::ffff:0:0/96, and a listener on :: sees every IPv4
    // visitor that way.
    let addr = addr.to_canonical();
    let table: &[IpNet] = if addr.is_ipv4() { &PREFIXES_V4 } else { &PREFIXES_V6 };
    table.iter().any(|net| net.contains(&addr))
}

/// The IPv4 address an IPv4-mapped IPv6 address carries, dotted, and any other
/// string as given: what a lookup sends and caches.
pub(crate) fn unmapped(ip: &str) -> Cow<'_, str> {
    match IpAddr::from_str(ip) {
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => Cow::Owned(v4.to_string()),
            None => Cow::Borrowed(ip),
        },
        _ => Cow::Borrowed(ip),
    }
}

/// The answer a bogon gets: the full shape the API serves on its widest plan,
/// every flag present and false, every detail object present and empty (the
/// web servers' list empty), every key of the location, AS, company and abuse
/// contact empty and every number 0, an empty hostname, and `is_bogon` true,
/// as the API answers a bogon.
///
/// Deliberately the WIDEST shape whatever plan you are on, so a caller must not
/// infer which fields their plan includes from a bogon answer.
pub(crate) fn bogon_lookup(ip: &str) -> Lookup {
    let empty = || Some(String::new());
    Lookup {
        is_bogon: true,
        answer: LookupResponse {
            ip: ip.to_owned(),
            is_bogon: Some(true),
            is_vpn: false,
            is_hosting: Some(false),
            is_relay: Some(false),
            is_tor: Some(false),
            is_cdn: Some(false),
            is_bot: Some(false),
            is_resproxy: Some(false),
            is_dcproxy: Some(false),
            is_mobproxy: Some(false),
            is_pubproxy: Some(false),
            is_anycast: Some(false),
            is_carrier: Some(false),
            is_satellite: Some(false),
            is_ssh: Some(false),
            is_smtp: Some(false),
            is_web: Some(false),
            is_dns_resolver: Some(false),
            is_bittorrent: Some(false),
            vpn: Some(Box::default()),
            hosting: Some(Box::default()),
            relay: Some(Box::default()),
            tor: Some(Box::default()),
            cdn: Some(Box::default()),
            bot: Some(Box::default()),
            resproxy: Some(Box::default()),
            dcproxy: Some(Box::default()),
            mobproxy: Some(Box::default()),
            pubproxy: Some(Box::default()),
            carrier: Some(Box::default()),
            satellite: Some(Box::default()),
            ssh: Some(Box::default()),
            smtp: Some(Box::default()),
            web: Some(Vec::new()),
            dns_resolver: Some(Box::default()),
            bittorrent: Some(Box::default()),
            location: Some(Box::new(Location {
                region: empty(),
                region_code: empty(),
                city: empty(),
                postal_code: empty(),
                latitude: Some(0.0),
                longitude: Some(0.0),
                accuracy_radius: Some(0),
                geoname_id: empty(),
                dma_code: empty(),
                last_changed: empty(),
                ..Location::default()
            })),
            asn: Some(Box::new(Asn { country: empty(), rpki_status: empty(), ..Asn::default() })),
            company: Some(Box::new(Company {
                r#type: empty(),
                country: empty(),
                ..Company::default()
            })),
            hostname: empty(),
            abuse: Some(Box::new(AbuseContact {
                name: empty(),
                phone: empty(),
                address: empty(),
                country: empty(),
                network: empty(),
                validated: Some(false),
                unvalidated_since: empty(),
                ..AbuseContact::default()
            })),
            // Only an answer to a lookup that sent a user agent carries it.
            user_agent: None,
            // Only a free-plan key's answers carry it, and a bogon is answered here.
            trial_expired: None,
            // Only a paid key's answers carry it, and a bogon is answered here.
            cap_reached: None,
        },
    }
}

// Parsed on first use rather than at load, so a consumer that never looks an
// address up pays nothing. The table is generated and checked upstream and the
// suite parses every entry, so an unparseable one is a broken build rather than
// something a caller can hit.
static PREFIXES_V4: LazyLock<Vec<IpNet>> = LazyLock::new(|| parse_prefixes(BOGON_V4));
static PREFIXES_V6: LazyLock<Vec<IpNet>> = LazyLock::new(|| parse_prefixes(BOGON_V6));

fn parse_prefixes(cidrs: &[&str]) -> Vec<IpNet> {
    cidrs
        .iter()
        .map(|cidr| {
            IpNet::from_str(cidr)
                .unwrap_or_else(|e| panic!("vpndetection: unparseable bogon range {cidr:?}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compiled-in table and the shared corpus are emitted by the same
    /// generator run, so a mismatch means one was regenerated without the other.
    /// This has to live inside the crate: the table is `pub(crate)`, and an
    /// integration test can only reach it through the predicate.
    #[test]
    fn the_table_matches_the_corpus() {
        #[derive(serde::Deserialize)]
        struct Tables {
            v4: Vec<String>,
            v6: Vec<String>,
        }
        let corpus: Tables =
            serde_json::from_str(include_str!("../testdata/bogons.json")).expect("bogons.json");
        assert_eq!(BOGON_V4, corpus.v4);
        assert_eq!(BOGON_V6, corpus.v6);
    }

    /// Guards the panic in parse_prefixes: it can only ever fire on a broken
    /// build, and this is what proves that.
    #[test]
    fn every_generated_range_parses() {
        assert_eq!(PREFIXES_V4.len(), BOGON_V4.len());
        assert_eq!(PREFIXES_V6.len(), BOGON_V6.len());
    }
}
