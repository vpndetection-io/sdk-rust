use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

use ipnet::IpNet;

use crate::bogons::{BOGON_V4, BOGON_V6};
use crate::lookup::Lookup;
use crate::models::LookupResponse;

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
    // A 4-in-6 address parses as V6 and is therefore tested against the v6
    // table, which is the routing every other SDK uses. Unmapping it first would
    // match it against the v4 table instead and disagree with all of them.
    let table: &[IpNet] = if addr.is_ipv4() { &PREFIXES_V4 } else { &PREFIXES_V6 };
    table.iter().any(|net| net.contains(&addr))
}

/// The answer a bogon gets: the full shape the API serves on its widest plan,
/// every flag present and false and every detail object present and empty, plus
/// the `is_bogon` marker that tells a computed answer from a served one.
///
/// Deliberately the WIDEST shape whatever plan you are on, so a caller must not
/// infer which fields their plan includes from a bogon answer.
pub(crate) fn bogon_lookup(ip: &str) -> Lookup {
    Lookup {
        is_bogon: true,
        answer: LookupResponse {
            ip: ip.to_owned(),
            is_vpn: false,
            is_hosting: Some(false),
            is_relay: Some(false),
            is_tor: Some(false),
            is_cdn: Some(false),
            is_resproxy: Some(false),
            is_dcproxy: Some(false),
            is_mobproxy: Some(false),
            vpn: Some(Box::default()),
            hosting: Some(Box::default()),
            relay: Some(Box::default()),
            tor: Some(Box::default()),
            cdn: Some(Box::default()),
            resproxy: Some(Box::default()),
            dcproxy: Some(Box::default()),
            mobproxy: Some(Box::default()),
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
