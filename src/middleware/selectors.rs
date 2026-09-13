use std::sync::Arc;

/// Enough of an incoming request for a selector to work with, whatever
/// framework it came from. An adapter supplies one of these per request.
pub struct RequestView<'a> {
    /// A request header by name, case-insensitively; `None` when absent.
    pub header: &'a dyn Fn(&str) -> Option<String>,

    /// The framework's own client-address accessor.
    pub framework_ip: &'a dyn Fn() -> Option<String>,
}

/// How the client address is decided.
///
/// There is no portable default: a framework's own accessor may return the
/// socket peer, or may already have walked a proxy chain, depending on the
/// framework and on how the application configured it. You know your framework
/// and your edge, so this is yours to choose - and anything of this shape works,
/// so an edge we have never heard of is a closure rather than a feature request:
///
/// ```
/// use std::sync::Arc;
/// use vpndetection::middleware::IpSelector;
///
/// let mine: IpSelector = Arc::new(|view| (view.header)("x-real-ip"));
/// ```
pub type IpSelector = Arc<dyn Fn(&RequestView<'_>) -> Option<String> + Send + Sync>;

/// The framework's own client-address accessor. The default.
pub fn framework_ip() -> IpSelector {
    Arc::new(|view| (view.framework_ip)())
}

/// An address from `X-Forwarded-For`.
///
/// The LEFT-MOST entry (`depth` 0) is whatever the caller sent, because proxies
/// append to this header, so a visitor who sets it themselves appears first and
/// this returns their forgery. It is only trustworthy when an edge you control
/// overwrites the header. When you know how many proxies sit in front, count
/// from the right: depth 1 is the address your nearest proxy saw.
pub fn xff(depth: usize) -> IpSelector {
    Arc::new(move |view| {
        let raw = (view.header)("x-forwarded-for").unwrap_or_default();
        let chain: Vec<&str> = raw.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
        if chain.is_empty() {
            return (view.framework_ip)();
        }
        let index = if depth == 0 || depth > chain.len() { 0 } else { chain.len() - depth };
        Some(chain[index].to_owned())
    })
}

/// An address from a single-value header your edge writes -
/// `header("CF-Connecting-IP")` behind Cloudflare. Falls back to the
/// framework's accessor when the header is absent.
pub fn header(name: impl Into<String>) -> IpSelector {
    let name = name.into();
    Arc::new(move |view| {
        match (view.header)(&name).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()) {
            Some(value) => Some(value),
            None => (view.framework_ip)(),
        }
    })
}
