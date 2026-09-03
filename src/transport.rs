use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, RETRY_AFTER};
use serde::de::DeserializeOwned;

use crate::error::{Error, ErrorKind};

/// Every request the crate makes. Six GET operations with no request bodies,
/// which is what the whole API is.
///
/// The generated client is not used for this: its `ResponseContent` carries no
/// headers, so a 429's `Retry-After` is unreachable, and its `download_database`
/// is typed `Result<(), _>`, discarding the 302 whose `Location` is that
/// endpoint's entire answer.
#[derive(Debug, Clone)]
pub(crate) struct Transport {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl Transport {
    pub(crate) fn new(http: reqwest::Client, base_url: String, api_key: Option<String>) -> Self {
        Self { http, base_url, api_key }
    }

    /// A JSON GET, decoded into `T`.
    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, Error> {
        let response = self.send(path, query).await?;
        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await?;
        if !(200..300).contains(&status) {
            return Err(Error::from_response(status, retry_after, &body));
        }
        // A body that will not decode is a transport-level failure rather than
        // the API saying no, so it is retryable like any other malformed read.
        serde_json::from_str(&body).map_err(|e| Error::Api {
            kind: ErrorKind::ServerError,
            message: format!("could not decode the response: {e}"),
            status,
            retry_after: None,
        })
    }

    /// The `Location` of a redirect the client must NOT follow.
    ///
    /// The download endpoint answers 302 to object storage, and the dataset
    /// behind it routinely runs to gigabytes, so following it would transfer the
    /// whole file to hand back a link. [`crate::ClientBuilder`] builds its client
    /// with `redirect::Policy::none()` for exactly this; a caller-supplied client
    /// that follows redirects is caught here rather than silently downloading.
    pub(crate) async fn get_redirect(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<String, Error> {
        let response = self.send(path, query).await?;
        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        match (status, location) {
            (300..400, Some(location)) => Ok(location),
            (300..400, None) => Err(Error::Api {
                kind: ErrorKind::ServerError,
                message: "the redirect carried no Location header".to_owned(),
                status,
                retry_after: None,
            }),
            (200..300, _) => Err(Error::Config(
                "the download redirect was followed, so its Location is gone: build the \
                 reqwest::Client you passed to ClientBuilder::http_client with \
                 reqwest::redirect::Policy::none()"
                    .to_owned(),
            )),
            _ => {
                let body = response.text().await?;
                Err(Error::from_response(status, retry_after, &body))
            }
        }
    }

    async fn send(&self, path: &str, query: &[(&str, &str)]) -> Result<reqwest::Response, Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.http.get(url).query(query);
        // Bearer only. The API also accepts X-Api-Key and ?apikey=, and the
        // generated client sends BOTH of those whenever a key is configured; a
        // key belongs in one header, not in a query string a proxy will log.
        if let Some(key) = &self.api_key {
            request = request.header(AUTHORIZATION, format!("Bearer {key}"));
        }
        Ok(request.send().await?)
    }
}

/// Percent-encodes an address for the `GET /{ip}` path template. An IPv6
/// literal contains colons, which are legal in a path segment but are worth
/// encoding anyway so an intermediary cannot read one as an authority.
pub(crate) fn encode_path_segment(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `Retry-After` is seconds or an HTTP date. Its ABSENCE on a 429 is what makes
/// that 429 a spent allowance rather than a throttle, so a header that will not
/// parse reads as absent rather than as zero.
fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim().to_owned();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let when = chrono::DateTime::parse_from_rfc2822(&value).ok()?;
    let wait = when.timestamp() - chrono::Utc::now().timestamp();
    Some(Duration::from_secs(wait.max(0) as u64))
}
