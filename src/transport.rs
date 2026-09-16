use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, RETRY_AFTER};
use serde::de::DeserializeOwned;

use crate::error::{Error, ErrorKind, kind_for_status};

/// Every request the crate makes: the GET operations, the batch POST and the
/// OAuth form POSTs.
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
    ///
    /// `timeout` runs from connecting to the last byte of the body, which is
    /// what reqwest's per-request timeout covers. It also takes precedence over
    /// a total timeout on a caller-supplied client, so the bound is the SDK's
    /// whichever client sends.
    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<T, Error> {
        let response = self.send(path, query, timeout).await?;
        decode(response).await
    }

    /// A JSON POST, decoded into `T`. The one request with a body: the batch.
    pub(crate) async fn post_json<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<T, Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.http.post(url).json(body).timeout(timeout);
        if let Some(key) = self.api_key.as_deref().filter(|k| !k.is_empty()) {
            request = request.header(AUTHORIZATION, format!("Bearer {key}"));
        }
        decode(request.send().await?).await
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
        timeout: Duration,
    ) -> Result<String, Error> {
        let response = self.send(path, query, timeout).await?;
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

    /// A GET to an absolute URL carrying NO credential, for a presigned link
    /// that authorizes itself.
    ///
    /// The body is handed back unread, so a dataset of any size is streamed by
    /// the caller rather than buffered here. No timeout is set: a deadline would
    /// decide how large a dataset can be fetched.
    ///
    /// The API key is not merely omitted from this request, the redirect is not
    /// followed at all: reqwest's redirect policy is a CLIENT-level setting and
    /// some versions carry request headers across a redirect, so issuing the
    /// second request by hand is the only way the key provably does not travel
    /// to object storage.
    pub(crate) async fn get_file(&self, url: &str) -> Result<reqwest::Response, Error> {
        let response = self.http.get(url).send().await?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(response);
        }
        // The body is left unread: the status is what separates a lapsed link
        // from a refused one, and nothing bounds the size of an error body.
        let retry_after = parse_retry_after(response.headers());
        Err(Error::Api {
            kind: kind_for_status(status, retry_after),
            message: format!("object storage refused the download link with status {status}"),
            status,
            retry_after,
        })
    }

    /// An OAuth GET. It never carries the API key: those endpoints have no use
    /// for it, and handing a credential to a request that does not need one
    /// only widens where it can leak.
    pub(crate) async fn get_keyless(&self, path: &str, timeout: Duration) -> Result<Answer, Error> {
        let url = format!("{}{}", self.base_url, path);
        Answer::read(self.http.get(url).timeout(timeout).send().await?).await
    }

    /// An OAuth POST of an `application/x-www-form-urlencoded` body, which
    /// never carries the API key either. On the token endpoint an
    /// `Authorization` header would read as client authentication, which these
    /// public clients do not have.
    pub(crate) async fn post_form(
        &self,
        path: &str,
        form: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Answer, Error> {
        let url = format!("{}{}", self.base_url, path);
        Answer::read(self.http.post(url).form(form).timeout(timeout).send().await?).await
    }

    async fn send(
        &self,
        path: &str,
        query: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<reqwest::Response, Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.http.get(url).query(query).timeout(timeout);
        // Bearer only. The API also accepts X-Api-Key and ?apikey=, and the
        // generated client sends BOTH of those whenever a key is configured; a
        // key belongs in one header, not in a query string a proxy will log.
        // An empty key is treated as no key: it is what an unset environment
        // variable or CI secret interpolates to, and `Bearer ` with nothing
        // behind it is never what anyone meant.
        if let Some(key) = self.api_key.as_deref().filter(|k| !k.is_empty()) {
            request = request.header(AUTHORIZATION, format!("Bearer {key}"));
        }
        Ok(request.send().await?)
    }
}

/// A response read whole, for a caller that classifies it itself. Reading the
/// body inside the request's timeout is what makes that bound cover it.
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) retry_after: Option<Duration>,
    pub(crate) body: String,
}

impl Answer {
    async fn read(response: reqwest::Response) -> Result<Self, Error> {
        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        Ok(Self { status, retry_after, body: response.text().await? })
    }
}

/// The JSON body of a 2xx, or the failure a non-2xx describes.
async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
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
