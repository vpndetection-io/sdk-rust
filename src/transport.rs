use std::time::Duration;

use chrono::TimeZone;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, RETRY_AFTER};
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

    /// What every path is appended to, with no trailing `/`.
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
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
    ///
    /// Any other 2xx is an answer this call cannot read, such as a proxy's page
    /// served as a 200, and is the retried server error every other call's is.
    /// Read as a followed redirect, it was a `bad_request` sent once that told
    /// the caller to fix a client they never passed (5.4.0, measured 2026-10-09).
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
            (200..300, _) if !self.answered_from(path, &response) => Err(Error::Config(
                "the download redirect was followed, so its Location is gone: build the \
                 reqwest::Client you passed to ClientBuilder::http_client with \
                 reqwest::redirect::Policy::none()"
                    .to_owned(),
            )),
            (200..300, _) => Err(Error::Api {
                kind: ErrorKind::ServerError,
                message: "expected a redirect to object storage".to_owned(),
                status,
                retry_after: None,
            }),
            _ => {
                let body = response.text().await?;
                Err(Error::from_response(status, retry_after, &body))
            }
        }
    }

    /// Whether `response` came from the URL sent for `path` rather than from
    /// wherever a redirect led, which only a client that follows them reaches.
    fn answered_from(&self, path: &str, response: &reqwest::Response) -> bool {
        let mut url = response.url().clone();
        url.set_query(None);
        reqwest::Url::parse(&format!("{}{}", self.base_url, path)).is_ok_and(|sent| sent == url)
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

    /// An OAuth POST of an `application/json` body, `/oauth/register`'s, which
    /// never carries the API key either.
    pub(crate) async fn post_json_keyless(
        &self,
        path: &str,
        body: String,
        timeout: Duration,
    ) -> Result<Answer, Error> {
        let url = format!("{}{}", self.base_url, path);
        let request = self
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(timeout);
        Answer::read(request.send().await?).await
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
    // Digits alone, as RFC 9110's delay-seconds is: `u64`'s parser also takes a
    // leading `+`, so `+1` waited a second (5.4.0, measured 2026-10-09).
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse::<u64>().ok().map(Duration::from_secs);
    }
    let wait = http_date(&value)? - chrono::Utc::now().timestamp();
    Some(Duration::from_secs(wait.max(0) as u64))
}

const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const LONG_DAY_NAMES: [&str; 7] =
    ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const MONTHS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// An HTTP date as a Unix timestamp, in exactly one of the three forms RFC 9110
/// has a recipient read, each of them GMT:
///
/// - `Sun, 06 Nov 1994 08:49:37 GMT`, the IMF-fixdate a server sends,
/// - `Sunday, 06-Nov-94 08:49:37 GMT`, RFC 850's,
/// - `Sun Nov  6 08:49:37 1994`, asctime's.
///
/// Nothing a general date parser would also take: an RFC 2822 parser reads
/// another zone, a missing day name, a two-digit year or a missing second, and
/// each would turn a spent quota into a throttle. The day name is read but not
/// checked against the date; a date that names no real time, such as 31 Nov,
/// is none.
fn http_date(value: &str) -> Option<i64> {
    let fields: Vec<&str> = value.split(' ').collect();
    let (year, month, day, time) = match fields.as_slice() {
        [name, day, month, year, time, "GMT"]
            if DAY_NAMES.iter().any(|d| name.strip_suffix(',') == Some(*d)) =>
        {
            (number(year, 4)?, *month, number(day, 2)?, *time)
        }
        [name, date, time, "GMT"]
            if LONG_DAY_NAMES.iter().any(|d| name.strip_suffix(',') == Some(*d)) =>
        {
            let [day, month, year] = date.split('-').collect::<Vec<_>>()[..] else {
                return None;
            };
            (full_year(number(year, 2)?), month, number(day, 2)?, *time)
        }
        [name, month, day, time, year] if DAY_NAMES.contains(name) => {
            (number(year, 4)?, *month, number(day, 2)?, *time)
        }
        [name, month, "", day, time, year] if DAY_NAMES.contains(name) => {
            (number(year, 4)?, *month, number(day, 1)?, *time)
        }
        _ => return None,
    };
    let month = MONTHS.iter().position(|m| *m == month)? as u32 + 1;
    let [hour, minute, second] = time.split(':').collect::<Vec<_>>()[..] else {
        return None;
    };
    // RFC 9110 allows a leap second, which chrono's time of day does not.
    let (second, leap) = match number(second, 2)? {
        60 => (59, 1),
        second => (second, 0),
    };
    let when = chrono::NaiveDate::from_ymd_opt(year as i32, month, day)?.and_hms_opt(
        number(hour, 2)?,
        number(minute, 2)?,
        second,
    )?;
    Some(chrono::Utc.from_utc_datetime(&when).timestamp() + leap)
}

/// A field of exactly `width` ASCII digits.
fn number(field: &str, width: usize) -> Option<u32> {
    if field.len() != width || !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

/// RFC 850's two-digit year, read as RFC 9110 says: one that would land more
/// than 50 years ahead is the most recent past year ending in those digits.
fn full_year(two_digits: u32) -> u32 {
    let now = chrono::Datelike::year(&chrono::Utc::now()) as u32;
    let year = now - now % 100 + two_digits;
    if year > now + 50 {
        year - 100
    } else if year + 100 <= now + 50 {
        year + 100
    } else {
        year
    }
}

#[cfg(test)]
mod tests {
    use super::{full_year, http_date};

    /// RFC 9110's own example, in each of its three forms.
    #[test]
    fn an_http_date_is_read_in_all_three_forms() {
        for value in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(http_date(value), Some(784_111_777), "{value}");
        }
        assert_eq!(http_date("Wed Nov 16 08:49:37 1994"), Some(784_975_777));
        assert_eq!(http_date("Sat, 31 Dec 2016 23:59:60 GMT"), Some(1_483_228_800));
    }

    /// What a general date parser would read, and an HTTP date must not.
    #[test]
    fn nothing_else_is_an_http_date() {
        for value in [
            "-1",
            "x",
            "tomorrow",
            "+1 day",
            "1e400",
            "1994-11-06",
            "Sun, 06 Nov 1994 08:49:37 +0500",
            "Sun, 06 Nov 1994 08:49:37 -0000",
            "Sun, 06 Nov 1994 08:49:37 EST",
            "Sun, 06 Nov 1994 08:49:37 UT",
            "Sun, 06 Nov 1994 08:49:37 Z",
            "06 Nov 1994 08:49:37 GMT",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 94 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49 GMT",
            "sun, 06 nov 1994 08:49:37 gmt",
            "Sun, 06 Nov 1994 08:49:37 GMT (comment)",
            "Sun, 06-Nov-94 08:49:37 GMT",
            "Sunday, 06-Nov-1994 08:49:37 GMT",
            "Sun Nov 6 08:49:37 1994",
            "Sun Nov 06 08:49:37 94",
            "Sunday Nov  6 08:49:37 1994",
            "Sun, 31 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 +8:49:37 GMT",
            "Sun,  06 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(http_date(value), None, "{value}");
        }
    }

    #[test]
    fn a_two_digit_year_is_never_more_than_50_years_ahead() {
        let now = chrono::Datelike::year(&chrono::Utc::now()) as u32;
        for two_digits in 0..100 {
            let year = full_year(two_digits);
            assert_eq!(year % 100, two_digits);
            assert!(year <= now + 50 && year > now + 50 - 100, "{two_digits} read as {year}");
        }
    }
}
