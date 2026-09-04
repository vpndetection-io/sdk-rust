// The dataset transfer half: what `download` and `download_bytes` must do with
// the 302, the bytes, and a transfer that does not finish.
//
// The stub records request HEADERS, because two of the guarantees here are about
// what a request did NOT carry, and a header that was never sent is invisible to
// any assertion made on a response.

mod support;

use std::path::{Path, PathBuf};

use support::{Route, Stub};
use vpndetection::{ErrorKind, Format};

const DATASET: &str = "cdn_ip_v1";
const KEY: &str = "test-api-key-never-real";
const STORAGE_PATH: &str = "/files/cdn_ip_v1.csv.gz";

#[tokio::test]
async fn download_streams_a_dataset_to_a_path_and_leaves_no_part_file() {
    let stub = serving(Route::ok(payload())).await;
    let client = stub.client().api_key(KEY).build().expect("build");
    let scratch = Scratch::new("streamed");
    let path = scratch.join("cdn_ip_v1.csv.gz");

    let written =
        client.database().download(DATASET, Format::Csvgz, &path).await.expect("download");

    assert_eq!(written, payload().len() as u64);
    assert_eq!(std::fs::read(&path).expect("reading the download back"), payload().as_bytes());
    assert!(!partial_of(&path).exists(), "the .part file outlived a successful transfer");
}

/// The presigned URL authorizes itself, so the request that follows the 302 must
/// carry no credential. reqwest's redirect policy is a CLIENT-level setting and
/// some versions carry headers across a redirect, which is why the SDK issues
/// this request itself rather than trusting a policy.
#[tokio::test]
async fn the_object_storage_request_carries_no_credential() {
    let stub = serving(Route::ok(payload())).await;
    let client = stub.client().api_key(KEY).build().expect("build");
    let scratch = Scratch::new("credential");

    client
        .database()
        .download(DATASET, Format::Csvgz, scratch.join("cdn_ip_v1.csv.gz"))
        .await
        .expect("download");

    let requests = stub.requests();
    let api = requests
        .iter()
        .find(|call| call.path == "/api/v1/database/download")
        .expect("the download endpoint was never asked");
    assert_eq!(api.header("authorization"), Some(format!("Bearer {KEY}").as_str()));

    let storage =
        requests.iter().find(|call| call.path == STORAGE_PATH).expect("no 302 was followed");
    assert_eq!(storage.header("authorization"), None, "the key was sent to object storage");
    // Every header, plus the synthetic one holding the request target, so a key
    // smuggled into a query string is caught as well as one in a header.
    for (name, value) in &storage.headers {
        assert!(!value.contains(KEY), "the API key reached object storage in {name}");
    }
}

#[tokio::test]
async fn download_bytes_agrees_with_the_streamed_copy() {
    let stub = serving(Route::ok(payload())).await;
    let client = stub.client().api_key(KEY).build().expect("build");
    let scratch = Scratch::new("agreement");
    let path = scratch.join("cdn_ip_v1.csv.gz");

    client.database().download(DATASET, Format::Csvgz, &path).await.expect("download");
    let bytes = client.database().download_bytes(DATASET, Format::Csvgz).await.expect("bytes");

    assert_eq!(bytes, std::fs::read(&path).expect("reading the download back"));
}

/// A short body must never be published as a whole dataset. The stub declares
/// four times the length it writes, and reqwest fails the stream against the
/// declared length before the crate's own backstop is reached; what this pins is
/// the contract, not which of the two layers enforces it.
#[tokio::test]
async fn a_truncated_transfer_fails_and_leaves_nothing_behind() {
    let short = Route::ok(payload()).promising(payload().len() as u64 * 4);
    let stub = serving(short).await;
    let client = stub.client().api_key(KEY).build().expect("build");
    let scratch = Scratch::new("truncated");
    let path = scratch.join("cdn_ip_v1.csv.gz");

    let err = client
        .database()
        .download(DATASET, Format::Csvgz, &path)
        .await
        .expect_err("a short body must not be written out as a whole dataset");

    assert!(err.retryable(), "a transfer that ended early is worth another attempt: {err}");
    assert!(!path.exists(), "a truncated transfer left a file that reads as a whole dataset");
    assert!(!partial_of(&path).exists(), "the .part file survived a failed transfer");
}

/// What the `.part` file is FOR. A download that dies half way must not take
/// yesterday's copy of the dataset with it, which is what writing straight to
/// the destination would do: the destination is truncated the moment the file is
/// opened, long before anyone knows whether the transfer will finish.
#[tokio::test]
async fn a_failed_transfer_leaves_the_dataset_already_on_disk_untouched() {
    let short = Route::ok(payload()).promising(payload().len() as u64 * 4);
    let stub = serving(short).await;
    let client = stub.client().api_key(KEY).build().expect("build");
    let scratch = Scratch::new("existing");
    let path = scratch.join("cdn_ip_v1.csv.gz");
    std::fs::write(&path, b"yesterday's dataset").expect("seeding the destination");

    client
        .database()
        .download(DATASET, Format::Csvgz, &path)
        .await
        .expect_err("the transfer must fail");

    assert_eq!(
        std::fs::read(&path).expect("yesterday's dataset is gone"),
        b"yesterday's dataset",
        "a failed download replaced a good dataset with nothing"
    );
}

#[tokio::test]
async fn a_truncated_download_bytes_fails_rather_than_returning_a_short_buffer() {
    let short = Route::ok(payload()).promising(payload().len() as u64 * 4);
    let stub = serving(short).await;
    let client = stub.client().api_key(KEY).build().expect("build");

    let err = client
        .database()
        .download_bytes(DATASET, Format::Csvgz)
        .await
        .expect_err("a short body must not come back as the dataset");

    assert!(err.retryable(), "a transfer that ended early is worth another attempt: {err}");
}

/// A licence refusal is a client error: it carries the API's own `rc`, it is not
/// retried, and it never reaches object storage at all.
#[tokio::test]
async fn a_dataset_the_organization_does_not_license_is_refused_once() {
    let stub = Stub::start([(
        "/api/v1/database/download".to_owned(),
        Route::json(403, r#"{"rc":"NOT_LICENSED"}"#),
    )])
    .await;
    let client = stub.client().api_key(KEY).retries(3).build().expect("build");
    let scratch = Scratch::new("unlicensed");
    let path = scratch.join("hosting_ip_v1.csv.gz");

    let err = client
        .database()
        .download("hosting_ip_v1", Format::Csvgz, &path)
        .await
        .expect_err("an unlicensed dataset must be refused");

    assert_eq!(err.kind(), ErrorKind::Forbidden);
    assert_eq!(err.status(), Some(403));
    assert!(!err.retryable(), "a licence refusal is not worth retrying");
    assert_eq!(err.message(), "NOT_LICENSED", "the API's own reason went unread");
    assert_eq!(stub.count(), 1, "a 4xx must be issued exactly once");
    assert!(!path.exists() && !partial_of(&path).exists(), "a refusal wrote something to disk");
}

/// Object storage refusing a lapsed link is a different failure from the API
/// refusing the request, and the message has to say which one happened.
#[tokio::test]
async fn a_refused_download_link_names_object_storage() {
    let stub = serving(Route::json(403, "<Error><Code>AccessDenied</Code></Error>")).await;
    let client = stub.client().api_key(KEY).retries(1).build().expect("build");

    let err = client
        .database()
        .download_bytes(DATASET, Format::Csvgz)
        .await
        .expect_err("a refused link must fail");

    assert_eq!(err.kind(), ErrorKind::Forbidden);
    assert!(err.message().contains("object storage"), "{}", err.message());
}

/// The API answers 302 and the whole point of `download` is the SECOND request,
/// so both must be on the record: one asking for the link, one taking the bytes.
async fn serving(storage: Route) -> std::sync::Arc<Stub> {
    let stub = Stub::start([]).await;
    let location = format!("{}{STORAGE_PATH}?X-Amz-Signature=presigned", stub.base_url);
    stub.route("/api/v1/database/download", Route::json(302, "").header("Location", &location));
    stub.route(STORAGE_PATH, storage);
    stub
}

/// A body big enough to arrive in more than one chunk, and recognizable in a
/// diff when one of these assertions fails.
fn payload() -> String {
    "ip_range_start,ip_range_end,provider\n".repeat(512)
}

fn partial_of(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.part", path.display()))
}

/// A scratch directory that removes itself. The crate has no tempfile
/// dependency and does not need one for this: the tests write kilobytes, and a
/// directory named after the test is easier to read in a failure than a random
/// one.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpndetection-rust-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("creating a scratch directory");
        Self(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
