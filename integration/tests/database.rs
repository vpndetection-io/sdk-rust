// The licensed-download half, which only the max key can reach: it is the tier
// holding dataset licences, and db.download is a scope the other three keys do
// not carry.
//
// The transfer is budgeted before it starts. Metadata publishes a size per
// format, and that size is checked against the ceiling below FIRST, so a
// mistaken dataset id can never quietly pull one of the gigabyte datasets
// through CI.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use vpndetection::{DatasetChecksums, ErrorKind, Format, LicenseType, Standing};
use vpndetection_integration::{
    STAGING, client_for, max_rung, recorder::Fact, recorder::Recorder, skip_unless,
};

/// The max organization licenses cdn_ip for license_type, and at ~10 KB it is
/// the only dataset small enough to move in CI.
const DATASET: &str = "cdn_ip_v1";
const FORMAT: Format = Format::Csvgz;

/// 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so
/// tripping it means the suite is pointed somewhere unintended, which is exactly
/// when a transfer must not go ahead.
const CEILING: i32 = 8 << 20;

/// A real catalogue id the max organization holds no licence for.
const UNLICENSED: &str = "hosting_ip_v1";

#[tokio::test]
async fn the_licensed_catalogue_answers_the_schema_the_client_was_generated_from() {
    skip_unless!(max_rung().skip_reason());
    let (client, recorder) = client_for(max_rung()).await;

    let datasets = client.database().list().await.expect("list");

    assert!(!datasets.is_empty(), "the max organization licenses nothing");
    // Named first, and with what actually arrived, because every typed assertion
    // below reads as a zero value when the payload disagrees, and a bare "want a
    // string" costs a whole CI cycle to interpret.
    let served = served_keys(&recorder, "/api/v1/database/list");
    for want in ["base", "versions"] {
        assert!(
            served.contains(want),
            "the payload carries {served:?}, and LicensedDataset declares {want}"
        );
    }
    assert!(
        !served.contains("docsGroup"),
        "docsGroup is a docs-site slug and must not be published as API surface"
    );

    let standings = [Standing::Expired, Standing::Licensed, Standing::Unlicensed];
    let rights = [LicenseType::Evaluation, LicenseType::Standard, LicenseType::Redistribute];
    let mut ids = Vec::new();
    for dataset in &datasets {
        assert!(!dataset.base.is_empty(), "a licensed family carries no base");
        assert!(!dataset.name.is_empty(), "{} carries no name", dataset.base);
        assert!(
            standings.contains(&dataset.standing),
            "{} has an undocumented standing",
            dataset.base
        );
        assert!(
            rights.contains(&dataset.license_type),
            "{} has an undocumented right",
            dataset.base
        );
        // The point of the family shape: a licence covers the family, and these
        // are the ids the download and checksum calls take. Before the spec was
        // corrected this list did not exist, so list() could not tell a caller
        // what to download.
        assert!(!dataset.versions.is_empty(), "{} carries no versions", dataset.base);
        for version in &dataset.versions {
            assert!(!version.id.is_empty(), "{} has a version with no id", dataset.base);
            assert!(!version.formats.is_empty(), "{} carries no formats", version.id);
            ids.push(version.id.clone());
        }
    }
    println!("licensed: {}", ids.join(", "));
}

#[tokio::test]
async fn a_dataset_the_organization_does_not_license_is_refused_cleanly() {
    skip_unless!(max_rung().skip_reason());
    let (client, recorder) = client_for(max_rung()).await;

    let err =
        client.database().download_url(UNLICENSED, FORMAT).await.unwrap_err_or_explain(UNLICENSED);

    assert_eq!(err.kind(), ErrorKind::Forbidden, "kind: {err}");
    assert_eq!(err.status(), Some(403));
    assert!(!err.retryable(), "a licence refusal is not worth retrying");
    // The API says which refusal this is (`{"rc":"NOT_LICENSED"}`). Falling back
    // to the status means the client never read the envelope.
    assert!(
        !err.message().starts_with("request failed with status"),
        "message {:?} is the client fallback, so the body went unread",
        err.message()
    );
    assert_eq!(recorder.facts().len(), 1, "a 4xx must not be retried");
}

#[tokio::test]
async fn download_streams_a_real_dataset_to_disk_intact() {
    skip_unless!(max_rung().skip_reason());
    let transfer = transferred().await;

    assert!(transfer.written > 0, "nothing was transferred");
    let body = std::fs::read(&transfer.path).expect("the download is not on disk");
    assert_eq!(body.len() as u64, transfer.written, "the file and the reported size disagree");
    assert!(!partial_of(&transfer.path).exists(), "the .part file outlived a successful transfer");
    assert_eq!(&body[..2], b"\x1f\x8b", "the payload is not gzip");

    let published = transfer.checksums.sha256.as_deref().unwrap_or_default();
    assert_eq!(published.len(), 64, "sha256 {published:?} did not unwrap past the envelope");
    assert_eq!(digest(&body), published, "the transferred bytes hash to something else");

    // The presigned URL authorizes itself, so the request that follows the 302
    // must carry no credential.
    let storage: Vec<&Fact> = transfer.facts.iter().filter(|fact| fact.origin != STAGING).collect();
    assert!(!storage.is_empty(), "nothing was fetched from object storage, so no 302 was followed");
    for fact in storage {
        assert!(!fact.carried_key, "the API key was sent to object storage at {}", fact.origin);
    }
}

#[tokio::test]
async fn download_bytes_agrees_with_the_streamed_copy() {
    skip_unless!(max_rung().skip_reason());
    let transfer = transferred().await;
    let (client, _) = client_for(max_rung()).await;

    let raw = client.database().download_bytes(DATASET, FORMAT).await.expect("download_bytes");

    assert_eq!(raw.len() as u64, transfer.written, "the in-memory copy is a different size");
    assert_eq!(
        digest(&raw),
        transfer.checksums.sha256.as_deref().unwrap_or_default(),
        "the in-memory copy hashes to something the API does not publish"
    );
}

struct Transfer {
    written: u64,
    path: PathBuf,
    checksums: DatasetChecksums,
    facts: Vec<Fact>,
}

/// Memoized so the two transfer tests share one download rather than pulling the
/// dataset twice each.
static TRANSFER: OnceCell<Transfer> = OnceCell::const_new();

async fn transferred() -> &'static Transfer {
    TRANSFER.get_or_init(transfer).await
}

async fn transfer() -> Transfer {
    let (client, recorder) = client_for(max_rung()).await;

    let meta = client.database().metadata(DATASET).await.expect("metadata");
    assert_eq!(meta.id, DATASET, "metadata answered about the wrong dataset");
    let size = published_size(&meta);
    assert!(
        size > 0 && size <= CEILING,
        "{DATASET} is {size} bytes, past the {CEILING} ceiling, so it is not transferred"
    );

    let path = scratch().join(format!("{DATASET}.csv.gz"));
    let written = client.database().download(DATASET, FORMAT, &path).await.expect("download");
    // Read AFTER the transfer, so a rebuild between the two calls shows up as a
    // digest mismatch rather than passing against a digest of nothing.
    let checksums = client.database().checksums(DATASET, FORMAT).await.expect("checksums");
    println!("{DATASET}.{FORMAT}: {written} bytes, metadata says {size}");

    Transfer { written, path, checksums, facts: recorder.facts() }
}

fn published_size(meta: &vpndetection::DatasetMetadata) -> i32 {
    let sizes = meta.size.as_ref().expect("no size is published to check a transfer against");
    *sizes
        .get(&FORMAT.to_string())
        .unwrap_or_else(|| panic!("{DATASET} publishes no {FORMAT} size"))
}

/// The keys the payload actually carried, which the typed decode cannot show: an
/// undocumented field disappears silently into a struct that has no home for it.
fn served_keys(recorder: &Arc<Recorder>, path: &str) -> BTreeSet<String> {
    let body = recorder
        .json_body(path)
        .unwrap_or_else(|| panic!("no JSON answer was captured for {path}"));
    body["datasets"]
        .as_array()
        .expect("datasets is an array")
        .iter()
        .filter_map(|dataset| dataset.as_object())
        .flat_map(|dataset| dataset.keys().cloned())
        .collect()
}

fn digest(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A scratch directory for the whole binary rather than for one test, because
/// the two transfer tests share the download and the second still has to read
/// what the first wrote.
fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vpndetection-integration-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creating a scratch directory");
    dir
}

fn partial_of(path: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.part", path.display()))
}

/// A refusal that arrives as anything else is almost always the dataset having
/// been licensed since, and a bare `unwrap` on it would say only "called
/// unwrap_err on an Ok value".
trait ExplainRefusal {
    fn unwrap_err_or_explain(self, id: &str) -> vpndetection::Error;
}

impl<T> ExplainRefusal for Result<T, vpndetection::Error> {
    fn unwrap_err_or_explain(self, id: &str) -> vpndetection::Error {
        match self {
            Err(err) => err,
            Ok(_) => panic!(
                "{id} was not refused. If it is now licensed to this organization, point this \
                 test at one that is not"
            ),
        }
    }
}
