use std::fmt;
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

use crate::client::{Client, with_retry};
use crate::error::Error;
use crate::models::dataset_format_size::Format;
use crate::models::{
    DatasetChecksums, DatasetChecksumsResponse, DatasetList, DatasetMetadata, Download,
    DownloadList, LicensedDataset,
};

/// The licensed dataset downloads. Access is granted by contract rather than
/// self-serve, and needs a key carrying the `db.download` scope.
///
/// Reached through [`Client::database`].
#[derive(Debug, Clone, Copy)]
pub struct Database<'a> {
    client: &'a Client,
}

impl<'a> Database<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// The dataset FAMILIES your organization is licensed to download.
    ///
    /// A licence covers a family while a download names one of its versions, so
    /// the ids [`Database::download`] and [`Database::checksums`] take come from
    /// [`LicensedDataset::versions`] rather than from the family itself.
    pub async fn list(&self) -> Result<Vec<LicensedDataset>, Error> {
        let response: DatasetList = self.get("/api/v1/database/list", &[]).await?;
        Ok(response.datasets)
    }

    /// What is inside one dataset: schema, samples, row count and sizes.
    ///
    /// It carries `updated` and `entries` without downloading anything, so poll
    /// it to decide whether today's build is worth fetching.
    pub async fn metadata(&self, id: &str) -> Result<DatasetMetadata, Error> {
        self.get("/api/v1/database/metadata", &[("id", id)]).await
    }

    /// The digests of one published file, for verifying a download.
    ///
    /// The whole set is returned rather than one algorithm, because which
    /// digests a dataset publishes is the API's choice. They nest under
    /// `checksums` in the response, and reading a top-level `sha256` is how the
    /// Node SDK shipped this broken in 1.0.x.
    pub async fn checksums(&self, id: &str, format: Format) -> Result<DatasetChecksums, Error> {
        let response: DatasetChecksumsResponse = self
            .get("/api/v1/database/checksum", &[("id", id), ("format", format.as_str())])
            .await?;
        Ok(*response.checksums)
    }

    /// Your organization's recent download attempts, newest first. `None` takes
    /// the API's own default.
    pub async fn downloads(&self, limit: Option<u32>) -> Result<Vec<Download>, Error> {
        let limit = limit.map(|n| n.to_string());
        let query: Vec<(&str, &str)> = match &limit {
            Some(n) => vec![("limit", n.as_str())],
            None => vec![],
        };
        let response: DownloadList = self.get("/api/v1/database/downloads", &query).await?;
        Ok(response.downloads)
    }

    /// The time-limited URL for one dataset file.
    ///
    /// The API answers 302 to object storage. The URL is returned rather than
    /// the bytes so the caller decides how to transfer a file that routinely
    /// runs to gigabytes; the link authorizes the START of a transfer, so one
    /// already running is not interrupted when it lapses.
    pub async fn download_url(&self, id: &str, format: Format) -> Result<String, Error> {
        let query = [("id", id), ("format", format.as_str())];
        with_retry(self.client.retries(), || {
            self.client.transport().get_redirect("/api/v1/database/download", &query)
        })
        .await
    }

    /// Downloads one dataset file to `path` and returns the bytes written.
    ///
    /// The bytes stream straight to disk, so nothing beyond a single chunk is
    /// held in memory whatever the dataset weighs. They land in a neighboring
    /// `.part` file that is renamed on completion, so a transfer that dies half
    /// way leaves no truncated file that reads as a whole dataset, and a short
    /// transfer fails rather than being written out.
    pub async fn download(
        &self,
        id: &str,
        format: Format,
        path: impl AsRef<Path>,
    ) -> Result<u64, Error> {
        let path = path.as_ref();
        let partial = partial_path(path);
        let response = self.fetch_file(id, format).await?;

        let outcome = match stream_to_file(response, &partial).await {
            Ok(written) => {
                tokio::fs::rename(&partial, path).await.map(|()| written).map_err(Error::from)
            }
            Err(err) => Err(err),
        };
        if outcome.is_err() {
            // Best effort: the transfer already failed, and a partial file that
            // cannot be removed is not a second failure worth reporting over the
            // first one.
            let _ = tokio::fs::remove_file(&partial).await;
        }
        outcome
    }

    /// Downloads one dataset file and hands back its bytes.
    ///
    /// **This holds the entire file in memory**, and the catalog spans five
    /// orders of magnitude, from `cdn_ip_v1` at 10 KB to `resproxy_ip_90d_v1` at
    /// 1.79 GB. Reach for it at the small end, where the bytes go straight into
    /// a parser, and use [`Database::download`] for anything you have not
    /// measured.
    pub async fn download_bytes(&self, id: &str, format: Format) -> Result<Vec<u8>, Error> {
        let mut response = self.fetch_file(id, format).await?;
        let declared = response.content_length();
        // Allocated once from the declared length. A Vec grows by doubling, so
        // the last grow of a large dataset alone costs twice the file.
        let mut bytes = Vec::with_capacity(declared.unwrap_or(0) as usize);
        while let Some(chunk) = response.chunk().await? {
            bytes.extend_from_slice(&chunk);
        }
        assert_whole_transfer(declared, bytes.len() as u64)?;
        Ok(bytes)
    }

    // The 302 is followed as a SECOND request rather than by loosening the
    // redirect guard, because the presigned URL authorizes itself and
    // forwarding the API key would hand a credential to a host with no business
    // holding it. Transport::get_file builds that request without one.
    async fn fetch_file(&self, id: &str, format: Format) -> Result<reqwest::Response, Error> {
        let url = self.download_url(id, format).await?;
        with_retry(self.client.retries(), || self.client.transport().get_file(&url)).await
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, Error> {
        with_retry(self.client.retries(), || self.client.transport().get_json(path, query)).await
    }
}

/// Streams a response body into `partial`, returning the bytes written.
///
/// The file is closed before the caller renames it: on some platforms a rename
/// over an open handle is refused, and a flush that fails after the rename has
/// already happened would publish a short file as a whole one.
async fn stream_to_file(mut response: reqwest::Response, partial: &Path) -> Result<u64, Error> {
    let declared = response.content_length();
    let mut file = tokio::fs::File::create(partial).await?;
    let mut written = 0u64;
    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk).await?;
        written += chunk.len() as u64;
    }
    file.flush().await?;
    drop(file);
    assert_whole_transfer(declared, written)?;
    Ok(written)
}

/// `path` with `.part` appended, rather than [`Path::with_extension`], which
/// would turn `cdn_ip_v1.csv.gz` into `cdn_ip_v1.csv.part` and take a real
/// extension with it.
fn partial_path(path: &Path) -> PathBuf {
    let mut partial = path.as_os_str().to_owned();
    partial.push(".part");
    PathBuf::from(partial)
}

/// A backstop against a short transfer being written out as a whole dataset.
///
/// reqwest 0.13 gets there first: hyper compares the body against
/// `Content-Length` itself and fails the stream with "error decoding response
/// body", which is what the truncation tests actually observe. That is a
/// transport promise rather than an API one, and this crate owns the guarantee,
/// so the comparison is made again here for the version that stops making it.
/// `UnexpectedEof` rather than a kind of our own, because that is what this is
/// and it is what makes [`Error::retryable`] true for it.
fn assert_whole_transfer(declared: Option<u64>, written: u64) -> Result<(), Error> {
    match declared {
        Some(want) if want != written => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("the transfer ended after {written} of {want} bytes"),
        ))),
        _ => Ok(()),
    }
}

/// Not every dataset is built in every format: the `_provider` catalogs are keyed
/// by provider id rather than by IP range, so no MMDB exists for them.
impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csvgz => "csvgz",
            Self::Mmdb => "mmdb",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
