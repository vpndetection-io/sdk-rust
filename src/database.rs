use std::fmt;

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

    /// The datasets your organization is licensed to download.
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

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, Error> {
        with_retry(self.client.retries(), || self.client.transport().get_json(path, query)).await
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
