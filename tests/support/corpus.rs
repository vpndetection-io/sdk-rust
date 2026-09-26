// The shared conformance corpus, generated into testdata/ and
// identical across every VPNDetection SDK. It is embedded rather than read at
// run time so a missing or malformed corpus is a build failure.
#![allow(dead_code)]

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

pub fn load() -> Corpus {
    serde_json::from_str(include_str!("../../testdata/testdata.json")).expect("parsing the corpus")
}

#[derive(Deserialize)]
pub struct Corpus {
    #[serde(rename = "isBogon")]
    pub is_bogon: Vec<BogonCase>,
    #[serde(rename = "bogonResponse")]
    pub bogon_response: BogonResponse,
    pub lookup: Vec<LookupCase>,
    pub errors: Vec<ErrorCase>,
    pub batch: Vec<BatchCase>,
    pub bogons: Bogons,
    pub middleware: Middleware,
    pub oauth: Oauth,
}

impl Corpus {
    pub fn batch_case(&self, name: &str) -> &BatchCase {
        self.batch
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("the corpus has no batch case named {name:?}"))
    }
}

#[derive(Deserialize)]
pub struct BogonCase {
    pub ip: String,
    pub expect: bool,
    pub why: String,
}

#[derive(Deserialize)]
pub struct BogonResponse {
    #[serde(rename = "flagsFalse")]
    pub flags_false: Vec<String>,
    #[serde(rename = "emptyObjects")]
    pub empty_objects: Vec<String>,
}

#[derive(Deserialize)]
pub struct LookupCase {
    pub name: String,
    pub status: u16,
    pub body: Value,
    pub expect: LookupExpect,
}

#[derive(Deserialize)]
pub struct LookupExpect {
    pub ip: String,
    #[serde(rename = "isBogon")]
    pub is_bogon: bool,
    #[serde(default)]
    pub present: HashMap<String, bool>,
    #[serde(default)]
    pub absent: Vec<String>,
    #[serde(default, rename = "emptyPresent")]
    pub empty_present: Vec<String>,
    pub vpn: Option<Value>,
    pub hosting: Option<Value>,
    pub dcproxy: Option<Value>,
}

#[derive(Deserialize)]
pub struct ErrorCase {
    pub name: String,
    pub status: u16,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Value,
    pub expect: ErrorExpect,
}

#[derive(Deserialize)]
pub struct ErrorExpect {
    pub kind: String,
    pub retryable: bool,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default, rename = "retryAfterSeconds")]
    pub retry_after_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub struct BatchCase {
    pub name: String,
    pub input: Vec<String>,
    #[serde(default)]
    pub repeat: Option<u32>,
    pub expect: BatchExpect,
}

#[derive(Deserialize)]
pub struct BatchExpect {
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(rename = "httpRequests")]
    pub http_requests: Option<usize>,
    #[serde(default, rename = "bogonKeys")]
    pub bogon_keys: Vec<String>,
    #[serde(default, rename = "errorKeys")]
    pub error_keys: Vec<String>,
    #[serde(default, rename = "keyCount")]
    pub key_count: Option<usize>,
    #[serde(default, rename = "errorKinds")]
    pub error_kinds: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct Bogons {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

#[derive(Deserialize)]
pub struct Middleware {
    pub conditions: Vec<ConditionCase>,
    #[serde(rename = "invalidConditions")]
    pub invalid_conditions: Vec<InvalidConditionCase>,
}

#[derive(Deserialize)]
pub struct ConditionCase {
    pub name: String,
    pub why: String,
    #[serde(default)]
    pub bogon: Option<String>,
    #[serde(default)]
    pub body: Option<Value>,
    pub condition: Value,
    pub expect: ConditionExpect,
}

#[derive(Deserialize)]
pub struct ConditionExpect {
    pub blocked: bool,
    #[serde(default)]
    pub missing: Vec<String>,
}

#[derive(Deserialize)]
pub struct InvalidConditionCase {
    pub name: String,
    pub why: String,
    pub condition: Value,
}

/// The `oauth` section, less `deferred`, which names operations this release
/// does not ship and is never read.
#[derive(Deserialize)]
pub struct Oauth {
    pub endpoints: HashMap<String, OauthEndpoint>,
    #[serde(rename = "noCredential")]
    pub no_credential: NoCredential,
    pub forms: Forms,
    pub responses: OauthResponses,
    pub errors: OauthErrors,
    pub retries: OauthRetries,
    pub poll: Poll,
}

#[derive(Deserialize)]
pub struct OauthEndpoint {
    pub method: String,
    pub path: String,
}

#[derive(Deserialize)]
pub struct NoCredential {
    #[serde(rename = "apiKey")]
    pub api_key: String,
    #[serde(rename = "forbiddenHeaders")]
    pub forbidden_headers: Vec<String>,
    #[serde(rename = "forbiddenQuery")]
    pub forbidden_query: Vec<String>,
}

#[derive(Deserialize)]
pub struct Forms {
    #[serde(rename = "contentType")]
    pub content_type: String,
    pub cases: Vec<FormCase>,
}

#[derive(Deserialize)]
pub struct FormCase {
    pub name: String,
    pub operation: String,
    pub endpoint: String,
    pub args: OauthArgs,
    pub fields: HashMap<String, String>,
}

#[derive(Deserialize, Default, Clone)]
pub struct OauthArgs {
    #[serde(default, rename = "clientId")]
    pub client_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default, rename = "deviceCode")]
    pub device_code: Option<String>,
    #[serde(default, rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Deserialize)]
pub struct OauthResponses {
    pub metadata: Vec<ResponseCase>,
    #[serde(rename = "deviceAuthorization")]
    pub device_authorization: Vec<ResponseCase>,
    pub token: Vec<ResponseCase>,
    pub revoke: Vec<Served>,
}

#[derive(Deserialize)]
pub struct ResponseCase {
    pub name: String,
    #[serde(flatten)]
    pub served: Served,
    pub expect: Members,
}

#[derive(Deserialize)]
pub struct Members {
    pub present: serde_json::Map<String, Value>,
    pub absent: Vec<String>,
}

/// One canned response: `body` is sent as JSON, `rawBody` verbatim.
#[derive(Deserialize, Clone)]
pub struct Served {
    #[serde(default)]
    pub name: String,
    pub status: u16,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default, rename = "rawBody")]
    pub raw_body: Option<String>,
}

impl Served {
    pub fn text(&self) -> String {
        match (&self.raw_body, &self.body) {
            (Some(raw), _) => raw.clone(),
            (None, Some(body)) => body.to_string(),
            (None, None) => String::new(),
        }
    }
}

#[derive(Deserialize)]
pub struct OauthErrors {
    pub cases: Vec<OauthErrorCase>,
}

#[derive(Deserialize)]
pub struct OauthErrorCase {
    pub name: String,
    #[serde(flatten)]
    pub served: Served,
    pub expect: OauthExpect,
}

/// What an OAuth failure must look like. A member the corpus leaves out is not
/// asserted; one it sets to null must be absent.
#[derive(Deserialize, Default)]
pub struct OauthExpect {
    #[serde(default, rename = "type", alias = "outcome")]
    pub outcome: String,
    #[serde(default, rename = "errorCode")]
    pub error_code: Option<String>,
    #[serde(default, rename = "errorDescription", deserialize_with = "stated")]
    pub error_description: Option<Option<String>>,
    #[serde(default, deserialize_with = "stated")]
    pub status: Option<Option<u16>>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub retryable: Option<bool>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub requests: Option<usize>,
    #[serde(default)]
    pub waits: Vec<u64>,
    #[serde(default)]
    pub token: Option<serde_json::Map<String, Value>>,
}

#[derive(Deserialize)]
pub struct OauthRetries {
    pub cases: Vec<RetryCase>,
}

#[derive(Deserialize)]
pub struct RetryCase {
    pub name: String,
    pub operation: String,
    pub args: OauthArgs,
    pub responses: Vec<Served>,
    pub expect: OauthExpect,
}

#[derive(Deserialize)]
pub struct Poll {
    pub cases: Vec<PollCase>,
}

#[derive(Deserialize)]
pub struct PollCase {
    pub name: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    pub device: Value,
    pub responses: Vec<Served>,
    pub expect: OauthExpect,
}

/// Tells a member set to null (`Some(None)`) from one left out (`None`).
fn stated<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
