// The shared conformance corpus, generated into testdata/ by the monorepo and
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
    pub keys: Vec<String>,
    #[serde(rename = "httpRequests")]
    pub http_requests: Option<usize>,
    #[serde(default, rename = "bogonKeys")]
    pub bogon_keys: Vec<String>,
    #[serde(default, rename = "errorKeys")]
    pub error_keys: Vec<String>,
}

#[derive(Deserialize)]
pub struct Bogons {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}
