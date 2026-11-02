//! A `type: object` the spec gives no properties, read as a JSON object and
//! nothing else.
//!
//! The generator types such a member `serde_json::Value`, which takes any JSON
//! at all, so through 5.9.4 a metadata `sample` row of `1`, `"x"`, `[]`, `true`
//! or `null` came back as the answer. `scripts/generate.sh` points every such
//! member of the generated models here; anything else is an answer this client
//! cannot read, the same retried `server_error` as a member of the wrong type.
//! The public type stays `serde_json::Value`, so each row is a `Value::Object`.

use std::collections::HashMap;

use serde::Deserialize;
use serde::de::Deserializer;
use serde_json::{Map, Value};

/// An optional map of lists of objects: metadata's `sample`, its rows keyed by
/// format. Absent and null are both `None`, as they were for
/// `Option::deserialize`, which this replaces.
pub(crate) fn option_object_lists<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<HashMap<String, Vec<Value>>>, D::Error> {
    let lists = Option::<HashMap<String, Vec<Map<String, Value>>>>::deserialize(deserializer)?;
    Ok(lists.map(|lists| {
        lists
            .into_iter()
            .map(|(key, objects)| (key, objects.into_iter().map(Value::Object).collect()))
            .collect()
    }))
}
