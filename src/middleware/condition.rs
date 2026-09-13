use std::fmt;

use indexmap::IndexMap;
use serde_json::Value as Json;

/// A numeric bound, or a range when you chain them.
///
/// `Bound::gte(5)` reads "at least 5"; `Bound::gte(5).lt(100)` is the half-open
/// range. Every bound you give must hold, and a non-numeric answer satisfies
/// none of them.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Bound {
    gte: Option<f64>,
    gt: Option<f64>,
    lte: Option<f64>,
    lt: Option<f64>,
}

impl Bound {
    pub fn gte(value: f64) -> Self {
        Self { gte: Some(value), ..Self::default() }
    }

    pub fn gt(value: f64) -> Self {
        Self { gt: Some(value), ..Self::default() }
    }

    pub fn lte(value: f64) -> Self {
        Self { lte: Some(value), ..Self::default() }
    }

    pub fn lt(value: f64) -> Self {
        Self { lt: Some(value), ..Self::default() }
    }

    #[must_use]
    pub fn and_gte(mut self, value: f64) -> Self {
        self.gte = Some(value);
        self
    }

    #[must_use]
    pub fn and_gt(mut self, value: f64) -> Self {
        self.gt = Some(value);
        self
    }

    #[must_use]
    pub fn and_lte(mut self, value: f64) -> Self {
        self.lte = Some(value);
        self
    }

    #[must_use]
    pub fn and_lt(mut self, value: f64) -> Self {
        self.lt = Some(value);
        self
    }

    fn holds(self, got: f64) -> bool {
        self.gte.is_none_or(|b| got >= b)
            && self.gt.is_none_or(|b| got > b)
            && self.lte.is_none_or(|b| got <= b)
            && self.lt.is_none_or(|b| got < b)
    }

    fn is_empty(self) -> bool {
        self.gte.is_none() && self.gt.is_none() && self.lte.is_none() && self.lt.is_none()
    }
}

/// One term of a condition.
///
/// You rarely name this type: `true`, `"nordvpn"`, `5`, a [`Bound`], a nested
/// [`Condition`] and a `Vec` of any of them all convert into it.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Text(String),
    Number(f64),
    /// Any of these. `vec!["high", "medium"]` converts into it.
    AnyOf(Vec<Value>),
    Bound(Bound),
    Nested(Condition),
    /// Ignored, exactly like [`Value::Bool(false)`].
    Null,
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<Bound> for Value {
    fn from(value: Bound) -> Self {
        Self::Bound(value)
    }
}

impl From<Condition> for Value {
    fn from(value: Condition) -> Self {
        Self::Nested(value)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(value: Vec<T>) -> Self {
        Self::AnyOf(value.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

macro_rules! value_from_number {
    ($($t:ty),*) => {
        $(impl From<$t> for Value {
            fn from(value: $t) -> Self {
                Self::Number(f64::from(value))
            }
        })*
    };
}

value_from_number!(i8, i16, i32, u8, u16, u32, f32, f64);

/// What to block on, written in the shape of an answer.
///
/// Keyed by the same names the API serves, so what you write here reads like
/// what you get back, and only the members you name are considered:
///
/// ```
/// use vpndetection::middleware::{Bound, Condition};
///
/// Condition::from([("is_vpn", true)]);
/// Condition::new()
///     .with("is_vpn", true)
///     .with("vpn", Condition::from([("provider", "nordvpn")]));
/// Condition::from([("resproxy", Condition::from([("hits", Bound::gte(5.0))]))]);
/// ```
///
/// A member set to `false` or [`Value::Null`] is ignored entirely - a condition
/// states the positive signals you act on, so there is no way to write "block
/// when this is false", which would otherwise read as blocking everybody.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Condition(IndexMap<String, Value>);

impl Condition {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, member: impl Into<String>, value: impl Into<Value>) -> Self {
        self.0.insert(member.into(), value.into());
        self
    }
}

impl<K: Into<String>, V: Into<Value>, const N: usize> From<[(K, V); N]> for Condition {
    fn from(entries: [(K, V); N]) -> Self {
        entries.into_iter().fold(Self::new(), |c, (k, v)| c.with(k, v))
    }
}

/// A list of conditions is OR; the members within one are AND.
pub type Conditions = Vec<Condition>;

/// A condition that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionError(String);

impl ConditionError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vpndetection: {}", self.0)
    }
}

impl std::error::Error for ConditionError {}

/// Reads a condition out of JSON, for an app whose policy lives in its config
/// rather than in its source.
///
/// The shape is the one the README documents: an object is a condition, an
/// array of objects is OR, an array of scalars is any-of, and an object whose
/// keys are all `gte`/`gt`/`lte`/`lt` is a bound.
pub fn from_json(raw: &Json) -> Result<Conditions, ConditionError> {
    match raw {
        Json::Array(entries) => entries.iter().map(object).collect(),
        other => Ok(vec![object(other)?]),
    }
}

fn object(raw: &Json) -> Result<Condition, ConditionError> {
    let Json::Object(members) = raw else {
        return Err(ConditionError(format!("a condition must be an object, got {raw}")));
    };
    members.iter().try_fold(Condition::new(), |c, (member, value)| {
        Ok(c.with(member.clone(), value_from_json(value)?))
    })
}

fn value_from_json(raw: &Json) -> Result<Value, ConditionError> {
    Ok(match raw {
        Json::Bool(value) => Value::Bool(*value),
        Json::String(value) => Value::Text(value.clone()),
        Json::Null => Value::Null,
        Json::Number(value) => Value::Number(
            value
                .as_f64()
                .ok_or_else(|| ConditionError(format!("{value} is not a finite number")))?,
        ),
        Json::Array(entries) => {
            Value::AnyOf(entries.iter().map(value_from_json).collect::<Result<_, _>>()?)
        }
        Json::Object(members) => {
            if let Some(bound) = bound_from_json(members)? {
                Value::Bound(bound)
            } else {
                Value::Nested(object(raw)?)
            }
        }
    })
}

const BOUND_KEYS: [&str; 4] = ["gte", "gt", "lte", "lt"];

fn bound_from_json(
    members: &serde_json::Map<String, Json>,
) -> Result<Option<Bound>, ConditionError> {
    if members.is_empty() || !members.keys().all(|k| BOUND_KEYS.contains(&k.as_str())) {
        return Ok(None);
    }
    let mut bound = Bound::default();
    for (key, value) in members {
        let n = value
            .as_f64()
            .ok_or_else(|| ConditionError(format!("bound {key} must be a number, got {value}")))?;
        bound = match key.as_str() {
            "gte" => bound.and_gte(n),
            "gt" => bound.and_gt(n),
            "lte" => bound.and_lte(n),
            _ => bound.and_lt(n),
        };
    }
    Ok(Some(bound))
}

/// Whether an answer satisfies any of the conditions, and should be blocked.
pub(crate) fn matches(conditions: &[Condition], answer: &Json) -> bool {
    conditions.iter().any(|one| matches_object(one, Some(answer)))
}

/// The top-level members a condition names that this answer did not carry.
///
/// A field your plan does not include is absent rather than false, so a
/// condition naming one can never match and the block would silently never
/// fire. Gating is per top-level member, which is why only the first path
/// segment is checked: a detail object present but empty is a real answer
/// meaning the flag is false, not a plan gap.
pub(crate) fn missing_members(conditions: &[Condition], answer: &Json) -> Vec<String> {
    let mut missing: Vec<String> = Vec::new();
    for one in conditions {
        for (member, want) in &one.0 {
            if constraints(want) == 0 || missing.iter().any(|m| m == member) {
                continue;
            }
            if answer.get(member).is_none() {
                missing.push(member.clone());
            }
        }
    }
    missing
}

/// Refuses a condition that constrains nothing.
///
/// Ignoring `false` means `{"is_vpn": false}` and `{}` have no terms left to
/// satisfy, so they would match every answer and block all traffic. Nobody
/// writes that on purpose, and failing when the middleware is built beats
/// discovering it in production.
pub(crate) fn validate(conditions: &[Condition]) -> Result<(), ConditionError> {
    for one in conditions {
        if one.0.values().map(constraints).sum::<usize>() == 0 {
            return Err(ConditionError(format!(
                "block condition {one:?} constrains nothing, which would block every request; \
                 a member set to false or null is ignored, so state the positive signals you \
                 act on"
            )));
        }
    }
    Ok(())
}

/// How many leaf constraints a term actually carries.
fn constraints(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(false) => 0,
        Value::AnyOf(entries) => entries.iter().map(constraints).sum(),
        Value::Nested(nested) => nested.0.values().map(constraints).sum(),
        Value::Bound(bound) => usize::from(!bound.is_empty()),
        _ => 1,
    }
}

fn matches_object(condition: &Condition, value: Option<&Json>) -> bool {
    condition.0.iter().all(|(member, want)| {
        constraints(want) == 0 || matches_value(want, value.and_then(|v| v.get(member)))
    })
}

/// An ABSENT member arrives here as `None`, which is exactly what "not in your
/// plan" looks like. Every branch below must therefore reject it, which is what
/// makes an unserved member fail a match rather than pass it.
fn matches_value(want: &Value, got: Option<&Json>) -> bool {
    match want {
        Value::AnyOf(entries) => entries.iter().any(|entry| matches_value(entry, got)),
        Value::Nested(nested) => got.is_some() && matches_object(nested, got),
        Value::Bound(bound) => got.and_then(Json::as_f64).is_some_and(|n| bound.holds(n)),
        // Providers are lowercase slugs on the wire and a caller should not have
        // to know that, so a string compares without case.
        Value::Text(text) => {
            got.and_then(Json::as_str).is_some_and(|s| s.eq_ignore_ascii_case(text))
        }
        Value::Bool(value) => got.and_then(Json::as_bool) == Some(*value),
        Value::Number(value) => got.and_then(Json::as_f64) == Some(*value),
        Value::Null => false,
    }
}
