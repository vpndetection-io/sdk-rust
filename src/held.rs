//! A member the spec requires whose public type a minor keeps optional.
//!
//! `scripts/generate.sh` generates the AS's `country` and `rpki_status` as
//! `Option<String>`, the type they had while the spec left them optional, and
//! points each here, so an answer without one, or with a null there, is still
//! one this client cannot read: the same retried `server_error` as any other
//! required member missing. The type moves to `String` at the next major.

use serde::Deserialize;
use serde::de::Deserializer;

/// The member as served, never absent or null. serde reads a member with a
/// `deserialize_with` and no `default` as required, so an absent one fails too.
pub(crate) fn required<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}
