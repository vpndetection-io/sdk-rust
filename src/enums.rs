//! The readers the generator does not emit for the API's closed vocabularies.
//!
//! Every one of these arrives as a string on the wire and is a Rust enum here,
//! so `{:?}` would print `Csvgz` where the API says `csvgz`. `as_str` is the
//! wire spelling and [`std::fmt::Display`] uses it, which is what makes a
//! catalog listing or a log line read as the API's own words. The conformance
//! suite asserts each one against what serde serializes, so a reader cannot
//! drift from the value actually sent.
//!
//! Each enum is `#[non_exhaustive]`, with an `Other` variant carrying a value
//! this release was not built with (scripts/generate.sh), so both readers print
//! that value as served.

use std::fmt;

use crate::models::database::LicenseType;
use crate::models::download::Outcome;
use crate::models::{DatabaseFormat, Standing};

/// Writes the `as_str` + `Display` pair for an enum the generator leaves bare.
/// The generated `Display` of a named enum is removed by scripts/generate.sh,
/// since its match has no arm for `Other`.
macro_rules! wire_spelling {
    ($type:ty { $($variant:ident => $wire:literal),+ $(,)? }) => {
        impl $type {
            /// The spelling the API uses, which is not the Rust variant name,
            /// and for `Other` the value as the API served it.
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $wire,)+
                    Self::Other(value) => value,
                }
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

// Not every database is built in every format: the `_provider` catalogs are
// keyed by provider ID rather than by IP range, so no MMDB exists for them.
// `Database::versions` says which formats each version has. Plain comments
// rather than doc ones, because rustdoc does not document what a macro
// invocation expands to.
wire_spelling!(DatabaseFormat { Csvgz => "csvgz", Mmdb => "mmdb" });

wire_spelling!(Standing {
    Expired => "expired",
    Licensed => "licensed",
    Unlicensed => "unlicensed",
});

wire_spelling!(LicenseType {
    Evaluation => "evaluation",
    Standard => "standard",
    Redistribute => "redistribute",
});

wire_spelling!(Outcome {
    Ok => "ok",
    Unauthorized => "unauthorized",
    Denied => "denied",
    Expired => "expired",
    Unknown => "unknown",
    Unavailable => "unavailable",
});

/// A format read off an answer, `version.formats[0]` say, can be handed to a
/// download as it is, without a `clone()`.
impl From<&DatabaseFormat> for DatabaseFormat {
    fn from(format: &DatabaseFormat) -> Self {
        format.clone()
    }
}
