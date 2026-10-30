//! The two date forms the spec names, read as written and nothing else.
//!
//! `scripts/generate.sh` points every date member of the generated models here,
//! and the hand-written entitlement types name these readers themselves.
//! chrono's own serde reader is a relaxed one: through 5.9.0 it took
//! `2026-10-5`, ` 2026-10-20`, `+2026-10-20`, a space for the `T`, `+0500` and
//! a leap second, each as some date, where the spec promises RFC 3339's
//! `full-date` for `format: date` and its `date-time`, with a zone, for
//! `format: date-time`. Anything else is an answer this client cannot read, the
//! same retried `server_error` as a member of the wrong type. RFC 3339 lets the
//! `T` and the `Z` be lowercase, which 5.9.3 refused.

use chrono::{DateTime, FixedOffset, NaiveDate};
use serde::Deserialize;
use serde::de::{Deserializer, Error as _};

/// A `format: date` member.
pub(crate) fn date<'de, D: Deserializer<'de>>(deserializer: D) -> Result<NaiveDate, D::Error> {
    let value = String::deserialize(deserializer)?;
    parse_date(&value).ok_or_else(|| D::Error::custom(format!("{value:?} is not a date")))
}

/// A required `format: date-time` member.
pub(crate) fn date_time<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DateTime<FixedOffset>, D::Error> {
    let value = String::deserialize(deserializer)?;
    parse_date_time(&value).ok_or_else(|| D::Error::custom(format!("{value:?} is not a date-time")))
}

/// A required, nullable `format: date-time` member: present, and null or a
/// date-time. Missing is refused as it is for `Option::deserialize`, which this
/// replaces.
pub(crate) fn option_date_time<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DateTime<FixedOffset>>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| {
            parse_date_time(&value)
                .ok_or_else(|| D::Error::custom(format!("{value:?} is not a date-time")))
        })
        .transpose()
}

/// An optional `format: date` member, such as a lookup's `last_seen`: absent
/// or null is `None`, as `Option::deserialize` reads it. Its field also needs
/// `default`, since a field with its own reader is otherwise required.
pub(crate) fn option_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NaiveDate>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| {
            parse_date(&value).ok_or_else(|| D::Error::custom(format!("{value:?} is not a date")))
        })
        .transpose()
}

/// An optional, nullable `format: date-time` member, read as
/// `serde_with::rust::double_option` reads one: absent is `None` (through the
/// field's `default`), null is `Some(None)` and a date-time `Some(Some(..))`.
pub(crate) fn double_option_date_time<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<DateTime<FixedOffset>>>, D::Error> {
    option_date_time(deserializer).map(Some)
}

/// `YYYY-MM-DD`, on a day that exists.
fn parse_date(value: &str) -> Option<NaiveDate> {
    let b = value.as_bytes();
    if b.len() != 10 || !is_date_shape(b) {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

/// `YYYY-MM-DDTHH:MM:SS`, an optional fraction, then `Z` or `+HH:MM`/`-HH:MM`,
/// at a time that exists: no hour 24, no minute or second 60. The `T` and the
/// `Z` in either case.
fn parse_date_time(value: &str) -> Option<DateTime<FixedOffset>> {
    let b = value.as_bytes();
    if b.len() < 20 || !is_date_shape(&b[..10]) || !matches!(b[10], b'T' | b't') {
        return None;
    }
    let time = &b[11..19];
    if !(digits(&time[0..2]) && time[2] == b':' && digits(&time[3..5]) && time[5] == b':')
        || !digits(&time[6..8])
        || &time[6..8] >= b"60".as_slice()
    {
        return None;
    }
    let mut rest = &b[19..];
    if let Some(fraction) = rest.strip_prefix(b".") {
        let n = fraction.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        rest = &fraction[n..];
    }
    let zoned = rest == b"Z"
        || rest == b"z"
        || (rest.len() == 6
            && matches!(rest[0], b'+' | b'-')
            && digits(&rest[1..3])
            && rest[3] == b':'
            && digits(&rest[4..6]));
    if !zoned {
        return None;
    }
    DateTime::parse_from_rfc3339(value).ok()
}

fn is_date_shape(b: &[u8]) -> bool {
    digits(&b[0..4]) && b[4] == b'-' && digits(&b[5..7]) && b[7] == b'-' && digits(&b[8..10])
}

fn digits(b: &[u8]) -> bool {
    b.iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::{parse_date, parse_date_time};
    use crate::generated::models::{AccountOrg, ApikeyDetail, VpnDetail};

    /// The three shapes internetdata's models lack: an optional date, and an
    /// optional, nullable date-time read as absent, null or a value.
    #[test]
    fn each_generated_shape_reads_through_the_strict_reader() {
        let read = |json: &str| serde_json::from_str::<VpnDetail>(json).map(|v| v.last_seen);
        assert_eq!(read("{}").expect("absent"), None);
        assert_eq!(read(r#"{"last_seen":null}"#).expect("null"), None);
        assert_eq!(
            read(r#"{"last_seen":"2026-10-20"}"#).expect("a date").map(|d| d.to_string()),
            Some("2026-10-20".to_owned())
        );
        assert!(read(r#"{"last_seen":"2026-10-5"}"#).is_err());

        let id = r#""id":"0ab424cc-7619-4dad-b027-afacdc2cedb0""#;
        let org = |rest: &str| {
            serde_json::from_str::<AccountOrg>(&format!("{{{id}{rest}}}")).map(|o| o.created)
        };
        assert_eq!(org("").expect("absent"), None);
        assert_eq!(org(r#","created":null"#).expect("null"), Some(None));
        assert!(
            org(r#","created":"2026-10-20T10:00:00Z""#)
                .expect("a date-time")
                .is_some_and(|c| c.is_some())
        );
        assert!(org(r#","created":"2026-10-20 10:00:00Z""#).is_err());

        let key = |created: &str| {
            serde_json::from_str::<ApikeyDetail>(&format!(
                r#"{{{id},"name":"n","key_prefix":"p","created":"{created}","expires":null}}"#
            ))
        };
        let detail = key("2026-10-20T10:00:00Z").expect("a date-time");
        assert_eq!((detail.expires, detail.last_used_at), (Some(None), None));
        assert!(key("2026-10-20T10:00:00+0500").is_err());
        // The writer is serde_with's still: absent stays absent, null stays null.
        let written = serde_json::to_value(&detail).expect("write");
        assert_eq!(written.get("expires"), Some(&serde_json::Value::Null));
        assert_eq!(written.get("last_used_at"), None);
    }

    #[test]
    fn a_date_is_a_full_date_on_a_day_that_exists() {
        assert_eq!(parse_date("2026-10-19").map(|d| d.to_string()), Some("2026-10-19".to_owned()));
        assert_eq!(parse_date("2028-02-29").map(|d| d.to_string()), Some("2028-02-29".to_owned()));
        for value in [
            "",
            "x",
            "tomorrow",
            "monday",
            "2026-02-30",
            "2026-11-31",
            "2027-02-29",
            "2026-13-01",
            "2026-10-5",
            "2026-1-05",
            "+2026-10-20",
            " 2026-10-20",
            "2026-10-20 ",
            "-0001-10-20",
            "+12026-10-20",
            "20261020",
            "2026-W43-2",
            "2026-293",
            "2026-10-20T10:00:00Z",
            "２026-10-20",
        ] {
            assert_eq!(parse_date(value), None, "{value:?}");
        }
    }

    #[test]
    fn a_date_time_is_rfc_3339_with_a_zone_at_a_time_that_exists() {
        for (value, read) in [
            ("2026-09-04T10:00:00.123Z", "2026-09-04T10:00:00.123+00:00"),
            ("2026-09-04T10:00:00Z", "2026-09-04T10:00:00+00:00"),
            ("2026-09-04T10:00:00+05:00", "2026-09-04T10:00:00+05:00"),
            ("2026-09-04T10:00:00.5-08:30", "2026-09-04T10:00:00.500-08:30"),
            ("2028-02-29T23:59:59Z", "2028-02-29T23:59:59+00:00"),
            ("2026-10-20t10:00:00Z", "2026-10-20T10:00:00+00:00"),
            ("2026-10-20T10:00:00z", "2026-10-20T10:00:00+00:00"),
            ("2026-10-20t10:00:00.5z", "2026-10-20T10:00:00.500+00:00"),
        ] {
            assert_eq!(
                parse_date_time(value).map(|d| d.to_rfc3339()),
                Some(read.to_owned()),
                "{value:?}"
            );
        }
        for value in [
            "",
            "x",
            "tomorrow",
            "monday",
            "10:00",
            "2026-10-20",
            "2026-10-20T10:00:00",
            "2026-10-20T10:00Z",
            "2026-02-30T00:00:00Z",
            "2026-11-31T00:00:00Z",
            "2026-10-20T24:00:00Z",
            "2026-10-20T23:60:00Z",
            "2026-10-20T23:59:60Z",
            "2026-10-20 10:00:00Z",
            "2026-10-20T10:00:00Z\n",
            "2026-10-20T10:00:00+0500",
            "2026-10-20T10:00:00+05",
            "2026-10-20T10:00:00.Z",
            "  2026-10-20T10:00:00Z",
            "2026-10-20T10:00:00Z ",
            "+002026-10-20T10:00:00Z",
            "2026-10-20T10:00:00+24:00",
            "2026-10-20T10:00:00 +05:00",
            "2026-10-20T10:00:00+05:00x",
            "2026-10-20T10:00:00.１Z",
        ] {
            assert_eq!(parse_date_time(value), None, "{value:?}");
        }
    }
}
