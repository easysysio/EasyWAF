// src/clock.rs
//
// UTC time, and the few textual forms EasyWAF writes and reads it in.
//
// Everything is UTC: SQLite's `datetime('now')` is, and so is every stamp this
// code stores, so a value written in one place compares and parses the same
// everywhere else.

use time::format_description::well_known::Rfc3339;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};

pub use time::Duration;

/// A point in time. Every one this module hands out is in UTC.
pub type Utc = OffsetDateTime;

/// SQLite's own form, `YYYY-MM-DD HH:MM:SS`: what the `timestamp` and
/// `created_at` columns hold, so a cutoff in it compares as text.
pub const SQL: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

/// `YYYY-MM-DD HH:MM`: the hour keys the charts group by.
pub const SQL_MINUTE: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]");

/// `YYYY-MM-DDTHH:MM:SSZ`, whole seconds.
pub const ISO: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// `YYYY-MM-DD`.
pub const DAY: &[BorrowedFormatItem<'static>] = format_description!("[year]-[month]-[day]");

pub fn now() -> Utc {
    OffsetDateTime::now_utc()
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> i64 {
    now().unix_timestamp()
}

/// `t` in the given form. The forms here cannot fail on a time inside the
/// years 0–9999, so there is no error to hand back.
pub fn format(t: Utc, form: &[BorrowedFormatItem<'_>]) -> String {
    t.format(form).unwrap_or_default()
}

/// `t` as RFC 3339, for stamps that are stored and parsed back.
pub fn rfc3339(t: Utc) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// An RFC 3339 stamp, in UTC whatever offset it was written with.
pub fn parse_rfc3339(raw: &str) -> Option<Utc> {
    OffsetDateTime::parse(raw, &Rfc3339).ok().map(|t| t.to_offset(UtcOffset::UTC))
}

/// A time written in `form` without an offset, read as UTC.
pub fn parse_utc(raw: &str, form: &[BorrowedFormatItem<'_>]) -> Option<Utc> {
    PrimitiveDateTime::parse(raw, form).ok().map(PrimitiveDateTime::assume_utc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stamp_reads_back_as_the_same_instant() {
        let t = parse_utc("2026-09-27 08:05:09", SQL).unwrap();
        assert_eq!(format(t, SQL), "2026-09-27 08:05:09");
        assert_eq!(format(t, ISO), "2026-09-27T08:05:09Z");
        assert_eq!(parse_rfc3339(&rfc3339(t)), Some(t));
    }

    #[test]
    fn stamps_already_stored_still_parse() {
        // The form earlier releases wrote: `+00:00`, with nanoseconds.
        let old = parse_rfc3339("2026-09-27T08:05:09.123456789+00:00").unwrap();
        assert_eq!(format(old, SQL), "2026-09-27 08:05:09");
        let east = parse_rfc3339("2026-09-27T10:05:09+02:00").unwrap();
        assert_eq!(format(east, SQL), "2026-09-27 08:05:09");
    }

    #[test]
    fn a_form_with_trailing_text_does_not_parse() {
        assert!(parse_utc("2026-09-27 08:05:09.5", SQL).is_none());
        assert!(parse_utc("2026-09-27 08:05", SQL).is_none());
        assert!(parse_utc("2026-09-27 08:05", SQL_MINUTE).is_some());
    }
}
