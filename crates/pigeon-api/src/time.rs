//! Time helpers, dependency-free.
//!
//! The API speaks ISO 8601 UTC (`2026-11-06T00:00:00Z`) while SQLite stores
//! `datetime('now')` (`2026-11-06 00:00:00`). Both directions are converted
//! here so handlers never format a timestamp themselves, and so the conversion
//! is covered by tests instead of being an inline `format!` nobody checks.
//!
//! The arithmetic is Howard Hinnant's `days_from_civil` / `civil_from_days`,
//! which is exact for every proleptic Gregorian date and needs no proleptic
//! leap-second table (nothing in this API observes leap seconds).

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, `0` if the system clock is before 1970.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        // A clock before 1970 is not representable; clamp instead of panicking.
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// `YYYY-MM-DDTHH:MM:SSZ` for `secs` (UTC).
pub fn iso_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// ISO 8601 for "now".
pub fn iso_now() -> String {
    iso_from_unix(now_unix())
}

/// Convert a SQLite `datetime('now')` value (`YYYY-MM-DD HH:MM:SS`) into ISO
/// 8601 UTC. Values this crate did not write (already ISO, or garbage) are
/// passed through unchanged rather than being silently turned into the epoch:
/// a wrong timestamp is worse than a visibly foreign string.
pub fn iso_from_sqlite(value: &str) -> String {
    let trimmed = value.trim();
    let mut parts = trimmed.split(' ');
    let (Some(date), Some(time), None) = (parts.next(), parts.next(), parts.next()) else {
        return trimmed.to_string();
    };
    let mut time_parts = time.split(':');
    let (Some(_), Some(_), _) = (time_parts.next(), time_parts.next(), ()) else {
        return trimmed.to_string();
    };
    format!("{date}T{time}Z")
}

/// Parse the RFC 3339 subset the API accepts: `YYYY-MM-DD` `T` `HH:MM[:SS]`
/// with an optional fractional part and `Z` / `+HH:MM` / `-HH:MM` offset.
/// A space is accepted in place of `T` so a SQLite timestamp round-trips.
pub fn parse_iso(input: &str) -> Option<i64> {
    let trimmed = input.trim();
    let (date, rest) = trimmed.split_once(['T', 't', ' '])?;
    let (year, month, day) = parse_date(date)?;
    let (time, offset_secs) = split_offset(rest)?;
    let (hour, minute, second) = parse_time(time)?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs)
}

/// Unix seconds of the next UTC midnight strictly after `from`; used for the
/// `quota.reset_at` field.
pub fn next_utc_midnight(from: i64) -> i64 {
    (from.div_euclid(86_400) + 1) * 86_400
}

/// RFC 5322 `Date:` value for `secs` (`Thu, 06 Nov 2026 00:00:00 +0000`).
pub fn rfc5322_date(secs: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, so the epoch's weekday is index 0.
    let weekday = WEEKDAYS[days.rem_euclid(7) as usize];
    let month_name = MONTHS[(month.clamp(1, 12) - 1) as usize];
    format!(
        "{weekday}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} +0000",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn parse_date(date: &str) -> Option<(i64, u32, u32)> {
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// Split a trailing `Z` or `±HH:MM` off the time part, returning the remaining
/// time and the offset in seconds east of UTC.
fn split_offset(rest: &str) -> Option<(&str, i64)> {
    if let Some(time) = rest.strip_suffix(['Z', 'z']) {
        return Some((time, 0));
    }
    // The sign of an offset can only appear after the time itself.
    if let Some(index) = rest.rfind(['+', '-']) {
        let (time, offset) = rest.split_at(index);
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let body = &offset[1..];
        let (hours, minutes) = match body.split_once(':') {
            Some((hours, minutes)) => (hours.parse::<i64>().ok()?, minutes.parse::<i64>().ok()?),
            None if body.len() == 4 => (
                body[..2].parse::<i64>().ok()?,
                body[2..].parse::<i64>().ok()?,
            ),
            None => return None,
        };
        if hours > 23 || minutes > 59 {
            return None;
        }
        return Some((time, sign * (hours * 3600 + minutes * 60)));
    }
    Some((rest, 0))
}

fn parse_time(time: &str) -> Option<(i64, i64, i64)> {
    let time = match time.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            whole
        }
        None => time,
    };
    let mut parts = time.split(':');
    let hour: i64 = parts.next()?.parse().ok()?;
    let minute: i64 = parts.next()?.parse().ok()?;
    let second: i64 = match parts.next() {
        Some(value) => value.parse().ok()?,
        None => 0,
    };
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 } as i64;
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_formats_and_parses() {
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn known_timestamps_round_trip() {
        for secs in [
            0,
            1,
            59,
            86_399,
            86_400,
            951_782_400, // 2000-02-29
            1_760_000_000,
            2_147_483_647,
        ] {
            let iso = iso_from_unix(secs);
            assert_eq!(parse_iso(&iso), Some(secs), "{iso} must round-trip");
        }
    }

    #[test]
    fn leap_day_and_month_boundaries() {
        assert_eq!(iso_from_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_from_unix(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(iso_from_unix(1_735_689_599), "2024-12-31T23:59:59Z");
        assert_eq!(iso_from_unix(1_735_689_600), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn offsets_and_fractions_are_accepted() {
        assert_eq!(parse_iso("2026-11-06T00:00:00Z"), Some(1_793_923_200));
        assert_eq!(parse_iso("2026-11-06T00:00:00.123Z"), Some(1_793_923_200));
        assert_eq!(parse_iso("2026-11-06T01:00:00+01:00"), Some(1_793_923_200));
        assert_eq!(parse_iso("2026-11-05T19:00:00-05:00"), Some(1_793_923_200));
        assert_eq!(parse_iso("2026-11-06 00:00:00"), Some(1_793_923_200));
        assert_eq!(parse_iso(" 2026-11-06T00:00:00Z "), Some(1_793_923_200));
    }

    #[test]
    fn garbage_is_rejected_instead_of_guessed() {
        for input in [
            "",
            "not-a-date",
            "2026-11-06",
            "2026-13-01T00:00:00Z",
            "2026-11-32T00:00:00Z",
            "2026-11-06T24:00:00Z",
            "2026-11-06T00:60:00Z",
            "2026-11-06T00:00:00.",
            "2026-11-06T00:00:00+99:00",
            "2026-11-06T00:00:00Q",
        ] {
            assert_eq!(parse_iso(input), None, "{input:?} must not parse");
        }
    }

    #[test]
    fn sqlite_timestamps_become_iso_and_foreign_values_pass_through() {
        assert_eq!(
            iso_from_sqlite("2026-11-06 12:34:56"),
            "2026-11-06T12:34:56Z"
        );
        assert_eq!(
            iso_from_sqlite("2026-11-06T12:34:56Z"),
            "2026-11-06T12:34:56Z"
        );
        assert_eq!(iso_from_sqlite("garbage"), "garbage");
        assert_eq!(iso_from_sqlite(""), "");
    }

    #[test]
    fn next_midnight_is_strictly_after_the_input() {
        assert_eq!(next_utc_midnight(0), 86_400);
        assert_eq!(next_utc_midnight(86_399), 86_400);
        assert_eq!(next_utc_midnight(86_400), 172_800);
    }

    #[test]
    fn rfc5322_dates_name_the_right_weekday_and_month() {
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        // 2026-11-06 is a Friday.
        assert_eq!(
            rfc5322_date(1_793_923_200),
            "Fri, 06 Nov 2026 00:00:00 +0000"
        );
        assert_eq!(
            rfc5322_date(1_709_164_800),
            "Thu, 29 Feb 2024 00:00:00 +0000"
        );
        assert!(rfc5322_date(1_760_000_000).ends_with(" +0000"));
    }

    #[test]
    fn now_is_a_plausible_unix_timestamp() {
        // 2020-01-01 .. 2100-01-01: any machine running this suite is inside.
        let now = now_unix();
        assert!((1_577_836_800..4_102_444_800).contains(&now), "{now}");
        assert!(iso_now().ends_with('Z'));
    }
}
