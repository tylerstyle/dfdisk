//! Points in time on the host's clock, in UTC: the only module that names
//! the date library (jiff).
//!
//! Reports, audit records and rescue records carry these timestamps, and
//! dfdisk reads them back (a resumed rescue, a verification against a report),
//! so their text form is part of the report format. It is the one dfdisk has
//! written since its first release, when chrono produced it:
//!
//! - in JSON: RFC 3339 with `Z` and no, three, six or nine fractional digits,
//!   whichever is the shortest of these that loses nothing
//!   (`2026-11-23T17:37:08.120Z`, never `…08.12Z`);
//! - [`UtcTime::to_rfc3339`]: the same with `+00:00` for `Z`.
//!
//! Reading accepts any RFC 3339 timestamp, with any offset and any number of
//! fractional digits.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const NANOS_PER_SEC: i128 = 1_000_000_000;

/// A point in time, UTC, with nanosecond resolution.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime(jiff::Timestamp);

impl UtcTime {
    /// The host's system clock now.
    pub fn now() -> Self {
        Self(jiff::Timestamp::now())
    }

    /// `seconds` since 1970-01-01T00:00:00Z plus `nanoseconds` (below one
    /// second); `None` for a full second or more of nanoseconds and outside
    /// the years jiff represents (-9999 to 9999).
    pub fn from_unix(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if i128::from(nanoseconds) >= NANOS_PER_SEC {
            return None;
        }
        let total = i128::from(seconds) * NANOS_PER_SEC + i128::from(nanoseconds);
        jiff::Timestamp::from_nanosecond(total).ok().map(Self)
    }

    /// Whole seconds since 1970-01-01T00:00:00Z, rounded down.
    pub fn unix_seconds(self) -> i64 {
        // The quotient of a jiff timestamp's nanoseconds fits an i64
        self.0.as_nanosecond().div_euclid(NANOS_PER_SEC) as i64
    }

    /// The fraction of the second, 0 to 999 999 999.
    fn subsec_nanos(self) -> u32 {
        self.0.as_nanosecond().rem_euclid(NANOS_PER_SEC) as u32
    }

    /// `.120`, `.123400`, `.123456789` or nothing: three, six or nine digits,
    /// the fewest of these that lose nothing.
    fn fraction(self) -> String {
        let nanos = self.subsec_nanos();
        if nanos == 0 {
            String::new()
        } else if nanos.is_multiple_of(1_000_000) {
            format!(".{:03}", nanos / 1_000_000)
        } else if nanos.is_multiple_of(1_000) {
            format!(".{:06}", nanos / 1_000)
        } else {
            format!(".{nanos:09}")
        }
    }

    /// The whole second this time lies in: the fields are those of the
    /// second rounded down, also before 1970.
    fn whole_second(self) -> jiff::Timestamp {
        jiff::Timestamp::from_second(self.unix_seconds()).unwrap_or(self.0)
    }

    fn rfc3339(self, utc_suffix: &str) -> String {
        format!(
            "{}{}{utc_suffix}",
            self.whole_second().strftime("%Y-%m-%dT%H:%M:%S"),
            self.fraction()
        )
    }

    /// The JSON form: `2026-11-23T17:37:08.123456789Z`.
    pub fn to_rfc3339_z(self) -> String {
        self.rfc3339("Z")
    }

    /// `2026-11-23T17:37:08.123456789+00:00`: the form of the rescue records'
    /// text lines.
    pub fn to_rfc3339(self) -> String {
        self.rfc3339("+00:00")
    }

    /// `2026-11-23 17:37:08`, for the text reports.
    pub fn date_time(self) -> String {
        self.whole_second()
            .strftime("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    /// `17:37:08`, for the text reports.
    pub fn time_of_day(self) -> String {
        self.whole_second().strftime("%H:%M:%S").to_string()
    }

    /// `20261123T173708Z`, for file names.
    pub fn compact(self) -> String {
        self.whole_second().strftime("%Y%m%dT%H%M%SZ").to_string()
    }
}

impl fmt::Debug for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339_z())
    }
}

impl FromStr for UtcTime {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<jiff::Timestamp>()
            .map(Self)
            .map_err(|e| format!("not an RFC 3339 timestamp: {e}"))
    }
}

impl Serialize for UtcTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339_z())
    }
}

impl<'de> Deserialize<'de> for UtcTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Seconds the host's local time is ahead of UTC at `at` (east positive),
/// from `$TZ` or /etc/localtime; 0 when neither names a usable zone.
pub fn local_utc_offset_seconds(at: UtcTime) -> i32 {
    offset_seconds(&jiff::tz::TimeZone::system(), at)
}

fn offset_seconds(zone: &jiff::tz::TimeZone, at: UtcTime) -> i32 {
    zone.to_offset(at.0).seconds()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-23T17:37:08Z
    const SECS: i64 = 1_795_455_428;

    /// (seconds, nanoseconds, JSON form): what chrono 0.4.45 wrote for these
    /// values (`serde_json::to_string` of a `DateTime<Utc>`), taken from a run
    /// of it. dfdisk 0.2.1 and earlier wrote exactly these strings.
    const GOLDEN: &[(i64, u32, &str)] = &[
        (SECS, 0, "2026-11-23T17:37:08Z"),
        (SECS, 100_000_000, "2026-11-23T17:37:08.100Z"),
        (SECS, 120_000_000, "2026-11-23T17:37:08.120Z"),
        (SECS, 123_000_000, "2026-11-23T17:37:08.123Z"),
        (SECS, 123_400_000, "2026-11-23T17:37:08.123400Z"),
        (SECS, 123_456_000, "2026-11-23T17:37:08.123456Z"),
        (SECS, 123_456_700, "2026-11-23T17:37:08.123456700Z"),
        (SECS, 123_456_789, "2026-11-23T17:37:08.123456789Z"),
        (SECS, 1_000, "2026-11-23T17:37:08.000001Z"),
        (SECS, 1, "2026-11-23T17:37:08.000000001Z"),
        (0, 0, "1970-01-01T00:00:00Z"),
        (951_782_400, 0, "2000-02-29T00:00:00Z"),
        (4_107_542_399, 999_999_999, "2100-02-28T23:59:59.999999999Z"),
        (-1, 500_000_000, "1969-12-31T23:59:59.500Z"),
    ];

    fn at(seconds: i64, nanoseconds: u32) -> UtcTime {
        UtcTime::from_unix(seconds, nanoseconds).unwrap()
    }

    #[test]
    fn json_form_is_the_one_chrono_wrote() {
        for &(secs, nanos, expected) in GOLDEN {
            let t = at(secs, nanos);
            assert_eq!(t.to_rfc3339_z(), expected);
            assert_eq!(
                serde_json::to_string(&t).unwrap(),
                format!("\"{expected}\""),
                "{secs}.{nanos:09}"
            );
        }
    }

    #[test]
    fn rfc3339_form_has_the_numeric_utc_offset() {
        for &(secs, nanos, json) in GOLDEN {
            let expected = format!("{}+00:00", json.strip_suffix('Z').unwrap());
            assert_eq!(at(secs, nanos).to_rfc3339(), expected);
        }
    }

    #[test]
    fn reads_back_both_forms_it_writes() {
        for &(secs, nanos, json) in GOLDEN {
            let t = at(secs, nanos);
            assert_eq!(json.parse::<UtcTime>().unwrap(), t);
            assert_eq!(t.to_rfc3339().parse::<UtcTime>().unwrap(), t);
            let quoted = format!("\"{json}\"");
            assert_eq!(serde_json::from_str::<UtcTime>(&quoted).unwrap(), t);
        }
    }

    #[test]
    fn reads_other_offsets_and_fraction_lengths() {
        let t = at(SECS, 120_000_000);
        for text in [
            "2026-11-23T17:37:08.12Z",
            "2026-11-23T17:37:08.120000000Z",
            "2026-11-23T18:37:08.12+01:00",
            "2026-11-23T14:07:08.120-03:30",
            "2026-11-23t17:37:08.12z",
        ] {
            assert_eq!(text.parse::<UtcTime>().unwrap(), t, "{text}");
        }
    }

    #[test]
    fn rejects_what_is_not_a_timestamp() {
        for text in [
            "",
            "2026-11-23",
            "2026-11-23T17:37:08",
            "yesterday",
            "1795455428",
        ] {
            assert!(text.parse::<UtcTime>().is_err(), "{text:?}");
            let quoted = format!("\"{text}\"");
            assert!(
                serde_json::from_str::<UtcTime>(&quoted).is_err(),
                "{text:?}"
            );
        }
        assert!(serde_json::from_str::<UtcTime>("1795455428").is_err());
    }

    #[test]
    fn a_struct_round_trips_through_json() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Record {
            started: UtcTime,
            ended: Option<UtcTime>,
            missing: Option<UtcTime>,
        }
        let record = Record {
            started: at(SECS, 123_400_000),
            ended: Some(at(SECS + 61, 0)),
            missing: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(
            json,
            r#"{"started":"2026-11-23T17:37:08.123400Z","ended":"2026-11-23T17:38:09Z","missing":null}"#
        );
        assert_eq!(serde_json::from_str::<Record>(&json).unwrap(), record);
    }

    #[test]
    fn text_forms_drop_the_fraction() {
        let t = at(SECS, 999_999_999);
        assert_eq!(t.date_time(), "2026-11-23 17:37:08");
        assert_eq!(t.time_of_day(), "17:37:08");
        assert_eq!(t.compact(), "20261123T173708Z");
        let early = at(-1, 500_000_000);
        assert_eq!(early.date_time(), "1969-12-31 23:59:59");
        assert_eq!(early.compact(), "19691231T235959Z");
    }

    #[test]
    fn from_unix_takes_less_than_a_second_of_nanoseconds() {
        assert!(UtcTime::from_unix(SECS, 999_999_999).is_some());
        assert!(UtcTime::from_unix(SECS, 1_000_000_000).is_none());
        assert!(UtcTime::from_unix(SECS, 1_500_000_000).is_none());
        assert!(UtcTime::from_unix(SECS, u32::MAX).is_none());
        // Outside the years -9999 to 9999
        assert!(UtcTime::from_unix(i64::MAX, 0).is_none());
        assert!(UtcTime::from_unix(i64::MIN, 0).is_none());
    }

    #[test]
    fn unix_seconds_round_down() {
        assert_eq!(at(SECS, 999_999_999).unix_seconds(), SECS);
        assert_eq!(at(0, 0).unix_seconds(), 0);
        assert_eq!(at(-1, 500_000_000).unix_seconds(), -1);
    }

    #[test]
    fn times_order_and_now_is_recent() {
        assert!(at(SECS, 1) > at(SECS, 0));
        assert!(at(SECS + 1, 0) > at(SECS, 999_999_999));
        // After this file was written, before the year 2100
        let now = UtcTime::now().unix_seconds();
        assert!(now > SECS && now < 4_102_444_800, "{now}");
    }

    #[test]
    fn debug_is_the_json_form() {
        assert_eq!(
            format!("{:?}", at(SECS, 120_000_000)),
            "2026-11-23T17:37:08.120Z"
        );
    }

    /// POSIX zone rules need no time zone database, so these run in a build
    /// sandbox without /usr/share/zoneinfo too.
    #[test]
    fn offset_follows_the_zone_rule_at_that_time() {
        use jiff::tz::TimeZone;
        let winter = at(SECS, 0); // 23 November
        let summer = at(1_782_000_000, 0); // 21 June 2026
        let berlin = TimeZone::posix("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        assert_eq!(offset_seconds(&berlin, winter), 3600);
        assert_eq!(offset_seconds(&berlin, summer), 7200);
        let st_johns = TimeZone::posix("NST3:30NDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!(offset_seconds(&st_johns, winter), -12600);
        assert_eq!(offset_seconds(&st_johns, summer), -9000);
        let kolkata = TimeZone::posix("IST-5:30").unwrap();
        assert_eq!(offset_seconds(&kolkata, winter), 19800);
        assert_eq!(offset_seconds(&TimeZone::UTC, winter), 0);
    }

    /// Not a test of its own: prints what this process sees as local offset,
    /// for [`local_offset_follows_tz`], which runs it with `$TZ` set.
    #[test]
    #[ignore = "helper run by local_offset_follows_tz"]
    fn print_local_offset() {
        println!("local-offset={}", local_utc_offset_seconds(UtcTime::now()));
    }

    /// `$TZ` is read once per process and other tests run in this one, so the
    /// offsets are taken in child processes of this test binary.
    #[test]
    fn local_offset_follows_tz() {
        let exe = std::env::current_exe().unwrap();
        let offset_under = |tz: &str| -> String {
            let out = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "models::timestamp::tests::print_local_offset",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("TZ", tz)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(out.status.success(), "TZ={tz}: {text}");
            text.lines()
                .find_map(|l| l.split("local-offset=").nth(1))
                .unwrap_or_else(|| panic!("TZ={tz}: no offset in {text:?}"))
                .trim()
                .to_string()
        };
        // Fixed offsets, so the result does not depend on today's date
        assert_eq!(offset_under("UTC0"), "0");
        assert_eq!(offset_under("IST-5:30"), "19800");
        assert_eq!(offset_under("EST5"), "-18000");
        assert_eq!(offset_under("<+0845>-8:45"), "31500");
    }
}
