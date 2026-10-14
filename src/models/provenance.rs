//! Where a report came from: the dfdisk and dfcore builds, the host, the
//! external tools and every command line that ran (D17, §11), and the clock the
//! timestamps were read from.

use crate::models::text::sanitize_line;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// dfdisk version (Cargo.toml).
pub const DFDISK_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git revision of the dfdisk source this binary was built from, or "unknown".
pub const DFDISK_GIT_REV: &str = env!("DFDISK_GIT_REV");
/// Version of the dfcore crate linked into this binary, or "unknown".
pub const DFCORE_VERSION: &str = env!("DFCORE_VERSION");
/// Git revision of the dfcore source this binary was built with, or "unknown".
pub const DFCORE_GIT_REV: &str = env!("DFCORE_GIT_REV");

/// `dfdisk --version` text: version and both source revisions.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ndfdisk git revision: ",
    env!("DFDISK_GIT_REV"),
    "\ndfcore ",
    env!("DFCORE_VERSION"),
    " git revision: ",
    env!("DFCORE_GIT_REV")
);

/// One external command dfdisk ran, as run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    /// Program and arguments exactly as passed (non-UTF-8 bytes replaced)
    pub argv: Vec<String>,
    pub started: DateTime<Utc>,
    pub ended: DateTime<Utc>,
    /// Exit status; `None` when killed by a signal or never started
    pub exit_code: Option<i32>,
    /// Signal that ended the process, if any
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// How dfdisk stopped it, e.g. "aborted: SIGINT", "timed out: SIGTERM, SIGKILL"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<String>,
    /// Why it could not be started
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Last lines of standard output and standard error (sanitised, bounded)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stdout_tail: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stderr_tail: Vec<String>,
}

impl CommandRecord {
    /// The command line in shell notation, for reports.
    pub fn command_line(&self) -> String {
        self.argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// "exit 0", "signal 9", "not started: ...".
    pub fn status_text(&self) -> String {
        let mut s = match (&self.error, self.exit_code, self.signal) {
            (Some(e), _, _) => format!("not started: {e}"),
            (None, Some(code), _) => format!("exit {code}"),
            (None, None, Some(sig)) => format!("signal {sig}"),
            (None, None, None) => "unknown status".to_string(),
        };
        if let Some(stop) = &self.stop {
            s.push_str(&format!(" ({stop})"));
        }
        s
    }
}

/// Single-quote `arg` for a POSIX shell when it needs quoting.
pub fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", sanitize_line(arg).replace('\'', r"'\''"))
    }
}

#[derive(Debug, Default)]
struct RecorderInner {
    commands: Vec<CommandRecord>,
    tools: BTreeMap<String, String>,
}

/// Collects the commands of one acquisition and the versions of the tools it
/// used; cheap to clone and shared with the process helper
/// ([`crate::engines::process`]), which records every run into it.
#[derive(Debug, Clone, Default)]
pub struct ProvenanceRecorder {
    inner: Arc<Mutex<RecorderInner>>,
}

impl ProvenanceRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_command(&self, record: CommandRecord) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.commands.push(record);
        }
    }

    pub fn set_tool_version(&self, tool: &str, version: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.tools.insert(tool.to_string(), version.to_string());
        }
    }

    pub fn commands(&self) -> Vec<CommandRecord> {
        self.inner
            .lock()
            .map(|i| i.commands.clone())
            .unwrap_or_default()
    }

    pub fn tools(&self) -> BTreeMap<String, String> {
        self.inner
            .lock()
            .map(|i| i.tools.clone())
            .unwrap_or_default()
    }

    /// Copy everything recorded so far into `provenance` (tools merged,
    /// commands appended).
    pub fn fill(&self, provenance: &mut ToolProvenance) {
        provenance.tools.extend(self.tools());
        provenance.commands.extend(self.commands());
    }
}

/// Build, host and tool provenance of a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolProvenance {
    pub dfdisk_version: String,
    pub dfdisk_git_rev: String,
    pub dfcore_version: String,
    pub dfcore_git_rev: String,
    /// DFNIX_REVISION of the running dfnix system, `None` outside dfnix
    pub dfnix_revision: Option<String>,
    /// Kernel release of the examination host
    pub kernel: Option<String>,
    pub hostname: Option<String>,
    /// Version line of every external tool used, by program name
    pub tools: BTreeMap<String, String>,
    /// Every external command run, in order
    pub commands: Vec<CommandRecord>,
}

impl Default for ToolProvenance {
    /// Build constants only; no host facts (see [`ToolProvenance::capture`]).
    fn default() -> Self {
        Self {
            dfdisk_version: DFDISK_VERSION.to_string(),
            dfdisk_git_rev: DFDISK_GIT_REV.to_string(),
            dfcore_version: DFCORE_VERSION.to_string(),
            dfcore_git_rev: DFCORE_GIT_REV.to_string(),
            dfnix_revision: None,
            kernel: None,
            hostname: None,
            tools: BTreeMap::new(),
            commands: Vec::new(),
        }
    }
}

impl ToolProvenance {
    /// Build constants plus the facts of this host (dfnix revision, kernel,
    /// hostname). Reads only /proc and /etc; runs nothing.
    pub fn capture() -> Self {
        Self {
            dfnix_revision: dfcore::release::system_revision(),
            kernel: dfcore::host::kernel_release(),
            hostname: dfcore::host::hostname(),
            ..Self::default()
        }
    }
}

/// Arguments that make `tool` print its version.
pub fn version_args(tool: &str) -> &'static [&'static str] {
    match tool {
        "ewfacquire" | "ewfacquirestream" | "ewfverify" | "ewfinfo" | "ewfexport" => &["-V"],
        "hdparm" => &["-V"],
        "nvme" => &["version"],
        _ => &["--version"],
    }
}

/// Version line of each tool in `names` (see [`version_args`]); tools that
/// cannot be run are listed as "not available". Each probe times out after 5 s.
pub async fn capture_tool_versions(names: &[&str]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for name in names {
        let version =
            crate::engines::process::tool_version(name, version_args(name), Duration::from_secs(5))
                .await
                .unwrap_or_else(|| "not available".to_string());
        out.insert(name.to_string(), version);
    }
    out
}

/// What `timedatectl show` reports about the clock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimedatectlInfo {
    pub timezone: Option<String>,
    /// NTP= (time synchronisation service enabled)
    pub ntp: Option<bool>,
    /// NTPSynchronized=
    pub ntp_synchronized: Option<bool>,
    /// LocalRTC= (RTC keeps local time instead of UTC)
    pub local_rtc: Option<bool>,
}

fn yes_no(v: &str) -> Option<bool> {
    match v.trim() {
        "yes" | "true" | "1" => Some(true),
        "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

/// Parse `timedatectl show` (`Key=value` lines).
pub fn parse_timedatectl_show(text: &str) -> TimedatectlInfo {
    let mut info = TimedatectlInfo::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "Timezone" => info.timezone = Some(value.trim().to_string()).filter(|v| !v.is_empty()),
            "NTP" => info.ntp = yes_no(value),
            "NTPSynchronized" => info.ntp_synchronized = yes_no(value),
            "LocalRTC" => info.local_rtc = yes_no(value),
            _ => {}
        }
    }
    info
}

/// Zone name from the target of the /etc/localtime link, e.g.
/// "/usr/share/zoneinfo/Europe/Berlin" or "../etc/zoneinfo/UTC".
pub fn timezone_from_localtime_target(target: &str) -> Option<String> {
    let (_, zone) = target.rsplit_once("zoneinfo/")?;
    let zone = zone.trim_matches('/');
    let zone = zone
        .strip_prefix("posix/")
        .or_else(|| zone.strip_prefix("right/"))
        .unwrap_or(zone);
    (!zone.is_empty()).then(|| zone.to_string())
}

/// Seconds the RTC is ahead of the system clock (negative: behind), from the
/// content of /sys/class/rtc/rtc0/since_epoch.
pub fn rtc_offset_seconds(rtc_since_epoch: &str, system_unix: i64) -> Option<i64> {
    let rtc: i64 = rtc_since_epoch.trim().parse().ok()?;
    Some(rtc - system_unix)
}

/// "+02:00", "-05:30", "+00:00".
pub fn format_utc_offset(seconds_east: i32) -> String {
    let sign = if seconds_east < 0 { '-' } else { '+' };
    let abs = seconds_east.unsigned_abs();
    format!("{}{:02}:{:02}", sign, abs / 3600, abs % 3600 / 60)
}

/// The kernel's view of NTP synchronisation (adjtimex): synchronised when the
/// STA_UNSYNC bit is clear and the maximum error is below 16 s, the rule
/// systemd's timedatectl applies.
pub fn ntp_synced_from_timex(status: libc::c_int, maxerror_us: libc::c_long) -> bool {
    status & libc::STA_UNSYNC == 0 && maxerror_us < 16_000_000
}

fn kernel_ntp_synchronized() -> Option<bool> {
    // SAFETY: modes = 0 only reads the kernel clock state; the struct is ours
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::adjtimex(&mut tx) };
    (rc >= 0).then(|| ntp_synced_from_timex(tx.status, tx.maxerror))
}

/// Label for timestamps: plain UTC only when the clock is known to be NTP
/// synchronised (R9).
pub const LABEL_SYNCHRONIZED: &str = "UTC (NTP synchronized)";
pub const LABEL_NOT_SYNCHRONIZED: &str = "host system time, NOT synchronized";

/// The clock the report's timestamps come from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClockInfo {
    /// Start of the run, host system clock, UTC
    pub start_utc: DateTime<Utc>,
    /// End of the run, host system clock, UTC
    pub end_utc: Option<DateTime<Utc>>,
    /// IANA zone of the host, e.g. "Europe/Berlin"
    pub timezone: Option<String>,
    /// Offset of local time from UTC at the start, e.g. "+02:00"
    pub utc_offset: Option<String>,
    /// `None`: unknown
    pub ntp_synchronized: Option<bool>,
    /// Whether a time synchronisation service was enabled (timedatectl NTP=)
    pub ntp_service: Option<bool>,
    pub local_rtc: Option<bool>,
    /// RTC minus system clock at the start, seconds
    pub rtc_offset_seconds: Option<i64>,
    /// Duration of the run from the monotonic clock (immune to clock changes)
    pub monotonic_elapsed_secs: f64,
    /// [`LABEL_SYNCHRONIZED`] or [`LABEL_NOT_SYNCHRONIZED`]; kept in step with
    /// `ntp_synchronized` by [`ClockInfo::refresh_basis`]
    pub timestamp_basis: String,
    pub note: Option<String>,
}

impl Default for ClockInfo {
    fn default() -> Self {
        Self::from_parts(Utc::now(), &TimedatectlInfo::default(), None, None, None)
    }
}

impl ClockInfo {
    /// Pure constructor from probe results (tests and [`ClockInfo::capture_start`]).
    pub fn from_parts(
        start_utc: DateTime<Utc>,
        timedatectl: &TimedatectlInfo,
        timezone_fallback: Option<String>,
        rtc_offset_seconds: Option<i64>,
        utc_offset: Option<String>,
    ) -> Self {
        let mut info = Self {
            start_utc,
            end_utc: None,
            timezone: timedatectl.timezone.clone().or(timezone_fallback),
            utc_offset,
            ntp_synchronized: timedatectl.ntp_synchronized,
            ntp_service: timedatectl.ntp,
            local_rtc: timedatectl.local_rtc,
            rtc_offset_seconds,
            monotonic_elapsed_secs: 0.0,
            timestamp_basis: String::new(),
            note: None,
        };
        info.refresh_basis();
        info
    }

    /// Read the host clock state now: `timedatectl show` when present (3 s
    /// timeout), the kernel's NTP state otherwise, /etc/localtime (or $TZ),
    /// and the RTC offset from /sys/class/rtc/rtc0/since_epoch.
    pub fn capture_start() -> Self {
        let start = Utc::now();
        let mut td = crate::engines::process::run_blocking(
            &crate::engines::process::ProcessSpec::new("timedatectl")
                .arg("show")
                .timeout(Duration::from_secs(3)),
            None,
        )
        .ok()
        .filter(|o| o.outcome.success())
        .map(|o| parse_timedatectl_show(&o.stdout.join("\n")))
        .unwrap_or_default();
        if td.ntp_synchronized.is_none() {
            td.ntp_synchronized = kernel_ntp_synchronized();
        }
        let tz_env = std::env::var("TZ").ok().filter(|v| !v.trim().is_empty());
        let tz_fallback = tz_env.clone().or_else(|| {
            std::fs::read_link("/etc/localtime")
                .ok()
                .and_then(|t| timezone_from_localtime_target(&t.to_string_lossy()))
        });
        if tz_env.is_some() {
            // $TZ decides what local time this process sees
            td.timezone = None;
        }
        let rtc = std::fs::read_to_string(Path::new("/sys/class/rtc/rtc0/since_epoch"))
            .ok()
            .and_then(|s| rtc_offset_seconds(&s, start.timestamp()));
        let offset = chrono::Local::now().offset().local_minus_utc();
        Self::from_parts(
            start,
            &td,
            tz_fallback,
            rtc,
            Some(format_utc_offset(offset)),
        )
    }

    /// Record the end of the run; `elapsed` comes from an `Instant` taken at
    /// the start.
    pub fn finish(&mut self, elapsed: Duration) {
        self.end_utc = Some(Utc::now());
        self.monotonic_elapsed_secs = elapsed.as_secs_f64();
        self.refresh_basis();
    }

    /// [`LABEL_SYNCHRONIZED`] only when NTP synchronisation is known.
    pub fn label(&self) -> &'static str {
        if self.ntp_synchronized == Some(true) {
            LABEL_SYNCHRONIZED
        } else {
            LABEL_NOT_SYNCHRONIZED
        }
    }

    /// Recompute `timestamp_basis` and `note` from the other fields.
    pub fn refresh_basis(&mut self) {
        self.timestamp_basis = self.label().to_string();
        let mut notes = Vec::new();
        match self.ntp_synchronized {
            Some(true) => {}
            Some(false) => notes.push(
                "the host clock was not NTP-synchronized; timestamps are the host system time"
                    .to_string(),
            ),
            None => notes.push(
                "whether the host clock was NTP-synchronized is unknown; timestamps are the host system time"
                    .to_string(),
            ),
        }
        if self.ntp_synchronized != Some(true) {
            if let Some(off) = self.rtc_offset_seconds {
                notes.push(format!(
                    "the hardware clock (RTC) differed from the system clock by {off:+} s"
                ));
            }
        }
        if self.local_rtc == Some(true) {
            notes.push("the RTC keeps local time, so its offset includes the UTC offset".into());
        }
        self.note = (!notes.is_empty()).then(|| notes.join("; "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_revisions_are_embedded() {
        assert!(!DFDISK_GIT_REV.is_empty());
        assert!(!DFCORE_GIT_REV.is_empty());
        assert!(LONG_VERSION.starts_with(DFDISK_VERSION));
        assert!(LONG_VERSION.contains(DFDISK_GIT_REV));
        assert!(LONG_VERSION.contains(DFCORE_GIT_REV));
        let p = ToolProvenance::default();
        assert_eq!(p.dfdisk_version, DFDISK_VERSION);
        assert_eq!(p.dfcore_version, DFCORE_VERSION);
    }

    #[test]
    fn parses_timedatectl_show() {
        let text = "Timezone=Europe/Berlin\nLocalRTC=no\nCanNTP=yes\nNTP=yes\nNTPSynchronized=no\nTimeUSec=Wed 2026-10-14 12:00:00 CEST\n";
        let info = parse_timedatectl_show(text);
        assert_eq!(info.timezone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(info.ntp, Some(true));
        assert_eq!(info.ntp_synchronized, Some(false));
        assert_eq!(info.local_rtc, Some(false));
        assert_eq!(parse_timedatectl_show(""), TimedatectlInfo::default());
        assert_eq!(
            parse_timedatectl_show("Timezone=\nNTPSynchronized=maybe").ntp_synchronized,
            None
        );
    }

    #[test]
    fn zone_from_localtime_link() {
        for (target, zone) in [
            ("/usr/share/zoneinfo/Europe/Berlin", Some("Europe/Berlin")),
            ("../usr/share/zoneinfo/UTC", Some("UTC")),
            ("/etc/zoneinfo/America/New_York", Some("America/New_York")),
            ("/usr/share/zoneinfo/posix/Asia/Tokyo", Some("Asia/Tokyo")),
            ("/usr/share/zoneinfo/", None),
            ("/etc/localtime.real", None),
        ] {
            assert_eq!(timezone_from_localtime_target(target).as_deref(), zone);
        }
    }

    #[test]
    fn rtc_offset_and_utc_offset() {
        assert_eq!(rtc_offset_seconds("1791730012\n", 1791730000), Some(12));
        assert_eq!(rtc_offset_seconds("1791729990", 1791730000), Some(-10));
        assert_eq!(rtc_offset_seconds("garbage", 1), None);
        assert_eq!(format_utc_offset(7200), "+02:00");
        assert_eq!(format_utc_offset(-19800), "-05:30");
        assert_eq!(format_utc_offset(0), "+00:00");
    }

    #[test]
    fn kernel_ntp_state_rule() {
        assert!(ntp_synced_from_timex(0, 1000));
        assert!(!ntp_synced_from_timex(libc::STA_UNSYNC, 1000));
        assert!(!ntp_synced_from_timex(0, 16_000_000));
    }

    #[test]
    fn unsynchronized_or_unknown_clock_is_labelled() {
        let synced = TimedatectlInfo {
            ntp_synchronized: Some(true),
            ..Default::default()
        };
        let c = ClockInfo::from_parts(Utc::now(), &synced, None, Some(30), None);
        assert_eq!(c.label(), LABEL_SYNCHRONIZED);
        assert_eq!(c.timestamp_basis, LABEL_SYNCHRONIZED);
        assert_eq!(c.note, None);

        let unsynced = TimedatectlInfo {
            ntp_synchronized: Some(false),
            local_rtc: Some(true),
            ..Default::default()
        };
        let mut c = ClockInfo::from_parts(
            Utc::now(),
            &unsynced,
            Some("UTC".into()),
            Some(-4),
            Some("+00:00".into()),
        );
        assert_eq!(c.timestamp_basis, LABEL_NOT_SYNCHRONIZED);
        let note = c.note.clone().unwrap();
        assert!(note.contains("not NTP-synchronized"), "{note}");
        assert!(note.contains("-4 s"), "{note}");
        assert!(note.contains("local time"), "{note}");
        assert_eq!(c.timezone.as_deref(), Some("UTC"));
        c.finish(Duration::from_millis(1500));
        assert!(c.end_utc.is_some());
        assert_eq!(c.monotonic_elapsed_secs, 1.5);

        let unknown = ClockInfo::default();
        assert_eq!(unknown.label(), LABEL_NOT_SYNCHRONIZED);
        assert!(unknown.note.unwrap().contains("unknown"));
    }

    #[test]
    fn command_records_render_shell_notation() {
        let r = CommandRecord {
            argv: vec![
                "ewfacquire".into(),
                "-C".into(),
                "Case 1".into(),
                "-t".into(),
                "/cases/o'brien".into(),
            ],
            started: Utc::now(),
            ended: Utc::now(),
            exit_code: Some(0),
            signal: None,
            stop: None,
            error: None,
            stdout_tail: vec![],
            stderr_tail: vec![],
        };
        assert_eq!(
            r.command_line(),
            r"ewfacquire -C 'Case 1' -t '/cases/o'\''brien'"
        );
        assert_eq!(r.status_text(), "exit 0");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a\nb"), "'a b'");
    }

    #[test]
    fn recorder_is_shared_between_clones() {
        let rec = ProvenanceRecorder::new();
        let other = rec.clone();
        other.set_tool_version("ewfacquire", "ewfacquire 20231119");
        other.record_command(CommandRecord {
            argv: vec!["true".into()],
            started: Utc::now(),
            ended: Utc::now(),
            exit_code: Some(0),
            signal: None,
            stop: None,
            error: None,
            stdout_tail: vec![],
            stderr_tail: vec![],
        });
        let mut p = ToolProvenance::default();
        rec.fill(&mut p);
        assert_eq!(p.tools["ewfacquire"], "ewfacquire 20231119");
        assert_eq!(p.commands.len(), 1);
        assert_eq!(version_args("nvme"), ["version"]);
        assert_eq!(version_args("ewfverify"), ["-V"]);
        assert_eq!(version_args("ddrescue"), ["--version"]);
    }
}
