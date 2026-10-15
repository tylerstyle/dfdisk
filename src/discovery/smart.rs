//! SMART snapshots of the physical disk of a source (§8, M1, F12, R6, P4).
//!
//! Never part of a discovery scan. The session takes one before an
//! acquisition (and after a rescue) per `--smart off|basic|full`; the CLI
//! (`list --smart`) and the TUI query on explicit request only, with
//! `-n standby` so a sleeping disk is not spun up ([`query_on_demand`]).
//!
//! What is sent (identify-class reads only; no SCT command, since SCT
//! commands are written to the drive's SCT log page E0h):
//! - basic: `smartctl -j -i -H -A -l error <disk>` ([`BASIC_ARGS`])
//! - full: everything `smartctl -x` reads except `-l scttemp` and
//!   `-l scterc` (SCT), i.e. [`FULL_ARGS`]: identity, health, capabilities,
//!   attributes, extended error and self-test logs, selective self-test log,
//!   log directories, device statistics, pending defects, SATA/SAS PHY
//!   counters (never with `,reset`), SCSI background/SSD logs, and the `-g all`
//!   settings that are read from IDENTIFY / mode pages (`wcreorder` and
//!   `wcache-sct` are SCT and are not requested; smartctl's own `-x` also
//!   skips `wcreorder`).
//!
//! 30 s timeout through a [`ToolRunner`](crate::discovery::runner::ToolRunner)
//! (`engines::process` on the host), the command recorded. A disk whose
//! SMART cannot be read is UNKNOWN, never FAILED. smartctl's raw JSON is
//! saved (`<base>.smart-before.json`, created new, fsynced) with its SHA-256;
//! the serial number the drive reported is returned as `device_serial`
//! (the session adds it to the source's serial candidates).

use crate::discovery::runner::{physical_disk, ProbeEnv, ToolRun};
use crate::engines::process::StopControl;
use crate::models::config::SmartPolicy;
use crate::models::device::{SmartHealth, SmartInfo, SmartSnapshot};
use crate::models::identity::{SourceIdentity, SourceKind};
use crate::models::info_report::{sha256_hex, sync_dir};
use crate::models::provenance::ProvenanceRecorder;
use crate::models::text::{sanitize_line, sanitize_opt};
use chrono::Utc;
use serde_json::Value;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

/// Timeout of a SMART query (§8).
pub const SMART_TIMEOUT: Duration = Duration::from_secs(30);

/// `--smart basic`: identity, overall health, attributes, error log.
pub const BASIC_ARGS: &[&str] = &["-j", "-i", "-H", "-A", "-l", "error"];

/// `--smart full`: what `smartctl -x` reads, without SCT commands.
pub const FULL_ARGS: &[&str] = &[
    "-j",
    "-i",
    "-H",
    "-c",
    "-A",
    "-f",
    "brief",
    "-l",
    "xerror,error",
    "-l",
    "xselftest,selftest",
    "-l",
    "selective",
    "-l",
    "directory",
    "-l",
    "devstat",
    "-l",
    "defects",
    "-l",
    "sataphy",
    "-l",
    "sasphy",
    "-l",
    "background",
    "-l",
    "ssd",
    "-g",
    "all",
];

/// Added for on-demand queries: do not wake a disk in STANDBY or SLEEP.
pub const STANDBY_ARGS: &[&str] = &["-n", "standby"];

/// Arguments of a smartctl run for `policy` against `device` (`None` for off).
pub fn smartctl_args(
    policy: SmartPolicy,
    standby_check: bool,
    device: &str,
) -> Option<Vec<String>> {
    let base = match policy {
        SmartPolicy::Off => return None,
        SmartPolicy::Basic => BASIC_ARGS,
        SmartPolicy::Full => FULL_ARGS,
    };
    let mut args: Vec<String> = base.iter().map(|a| a.to_string()).collect();
    if standby_check {
        args.extend(STANDBY_ARGS.iter().map(|a| a.to_string()));
    }
    args.push(device.to_string());
    Some(args)
}

/// What to query and where the raw output goes.
#[derive(Debug, Clone, Copy)]
pub struct SmartRequest<'a> {
    pub policy: SmartPolicy,
    /// Where smartctl's raw JSON is saved (created new, never overwritten)
    pub json_file: Option<&'a Path>,
    /// Add `-n standby` (on-demand queries)
    pub standby_check: bool,
}

/// SMART snapshot of the disk the source is stored on, per `policy` (§8, P4).
/// `None` when the policy is off or no physical disk applies (regular file,
/// loop device, virtual device). `json_file`: where smartctl's raw JSON is
/// saved (`<base>.smart-before.json` / `-after.json`); `None` saves nothing
/// (`check`). Never fails: an inaccessible device is a snapshot with health
/// UNKNOWN, never FAILED.
pub async fn snapshot(
    identity: &SourceIdentity,
    policy: SmartPolicy,
    json_file: Option<&Path>,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> Option<SmartSnapshot> {
    let request = SmartRequest {
        policy,
        json_file,
        standby_check: false,
    };
    snapshot_with(&ProbeEnv::host(), identity, request, control, recorder).await
}

/// On-demand query for the CLI (`list --smart`) and the TUI: `-n standby`,
/// nothing saved, not recorded anywhere.
pub async fn query_on_demand(
    identity: &SourceIdentity,
    policy: SmartPolicy,
) -> Option<SmartSnapshot> {
    let request = SmartRequest {
        policy,
        json_file: None,
        standby_check: true,
    };
    snapshot_with(
        &ProbeEnv::host(),
        identity,
        request,
        &StopControl::none(),
        None,
    )
    .await
}

/// [`snapshot`] in a given environment (tests: fake sysfs, scripted tools).
pub async fn snapshot_with(
    env: &ProbeEnv<'_>,
    identity: &SourceIdentity,
    request: SmartRequest<'_>,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> Option<SmartSnapshot> {
    if request.policy == SmartPolicy::Off
        || matches!(
            identity.kind,
            SourceKind::RegularFile | SourceKind::Loop { .. } | SourceKind::Other
        )
    {
        return None;
    }
    let disk = match physical_disk(env, identity) {
        Ok(d) => d,
        Err(reason) => {
            let mut snap = unknown_snapshot(request.policy, format!("SMART not queried: {reason}"));
            snap.note = Some(format!("SMART was not queried: {reason}"));
            return Some(snap);
        }
    };
    let args = smartctl_args(request.policy, request.standby_check, &disk.path)?;
    if crate::discovery::capacity::is_stopped(control) {
        let mut snap = unknown_snapshot(request.policy, "SMART not queried: aborted".into());
        snap.note = Some("SMART was not queried: the run was aborted".into());
        return Some(snap);
    }
    let taken_at = Utc::now();
    let run = env
        .runner
        .run("smartctl", &args, SMART_TIMEOUT, control, recorder)
        .await;
    let mut snap = snapshot_from_run(request.policy, &run, taken_at);
    let mut notes: Vec<String> = snap.note.take().into_iter().collect();
    if let Some(statement) = disk.r6_statement(identity) {
        notes.push(statement);
    }
    if let Some(path) = request.json_file {
        if run.stdout.trim().is_empty() {
            notes.push("smartctl produced no output; no raw output file was written".into());
        } else {
            match save_raw_output(path, run.stdout.as_bytes()) {
                Ok(sha) => {
                    snap.json_file = Some(path.to_string_lossy().into_owned());
                    snap.json_sha256 = Some(sha);
                }
                Err(e) => notes.push(format!(
                    "smartctl's raw output was not saved to {}: {e}",
                    path.display()
                )),
            }
        }
    }
    snap.note = (!notes.is_empty()).then(|| notes.join("; "));
    Some(snap)
}

fn unknown_snapshot(policy: SmartPolicy, assessment: String) -> SmartSnapshot {
    SmartSnapshot {
        policy,
        command: Vec::new(),
        smartctl_version: None,
        exit_status: None,
        taken_at: Utc::now(),
        summary: SmartInfo {
            health: SmartHealth::Unknown,
            passed: false,
            assessment,
            ..Default::default()
        },
        json_file: None,
        json_sha256: None,
        note: None,
        device_serial: None,
    }
}

/// Write smartctl's output to `path` (must not exist), fsync it and its
/// directory; the SHA-256 of what was written.
pub fn save_raw_output(path: &Path, bytes: &[u8]) -> std::io::Result<String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(sha256_hex(bytes))
}

/// smartctl exit status bits (smartctl(8) "RETURN VALUES") beyond the health
/// verdict, as statements for the snapshot note.
fn exit_status_notes(status: i32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if status & 0x04 != 0 {
        out.push("some SMART or other ATA command failed, or a data structure checksum error occurred (exit bit 2)");
    }
    if status & 0x10 != 0 {
        out.push("prefail attributes are at or below their thresholds (exit bit 4)");
    }
    if status & 0x20 != 0 {
        out.push("usage or prefail attributes were at or below their thresholds in the past (exit bit 5)");
    }
    if status & 0x40 != 0 {
        out.push("the device error log contains records of errors (exit bit 6)");
    }
    if status & 0x80 != 0 {
        out.push("the self-test log contains records of errors (exit bit 7)");
    }
    out
}

/// The snapshot a smartctl run describes (pure; tests feed captured runs).
pub fn snapshot_from_run(
    policy: SmartPolicy,
    run: &ToolRun,
    taken_at: chrono::DateTime<Utc>,
) -> SmartSnapshot {
    let mut snap = SmartSnapshot {
        policy,
        command: run.argv.clone(),
        smartctl_version: None,
        exit_status: run.exit_code,
        taken_at,
        summary: SmartInfo::default(),
        json_file: None,
        json_sha256: None,
        note: None,
        device_serial: None,
    };
    let mut notes: Vec<String> = Vec::new();
    if let Some(e) = &run.start_error {
        snap.summary.assessment = format!("SMART not readable: smartctl could not be run ({e})");
        snap.note = Some(format!("smartctl could not be run: {e}"));
        return snap;
    }
    if run.stopped {
        notes.push(format!("smartctl was stopped: {}", run.status));
    }
    match serde_json::from_str::<Value>(run.stdout.trim()) {
        Ok(json) => {
            snap.summary = SmartChecker::parse_smart_json(&json);
            snap.smartctl_version = smartctl_version(&json);
            snap.device_serial = json
                .get("serial_number")
                .and_then(Value::as_str)
                .and_then(sanitize_opt);
            notes.extend(smartctl_messages(&json));
        }
        Err(_) => {
            snap.summary.assessment = format!(
                "SMART not readable: smartctl output is not JSON ({})",
                run.status
            );
            if let Some(m) = run.first_message() {
                notes.push(m);
            }
        }
    }
    if let Some(status) = run.exit_code {
        notes.extend(exit_status_notes(status).into_iter().map(str::to_string));
    }
    snap.note = (!notes.is_empty()).then(|| notes.join("; "));
    snap
}

/// "smartctl 7.5 r5714" from the JSON `smartctl` block.
fn smartctl_version(json: &Value) -> Option<String> {
    let v = json.pointer("/smartctl/version")?.as_array()?;
    let parts: Vec<String> = v
        .iter()
        .filter_map(Value::as_u64)
        .map(|n| n.to_string())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut s = format!("smartctl {}", parts.join("."));
    if let Some(rev) = json
        .pointer("/smartctl/svn_revision")
        .and_then(Value::as_str)
    {
        s.push_str(&format!(" r{}", sanitize_line(rev)));
    }
    Some(s)
}

/// smartctl's own messages (errors and information), sanitised.
fn smartctl_messages(json: &Value) -> Vec<String> {
    json.pointer("/smartctl/messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|m| {
            let text = sanitize_opt(m.get("string")?.as_str()?)?;
            let severity = m
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("message");
            Some(format!("smartctl {severity}: {text}"))
        })
        .collect()
}

/// Power mode that made smartctl stop under `-n standby` ("STANDBY", "SLEEP").
fn low_power_mode(json: &Value) -> Option<String> {
    let exit = json
        .pointer("/smartctl/exit_status")
        .and_then(Value::as_i64)?;
    if exit & 0x02 == 0 {
        return None;
    }
    let from_messages = smartctl_messages(json).into_iter().find_map(|m| {
        let i = m.find("Device is in ")?;
        let rest = &m[i + "Device is in ".len()..];
        Some(rest.split(" mode").next()?.to_string())
    });
    from_messages.or_else(|| {
        let name = json.pointer("/power_mode/name")?.as_str()?;
        (name.contains("STANDBY") || name.contains("SLEEP")).then(|| name.to_string())
    })
}

pub struct SmartChecker;

impl SmartChecker {
    /// Summary of a smartctl JSON document. Whatever could not be read is
    /// UNKNOWN, never FAILED; FAILED only when the drive's overall-health
    /// self-assessment says so.
    pub fn parse_smart_json(val: &Value) -> SmartInfo {
        let smart_status = val
            .pointer("/smart_status/passed")
            .and_then(|v| v.as_bool());
        let smartctl_exit = val
            .pointer("/smartctl/exit_status")
            .and_then(|v| v.as_i64());

        // Bit 0: command line not parsed; bit 1: device open failed, IDENTIFY
        // failed or the device is in a low-power mode (-n)
        let is_inaccessible = if let Some(exit) = smartctl_exit {
            (exit & 0x03 != 0) || (exit != 0 && smart_status.is_none())
        } else {
            false
        };

        let first_error = smartctl_messages(val)
            .into_iter()
            .find(|m| m.starts_with("smartctl error:"))
            .map(|m| m.trim_start_matches("smartctl error: ").to_string());
        let (health, assessment) = match smart_status {
            _ if is_inaccessible => (
                SmartHealth::Unknown,
                match (low_power_mode(val), first_error) {
                    (Some(mode), _) => format!("device in {mode} mode, not woken up"),
                    (None, Some(e)) => format!("SMART not readable: {e}"),
                    (None, None) => "SMART not readable".to_string(),
                },
            ),
            Some(true) => (
                SmartHealth::Passed,
                "overall-health self-assessment passed".to_string(),
            ),
            Some(false) => (
                SmartHealth::Failed,
                "overall-health self-assessment reports FAILURE".to_string(),
            ),
            None => (SmartHealth::Unknown, "no SMART status reported".to_string()),
        };

        let power_on_hours = val.pointer("/power_on_time/hours").and_then(|v| v.as_u64());
        let mut temperature_celsius = val
            .pointer("/temperature/current")
            .and_then(|v| v.as_i64())
            .and_then(normalize_temperature);

        let mut reallocated = None;
        let mut pending = None;
        let mut uncorrectable = None;

        if let Some(table) = val
            .pointer("/ata_smart_attributes/table")
            .and_then(|v| v.as_array())
        {
            for attr in table {
                let id = attr.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let raw_val = attr.pointer("/raw/value").and_then(|v| v.as_u64());
                match id {
                    5 => reallocated = raw_val,
                    197 => pending = raw_val,
                    198 => uncorrectable = raw_val,
                    _ => {}
                }
                // If temperature is missing, ATA attributes 194 / 190
                if temperature_celsius.is_none() && (id == 194 || id == 190) {
                    if let Some(raw) = raw_val {
                        temperature_celsius = normalize_temperature((raw & 0xFFFF) as i64);
                    }
                }
            }
        }

        // Endurance used: NVMe percentage_used, else what smartctl itself
        // derived (ATA device statistics, or its documented attribute rule).
        // Raw vendor attribute values are not percentages and are not used.
        let mut wear = val
            .pointer("/endurance_used/current_percent")
            .and_then(|v| v.as_u64())
            .map(|w| w.min(u64::from(u32::MAX)) as u32);
        if let Some(nvme) = val.pointer("/nvme_smart_health_information_log") {
            if let Some(used) = nvme.get("percentage_used").and_then(|v| v.as_u64()) {
                wear = Some(used.min(u64::from(u32::MAX)) as u32);
            }
            // smartctl 7.x calls it "media_errors" (NVMe "Media and Data
            // Integrity Errors"); the long name is accepted as well
            if let Some(errs) = nvme
                .get("media_errors")
                .or_else(|| nvme.get("media_and_data_integrity_errors"))
                .and_then(|v| v.as_u64())
            {
                uncorrectable = Some(errs);
            }
            if temperature_celsius.is_none() {
                if let Some(temp) = nvme.get("temperature").and_then(|v| v.as_i64()) {
                    temperature_celsius = normalize_temperature(temp);
                }
            }
        }

        SmartInfo {
            health,
            passed: health == SmartHealth::Passed,
            power_on_hours,
            temperature_celsius,
            reallocated_sectors: reallocated,
            pending_sectors: pending,
            uncorrectable_errors: uncorrectable,
            wear_percentage: wear,
            assessment: sanitize_line(&assessment),
        }
    }
}

pub fn normalize_temperature(val: i64) -> Option<i32> {
    if (200..=400).contains(&val) {
        // Kelvin -> Celsius (200 K = -73°C, 400 K = +127°C)
        Some((val - 273) as i32)
    } else if (-30..=120).contains(&val) {
        // Legitimate Celsius operating range
        Some(val as i32)
    } else {
        // Out of physical operational bounds, uninitialized, or sensor error sentinel
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::runner::ScriptedRunner;
    use crate::discovery::sysfs::fake::FakeSysfs;
    use serde_json::json;

    const SATA: &str = "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0";

    #[test]
    fn test_parse_smart_passed() {
        let val = json!({
            "smartctl": { "exit_status": 0 },
            "smart_status": { "passed": true },
            "power_on_time": { "hours": 1234 },
            "temperature": { "current": 35 }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(info.passed);
        assert_eq!(info.assessment, "overall-health self-assessment passed");
        assert_eq!(info.power_on_hours, Some(1234));
        assert_eq!(info.temperature_celsius, Some(35));
    }

    #[test]
    fn test_parse_smart_failed() {
        let val = json!({
            "smartctl": { "exit_status": 8 },
            "smart_status": { "passed": false },
            "ata_smart_attributes": {
                "table": [
                    { "id": 5, "raw": { "value": 42 } },
                    { "id": 197, "raw": { "value": 10 } },
                    { "id": 233, "value": 97, "raw": { "value": 123456 } }
                ]
            }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(!info.passed);
        assert_eq!(info.health, SmartHealth::Failed);
        assert_eq!(info.reallocated_sectors, Some(42));
        assert_eq!(info.pending_sectors, Some(10));
        // A raw vendor attribute is never reported as a wear percentage
        assert_eq!(info.wear_percentage, None);
    }

    #[test]
    fn test_parse_smart_permission_denied() {
        let val = json!({
            "smartctl": {
                "exit_status": 2,
                "messages": [{ "severity": "error", "string": "Permission denied" }]
            }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(!info.passed);
        assert_eq!(info.health, SmartHealth::Unknown);
        assert_eq!(info.assessment, "SMART not readable: Permission denied");
    }

    #[test]
    fn test_parse_smart_missing_status() {
        let val = json!({ "device": { "name": "/dev/sda" } });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(!info.passed);
        assert_eq!(info.health, SmartHealth::Unknown);
        assert_eq!(info.assessment, "no SMART status reported");
    }

    #[test]
    fn test_parse_smart_standby() {
        let val = json!({
            "smartctl": {
                "exit_status": 2,
                "messages": [{ "severity": "information", "string": "Device is in STANDBY mode, exit(2)" }]
            },
            "power_mode": { "ata_value": 0, "name": "STANDBY" }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert_eq!(info.health, SmartHealth::Unknown);
        assert_eq!(info.assessment, "device in STANDBY mode, not woken up");
    }

    #[test]
    fn test_parse_smart_nvme_kelvin_and_endurance() {
        let val = json!({
            "smartctl": { "exit_status": 0 },
            "smart_status": { "passed": true },
            "nvme_smart_health_information_log": {
                "available_spare": 95,
                "percentage_used": 3,
                "media_errors": 0,
                "temperature": 310
            }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(info.passed);
        assert_eq!(info.temperature_celsius, Some(37)); // 310 - 273 = 37
        assert_eq!(info.wear_percentage, Some(3)); // percentage_used, not spare
        assert_eq!(info.uncorrectable_errors, Some(0));
        let ata = json!({ "smart_status": { "passed": true }, "endurance_used": { "current_percent": 7 } });
        assert_eq!(
            SmartChecker::parse_smart_json(&ata).wear_percentage,
            Some(7)
        );
    }

    #[test]
    fn test_normalize_temperature() {
        assert_eq!(normalize_temperature(310), Some(37));
        assert_eq!(normalize_temperature(273), Some(0));
        assert_eq!(normalize_temperature(45), Some(45));
        assert_eq!(normalize_temperature(0), Some(0));
        assert_eq!(normalize_temperature(-10), Some(-10));
        assert_eq!(normalize_temperature(65535), None);
        assert_eq!(normalize_temperature(-100), None);
        assert_eq!(normalize_temperature(150), None);
    }

    #[test]
    fn args_per_policy_never_include_sct() {
        assert_eq!(smartctl_args(SmartPolicy::Off, false, "/dev/sdb"), None);
        let basic = smartctl_args(SmartPolicy::Basic, false, "/dev/sdb").unwrap();
        assert_eq!(basic, ["-j", "-i", "-H", "-A", "-l", "error", "/dev/sdb"]);
        let full = smartctl_args(SmartPolicy::Full, true, "/dev/sdb").unwrap();
        assert_eq!(full.last().map(String::as_str), Some("/dev/sdb"));
        assert!(full.windows(2).any(|w| w == ["-n", "standby"]));
        for arg in &full {
            assert!(!arg.contains("sct"), "{arg}");
            assert!(!arg.contains("reset"), "{arg}");
            assert!(!arg.contains("wcreorder"), "{arg}");
            assert_ne!(arg, "-x");
            assert_ne!(arg, "-s");
            assert_ne!(arg, "-t");
        }
    }

    fn node_dev(p: &Path) -> Option<(u32, u32)> {
        (p.file_name()?.to_str()? == "sdb").then_some((8, 16))
    }

    #[tokio::test]
    async fn snapshot_saves_raw_json_and_reports_the_drive_serial() {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 1000);
        f.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 100);
        let out = r#"{"json_format_version":[1,0],"smartctl":{"version":[7,5],"svn_revision":"5714","exit_status":64},"serial_number":"WD-WX12A3456789","smart_status":{"passed":true}}"#;
        let argv = [
            "smartctl", "-j", "-i", "-H", "-A", "-l", "error", "/dev/sdb",
        ];
        let runner = ScriptedRunner::new().respond(&argv, ToolRun::exited(&argv, 64, out, ""));
        let env = ProbeEnv {
            sys: f.root(),
            dev_dir: "/dev".into(),
            node_dev: &node_dev,
            runner: &runner,
        };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("case.smart-before.json");
        let id = SourceIdentity {
            path: "/dev/sdb1".into(),
            kernel_name: "sdb1".into(),
            kind: SourceKind::Partition,
            parent_disks: vec!["/dev/sdb".into()],
            ..Default::default()
        };
        let req = SmartRequest {
            policy: SmartPolicy::Basic,
            json_file: Some(&file),
            standby_check: false,
        };
        let snap = snapshot_with(&env, &id, req, &StopControl::none(), None)
            .await
            .unwrap();
        assert_eq!(snap.summary.health, SmartHealth::Passed);
        assert_eq!(snap.device_serial.as_deref(), Some("WD-WX12A3456789"));
        assert_eq!(snap.smartctl_version.as_deref(), Some("smartctl 7.5 r5714"));
        assert_eq!(snap.exit_status, Some(64));
        assert_eq!(snap.command, argv);
        let note = snap.note.unwrap();
        assert!(note.contains("error log contains records"), "{note}");
        assert!(note.contains("physical disk /dev/sdb"), "{note}");
        let saved = std::fs::read(&file).unwrap();
        assert_eq!(saved, out.as_bytes());
        assert_eq!(snap.json_sha256.unwrap(), sha256_hex(out.as_bytes()));
        assert_eq!(snap.json_file.unwrap(), file.to_string_lossy());

        // A second snapshot never overwrites the first file
        let again = snapshot_with(&env, &id, req, &StopControl::none(), None)
            .await
            .unwrap();
        assert!(again.json_file.is_none());
        assert!(again.note.unwrap().contains("not saved"));
        assert_eq!(std::fs::read(&file).unwrap(), out.as_bytes());
    }

    #[tokio::test]
    async fn no_smart_for_files_loops_or_off_and_unknown_when_missing() {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 1000);
        let runner = ScriptedRunner::new();
        let env = ProbeEnv {
            sys: f.root(),
            dev_dir: "/dev".into(),
            node_dev: &node_dev,
            runner: &runner,
        };
        let req = |policy| SmartRequest {
            policy,
            json_file: None,
            standby_check: true,
        };
        let disk = SourceIdentity {
            path: "/dev/sdb".into(),
            kernel_name: "sdb".into(),
            kind: SourceKind::Disk,
            ..Default::default()
        };
        let none = StopControl::none();
        assert!(
            snapshot_with(&env, &disk, req(SmartPolicy::Off), &none, None)
                .await
                .is_none()
        );
        let file = SourceIdentity {
            kind: SourceKind::RegularFile,
            ..Default::default()
        };
        assert!(
            snapshot_with(&env, &file, req(SmartPolicy::Basic), &none, None)
                .await
                .is_none()
        );
        let lp = SourceIdentity {
            kind: SourceKind::Loop { backing_file: None },
            ..Default::default()
        };
        assert!(
            snapshot_with(&env, &lp, req(SmartPolicy::Basic), &none, None)
                .await
                .is_none()
        );
        assert!(runner.calls().is_empty());

        // smartctl missing: UNKNOWN, never FAILED
        let snap = snapshot_with(&env, &disk, req(SmartPolicy::Basic), &none, None)
            .await
            .unwrap();
        assert_eq!(snap.summary.health, SmartHealth::Unknown);
        assert!(snap.summary.assessment.contains("could not be run"));
        assert_eq!(
            runner.calls(),
            [vec![
                "smartctl", "-j", "-i", "-H", "-A", "-l", "error", "-n", "standby", "/dev/sdb"
            ]]
        );
    }

    /// smartctl cannot talk to a virtio disk: the snapshot is UNKNOWN with
    /// smartctl's message, for the disk and for a dm mapping over it (the
    /// query goes to the disk, R6), never FAILED and never an error.
    #[tokio::test]
    async fn virtio_disks_and_dm_over_them_are_unknown() {
        const VIRTIO: &str = "pci0000:00/0000:00:05.0/virtio2";
        let f = FakeSysfs::new();
        f.add_disk(VIRTIO, "vdb", (252, 16), 131_072);
        let out = r#"{"json_format_version":[1,0],"smartctl":{"version":[7,4],"svn_revision":"5530","exit_status":1,"messages":[{"string":"/dev/vdb: Unable to detect device type","severity":"error"}]}}"#;
        let argv = [
            "smartctl", "-j", "-i", "-H", "-A", "-l", "error", "/dev/vdb",
        ];
        let runner = ScriptedRunner::new().respond(&argv, ToolRun::exited(&argv, 1, out, ""));
        let node = |p: &Path| (p.file_name()?.to_str()? == "vdb").then_some((252, 16));
        let env = ProbeEnv {
            sys: f.root(),
            dev_dir: "/dev".into(),
            node_dev: &node,
            runner: &runner,
        };
        let req = SmartRequest {
            policy: SmartPolicy::Basic,
            json_file: None,
            standby_check: false,
        };
        let disk = SourceIdentity {
            path: "/dev/vdb".into(),
            kernel_name: "vdb".into(),
            kind: SourceKind::Disk,
            ..Default::default()
        };
        let dm = SourceIdentity {
            path: "/dev/mapper/lin".into(),
            kernel_name: "dm-2".into(),
            kind: SourceKind::DeviceMapper {
                crypt_plaintext: false,
            },
            parent_disks: vec!["/dev/vdb".into()],
            ..Default::default()
        };
        for id in [&disk, &dm] {
            let snap = snapshot_with(&env, id, req, &StopControl::none(), None)
                .await
                .unwrap();
            assert_eq!(snap.summary.health, SmartHealth::Unknown, "{snap:?}");
            assert_eq!(snap.exit_status, Some(1));
            assert_eq!(snap.device_serial, None);
        }
        assert_eq!(runner.calls().len(), 2);
        assert!(runner
            .calls()
            .iter()
            .all(|c| c.last().unwrap() == "/dev/vdb"));
    }
}
