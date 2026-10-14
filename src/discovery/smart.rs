use crate::engines::process::StopControl;
use crate::models::config::SmartPolicy;
use crate::models::device::{SmartHealth, SmartInfo, SmartSnapshot};
use crate::models::identity::SourceIdentity;
use crate::models::provenance::ProvenanceRecorder;
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Timeout of a SMART query (§8).
pub const SMART_TIMEOUT: Duration = Duration::from_secs(30);

/// SMART snapshot of the disk the source is stored on, per `policy` (§8, P4).
/// `None` when the policy is off or no physical disk applies (regular file,
/// loop device). `json_file`: where smartctl's raw JSON is saved
/// (`<base>.smart-before.json` / `-after.json`); `None` saves nothing
/// (`check`, TUI queries). Never fails: an inaccessible device is a snapshot
/// with health UNKNOWN, never FAILED.
///
/// DISCOVERY AGENT: placeholder with its final signature. Implement per §8:
/// basic = `smartctl -j -i -H -A -l error`, full adds the `-x` logs without
/// SCT; 30 s timeout through `engines::process` with `control`, the command
/// recorded in `recorder` and in `SmartSnapshot::command`; target the
/// physical disk (R6); save the raw JSON to `json_file` (fsync) with its
/// SHA-256; fill `device_serial` from the IDENTIFY data.
pub async fn snapshot(
    identity: &SourceIdentity,
    policy: SmartPolicy,
    json_file: Option<&Path>,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> Option<SmartSnapshot> {
    let _ = (json_file, control, recorder);
    if policy == SmartPolicy::Off || !identity.is_block_device() {
        return None;
    }
    Some(SmartSnapshot {
        policy,
        command: Vec::new(),
        smartctl_version: None,
        exit_status: None,
        taken_at: chrono::Utc::now(),
        summary: SmartInfo {
            health: SmartHealth::Unknown,
            passed: false,
            assessment: "UNKNOWN (SMART was not queried)".into(),
            ..Default::default()
        },
        json_file: None,
        json_sha256: None,
        note: Some("SMART snapshots are not implemented in this build".into()),
        device_serial: None,
    })
}

pub struct SmartChecker;

impl SmartChecker {
    pub fn query_smart(device_path: &str) -> Option<SmartInfo> {
        let output = Command::new("smartctl")
            .arg("-j")
            .arg("-x")
            .arg(device_path)
            .output()
            .ok()?;

        let json_str = String::from_utf8_lossy(&output.stdout);
        if json_str.trim().is_empty() {
            return None;
        }

        let val: Value = serde_json::from_str(&json_str).ok()?;
        Some(Self::parse_smart_json(&val))
    }

    pub fn parse_smart_json(val: &Value) -> SmartInfo {
        let smart_status = val
            .pointer("/smart_status/passed")
            .and_then(|v| v.as_bool());
        let smartctl_exit = val
            .pointer("/smartctl/exit_status")
            .and_then(|v| v.as_i64());

        // Bit 1 (value 2) indicates device open failed / permission denied
        let is_inaccessible = if let Some(exit) = smartctl_exit {
            (exit & 2 != 0) || (exit != 0 && smart_status.is_none())
        } else {
            false
        };

        // Whatever could not be read is UNKNOWN, never FAILED
        let (health, assessment) = match smart_status {
            _ if is_inaccessible => (
                SmartHealth::Unknown,
                "UNKNOWN (Inaccessible / Permission Denied)",
            ),
            Some(true) => (SmartHealth::Passed, "PASSED (Healthy)"),
            Some(false) => (SmartHealth::Failed, "WARNING / FAILED"),
            None => (SmartHealth::Unknown, "UNKNOWN (no SMART status reported)"),
        };

        let power_on_hours = val.pointer("/power_on_time/hours").and_then(|v| v.as_u64());
        let mut temperature_celsius = val
            .pointer("/temperature/current")
            .and_then(|v| v.as_i64())
            .and_then(normalize_temperature);

        let mut reallocated = None;
        let mut pending = None;
        let mut uncorrectable = None;
        let mut wear = None;

        // Check ATA attributes table if present
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
                    231 | 233 => wear = raw_val.map(|w| w as u32),
                    _ => {}
                }

                // If temperature missing, check ATA attributes 194 / 190
                if temperature_celsius.is_none() && (id == 194 || id == 190) {
                    if let Some(raw) = raw_val {
                        let temp_candidate = (raw & 0xFFFF) as i64;
                        if let Some(c) = normalize_temperature(temp_candidate) {
                            temperature_celsius = Some(c);
                        }
                    }
                }
            }
        }

        // Check NVMe health log if present; wear is the endurance used
        // (percentage_used, may exceed 100), not the spare capacity left
        if let Some(nvme) = val.pointer("/nvme_smart_health_information_log") {
            if let Some(used) = nvme.get("percentage_used").and_then(|v| v.as_u64()) {
                wear = Some(used.min(u64::from(u32::MAX)) as u32);
            }
            if let Some(errs) = nvme
                .get("media_and_data_integrity_errors")
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
            assessment: assessment.to_string(),
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
    use serde_json::json;

    #[test]
    fn test_parse_smart_passed_healthy() {
        let val = json!({
            "smartctl": { "exit_status": 0 },
            "smart_status": { "passed": true },
            "power_on_time": { "hours": 1234 },
            "temperature": { "current": 35 }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(info.passed);
        assert_eq!(info.assessment, "PASSED (Healthy)");
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
                    { "id": 197, "raw": { "value": 10 } }
                ]
            }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(!info.passed);
        assert_eq!(info.assessment, "WARNING / FAILED");
        assert_eq!(info.reallocated_sectors, Some(42));
        assert_eq!(info.pending_sectors, Some(10));
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
        assert_eq!(
            info.assessment,
            "UNKNOWN (Inaccessible / Permission Denied)"
        );
    }

    #[test]
    fn test_parse_smart_missing_status() {
        let val = json!({
            "device": { "name": "/dev/sda" }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(!info.passed);
        assert_eq!(info.health, SmartHealth::Unknown);
        assert_eq!(info.assessment, "UNKNOWN (no SMART status reported)");
    }

    #[test]
    fn test_parse_smart_nvme_kelvin() {
        let val = json!({
            "smartctl": { "exit_status": 0 },
            "smart_status": { "passed": true },
            "nvme_smart_health_information_log": {
                "available_spare": 95,
                "percentage_used": 3,
                "media_and_data_integrity_errors": 0,
                "temperature": 310
            }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(info.passed);
        assert_eq!(info.health, SmartHealth::Passed);
        assert_eq!(info.temperature_celsius, Some(37)); // 310 - 273 = 37
        assert_eq!(info.wear_percentage, Some(3)); // percentage_used, not spare
        assert_eq!(info.uncorrectable_errors, Some(0));
    }

    #[test]
    fn test_normalize_temperature() {
        assert_eq!(normalize_temperature(310), Some(37)); // Kelvin -> 37°C
        assert_eq!(normalize_temperature(273), Some(0)); // 0°C
        assert_eq!(normalize_temperature(45), Some(45)); // Normal Celsius
        assert_eq!(normalize_temperature(0), Some(0));
        assert_eq!(normalize_temperature(-10), Some(-10));
        // Out-of-bounds error sentinels
        assert_eq!(normalize_temperature(65535), None);
        assert_eq!(normalize_temperature(-100), None);
        assert_eq!(normalize_temperature(150), None);
    }
}
