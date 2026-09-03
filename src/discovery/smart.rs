use crate::models::device::SmartInfo;
use serde_json::Value;
use std::process::Command;

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

        let (passed, assessment) = match smart_status {
            Some(true) if !is_inaccessible => (true, "PASSED (Healthy)".to_string()),
            Some(false) => (false, "WARNING / FAILED".to_string()),
            _ => (
                false,
                "UNKNOWN (Inaccessible / Permission Denied)".to_string(),
            ),
        };

        let power_on_hours = val.pointer("/power_on_time/hours").and_then(|v| v.as_u64());
        let mut temperature_celsius = val
            .pointer("/temperature/current")
            .and_then(|v| v.as_i64())
            .map(|t| t as i32);

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
            }
        }

        // Check NVMe health log if present
        if let Some(nvme) = val.pointer("/nvme_smart_health_information_log") {
            if let Some(spare) = nvme.get("available_spare").and_then(|v| v.as_u64()) {
                wear = Some(100u32.saturating_sub(spare as u32));
            }
            if let Some(errs) = nvme
                .get("media_and_data_integrity_errors")
                .and_then(|v| v.as_u64())
            {
                uncorrectable = Some(errs);
            }
            if temperature_celsius.is_none() {
                if let Some(temp) = nvme.get("temperature").and_then(|v| v.as_i64()) {
                    let temp_c = if temp > 200 {
                        (temp - 273) as i32
                    } else {
                        temp as i32
                    };
                    temperature_celsius = Some(temp_c);
                }
            }
        }

        SmartInfo {
            passed,
            power_on_hours,
            temperature_celsius,
            reallocated_sectors: reallocated,
            pending_sectors: pending,
            uncorrectable_errors: uncorrectable,
            wear_percentage: wear,
            assessment,
        }
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
        assert_eq!(
            info.assessment,
            "UNKNOWN (Inaccessible / Permission Denied)"
        );
    }

    #[test]
    fn test_parse_smart_nvme_kelvin() {
        let val = json!({
            "smartctl": { "exit_status": 0 },
            "smart_status": { "passed": true },
            "nvme_smart_health_information_log": {
                "available_spare": 95,
                "media_and_data_integrity_errors": 0,
                "temperature": 310
            }
        });
        let info = SmartChecker::parse_smart_json(&val);
        assert!(info.passed);
        assert_eq!(info.temperature_celsius, Some(37)); // 310 - 273 = 37
        assert_eq!(info.wear_percentage, Some(5)); // 100 - 95 = 5
        assert_eq!(info.uncorrectable_errors, Some(0));
    }
}
