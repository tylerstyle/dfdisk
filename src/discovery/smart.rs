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

        // Check if device opened successfully
        let passed = val.pointer("/smart_status/passed").and_then(|v| v.as_bool()).unwrap_or(true);
        let power_on_hours = val.pointer("/power_on_time/hours").and_then(|v| v.as_u64());
        let temperature_celsius = val.pointer("/temperature/current").and_then(|v| v.as_i64()).map(|t| t as i32);

        let mut reallocated = None;
        let mut pending = None;
        let mut uncorrectable = None;
        let mut wear = None;

        // Check ATA attributes table if present
        if let Some(table) = val.pointer("/ata_smart_attributes/table").and_then(|v| v.as_array()) {
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
            if let Some(errs) = nvme.get("media_and_data_integrity_errors").and_then(|v| v.as_u64()) {
                uncorrectable = Some(errs);
            }
            if let Some(temp) = nvme.get("temperature").and_then(|v| v.as_i64()) {
                if temperature_celsius.is_none() {
                    // NVMe temperature in kelvin or celsius depending on format
                    let temp_c = if temp > 200 { (temp - 273) as i32 } else { temp as i32 };
                    return Some(SmartInfo {
                        passed,
                        power_on_hours,
                        temperature_celsius: Some(temp_c),
                        reallocated_sectors: reallocated,
                        pending_sectors: pending,
                        uncorrectable_errors: uncorrectable,
                        wear_percentage: wear,
                        assessment: if passed { "PASSED (Healthy)".to_string() } else { "WARNING / FAILED".to_string() },
                    });
                }
            }
        }

        Some(SmartInfo {
            passed,
            power_on_hours,
            temperature_celsius,
            reallocated_sectors: reallocated,
            pending_sectors: pending,
            uncorrectable_errors: uncorrectable,
            wear_percentage: wear,
            assessment: if passed { "PASSED (Healthy)".to_string() } else { "WARNING / FAILED".to_string() },
        })
    }
}
