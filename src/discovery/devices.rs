use crate::discovery::{safety::SafetyChecker, smart::SmartChecker};
use crate::models::device::{BlockDevice, Partition};
use serde_json::Value;
use std::fs;
use std::process::Command;

pub struct DeviceScanner;

impl DeviceScanner {
    /// Scans the system for all physical block devices
    pub fn scan_devices() -> Result<Vec<BlockDevice>, String> {
        let output = Command::new("lsblk")
            .arg("-J")
            .arg("-b")
            .arg("-O")
            .output()
            .map_err(|e| format!("Failed to execute lsblk: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "lsblk failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let root: Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("Failed to parse lsblk JSON: {}", e))?;

        let blockdevices = root
            .get("blockdevices")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "No blockdevices array in lsblk output".to_string())?;

        let mut devices = Vec::new();

        for dev_val in blockdevices {
            let dev_type = dev_val.get("type").and_then(|v| v.as_str()).unwrap_or("");
            // We are interested in whole disks and loop devices (for testing)
            if dev_type != "disk" && dev_type != "loop" && dev_type != "mpath" {
                continue;
            }

            let name = dev_val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }

            let path = dev_val
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("/dev/{}", name));

            let size_bytes = parse_u64(dev_val.get("size"));
            let model = dev_val
                .get("model")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            let vendor = dev_val
                .get("vendor")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            let serial_lsblk = dev_val
                .get("serial")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            let wwn = dev_val
                .get("wwn")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            let revision = dev_val
                .get("rev")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());
            let tran = dev_val.get("tran").and_then(|v| v.as_str()).unwrap_or("");

            let bus_type = if !tran.is_empty() {
                tran.to_uppercase()
            } else if path.contains("nvme") {
                "NVME".to_string()
            } else if path.contains("mmcblk") {
                "MMC/SD".to_string()
            } else if dev_type == "loop" {
                "VIRTUAL LOOP".to_string()
            } else {
                "UNKNOWN".to_string()
            };

            let is_removable = dev_val.get("rm").and_then(|v| v.as_bool()).unwrap_or(false)
                || dev_val
                    .get("hotplug")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

            let is_read_only = dev_val.get("ro").and_then(|v| v.as_bool()).unwrap_or(false);

            let logical_sector_size = dev_val
                .get("log-sec")
                .and_then(|v| v.as_u64())
                .unwrap_or(512) as u32;

            let physical_sector_size = dev_val
                .get("phy-sec")
                .and_then(|v| v.as_u64())
                .unwrap_or(512) as u32;

            let partition_table_type = dev_val
                .get("pttype")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let is_rotational = dev_val.get("rota").and_then(|v| v.as_bool()).or_else(|| {
                // Fallback to /sys/block/<name>/queue/rotational
                let sys_path = format!("/sys/block/{}/queue/rotational", name);
                fs::read_to_string(sys_path)
                    .ok()
                    .and_then(|content| match content.trim() {
                        "1" => Some(true),
                        "0" => Some(false),
                        _ => None,
                    })
            });

            // Parse partitions and mountpoints
            let mut partitions = Vec::new();
            let mut all_mountpoints = Vec::new();
            let mut swap_active = false;

            // Direct mountpoint on disk itself
            if let Some(mp) = dev_val.get("mountpoint").and_then(|v| v.as_str()) {
                if !mp.is_empty() {
                    all_mountpoints.push(mp.to_string());
                }
            }
            if let Some(mps) = dev_val.get("mountpoints").and_then(|v| v.as_array()) {
                for m in mps {
                    if let Some(s) = m.as_str() {
                        if !s.is_empty() && !all_mountpoints.contains(&s.to_string()) {
                            all_mountpoints.push(s.to_string());
                        }
                    }
                }
            }

            if let Some(children) = dev_val.get("children").and_then(|v| v.as_array()) {
                for child in children {
                    let part_name = child
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let part_path = child
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("/dev/{}", part_name));
                    let part_size = parse_u64(child.get("size"));
                    let fstype = child
                        .get("fstype")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let label = child
                        .get("label")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let uuid = child
                        .get("uuid")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let part_ro = child.get("ro").and_then(|v| v.as_bool()).unwrap_or(false);

                    let mut part_mp = child
                        .get("mountpoint")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if let Some(mps) = child.get("mountpoints").and_then(|v| v.as_array()) {
                        for m in mps {
                            if let Some(s) = m.as_str() {
                                if !s.is_empty() {
                                    if part_mp.is_none() {
                                        part_mp = Some(s.to_string());
                                    }
                                    if !all_mountpoints.contains(&s.to_string()) {
                                        all_mountpoints.push(s.to_string());
                                    }
                                }
                            }
                        }
                    }

                    if let Some(ref mp) = part_mp {
                        if !all_mountpoints.contains(mp) {
                            all_mountpoints.push(mp.clone());
                        }
                    }

                    if fstype.as_deref() == Some("swap") {
                        swap_active = true;
                    }

                    partitions.push(Partition {
                        name: part_name,
                        path: part_path,
                        size_bytes: part_size,
                        fstype,
                        label,
                        uuid,
                        mountpoint: part_mp,
                        is_read_only: part_ro,
                    });
                }
            }

            // Fetch udev properties for hardware links and serial numbers
            let (udev_serial, devlinks) = query_udev_props(&path);
            let final_serial = serial_lsblk.or(udev_serial);

            // Safety evaluation
            let safety = SafetyChecker::evaluate_safety(&all_mountpoints, swap_active);

            // Optional SMART probing
            let smart = SmartChecker::query_smart(&path);

            devices.push(BlockDevice {
                name,
                path,
                devlinks,
                size_bytes,
                model,
                vendor,
                serial: final_serial,
                wwn,
                revision,
                bus_type,
                is_rotational,
                is_removable,
                is_read_only,
                logical_sector_size,
                physical_sector_size,
                partition_table_type,
                partitions,
                mountpoints: all_mountpoints,
                safety,
                smart,
            });
        }

        Ok(devices)
    }
}

fn parse_u64(val: Option<&Value>) -> u64 {
    match val {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn query_udev_props(device_path: &str) -> (Option<String>, Vec<String>) {
    let output = Command::new("udevadm")
        .arg("info")
        .arg("--query=property")
        .arg(format!("--name={}", device_path))
        .output();

    let mut serial = None;
    let mut devlinks = Vec::new();

    if let Ok(out) = output {
        if out.status.success() {
            let props = String::from_utf8_lossy(&out.stdout);
            for line in props.lines() {
                if let Some(val) = line.strip_prefix("ID_SERIAL_SHORT=") {
                    let clean = val.trim().to_string();
                    if !clean.is_empty() {
                        serial = Some(clean);
                    }
                } else if serial.is_none() {
                    if let Some(val) = line.strip_prefix("ID_SERIAL=") {
                        let clean = val.trim().to_string();
                        if !clean.is_empty() {
                            serial = Some(clean);
                        }
                    }
                }

                if let Some(links) = line.strip_prefix("DEVLINKS=") {
                    for link in links.split_whitespace() {
                        devlinks.push(link.to_string());
                    }
                }
            }
        }
    }

    (serial, devlinks)
}
