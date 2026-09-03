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

        let (proc_swaps_available, active_swaps) = get_active_swaps();
        let mut devices = Vec::new();

        for dev_val in blockdevices {
            if let Some(dev) =
                Self::parse_device_from_json(dev_val, proc_swaps_available, &active_swaps)
            {
                devices.push(dev);
            }
        }

        Ok(devices)
    }

    /// Parses a single block device from lsblk JSON, recursively traversing children and checking active swaps
    pub fn parse_device_from_json(
        dev_val: &Value,
        proc_swaps_available: bool,
        active_swaps: &std::collections::HashSet<String>,
    ) -> Option<BlockDevice> {
        let dev_type = dev_val.get("type").and_then(|v| v.as_str()).unwrap_or("");
        // We are interested in whole disks and loop devices (for testing)
        if dev_type != "disk" && dev_type != "loop" && dev_type != "mpath" {
            return None;
        }

        let name = dev_val
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            return None;
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

        // Check if top-level device itself is an active swap
        if proc_swaps_available
            && (active_swaps.contains(&path) || active_swaps.contains(&format!("/dev/{}", name)))
        {
            swap_active = true;
        }

        // Recursive partition scanning for nested children (e.g. partition -> LUKS -> LVM)
        if let Some(children) = dev_val.get("children").and_then(|v| v.as_array()) {
            for child in children {
                collect_partitions_recursive(
                    child,
                    &mut partitions,
                    &mut all_mountpoints,
                    &mut swap_active,
                    proc_swaps_available,
                    active_swaps,
                );
            }
        }

        // Fetch udev properties for hardware links and serial numbers
        let (udev_serial, devlinks) = query_udev_props(&path);
        let final_serial = serial_lsblk.or(udev_serial);

        // Safety evaluation
        let safety = SafetyChecker::evaluate_safety(&all_mountpoints, swap_active);

        // Optional SMART probing
        let smart = SmartChecker::query_smart(&path);

        Some(BlockDevice {
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
        })
    }
}

pub fn collect_partitions_recursive(
    child: &Value,
    partitions: &mut Vec<Partition>,
    all_mountpoints: &mut Vec<String>,
    swap_active: &mut bool,
    proc_swaps_available: bool,
    active_swaps: &std::collections::HashSet<String>,
) {
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

    if proc_swaps_available {
        let is_in_swaps = active_swaps.contains(&part_path)
            || active_swaps.contains(&format!("/dev/{}", part_name))
            || active_swaps.contains(&part_name)
            || std::fs::canonicalize(&part_path)
                .map(|p| active_swaps.contains(&p.to_string_lossy().to_string()))
                .unwrap_or(false);
        if is_in_swaps {
            *swap_active = true;
        }
    } else if fstype.as_deref() == Some("swap") {
        *swap_active = true;
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

    if let Some(nested_children) = child.get("children").and_then(|v| v.as_array()) {
        for nested in nested_children {
            collect_partitions_recursive(
                nested,
                partitions,
                all_mountpoints,
                swap_active,
                proc_swaps_available,
                active_swaps,
            );
        }
    }
}

fn get_active_swaps() -> (bool, std::collections::HashSet<String>) {
    let mut swaps = std::collections::HashSet::new();
    match std::fs::read_to_string("/proc/swaps") {
        Ok(content) => {
            for line in content.lines().skip(1) {
                if let Some(path) = line.split_whitespace().next() {
                    swaps.insert(path.to_string());
                    if let Ok(canonical) = std::fs::canonicalize(path) {
                        swaps.insert(canonical.to_string_lossy().to_string());
                    }
                }
            }
            (true, swaps)
        }
        Err(_) => (false, swaps),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::device::DeviceSafety;
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn test_nested_luks_lvm_partition_scanning() {
        let fixture = json!({
            "name": "sda",
            "path": "/dev/sda",
            "type": "disk",
            "size": 500107862016u64,
            "children": [
                {
                    "name": "sda1",
                    "path": "/dev/sda1",
                    "size": 536870912u64,
                    "fstype": "vfat",
                    "mountpoint": "/boot/efi"
                },
                {
                    "name": "sda2",
                    "path": "/dev/sda2",
                    "size": 499570991104u64,
                    "fstype": "crypto_LUKS",
                    "children": [
                        {
                            "name": "cryptroot",
                            "path": "/dev/mapper/cryptroot",
                            "size": 499554213888u64,
                            "fstype": "LVM2_member",
                            "children": [
                                {
                                    "name": "vg-root",
                                    "path": "/dev/mapper/vg-root",
                                    "size": 107374182400u64,
                                    "fstype": "ext4",
                                    "mountpoint": "/"
                                },
                                {
                                    "name": "vg-home",
                                    "path": "/dev/mapper/vg-home",
                                    "size": 392180031488u64,
                                    "fstype": "ext4",
                                    "mountpoint": "/home"
                                }
                            ]
                        }
                    ]
                }
            ]
        });

        let dev = DeviceScanner::parse_device_from_json(&fixture, false, &HashSet::new())
            .expect("Device should be parsed");

        // Should recursively collect all 5 partitions (sda1, sda2, cryptroot, vg-root, vg-home)
        assert_eq!(dev.partitions.len(), 5);
        assert!(dev.mountpoints.contains(&"/boot/efi".to_string()));
        assert!(dev.mountpoints.contains(&"/".to_string()));
        assert!(dev.mountpoints.contains(&"/home".to_string()));

        // Crucially, safety evaluation must mark it as SystemDisk because "/" is inside nested LVM
        match dev.safety {
            DeviceSafety::SystemDisk(crit) => {
                assert!(crit.contains(&"/".to_string()));
                assert!(crit.contains(&"/boot/efi".to_string()));
                assert!(crit.contains(&"/home".to_string()));
            }
            _ => panic!("Expected SystemDisk due to nested mountpoints"),
        }
    }

    #[test]
    fn test_dormant_swap_not_flagged_active() {
        let fixture = json!({
            "name": "sdb",
            "path": "/dev/sdb",
            "type": "disk",
            "size": 1000000000u64,
            "children": [
                {
                    "name": "sdb1",
                    "path": "/dev/sdb1",
                    "size": 1000000000u64,
                    "fstype": "swap",
                    "mountpoint": null
                }
            ]
        });

        // /proc/swaps is available, but active_swaps does NOT contain /dev/sdb1
        let active_swaps = HashSet::new();
        let dev = DeviceScanner::parse_device_from_json(&fixture, true, &active_swaps)
            .expect("Device should be parsed");

        assert_eq!(dev.safety, DeviceSafety::Safe);
    }

    #[test]
    fn test_active_swap_flagged_system_disk() {
        let fixture = json!({
            "name": "sdb",
            "path": "/dev/sdb",
            "type": "disk",
            "size": 1000000000u64,
            "children": [
                {
                    "name": "sdb1",
                    "path": "/dev/sdb1",
                    "size": 1000000000u64,
                    "fstype": "swap",
                    "mountpoint": null
                }
            ]
        });

        // /proc/swaps is available, and active_swaps contains /dev/sdb1
        let mut active_swaps = HashSet::new();
        active_swaps.insert("/dev/sdb1".to_string());
        let dev = DeviceScanner::parse_device_from_json(&fixture, true, &active_swaps)
            .expect("Device should be parsed");

        match dev.safety {
            DeviceSafety::SystemDisk(crit) => {
                assert!(crit.contains(&"[SWAP ACTIVE]".to_string()));
            }
            _ => panic!("Expected SystemDisk due to active swap"),
        }
    }

    #[test]
    fn test_deep_recursive_partition_discovery() {
        // Construct a 5-level deep nested structure:
        // nvme0n1 (disk)
        //  -> nvme0n1p3 (partition)
        //    -> crypt_system (LUKS crypt)
        //      -> lvm_pv (LVM PV)
        //        -> vg_os-lv_root (LVM LV mounted at /)
        //        -> vg_os-lv_var (LVM LV mounted at /var)
        //        -> vg_os-lv_nix (LVM LV mounted at /nix)
        //        -> vg_os-lv_data (LVM LV mounted at /mnt/data)
        let fixture = json!({
            "name": "nvme0n1",
            "path": "/dev/nvme0n1",
            "type": "disk",
            "size": 1000000000000u64,
            "children": [
                {
                    "name": "nvme0n1p1",
                    "path": "/dev/nvme0n1p1",
                    "size": 536870912u64,
                    "fstype": "vfat",
                    "mountpoint": "/boot/efi"
                },
                {
                    "name": "nvme0n1p2",
                    "path": "/dev/nvme0n1p2",
                    "size": 1073741824u64,
                    "fstype": "ext4",
                    "mountpoint": "/boot"
                },
                {
                    "name": "nvme0n1p3",
                    "path": "/dev/nvme0n1p3",
                    "size": 998000000000u64,
                    "fstype": "crypto_LUKS",
                    "children": [
                        {
                            "name": "crypt_system",
                            "path": "/dev/mapper/crypt_system",
                            "size": 997000000000u64,
                            "fstype": "LVM2_member",
                            "children": [
                                {
                                    "name": "vg_os-lv_root",
                                    "path": "/dev/mapper/vg_os-lv_root",
                                    "size": 100000000000u64,
                                    "fstype": "ext4",
                                    "mountpoint": "/"
                                },
                                {
                                    "name": "vg_os-lv_var",
                                    "path": "/dev/mapper/vg_os-lv_var",
                                    "size": 50000000000u64,
                                    "fstype": "ext4",
                                    "mountpoint": "/var"
                                },
                                {
                                    "name": "vg_os-lv_nix",
                                    "path": "/dev/mapper/vg_os-lv_nix",
                                    "size": 300000000000u64,
                                    "fstype": "ext4",
                                    "mountpoint": "/nix"
                                },
                                {
                                    "name": "vg_os-lv_data",
                                    "path": "/dev/mapper/vg_os-lv_data",
                                    "size": 500000000000u64,
                                    "fstype": "ext4",
                                    "mountpoint": "/mnt/data"
                                }
                            ]
                        }
                    ]
                }
            ]
        });

        let dev = DeviceScanner::parse_device_from_json(&fixture, false, &HashSet::new())
            .expect("Device should parse");

        // All partitions across all levels must be collected:
        // nvme0n1p1, nvme0n1p2, nvme0n1p3, crypt_system, vg_os-lv_root, vg_os-lv_var, vg_os-lv_nix, vg_os-lv_data -> 8 total
        assert_eq!(dev.partitions.len(), 8);

        // All mountpoints collected
        assert!(dev.mountpoints.contains(&"/boot/efi".to_string()));
        assert!(dev.mountpoints.contains(&"/boot".to_string()));
        assert!(dev.mountpoints.contains(&"/".to_string()));
        assert!(dev.mountpoints.contains(&"/var".to_string()));
        assert!(dev.mountpoints.contains(&"/nix".to_string()));
        assert!(dev.mountpoints.contains(&"/mnt/data".to_string()));

        // SystemDisk evaluation must identify all critical mountpoints
        match dev.safety {
            DeviceSafety::SystemDisk(crit) => {
                assert!(crit.contains(&"/".to_string()));
                assert!(crit.contains(&"/boot".to_string()));
                assert!(crit.contains(&"/boot/efi".to_string()));
                assert!(crit.contains(&"/var".to_string()));
                assert!(crit.contains(&"/nix".to_string()));
                assert!(!crit.contains(&"/mnt/data".to_string()));
            }
            _ => panic!("Expected SystemDisk"),
        }
    }

    #[test]
    fn test_proc_swaps_top_level_and_nested_detection() {
        let fixture = json!({
            "name": "zram0",
            "path": "/dev/zram0",
            "type": "disk",
            "size": 8589934592u64,
            "children": []
        });

        let mut active_swaps = HashSet::new();
        active_swaps.insert("/dev/zram0".to_string());

        let dev = DeviceScanner::parse_device_from_json(&fixture, true, &active_swaps)
            .expect("Device should parse");

        match dev.safety {
            DeviceSafety::SystemDisk(crit) => {
                assert!(crit.contains(&"[SWAP ACTIVE]".to_string()));
            }
            _ => panic!("Expected top-level zram swap to be flagged SystemDisk"),
        }
    }

    #[test]
    fn test_proc_swaps_unavailable_fallback() {
        // When /proc/swaps is unreadable (proc_swaps_available = false),
        // any partition with fstype "swap" must be treated as active swap as a safety fallback.
        let fixture = json!({
            "name": "sdc",
            "path": "/dev/sdc",
            "type": "disk",
            "size": 1000000000u64,
            "children": [
                {
                    "name": "sdc1",
                    "path": "/dev/sdc1",
                    "size": 1000000000u64,
                    "fstype": "swap",
                    "mountpoint": null
                }
            ]
        });

        let dev = DeviceScanner::parse_device_from_json(&fixture, false, &HashSet::new())
            .expect("Device should parse");

        match dev.safety {
            DeviceSafety::SystemDisk(crit) => {
                assert!(crit.contains(&"[SWAP ACTIVE]".to_string()));
            }
            _ => panic!("Expected safety fallback to SystemDisk when /proc/swaps is unavailable"),
        }
    }
}
