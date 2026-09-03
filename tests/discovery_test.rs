#![allow(unused_imports, dead_code)]

#[path = "../src/models/mod.rs"]
mod models;

#[path = "../src/discovery/mod.rs"]
mod discovery;

use discovery::devices::DeviceScanner;
use discovery::smart::SmartChecker;
use models::device::DeviceSafety;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;

#[test]
fn test_parse_nested_luks_lvm_fixture() {
    let fixture_str = fs::read_to_string("tests/fixtures/lsblk_nested_luks.json")
        .expect("Failed to read lsblk_nested_luks.json fixture");
    let root: Value = serde_json::from_str(&fixture_str).expect("Valid JSON");
    let blockdevices = root["blockdevices"].as_array().expect("Array of devices");

    let mut active_swaps = HashSet::new();
    active_swaps.insert("/dev/mapper/vg_sys-swap".to_string());

    // 1. nvme0n1: Contains nested LUKS + LVM
    let nvme_val = &blockdevices[0];
    let dev = DeviceScanner::parse_device_from_json(nvme_val, true, &active_swaps)
        .expect("Must parse nvme0n1 disk");

    assert_eq!(dev.name, "nvme0n1");
    assert_eq!(dev.path, "/dev/nvme0n1");
    assert_eq!(dev.bus_type, "NVME");
    assert_eq!(dev.model.as_deref(), Some("Samsung SSD 980 PRO 1TB"));
    assert_eq!(dev.serial.as_deref(), Some("S5GXNF0R123456"));

    // Nested traversal should find all 8 child partitions across all nesting depths:
    // nvme0n1p1, nvme0n1p2, nvme0n1p3, luks-system, vg_sys-root, vg_sys-home, vg_sys-var, vg_sys-swap, vg_sys-data
    assert_eq!(dev.partitions.len(), 9);

    // Verify critical mountpoints are found
    assert!(dev.mountpoints.contains(&"/boot/efi".to_string()));
    assert!(dev.mountpoints.contains(&"/boot".to_string()));
    assert!(dev.mountpoints.contains(&"/".to_string()));
    assert!(dev.mountpoints.contains(&"/home".to_string()));
    assert!(dev.mountpoints.contains(&"/var".to_string()));
    assert!(dev.mountpoints.contains(&"/mnt/storage".to_string()));

    // Safety must be SystemDisk due to root and active swap
    match dev.safety {
        DeviceSafety::SystemDisk(critical) => {
            assert!(critical.contains(&"/".to_string()));
            assert!(critical.contains(&"/boot".to_string()));
            assert!(critical.contains(&"/boot/efi".to_string()));
            assert!(critical.contains(&"/home".to_string()));
            assert!(critical.contains(&"/var".to_string()));
            assert!(critical.contains(&"[SWAP ACTIVE]".to_string()));
            // Non-critical mount must not be in critical list
            assert!(!critical.contains(&"/mnt/storage".to_string()));
        }
        _ => panic!("Expected SystemDisk for nvme0n1 hosting root/boot/home/swap"),
    }

    // 2. sdb: Removable USB flash drive
    let sdb_val = &blockdevices[1];
    let usb_dev = DeviceScanner::parse_device_from_json(sdb_val, true, &active_swaps)
        .expect("Must parse sdb disk");

    assert_eq!(usb_dev.name, "sdb");
    assert_eq!(usb_dev.bus_type, "USB");
    assert_eq!(usb_dev.partitions.len(), 1);
    assert_eq!(
        usb_dev.mountpoints,
        vec!["/run/media/user/FORENSIC_USB".to_string()]
    );

    // USB drive is NOT a system disk, only normal Mounted
    match usb_dev.safety {
        DeviceSafety::Mounted(mounts) => {
            assert_eq!(mounts, vec!["/run/media/user/FORENSIC_USB".to_string()]);
        }
        _ => panic!(
            "Expected Mounted for external forensic USB, got: {:?}",
            usb_dev.safety
        ),
    }
}

#[test]
fn test_active_vs_dormant_swap_detection() {
    let fixture_str = fs::read_to_string("tests/fixtures/lsblk_nested_luks.json")
        .expect("Failed to read fixture");
    let root: Value = serde_json::from_str(&fixture_str).unwrap();
    let nvme_val = &root["blockdevices"][0];

    // Case A: Dormant swap (proc_swaps available, but swap partition NOT in active set)
    let empty_swaps = HashSet::new();
    let dev_dormant = DeviceScanner::parse_device_from_json(nvme_val, true, &empty_swaps)
        .expect("Must parse device");

    match dev_dormant.safety {
        DeviceSafety::SystemDisk(critical) => {
            // Root/boot are still critical, but [SWAP ACTIVE] must NOT be present
            assert!(!critical.contains(&"[SWAP ACTIVE]".to_string()));
        }
        _ => panic!("Expected SystemDisk due to / mount"),
    }

    // Case B: Active swap by partition path (/dev/mapper/vg_sys-swap)
    let mut active_swaps = HashSet::new();
    active_swaps.insert("/dev/mapper/vg_sys-swap".to_string());
    let dev_active = DeviceScanner::parse_device_from_json(nvme_val, true, &active_swaps)
        .expect("Must parse device");

    match dev_active.safety {
        DeviceSafety::SystemDisk(critical) => {
            assert!(critical.contains(&"[SWAP ACTIVE]".to_string()));
        }
        _ => panic!("Expected SystemDisk with active swap"),
    }

    // Case C: proc_swaps UNAVAILABLE (proc_swaps_available = false)
    // Safety fallback: partition with fstype "swap" must automatically trigger [SWAP ACTIVE]
    let dev_fallback = DeviceScanner::parse_device_from_json(nvme_val, false, &empty_swaps)
        .expect("Must parse device");

    match dev_fallback.safety {
        DeviceSafety::SystemDisk(critical) => {
            assert!(
                critical.contains(&"[SWAP ACTIVE]".to_string()),
                "When /proc/swaps is unavailable, swap partition must fallback to active"
            );
        }
        _ => panic!("Expected SystemDisk fallback on swap"),
    }
}

#[test]
fn test_smart_diagnostics_permission_denied() {
    let fixture_str = fs::read_to_string("tests/fixtures/smartctl_permission_denied.json")
        .expect("Failed to read smartctl_permission_denied.json fixture");
    let val: Value = serde_json::from_str(&fixture_str).unwrap();

    let info = SmartChecker::parse_smart_json(&val);

    // Permission denied must report passed: false and graceful diagnostic assessment
    assert!(!info.passed);
    assert_eq!(
        info.assessment,
        "UNKNOWN (Inaccessible / Permission Denied)"
    );
}

#[test]
fn test_smart_diagnostics_healthy_nvme() {
    let fixture_str = fs::read_to_string("tests/fixtures/smartctl_healthy.json")
        .expect("Failed to read smartctl_healthy.json fixture");
    let val: Value = serde_json::from_str(&fixture_str).unwrap();

    let info = SmartChecker::parse_smart_json(&val);

    assert!(info.passed);
    assert_eq!(info.assessment, "PASSED (Healthy)");
    assert_eq!(info.power_on_hours, Some(3450));
    assert_eq!(info.temperature_celsius, Some(38));
    assert_eq!(info.wear_percentage, Some(0)); // 100 - 100% available spare
    assert_eq!(info.uncorrectable_errors, Some(0));
}

#[test]
fn test_smart_diagnostics_failing_drive() {
    let fixture_str = fs::read_to_string("tests/fixtures/smartctl_failing.json")
        .expect("Failed to read smartctl_failing.json fixture");
    let val: Value = serde_json::from_str(&fixture_str).unwrap();

    let info = SmartChecker::parse_smart_json(&val);

    assert!(!info.passed);
    assert_eq!(info.assessment, "WARNING / FAILED");
    assert_eq!(info.power_on_hours, Some(45210));
    assert_eq!(info.temperature_celsius, Some(54));
    assert_eq!(info.reallocated_sectors, Some(1584));
    assert_eq!(info.pending_sectors, Some(320));
    assert_eq!(info.uncorrectable_errors, Some(112));
}

#[test]
fn test_smart_bitmask_error_variations() {
    // smartctl exit status bit 1 (value 2): device open failed (e.g. permission denied)
    let bitmask_cases = [
        (2, None, "UNKNOWN (Inaccessible / Permission Denied)"),
        (2, Some(true), "UNKNOWN (Inaccessible / Permission Denied)"), // Inaccessible overrides passed
        (6, None, "UNKNOWN (Inaccessible / Permission Denied)"),       // bits 1 and 2 set
        (1, None, "UNKNOWN (Inaccessible / Permission Denied)"), // non-zero with missing status
        (0, Some(true), "PASSED (Healthy)"),
        (0, Some(false), "WARNING / FAILED"),
    ];

    for (exit_code, smart_status, exp_assessment) in bitmask_cases {
        let json_val = serde_json::json!({
            "smartctl": { "exit_status": exit_code },
            "smart_status": smart_status.map(|p| serde_json::json!({ "passed": p }))
        });

        let info = SmartChecker::parse_smart_json(&json_val);
        assert_eq!(
            info.assessment, exp_assessment,
            "Failed for exit_code: {}, smart_status: {:?}",
            exit_code, smart_status
        );
    }
}
