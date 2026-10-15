//! Device scans from captured lsblk output (no tool is run, no device is
//! touched): an anonymised `lsblk -J -b -O` of util-linux 2.42 and a nested
//! LUKS/LVM tree, with mount table and swap list fixtures. sysfs is an empty
//! directory, so these exercise the lsblk-only path; the sysfs path is unit
//! tested in src/discovery/devices.

use dfdisk::discovery::devices::{find_source, scan, ScanInput, LIST_SCHEMA_VERSION};
use dfdisk::discovery::sysfs::SysRoot;
use dfdisk::engines::session::SwapEntry;
use dfdisk::models::device::DeviceSafety;
use dfdisk::models::identity::SourceKind;
use std::path::Path;

fn fixture(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The mount table that goes with the util-linux 2.42 capture.
const MOUNTINFO: &str = "\
26 1 259:1 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p1 rw
27 26 259:1 /nix/store /nix/store ro,relatime shared:2 - ext4 /dev/nvme0n1p1 rw
28 26 259:3 / /boot rw,relatime shared:3 - vfat /dev/nvme0n1p3 rw
29 26 259:1 /var/lib/containers/storage/overlay /var/lib/containers/storage/overlay rw - ext4 /dev/nvme0n1p1 rw
40 26 8:1 / /mnt/data rw,relatime shared:4 - ext4 /dev/sda1 rw
";

fn input(lsblk: &str, sys: &tempfile::TempDir) -> ScanInput {
    ScanInput {
        lsblk_json: lsblk.to_string(),
        sys: SysRoot::new(sys.path()),
        mountinfo: Ok(MOUNTINFO.into()),
        swaps: Ok(vec![SwapEntry {
            path: "/dev/nvme0n1p2".into(),
            kind: "partition".into(),
            dev: Some((259, 2)),
        }]),
        registry: Ok(None),
        dev_dir: sys.path().join("dev"),
    }
}

#[test]
fn util_linux_2_42_capture() {
    let sys = tempfile::tempdir().unwrap();
    let scan = scan(&input(
        &fixture("discovery/lsblk-util-linux-2.42.json"),
        &sys,
    ))
    .unwrap();
    let devices = scan.devices();
    let names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["sda", "nvme0n1"], "optical drives are not listed");

    let sda = &devices[0];
    assert_eq!(sda.safety, DeviceSafety::Mounted(vec!["/mnt/data".into()]));
    assert_eq!(sda.serial.as_deref(), Some("SATA-SERIAL-0001"));
    assert_eq!(sda.transport.as_deref(), Some("sata"));
    assert_eq!(sda.maj_min.as_deref(), Some("8:0"));
    assert_eq!(sda.vendor.as_deref(), Some("ATA"), "padding trimmed");
    assert!(!sda.hotplug && !sda.is_removable);
    assert_eq!(sda.partitions.len(), 1);
    assert_eq!(sda.partitions[0].start_sector, Some(2048));
    assert_eq!(sda.partitions[0].mountpoint.as_deref(), Some("/mnt/data"));

    let nvme = &devices[1];
    let DeviceSafety::SystemDisk(reasons) = &nvme.safety else {
        panic!("{:?}", nvme.safety)
    };
    for r in [
        "/dev/nvme0n1p1 mounted at /",
        "/dev/nvme0n1p2 mounted at [SWAP]",
        "/dev/nvme0n1p3 mounted at /boot",
        "active swap on this device: /dev/nvme0n1p2 (partition)",
    ] {
        assert!(reasons.iter().any(|x| x == r), "{r} missing in {reasons:?}");
    }
    assert!(nvme.mountpoints.contains(&"/nix/store".to_string()));
    assert!(!nvme.mountpoints.contains(&"[SWAP]".to_string()));
    assert_eq!(nvme.partitions[1].mountpoint.as_deref(), Some("[SWAP]"));

    let sources = scan.sources();
    assert_eq!(sources.len(), 6);
    let sda1 = find_source(&sources, "/dev/sda1").unwrap();
    assert_eq!(sda1.kind, SourceKind::Partition);
    assert_eq!(sda1.parent.as_deref(), Some("/dev/sda"));
    assert_eq!(sda1.start_sector, Some(2048));
    assert!(!sda1.safety.is_system());
    // A partition of the system disk is refused like the disk
    assert!(find_source(&sources, "/dev/nvme0n1p3")
        .unwrap()
        .safety
        .is_system());
    assert!(
        devices.iter().all(|d| d.smart.is_none()),
        "never SMART in a scan"
    );
}

#[test]
fn list_json_model() {
    let sys = tempfile::tempdir().unwrap();
    let scan = scan(&input(
        &fixture("discovery/lsblk-util-linux-2.42.json"),
        &sys,
    ))
    .unwrap();
    let v = serde_json::to_value(scan.listing()).unwrap();
    assert_eq!(v["schema_version"], LIST_SCHEMA_VERSION);
    assert_eq!(v["registry"]["state"], "absent");
    assert_eq!(v["active_swaps"][0]["path"], "/dev/nvme0n1p2");
    assert_eq!(v["active_swaps"][0]["device"], "259:2");
    let mut top: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    top.sort();
    assert_eq!(
        top,
        [
            "active_swaps",
            "devices",
            "generated_at",
            "notes",
            "registry",
            "schema_version"
        ]
    );
    let sda = &v["devices"][0];
    let mut keys: Vec<&str> = sda
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "active_swap",
            "badges",
            "children",
            "devlinks",
            "diskseq",
            "dm_name",
            "dm_uuid",
            "firmware_rev",
            "fstype",
            "holders",
            "hotplug",
            "kernel_name",
            "kind",
            "label",
            "logical_sector_size",
            "lsblk_type",
            "maj_min",
            "model",
            "mountpoints",
            "name",
            "parent_disks",
            "partition_number",
            "partition_table",
            "path",
            "physical_sector_size",
            "protected",
            "read_only",
            "removable",
            "rotational",
            "serial",
            "serial_candidates",
            "serial_note",
            "size_bytes",
            "start_sector",
            "system",
            "system_reasons",
            "transport",
            "uuid",
            "vendor",
            "wwn"
        ]
    );
    assert_eq!(sda["badges"][0], "MOUNTED");
    assert_eq!(sda["serial_candidates"][0]["source"], "lsblk");
    let sda1 = &sda["children"][0];
    assert_eq!(sda1["partition_number"], 1);
    assert_eq!(sda1["kind"]["type"], "partition");
    assert_eq!(sda1["fstype"], "ext4");
    let nvme = &v["devices"][1];
    assert_eq!(nvme["system"], true);
    assert_eq!(nvme["children"].as_array().unwrap().len(), 3);
    assert_eq!(
        nvme["children"][1]["active_swap"][0],
        "/dev/nvme0n1p2 (partition)"
    );
}

#[test]
fn nested_luks_lvm_tree() {
    let sys = tempfile::tempdir().unwrap();
    let mut inp = input(&fixture("lsblk_nested_luks.json"), &sys);
    inp.mountinfo = Ok(String::new());
    inp.swaps = Ok(vec![SwapEntry {
        path: "/dev/mapper/vg_sys-swap".into(),
        kind: "partition".into(),
        dev: None,
    }]);
    let scan = scan(&inp).unwrap();
    let devices = scan.devices();
    let nvme = &devices[0];
    assert_eq!(nvme.partitions.len(), 9);
    let DeviceSafety::SystemDisk(reasons) = &nvme.safety else {
        panic!("{:?}", nvme.safety)
    };
    assert!(
        reasons.iter().any(|r| r.contains("mounted at /")),
        "{reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r.contains("mounted at /home")),
        "{reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("active swap on this device: /dev/mapper/vg_sys-swap")),
        "{reasons:?}"
    );
    // LUKS and LVM devices are holders of the disk
    assert!(
        nvme.holders.contains(&"luks-system".to_string()),
        "{:?}",
        nvme.holders
    );

    let usb = &devices[1];
    assert_eq!(usb.bus_type, "USB");
    assert_eq!(
        usb.safety,
        DeviceSafety::Mounted(vec!["/run/media/user/FORENSIC_USB".into()])
    );

    // Unreadable swap list: a swap signature counts as active
    let mut fallback = input(&fixture("lsblk_nested_luks.json"), &sys);
    fallback.swaps = Err("permission denied".into());
    let scan = dfdisk::discovery::devices::scan(&fallback).unwrap();
    let DeviceSafety::SystemDisk(reasons) = &scan.devices()[0].safety else {
        panic!()
    };
    assert!(
        reasons.iter().any(|r| r.contains("swap signature")),
        "{reasons:?}"
    );
}
