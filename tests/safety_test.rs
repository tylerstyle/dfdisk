//! Source safety through the public API: system mount detection (dfdisk's
//! list united with dfcore's), the retired unmount-by-path, and the audited
//! unmount of a source tree against an injected host (sysfs tree, mount
//! table, registry, lsblk, audit log and unmount are all fakes).

use dfcore::lsblk::{DeviceIdentity, FlatDevice};
use dfcore::protected::{ProtectedDevice, Registry, Role};
use dfcore::sysfs::DevNum;
use dfdisk::discovery::safety::{
    is_system_mount, unmount_source_tree_with, SafetyChecker, UnmountHost,
};
use dfdisk::discovery::sysfs::SysRoot;
use dfdisk::engines::session::SwapEntry;
use dfdisk::engines::ErrorKind;
use dfdisk::models::device::DeviceSafety;
use dfdisk::models::identity::{SourceIdentity, SourceKind};
use serde_json::Value;
use std::cell::RefCell;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

#[test]
fn critical_and_system_mounts() {
    for root in ["/", "/boot", "/nix", "/home", "/var", "/usr", "/etc"] {
        assert!(SafetyChecker::is_critical_mount(root), "{root}");
        match SafetyChecker::evaluate_safety(&[root.to_string()], false) {
            DeviceSafety::SystemDisk(crit) => assert!(crit.contains(&root.to_string())),
            other => panic!("{root}: {other:?}"),
        }
    }
    for sub in [
        "/boot/efi",
        "/nix/store",
        "/home/examiner",
        "/var/log",
        "/usr/bin",
        "/etc/fstab",
    ] {
        assert!(SafetyChecker::is_critical_mount(sub), "{sub}");
    }
    // dfcore's list: the dfnix live medium, initramfs, swap
    for m in ["/iso", "/run/initramfs", "/sysroot", "[SWAP]"] {
        assert!(!SafetyChecker::is_critical_mount(m), "{m}");
        assert!(is_system_mount(m), "{m}");
        assert!(
            SafetyChecker::evaluate_safety(&[m.to_string()], false).is_system(),
            "{m}"
        );
    }
    for safe in [
        "/mnt/usb",
        "/media/external",
        "/run/media/examiner/FLASH_DRIVE",
        "/tmp/mount_test",
        "/homebrew",
        "/variable_data",
        "/usrobotics",
        "/etcetera",
    ] {
        assert!(!is_system_mount(safe), "{safe}");
        assert_eq!(
            SafetyChecker::evaluate_safety(&[safe.to_string()], false),
            DeviceSafety::Mounted(vec![safe.to_string()])
        );
    }
    // dfcore matches /boot and /nix as prefixes; erring on the safe side
    assert!(!SafetyChecker::is_critical_mount("/bootloader_backup"));
    assert!(is_system_mount("/bootloader_backup"));
    assert_eq!(
        SafetyChecker::evaluate_safety(&[], false),
        DeviceSafety::Safe
    );
}

#[test]
fn unmount_by_path_is_retired() {
    for list in [
        vec![],
        vec!["/mnt/usb_safe".to_string()],
        vec!["/".to_string(), "/media/external".to_string()],
    ] {
        let err = SafetyChecker::unmount_all(&list).unwrap_err();
        assert!(err.starts_with("REFUSING"), "{err}");
        assert!(err.contains("dfdisk unmount"), "{err}");
    }
}

/// sysfs like a host's: disk sdx (8:16) with partitions sdx1, sdx2.
fn sysfs(dir: &Path) {
    for d in ["class/block", "dev/block", "devices"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let hw = dir.join("devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0");
    let disk = hw.join("block/sdx");
    let node = |path: &Path, kname: &str, dev: (u32, u32), extra: &[(&str, &str)]| {
        std::fs::create_dir_all(path.join("holders")).unwrap();
        std::fs::write(path.join("dev"), format!("{}:{}\n", dev.0, dev.1)).unwrap();
        std::fs::write(path.join("size"), "1000\n").unwrap();
        std::fs::write(path.join("ro"), "0\n").unwrap();
        for (k, v) in extra {
            std::fs::write(path.join(k), format!("{v}\n")).unwrap();
        }
        symlink(path, dir.join("class/block").join(kname)).unwrap();
        symlink(path, dir.join(format!("dev/block/{}:{}", dev.0, dev.1))).unwrap();
    };
    node(&disk, "sdx", (8, 16), &[]);
    symlink(&hw, disk.join("device")).unwrap();
    node(
        &disk.join("sdx1"),
        "sdx1",
        (8, 17),
        &[("partition", "1"), ("start", "2048")],
    );
    node(
        &disk.join("sdx2"),
        "sdx2",
        (8, 18),
        &[("partition", "2"), ("start", "4096")],
    );
}

const LSBLK: &str = r#"{"blockdevices":[
  {"name":"sda","path":"/dev/sda","maj:min":"8:0","type":"disk","serial":"SYS1","children":[
    {"name":"sda1","path":"/dev/sda1","maj:min":"8:1","type":"part","mountpoints":["/"]}]},
  {"name":"sdx","path":"/dev/sdx","maj:min":"8:16","type":"disk","serial":"EVID9","children":[
    {"name":"sdx1","path":"/dev/sdx1","maj:min":"8:17","type":"part","mountpoints":["/media/ev"]},
    {"name":"sdx2","path":"/dev/sdx2","maj:min":"8:18","type":"part","mountpoints":["/media/ev/two"]}]}
]}"#;

const MOUNTINFO: &str = "\
22 1 8:1 / / rw - ext4 /dev/sda1 rw
40 22 8:17 / /media/ev rw - ext4 /dev/sdx1 rw
41 40 8:18 / /media/ev/two rw - vfat /dev/sdx2 rw
";

struct Host {
    dir: tempfile::TempDir,
    mountinfo: RefCell<String>,
    registry: Option<Registry>,
    unmounted: RefCell<Vec<String>>,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        sysfs(&dir.path().join("sys"));
        Host {
            dir,
            mountinfo: RefCell::new(MOUNTINFO.into()),
            registry: None,
            unmounted: RefCell::new(Vec::new()),
        }
    }

    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.audit_log())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

impl UnmountHost for Host {
    fn sysfs(&self) -> SysRoot {
        SysRoot::new(self.dir.path().join("sys"))
    }
    fn node_dev(&self, path: &Path) -> Option<DevNum> {
        match path.to_str()? {
            "/dev/sdx" => Some((8, 16)),
            "/dev/sdx2" => Some((8, 18)),
            _ => None,
        }
    }
    fn mountinfo(&self) -> Result<String, String> {
        Ok(self.mountinfo.borrow().clone())
    }
    fn swaps(&self) -> Result<Vec<SwapEntry>, String> {
        Ok(Vec::new())
    }
    fn registry(&self) -> Result<Option<Registry>, String> {
        Ok(self.registry.clone())
    }
    fn lsblk(&self) -> Result<Vec<FlatDevice>, String> {
        dfcore::lsblk::parse(LSBLK.as_bytes()).map_err(|e| e.to_string())
    }
    fn audit_log(&self) -> PathBuf {
        self.dir.path().join("audit/audit.jsonl")
    }
    fn unmount(&self, mount_point: &str) -> Result<(), String> {
        self.unmounted.borrow_mut().push(mount_point.to_string());
        let kept: Vec<String> = self
            .mountinfo
            .borrow()
            .lines()
            .filter(|l| l.split(' ').nth(4) != Some(mount_point))
            .map(str::to_string)
            .collect();
        *self.mountinfo.borrow_mut() = kept.join("\n") + "\n";
        Ok(())
    }
}

fn source(kname: &str, dev: &str, kind: SourceKind) -> SourceIdentity {
    SourceIdentity {
        path: format!("/dev/{kname}"),
        canonical_path: format!("/dev/{kname}"),
        kernel_name: kname.into(),
        maj_min: Some(dev.into()),
        kind,
        serial: Some("EVID9".into()),
        parent_disks: if kname == "sdx" {
            vec![]
        } else {
            vec!["/dev/sdx".into()]
        },
        ..Default::default()
    }
}

#[test]
fn unmounts_a_disk_deepest_first_with_an_audit_record() {
    let host = Host::new();
    let res = unmount_source_tree_with(&host, &source("sdx", "8:16", SourceKind::Disk)).unwrap();
    assert_eq!(res.unmounted, ["/media/ev/two", "/media/ev"]);
    assert_eq!(*host.unmounted.borrow(), res.unmounted);
    assert!(res.holders.is_empty());
    assert!(
        host.mountinfo.borrow().contains(" / / "),
        "the host's root stays"
    );
    let recs = host.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["action"], "unmount");
    assert_eq!(recs[0]["outcome"], "ok");
    assert_eq!(recs[0]["details"]["mounts_before"][1], "/media/ev/two");
    assert_eq!(recs[0]["hash"], res.audit_hash.unwrap().as_str());
}

#[test]
fn a_partition_source_unmounts_only_its_own_filesystems() {
    let host = Host::new();
    let res =
        unmount_source_tree_with(&host, &source("sdx2", "8:18", SourceKind::Partition)).unwrap();
    assert_eq!(res.unmounted, ["/media/ev/two"]);
    assert!(host.mountinfo.borrow().contains("/media/ev rw"));
}

#[test]
fn registry_protection_refuses_before_unmounting() {
    let mut host = Host::new();
    host.registry = Some(Registry {
        schema: dfcore::protected::SCHEMA,
        generated_at: "2026-01-01T00:00:00Z".into(),
        boot_id: None,
        devices: vec![ProtectedDevice {
            role: Role::LiveMedium,
            identity: DeviceIdentity {
                path: "/dev/sdx".into(),
                kernel_name: "sdx".into(),
                serial: Some("EVID9".into()),
                ..Default::default()
            },
            reasons: vec!["/dev/sdx1 has label DFNIX_LIVE".into()],
        }],
    });
    let err =
        unmount_source_tree_with(&host, &source("sdx", "8:16", SourceKind::Disk)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Refused);
    assert_eq!(err.exit_code(), 3);
    assert!(
        err.message.contains("protected by the dfnix registry"),
        "{err}"
    );
    assert!(host.unmounted.borrow().is_empty());
    assert_eq!(host.records()[0]["outcome"], "refused");
}
