//! Unmount and safety tests against a fake host: sysfs tree, mount table,
//! swap list, registry, lsblk tree and an unmount that edits the table.

use super::*;
use crate::discovery::sysfs::fake::FakeSysfs;
use crate::models::identity::SourceKind;
use dfcore::lsblk::DeviceIdentity;
use dfcore::protected::{ProtectedDevice, Role};
use serde_json::Value;
use std::cell::RefCell;

const SATA: &str = "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0";
const SYS_SATA: &str = "pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0";

/// Host disk sda (/, swap) and evidence disk sdb: sdb1 ext4, sdb2 LUKS ->
/// dm-0 "cryptdata".
const LSBLK: &str = r#"{"blockdevices":[
  {"name":"sda","path":"/dev/sda","maj:min":"8:0","size":"100G","ro":false,"type":"disk","serial":"SYS1","mountpoints":[null],"children":[
    {"name":"sda1","path":"/dev/sda1","maj:min":"8:1","type":"part","fstype":"ext4","mountpoints":["/"]}]},
  {"name":"sdb","path":"/dev/sdb","maj:min":"8:16","size":"500G","ro":false,"type":"disk","serial":"EVID1","mountpoints":[null],"children":[
    {"name":"sdb1","path":"/dev/sdb1","maj:min":"8:17","type":"part","fstype":"ext4","mountpoints":["/mnt/ev","/srv/bind"]},
    {"name":"sdb2","path":"/dev/sdb2","maj:min":"8:18","type":"part","fstype":"crypto_LUKS","mountpoints":[null],"children":[
      {"name":"cryptdata","path":"/dev/mapper/cryptdata","maj:min":"254:0","type":"crypt","fstype":"ext4","mountpoints":["/mnt/ev/crypt"]}]}]}
]}"#;

const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 8:17 / /mnt/ev rw,relatime shared:2 - ext4 /dev/sdb1 rw
41 40 254:0 / /mnt/ev/crypt rw,relatime - ext4 /dev/mapper/cryptdata rw
42 22 8:17 /data /srv/bind rw,relatime shared:2 - ext4 /dev/sdb1 rw
";

struct Fake {
    sys: FakeSysfs,
    mountinfo: RefCell<String>,
    swaps: Vec<SwapEntry>,
    registry: Result<Option<Registry>, String>,
    lsblk: &'static str,
    log: PathBuf,
    node: Option<DevNum>,
    /// Mount points whose umount fails
    busy: Vec<String>,
    /// umount succeeds but the mount stays (e.g. another namespace re-mounts)
    sticky: bool,
    calls: RefCell<Vec<String>>,
    _dir: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        let sys = FakeSysfs::new();
        sys.add_disk(SYS_SATA, "sda", (8, 0), 1000);
        sys.add_partition("sda", "sda1", (8, 1), 1, 2048, 900);
        sys.add_disk(SATA, "sdb", (8, 16), 10_000);
        sys.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 4000);
        sys.add_partition("sdb", "sdb2", (8, 18), 2, 6048, 3000);
        sys.add_virtual("dm-0", (254, 0), 2900);
        sys.set("dm-0", "dm/name", "cryptdata");
        sys.stack("dm-0", "sdb2");
        let dir = tempfile::tempdir().unwrap();
        Fake {
            sys,
            mountinfo: RefCell::new(MOUNTINFO.to_string()),
            swaps: Vec::new(),
            registry: Ok(None),
            lsblk: LSBLK,
            log: dir.path().join("audit.jsonl"),
            node: Some((8, 16)),
            busy: Vec::new(),
            sticky: false,
            calls: RefCell::new(Vec::new()),
            _dir: dir,
        }
    }

    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

impl UnmountHost for Fake {
    fn sysfs(&self) -> SysRoot {
        self.sys.root()
    }
    fn node_dev(&self, _path: &Path) -> Option<DevNum> {
        self.node
    }
    fn mountinfo(&self) -> Result<String, String> {
        Ok(self.mountinfo.borrow().clone())
    }
    fn swaps(&self) -> Result<Vec<SwapEntry>, String> {
        Ok(self.swaps.clone())
    }
    fn registry(&self) -> Result<Option<Registry>, String> {
        self.registry.clone()
    }
    fn lsblk(&self) -> Result<Vec<FlatDevice>, String> {
        dfcore::lsblk::parse(self.lsblk.as_bytes()).map_err(|e| e.to_string())
    }
    fn audit_log(&self) -> PathBuf {
        self.log.clone()
    }
    fn unmount(&self, mount_point: &str) -> Result<(), String> {
        self.calls.borrow_mut().push(mount_point.to_string());
        if self.busy.iter().any(|b| b == mount_point) {
            return Err("umount: target is busy".into());
        }
        if !self.sticky {
            // Remove the topmost mount at that path (the last one listed)
            let table = self.mountinfo.borrow().clone();
            let lines: Vec<&str> = table.lines().collect();
            let idx = lines
                .iter()
                .rposition(|l| l.split(' ').nth(4) == Some(mount_point))
                .ok_or("not mounted")?;
            let kept: Vec<&str> = lines
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, l)| *l)
                .collect();
            *self.mountinfo.borrow_mut() = kept.join("\n") + "\n";
        }
        Ok(())
    }
}

fn id(kname: &str, dev: &str, kind: SourceKind) -> SourceIdentity {
    SourceIdentity {
        path: format!("/dev/{kname}"),
        canonical_path: format!("/dev/{kname}"),
        kernel_name: kname.into(),
        maj_min: Some(dev.into()),
        kind,
        serial: Some("EVID1".into()),
        ..Default::default()
    }
}

fn sdb() -> SourceIdentity {
    id("sdb", "8:16", SourceKind::Disk)
}

#[test]
fn unmounts_the_whole_tree_deepest_first_and_audits() {
    let f = Fake::new();
    let res = unmount_source_tree_with(&f, &sdb()).unwrap();
    // The LUKS filesystem mounted inside /mnt/ev goes first, the bind mount
    // (listed later) before /mnt/ev
    assert_eq!(*f.calls.borrow(), ["/mnt/ev/crypt", "/srv/bind", "/mnt/ev"]);
    assert_eq!(res.unmounted, ["/mnt/ev/crypt", "/srv/bind", "/mnt/ev"]);
    assert_eq!(res.mounts_before, ["/mnt/ev", "/mnt/ev/crypt", "/srv/bind"]);
    assert_eq!(res.holders, ["dm-0"]);
    assert!(res.notes[0].contains("stay open"), "{:?}", res.notes);
    assert!(res.audit_error.is_none());
    let recs = f.records();
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r["action"], "unmount");
    assert_eq!(r["outcome"], "ok");
    assert_eq!(r["hash"], res.audit_hash.unwrap().as_str());
    assert_eq!(r["details"]["unmounted"][0], "/mnt/ev/crypt");
    assert_eq!(r["details"]["holders"][0], "dm-0");
    assert_eq!(r["details"]["remaining"].as_array().unwrap().len(), 0);
    assert_eq!(r["device"]["maj_min"], "8:16");
    // The host's root filesystem was not touched
    assert!(f.mountinfo.borrow().contains(" / / "));
}

#[test]
fn partition_source_unmounts_only_its_own_tree() {
    let f = Fake::new();
    let mut part = id("sdb2", "8:18", SourceKind::Partition);
    part.parent_disks = vec!["/dev/sdb".into()];
    let mut fake = f;
    fake.node = Some((8, 18));
    let res = unmount_source_tree_with(&fake, &part).unwrap();
    assert_eq!(res.unmounted, ["/mnt/ev/crypt"]);
    assert_eq!(res.holders, ["dm-0"]);
    assert!(fake.mountinfo.borrow().contains("/mnt/ev rw"));
}

#[test]
fn nothing_mounted_is_not_recorded() {
    let f = Fake::new();
    *f.mountinfo.borrow_mut() = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n".into();
    let res = unmount_source_tree_with(&f, &sdb()).unwrap();
    assert!(res.unmounted.is_empty());
    assert!(res
        .notes
        .iter()
        .any(|n| n.contains("nothing of the source")));
    assert!(f.calls.borrow().is_empty());
    assert!(f.records().is_empty());
}

fn refused(f: &Fake, identity: &SourceIdentity) -> String {
    let err = unmount_source_tree_with(f, identity).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Refused, "{err}");
    assert!(f.calls.borrow().is_empty(), "nothing may be unmounted");
    err.message
}

use crate::engines::ErrorKind;

#[test]
fn system_disk_and_system_mounts_are_refused_and_recorded() {
    let mut f = Fake::new();
    f.node = Some((8, 0));
    let msg = refused(&f, &id("sda", "8:0", SourceKind::Disk));
    assert!(msg.contains("disk of the running system"), "{msg}");
    assert!(msg.contains("a mount point of the running system"), "{msg}");
    let recs = f.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["outcome"], "refused");
    assert_eq!(recs[0]["details"]["error_kind"], "refused");
    assert!(recs[0]["details"]["refusals"].as_array().unwrap().len() >= 2);
}

#[test]
fn registry_is_checked_before_unmounting() {
    let mut f = Fake::new();
    f.registry = Ok(Some(Registry {
        schema: dfcore::protected::SCHEMA,
        generated_at: "2026-01-01T00:00:00Z".into(),
        boot_id: None,
        devices: vec![ProtectedDevice {
            role: Role::LiveMedium,
            identity: DeviceIdentity {
                path: "/dev/sdb".into(),
                kernel_name: "sdb".into(),
                serial: Some("EVID1".into()),
                ..Default::default()
            },
            reasons: vec!["/dev/sdb1 has label DFNIX_LIVE".into()],
        }],
    }));
    let msg = refused(&f, &sdb());
    assert!(msg.contains("protected by the dfnix registry"), "{msg}");

    let mut g = Fake::new();
    g.registry = Err("Corrupt protected-device registry".into());
    let msg = refused(&g, &sdb());
    assert!(msg.contains("fail closed"), "{msg}");
}

#[test]
fn active_swap_on_the_tree_is_refused_naming_the_entry() {
    let mut f = Fake::new();
    f.swaps = vec![
        SwapEntry {
            path: "/mnt/ev/swapfile".into(),
            kind: "file".into(),
            dev: Some((8, 17)),
        },
        SwapEntry {
            path: "/dev/zram0".into(),
            kind: "partition".into(),
            dev: Some((252, 0)),
        },
    ];
    let msg = refused(&f, &sdb());
    assert!(msg.contains("/mnt/ev/swapfile (file)"), "{msg}");
    assert!(msg.contains("never runs swapoff"), "{msg}");
    assert!(!msg.contains("zram0"), "{msg}");
}

#[test]
fn foreign_mounts_on_top_and_changed_nodes_are_refused() {
    let f = Fake::new();
    f.mountinfo
        .borrow_mut()
        .push_str("43 40 0:50 / /mnt/ev/tmp rw - tmpfs tmpfs rw\n");
    let msg = refused(&f, &sdb());
    assert!(
        msg.contains("tmpfs (tmpfs) is mounted at /mnt/ev/tmp"),
        "{msg}"
    );

    let mut g = Fake::new();
    g.node = Some((8, 32));
    let msg = refused(&g, &sdb());
    assert!(
        msg.contains("no longer refers to the selected device"),
        "{msg}"
    );

    let h = Fake::new();
    let mut no_dev = sdb();
    no_dev.maj_min = None;
    let msg = refused(&h, &no_dev);
    assert!(msg.contains("no major:minor"), "{msg}");
}

#[test]
fn failed_or_incomplete_unmounts_are_errors_and_recorded() {
    let mut f = Fake::new();
    f.busy = vec!["/srv/bind".into()];
    let err = unmount_source_tree_with(&f, &sdb()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Failed);
    assert!(err.message.contains("target is busy"), "{err}");
    assert!(
        err.message.contains("already unmounted: /mnt/ev/crypt"),
        "{err}"
    );
    // It stopped at the failure: /mnt/ev was not attempted
    assert_eq!(*f.calls.borrow(), ["/mnt/ev/crypt", "/srv/bind"]);
    let recs = f.records();
    assert_eq!(recs[0]["outcome"], "error");
    assert_eq!(recs[0]["details"]["unmounted"][0], "/mnt/ev/crypt");
    assert_eq!(recs[0]["details"]["remaining"].as_array().unwrap().len(), 2);

    let mut g = Fake::new();
    g.sticky = true;
    let err = unmount_source_tree_with(&g, &sdb()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Failed);
    assert!(
        err.message.contains("still mounted after unmounting"),
        "{err}"
    );
}

#[test]
fn regular_files_are_a_usage_error_and_dfnix_needs_a_writable_log() {
    let f = Fake::new();
    let file = SourceIdentity {
        path: "/tmp/x.img".into(),
        kind: SourceKind::RegularFile,
        ..Default::default()
    };
    assert_eq!(
        unmount_source_tree_with(&f, &file).unwrap_err().kind,
        ErrorKind::Usage
    );

    // On dfnix (registry present) an unwritable audit log refuses before
    // anything is unmounted
    let mut g = Fake::new();
    g.registry = Ok(Some(Registry {
        schema: dfcore::protected::SCHEMA,
        generated_at: "2026-01-01T00:00:00Z".into(),
        boot_id: None,
        devices: vec![],
    }));
    let blocker = g._dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"x").unwrap();
    g.log = blocker.join("audit.jsonl");
    // A file where the directory should be: open and access both fail
    let err = unmount_source_tree_with(&g, &sdb()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Refused, "{err}");
    assert!(err.message.contains("audit log cannot be written"), "{err}");
    assert!(g.calls.borrow().is_empty());
}

#[test]
fn mountinfo_records_unescape_and_nest() {
    let content = "\
22 1 8:1 / / rw - ext4 /dev/sda1 rw
40 22 8:17 / /mnt/my\\040disk rw shared:2 - ext4 /dev/sdb1 rw
41 40 8:17 / /mnt/my\\040disk rw - ext4 /dev/sdb1 rw
50 41 0:45 / /mnt/my\\040disk/x rw - btrfs /dev/mapper/a\\134b rw
garbage line
";
    let recs = parse_mountinfo_records(content);
    assert_eq!(recs.len(), 4);
    assert_eq!(recs[1].mount_point, "/mnt/my disk");
    assert_eq!(recs[3].source, "/dev/mapper/a\\b");
    assert_eq!(recs[3].fstype, "btrfs");
    let depth = mount_depths(&recs);
    assert_eq!(depth[&22], 0);
    assert_eq!(depth[&40], 1);
    // Stacked on the same mount point: one deeper
    assert_eq!(depth[&41], 2);
    assert_eq!(depth[&50], 3);
}

#[test]
fn system_reasons_are_the_union_of_both_lists() {
    let flat = dfcore::lsblk::parse(
        br#"{"blockdevices":[
      {"name":"sdc","path":"/dev/sdc","maj:min":"8:32","type":"disk","children":[
        {"name":"sdc1","path":"/dev/sdc1","maj:min":"8:33","type":"part","mountpoints":["/home"]},
        {"name":"sdc2","path":"/dev/sdc2","maj:min":"8:34","type":"part","mountpoints":["/iso"]}]},
      {"name":"sdd","path":"/dev/sdd","maj:min":"8:48","type":"disk","children":[
        {"name":"sdd1","path":"/dev/sdd1","maj:min":"8:49","type":"part","mountpoints":["/run/media/user/USB"]}]}
    ]}"#,
    )
    .unwrap();
    let r = system_reasons_for(&flat, "/dev/sdc2", None);
    assert!(r.iter().any(|x| x.contains("/iso")), "{r:?}"); // dfcore
    assert!(r.iter().any(|x| x.contains("/home")), "{r:?}"); // dfdisk
                                                             // By device number (another name for the node)
    assert_eq!(
        system_reasons_for(&flat, "/dev/disk/by-id/x", Some((8, 33))),
        r
    );
    assert!(system_reasons_for(&flat, "/dev/sdd1", None).is_empty());
    assert!(is_system_mount("[SWAP]"));
    assert!(is_system_mount("/run/initramfs"));
    assert!(is_system_mount("/sysroot"));
    assert!(!is_system_mount("/run/media/user/USB"));
    assert!(!is_system_mount("/mnt/evidence"));
}

#[test]
fn legacy_checker_uses_the_union_and_never_unmounts() {
    for m in [
        "/",
        "/boot/efi",
        "/nix/store",
        "/home/x",
        "/iso",
        "[SWAP]",
        "/var/log",
    ] {
        assert!(
            SafetyChecker::evaluate_safety(&[m.to_string()], false).is_system(),
            "{m}"
        );
    }
    assert_eq!(
        SafetyChecker::evaluate_safety(&["/mnt/usb".to_string()], false),
        DeviceSafety::Mounted(vec!["/mnt/usb".to_string()])
    );
    assert_eq!(
        SafetyChecker::evaluate_safety(&[], false),
        DeviceSafety::Safe
    );
    assert!(SafetyChecker::evaluate_safety(&[], true).is_system());
    for list in [vec![], vec!["/mnt/usb".to_string()], vec!["/".to_string()]] {
        let err = SafetyChecker::unmount_all(&list).unwrap_err();
        assert!(err.contains("REFUSING"), "{err}");
        assert!(err.contains("dfdisk unmount"), "{err}");
    }
    assert!(!SafetyChecker::is_critical_mount("/homebrew"));
    assert!(!SafetyChecker::is_critical_mount("/variable"));
    assert!(SafetyChecker::is_critical_mount(" /nix/store\t"));
}

/// LSBLK plus loop0 (an image) with a partition.
const LSBLK_LOOP: &str = r#"{"blockdevices":[
  {"name":"sda","path":"/dev/sda","maj:min":"8:0","size":"100G","ro":false,"type":"disk","serial":"SYS1","mountpoints":[null],"children":[
    {"name":"sda1","path":"/dev/sda1","maj:min":"8:1","type":"part","fstype":"ext4","mountpoints":["/"]}]},
  {"name":"loop0","path":"/dev/loop0","maj:min":"7:0","size":"512000","ro":false,"type":"loop","mountpoints":[null],"children":[
    {"name":"loop0p1","path":"/dev/loop0p1","maj:min":"259:0","type":"part","fstype":"ext4","mountpoints":["/mnt/img"]}]}
]}"#;

#[test]
fn a_loop_source_unmounts_the_filesystems_of_its_partitions() {
    // losetup -P of an image; loop0p1 mounted
    let mut host = Fake::new();
    host.lsblk = LSBLK_LOOP;
    host.sys
        .add_loop("loop0", (7, 0), 1000, "/srv/images/case.img");
    host.sys
        .add_partition("loop0", "loop0p1", (259, 0), 1, 2048, 900);
    host.mountinfo
        .borrow_mut()
        .push_str("60 22 259:0 / /mnt/img rw,relatime - ext4 /dev/loop0p1 rw\n");
    host.node = Some((7, 0));
    let res = unmount_source_tree_with(
        &host,
        &id(
            "loop0",
            "7:0",
            SourceKind::Loop {
                backing_file: Some("/srv/images/case.img".into()),
            },
        ),
    )
    .unwrap();
    assert_eq!(res.mounts_before, ["/mnt/img"]);
    assert_eq!(res.unmounted, ["/mnt/img"]);
    assert!(res.holders.is_empty(), "{:?}", res.holders);
    assert!(!host.mountinfo.borrow().contains("/mnt/img"));
}

#[test]
fn a_loop_over_the_source_is_a_holder_and_its_mounts_are_unmounted() {
    // losetup -P /dev/sdb; loop0p1 mounted: the source's data is mounted
    let mut host = Fake::new();
    host.sys.add_loop("loop0", (7, 0), 10_000, "/dev/sdb");
    host.sys
        .add_partition("loop0", "loop0p1", (259, 0), 1, 2048, 4000);
    host.mountinfo
        .borrow_mut()
        .push_str("60 22 259:0 / /mnt/loop rw,relatime - ext4 /dev/loop0p1 rw\n");
    host.node = Some((8, 16));
    let res = unmount_source_tree_with(&host, &id("sdb", "8:16", SourceKind::Disk)).unwrap();
    assert!(res.mounts_before.contains(&"/mnt/loop".to_string()));
    assert!(res.unmounted.contains(&"/mnt/loop".to_string()));
    assert!(
        res.holders.contains(&"loop0".to_string()),
        "{:?}",
        res.holders
    );
    assert!(
        res.notes.iter().any(|n| n.contains("loop0")),
        "{:?}",
        res.notes
    );
}

/// sdb with `losetup /dev/loop0 /dev/sdb; kpartx -a /dev/loop0`: dm-5
/// (loop0p1) maps sdb1's range, dm-6 (loop0p2) sdb2's; dfdisk does not read
/// their mapping tables. /mnt/kp1 is mounted from dm-5.
fn kpartx_over_a_whole_disk_loop() -> Fake {
    let f = Fake::new();
    f.sys.add_loop("loop0", (7, 0), 10_000, "/dev/sdb");
    f.sys.add_virtual("dm-5", (254, 5), 4000);
    f.sys.set("dm-5", "dm/name", "loop0p1");
    f.sys.stack("dm-5", "loop0");
    f.sys.add_virtual("dm-6", (254, 6), 3000);
    f.sys.set("dm-6", "dm/name", "loop0p2");
    f.sys.stack("dm-6", "loop0");
    *f.mountinfo.borrow_mut() = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
        60 22 254:5 / /mnt/kp1 rw - ext4 /dev/mapper/loop0p1 rw\n"
        .into();
    f
}

#[test]
fn a_mount_that_may_not_be_the_sources_is_refused_not_unmounted() {
    // S-N4: unmounting sdb2 unmounted /mnt/kp1, sdb1's filesystem
    let mut f = kpartx_over_a_whole_disk_loop();
    f.node = Some((8, 18));
    let mut part = id("sdb2", "8:18", SourceKind::Partition);
    part.parent_disks = vec!["/dev/sdb".into()];
    let e = unmount_source_tree_with(&f, &part).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused);
    assert!(
        e.message.contains(
            "cannot tell whether /mnt/kp1 belongs to /dev/sdb2: it is mounted from /dev/mapper/loop0p1 (stacked on loop0, a loop device over /dev/sdb, which holds the source)"
        ),
        "{e}"
    );
    assert!(e.message.contains("unmount it yourself"), "{e}");
    assert!(f.calls.borrow().is_empty(), "{:?}", f.calls.borrow());
    assert!(f.mountinfo.borrow().contains("/mnt/kp1"));
    let recs = f.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["outcome"], "refused");

    // The whole disk: everything on loop0 is sdb's data, dm-5 included
    let mut f = kpartx_over_a_whole_disk_loop();
    f.node = Some((8, 16));
    let res = unmount_source_tree_with(&f, &sdb()).unwrap();
    assert_eq!(res.unmounted, ["/mnt/kp1"]);
    assert!(!f.mountinfo.borrow().contains("/mnt/kp1"));
}
