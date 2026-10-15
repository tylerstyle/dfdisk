//! Scans against a fake host: sysfs tree, lsblk JSON as `lsblk -J -b -O`
//! prints it, mount table, swap list and registry.

use super::*;
use crate::discovery::sysfs::fake::FakeSysfs;
use dfcore::lsblk::DeviceIdentity;
use dfcore::protected::{ProtectedDevice, Role};

const SYS_SATA: &str = "pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0";
const USB_PORT: &str = "pci0000:00/0000:00:14.0/usb2/2-1";
const USB: &str = "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0";
const SATA: &str = "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0";

const LSBLK: &str = r#"{
   "blockdevices": [
      {"name":"sda", "kname":"sda", "path":"/dev/sda", "maj:min":"8:0", "rm":false, "hotplug":false, "ro":false, "size":512000, "type":"disk", "tran":"sata", "serial":"SYS1", "model":"System SSD", "log-sec":512, "phy-sec":512, "rota":false, "pttype":"gpt", "disk-seq":1, "mountpoints":[null],
         "children": [
            {"name":"sda1", "kname":"sda1", "path":"/dev/sda1", "maj:min":"8:1", "rm":false, "hotplug":false, "ro":false, "size":460800, "type":"part", "fstype":"ext4", "start":2048, "mountpoints":["/"]}
         ]
      },
      {"name":"sdb", "kname":"sdb", "path":"/dev/sdb", "maj:min":"8:16", "rm":false, "hotplug":true, "ro":false, "size":5120000, "type":"disk", "tran":"usb", "serial":"BRIDGE9", "model":"USB Bridge", "log-sec":512, "phy-sec":4096, "rota":true, "pttype":"gpt", "disk-seq":7, "mountpoints":[null],
         "children": [
            {"name":"sdb1", "kname":"sdb1", "path":"/dev/sdb1", "maj:min":"8:17", "rm":false, "hotplug":true, "ro":false, "size":2048000, "type":"part", "fstype":"ext4", "label":"EVIDENCE", "uuid":"1111-2222", "start":2048, "mountpoints":["/mnt/ev"]},
            {"name":"sdb2", "kname":"sdb2", "path":"/dev/sdb2", "maj:min":"8:18", "rm":false, "hotplug":true, "ro":false, "size":1536000, "type":"part", "fstype":"crypto_LUKS", "start":6048, "mountpoints":[null],
               "children": [
                  {"name":"cryptdata", "kname":"dm-0", "path":"/dev/mapper/cryptdata", "maj:min":"254:0", "rm":false, "hotplug":false, "ro":false, "size":1484800, "type":"crypt", "fstype":"ext4", "mountpoints":[null]}
               ]
            }
         ]
      },
      {"name":"sdc", "kname":"sdc", "path":"/dev/sdc", "maj:min":"8:32", "rm":false, "hotplug":false, "ro":true, "size":102400, "type":"disk", "tran":"sata", "serial":"RO-DISK", "mountpoints":[null]},
      {"name":"loop0", "kname":"loop0", "path":"/dev/loop0", "maj:min":"7:0", "rm":false, "hotplug":false, "ro":false, "size":51200, "type":"loop", "mountpoints":[null]},
      {"name":"sr0", "kname":"sr0", "path":"/dev/sr0", "maj:min":"11:0", "rm":true, "hotplug":true, "ro":false, "size":0, "type":"rom", "mountpoints":[null]}
   ]
}"#;

const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 8:17 / /mnt/ev rw,relatime shared:2 - ext4 /dev/sdb1 rw
";

fn host() -> FakeSysfs {
    let f = FakeSysfs::new();
    f.add_disk(SYS_SATA, "sda", (8, 0), 1000);
    f.add_partition("sda", "sda1", (8, 1), 1, 2048, 900);
    f.add_disk(USB, "sdb", (8, 16), 10_000);
    f.set("sdb", "diskseq", "7");
    f.set("sdb", "queue/physical_block_size", "4096");
    f.set("sdb", "queue/rotational", "1");
    f.set_hw(USB_PORT, "removable", "removable");
    f.set_hw(USB, "vpd_pg80", "DRIVE123");
    f.set_hw(USB, "model", "Ext HDD");
    f.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 4000);
    f.add_partition("sdb", "sdb2", (8, 18), 2, 6048, 3000);
    f.add_virtual("dm-0", (254, 0), 2900);
    f.set("dm-0", "dm/name", "cryptdata");
    f.set("dm-0", "dm/uuid", "CRYPT-LUKS2-0123abcd-cryptdata");
    f.stack("dm-0", "sdb2");
    f.add_disk(SATA, "sdc", (8, 32), 200);
    f.set("sdc", "ro", "1");
    f.add_virtual("loop0", (7, 0), 100);
    f.set("loop0", "loop/backing_file", "/srv/images/a.img");
    f
}

fn registry() -> Registry {
    Registry {
        schema: dfcore::protected::SCHEMA,
        generated_at: "2026-01-01T00:00:00Z".into(),
        boot_id: None,
        devices: vec![ProtectedDevice {
            role: Role::SystemDisk,
            identity: DeviceIdentity {
                path: "/dev/sda".into(),
                kernel_name: "sda".into(),
                serial: Some("SYS1".into()),
                ..Default::default()
            },
            reasons: vec!["/dev/sda1 mounted at /".into()],
        }],
    }
}

fn input(f: &FakeSysfs) -> ScanInput {
    ScanInput {
        lsblk_json: LSBLK.into(),
        sys: f.root(),
        mountinfo: Ok(MOUNTINFO.into()),
        swaps: Ok(vec![SwapEntry {
            path: "/mnt/ev/swapfile".into(),
            kind: "file".into(),
            dev: Some((8, 17)),
        }]),
        registry: Ok(Some(registry())),
        dev_dir: f.path().join("no-dev"),
    }
}

fn source<'a>(sources: &'a [BlockDevice], path: &str) -> &'a BlockDevice {
    sources
        .iter()
        .find(|d| d.path == path)
        .unwrap_or_else(|| panic!("{path} not among the sources"))
}

#[test]
fn disks_carry_attachment_facts_and_safety() {
    let f = host();
    let scan = scan(&input(&f)).unwrap();
    let devices = scan.devices();
    let names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
    // Optical drives are not listed; loop devices are
    assert_eq!(names, ["sda", "sdb", "sdc", "loop0"]);

    let sda = &devices[0];
    assert!(sda.safety.is_system());
    assert!(
        sda.protected
            .as_deref()
            .unwrap()
            .contains("system disk SYS1"),
        "{:?}",
        sda.protected
    );

    let sdb = &devices[1];
    assert_eq!(sdb.maj_min.as_deref(), Some("8:16"));
    assert_eq!(sdb.diskseq, Some(7));
    assert!(sdb.hotplug);
    assert!(!sdb.is_removable, "hot-pluggable is not removable media");
    assert_eq!(sdb.transport.as_deref(), Some("usb"));
    assert_eq!(sdb.media_type_str(), "Rotational HDD");
    assert_eq!(sdb.physical_sector_size, 4096);
    // The drive's own serial wins over the bridge's (lsblk) serial
    assert_eq!(sdb.serial.as_deref(), Some("DRIVE123"));
    assert!(sdb
        .serial_candidates
        .iter()
        .any(|c| c.value == "BRIDGE9" && c.source == SerialSource::Lsblk));
    assert_eq!(sdb.model.as_deref(), Some("Ext HDD"));
    assert_eq!(sdb.holders, ["dm-0"]);
    assert_eq!(sdb.mountpoints, ["/mnt/ev"]);
    assert!(sdb.protected.is_none());
    // R8: an active swap file on sdb1 makes the disk a refusal
    let DeviceSafety::SystemDisk(reasons) = &sdb.safety else {
        panic!("{:?}", sdb.safety)
    };
    assert!(reasons
        .iter()
        .any(|r| r == "active swap on this device: /mnt/ev/swapfile (file)"));
    let parts: Vec<(&str, Option<&str>, Option<u64>)> = sdb
        .partitions
        .iter()
        .map(|p| (p.name.as_str(), p.kind.as_deref(), p.start_sector))
        .collect();
    assert_eq!(
        parts,
        [
            ("sdb1", Some("part"), Some(2048)),
            ("sdb2", Some("part"), Some(6048)),
            ("cryptdata", Some("crypt"), None)
        ]
    );
    assert_eq!(sdb.partitions[0].mountpoint.as_deref(), Some("/mnt/ev"));
    assert_eq!(sdb.partitions[0].label.as_deref(), Some("EVIDENCE"));

    let sdc = &devices[2];
    assert!(sdc.is_read_only);
    assert_eq!(sdc.safety, DeviceSafety::Safe);
    assert_eq!(badges(sdc, None), ["RO"]);

    let lp = &devices[3];
    assert_eq!(
        lp.kind,
        SourceKind::Loop {
            backing_file: Some("/srv/images/a.img".into())
        }
    );
    // Never SMART in a scan
    assert!(devices.iter().all(|d| d.smart.is_none()));
}

#[test]
fn partitions_and_mappings_are_sources_with_their_own_tree() {
    let f = host();
    let scan = scan(&input(&f)).unwrap();
    let sources = scan.sources();
    let sdb1 = source(&sources, "/dev/sdb1");
    assert_eq!(sdb1.kind, SourceKind::Partition);
    assert_eq!(sdb1.parent.as_deref(), Some("/dev/sdb"));
    assert_eq!(sdb1.start_sector, Some(2048));
    assert_eq!(sdb1.mountpoints, ["/mnt/ev"]);
    assert!(sdb1.safety.is_system(), "swap file on it");
    // Hardware identity of a partition is its disk's
    assert_eq!(sdb1.serial.as_deref(), Some("DRIVE123"));

    let sdb2 = source(&sources, "/dev/sdb2");
    assert_eq!(sdb2.safety, DeviceSafety::Safe);
    assert_eq!(sdb2.holders, ["dm-0"]);
    assert_eq!(badges(sdb2, None), ["IN-USE"]);

    let dm = source(&sources, "/dev/mapper/cryptdata");
    assert_eq!(
        dm.kind,
        SourceKind::DeviceMapper {
            crypt_plaintext: true
        }
    );
    assert_eq!(
        dm.dm_uuid.as_deref(),
        Some("CRYPT-LUKS2-0123abcd-cryptdata")
    );
    assert_eq!(dm.parent.as_deref(), Some("/dev/sdb"));
    assert!(dm.holders.is_empty());

    // A system disk's partitions are system too, and protected
    let sda1 = source(&sources, "/dev/sda1");
    assert!(sda1.safety.is_system());
    assert!(sda1.protected.is_some());
    assert_eq!(sources.len(), 8);
}

#[test]
fn listing_is_a_nested_documented_model() {
    let f = host();
    let scan = scan(&input(&f)).unwrap();
    let list = scan.listing();
    let v = serde_json::to_value(&list).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["registry"]["state"], "present");
    assert_eq!(v["active_swaps"][0]["device"], "8:17");
    let sdb = &v["devices"][1];
    assert_eq!(sdb["path"], "/dev/sdb");
    assert_eq!(sdb["kernel_name"], "sdb");
    assert_eq!(sdb["hotplug"], true);
    assert_eq!(sdb["removable"], false);
    assert_eq!(sdb["system"], true);
    assert_eq!(sdb["kind"]["type"], "disk");
    assert!(sdb["serial_note"].as_str().unwrap().contains("USB bridge"));
    let badges: Vec<&str> = sdb["badges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_str().unwrap())
        .collect();
    assert_eq!(badges, ["SYSTEM", "MOUNTED", "IN-USE"]);
    assert!(sdb.get("smart").is_none(), "SMART only with --smart");
    let sdb2 = &sdb["children"][1];
    assert_eq!(sdb2["partition_number"], 2);
    assert_eq!(sdb2["start_sector"], 6048);
    let crypt = &sdb2["children"][0];
    assert_eq!(crypt["kernel_name"], "dm-0");
    assert_eq!(crypt["name"], "cryptdata");
    assert_eq!(crypt["lsblk_type"], "crypt");
    assert_eq!(crypt["kind"]["type"], "device_mapper");
    assert_eq!(crypt["kind"]["crypt_plaintext"], true);
    assert_eq!(crypt["dm_name"], "cryptdata");
    assert_eq!(crypt["parent_disks"][0], "/dev/sdb");
    assert!(v["devices"][0]["protected"].as_str().is_some());
}

#[test]
fn unreadable_inputs_fail_closed() {
    let f = host();
    let mut inp = input(&f);
    inp.registry = Err("Corrupt protected-device registry".into());
    inp.swaps = Err("permission denied".into());
    inp.mountinfo = Err("gone".into());
    inp.lsblk_json = LSBLK.replace(
        r#""type":"part", "fstype":"crypto_LUKS""#,
        r#""type":"part", "fstype":"swap""#,
    );
    let scan = scan(&inp).unwrap();
    assert_eq!(scan.notes.len(), 3, "{:?}", scan.notes);
    let sources = scan.sources();
    assert!(sources.iter().all(|d| d.protected.is_some()));
    // Swap signature counts as active swap when /proc/swaps is unreadable
    let sdb2 = source(&sources, "/dev/sdb2");
    assert!(sdb2.safety.is_system(), "{:?}", sdb2.safety);
    // Mounts still come from lsblk
    assert_eq!(source(&sources, "/dev/sdb1").mountpoints, ["/mnt/ev"]);
    assert!(scan.registry != RegistryPresence::Absent);
}

#[test]
fn without_sysfs_the_scan_uses_lsblk_alone() {
    let empty = FakeSysfs::new();
    let mut inp = input(&host());
    inp.sys = empty.root();
    inp.registry = Ok(None);
    let scan = scan(&inp).unwrap();
    let sources = scan.sources();
    let sdb = source(&sources, "/dev/sdb");
    assert_eq!(sdb.serial.as_deref(), Some("BRIDGE9"));
    assert!(sdb.hotplug);
    assert_eq!(sdb.diskseq, None);
    assert_eq!(sdb.holders, ["dm-0"]);
    assert_eq!(sdb.size_bytes, 5_120_000);
    let dm = source(&sources, "/dev/mapper/cryptdata");
    assert_eq!(dm.parent.as_deref(), Some("/dev/sdb"));
    assert!(scan.nodes.iter().all(|n| n
        .identity
        .probe_notes
        .iter()
        .any(|p| p.contains("taken from lsblk"))));
}

#[test]
fn device_links_and_lookup() {
    let f = host();
    let dev = f.path().join("dev");
    std::fs::create_dir_all(dev.join("disk/by-id")).unwrap();
    std::fs::create_dir_all(dev.join("mapper")).unwrap();
    std::os::unix::fs::symlink("../../sdb1", dev.join("disk/by-id/usb-Ext_HDD-part1")).unwrap();
    std::os::unix::fs::symlink("../dm-0", dev.join("mapper/cryptdata")).unwrap();
    let mut inp = input(&f);
    inp.dev_dir = dev.clone();
    let scan = scan(&inp).unwrap();
    let link = dev.join("disk/by-id/usb-Ext_HDD-part1");
    let link = link.to_string_lossy();
    let node = scan.find(&link).unwrap();
    assert_eq!(node.device.path, "/dev/sdb1");
    let sources = scan.sources();
    assert_eq!(find_source(&sources, &link).unwrap().path, "/dev/sdb1");
    assert!(find_source(&sources, "/dev/nonexistent").is_none());
    // Links are found by the kernel name they point to (dm-0)
    assert_eq!(
        source(&sources, "/dev/mapper/cryptdata").devlinks,
        [dev.join("mapper/cryptdata").to_string_lossy().into_owned()]
    );
}

#[test]
fn bad_lsblk_output_is_an_error() {
    let f = host();
    let mut inp = input(&f);
    inp.lsblk_json = "lsblk: unknown column".into();
    assert!(scan(&inp).is_err());
    inp.lsblk_json = "{}".into();
    assert!(scan(&inp).unwrap_err().contains("No blockdevices"));
}
