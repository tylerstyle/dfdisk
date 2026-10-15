//! Probe the identity of an acquisition source (§5, R3) from sysfs and udev,
//! right before an acquisition and again at its end. Read-only: nothing is
//! sent to the device (no SMART, no ioctl); udev is asked about its database.
//!
//! [`Prober`] takes the sysfs root and the udev query as parameters so tests
//! run against fake trees; [`probe`] uses the host's.

use crate::discovery::sysfs::{read_attr, SysRoot};
use crate::engines::process::{run_blocking, ProcessSpec};
use crate::models::identity::{SerialSource, SourceIdentity, SourceKind};
use crate::models::text::sanitize_opt;
use dfcore::lsblk::DeviceIdentity;
use dfcore::sysfs::{parse_dev_num, DevNum};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `udevadm info -q property` as key/value pairs.
pub type UdevProperties = BTreeMap<String, String>;

/// Asks udev for the properties of a device node path.
pub type UdevQuery<'a> = dyn Fn(&str) -> Result<UdevProperties, String> + Send + Sync + 'a;

/// Directory of the `by-diskseq` links udev creates.
pub const BY_DISKSEQ_DIR: &str = "/dev/disk/by-diskseq";

/// Parse `KEY=value` lines.
pub fn parse_udev_properties(text: &str) -> UdevProperties {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// `udevadm info -q property --name <path>` with a 5 s timeout.
pub fn host_udev_query(path: &str) -> Result<UdevProperties, String> {
    let spec = ProcessSpec::new("udevadm")
        .args(["info", "-q", "property", "--name"])
        .arg(path)
        .timeout(Duration::from_secs(5));
    let out = run_blocking(&spec, None).map_err(|e| e.to_string())?;
    if !out.outcome.success() {
        return Err(format!(
            "udevadm info {} failed ({})",
            path,
            out.outcome.record.status_text()
        ));
    }
    Ok(parse_udev_properties(&out.stdout.join("\n")))
}

/// Serial number from a binary SCSI VPD page 0x80 (4-byte header, then the
/// serial, padded with spaces or NULs).
pub fn parse_vpd_pg80(bytes: &[u8]) -> Option<String> {
    let payload = if bytes.len() >= 4 && bytes[1] == 0x80 {
        let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        &bytes[4..bytes.len().min(4 + len)]
    } else {
        bytes
    };
    sanitize_opt(&String::from_utf8_lossy(payload))
}

/// Transport from the hardware path in sysfs, as lsblk TRAN would say it.
pub fn transport_from_devpath(devpath: &str, kname: &str) -> Option<&'static str> {
    let parts: Vec<&str> = devpath.split('/').collect();
    if parts.iter().any(|p| p.starts_with("usb")) {
        Some("usb")
    } else if kname.starts_with("nvme") || parts.contains(&"nvme") {
        Some("nvme")
    } else if parts.iter().any(|p| p.starts_with("ata")) {
        Some("sata")
    } else if kname.starts_with("mmcblk") || parts.iter().any(|p| p.starts_with("mmc")) {
        Some("mmc")
    } else if parts.iter().any(|p| p.starts_with("virtio")) {
        Some("virtio")
    } else if parts.iter().any(|p| p.starts_with("host")) {
        Some("scsi")
    } else {
        None
    }
}

/// Probes block devices in a sysfs tree, asking `udev` for its database.
pub struct Prober<'a> {
    pub sys: SysRoot,
    pub udev: &'a UdevQuery<'a>,
}

fn none_udev(_: &str) -> Result<UdevProperties, String> {
    Err("udev not queried".into())
}

impl Prober<'static> {
    /// The host's /sys and udevadm.
    pub fn host() -> Self {
        Prober {
            sys: SysRoot::host(),
            udev: &host_udev_query,
        }
    }

    /// A sysfs tree without udev (tests, or when udev must not be asked).
    pub fn sysfs_only(sys: SysRoot) -> Self {
        Prober {
            sys,
            udev: &none_udev,
        }
    }
}

impl<'a> Prober<'a> {
    pub fn new(sys: SysRoot, udev: &'a UdevQuery<'a>) -> Self {
        Self { sys, udev }
    }

    /// Identity of the block device or regular file at `path`. Fails (and an
    /// acquisition must then be refused) when it cannot be identified.
    pub fn probe(&self, path: &str) -> Result<SourceIdentity, String> {
        let meta = std::fs::metadata(path).map_err(|e| format!("cannot inspect {path}: {e}"))?;
        if meta.is_file() {
            return probe_file(path);
        }
        let dev = dfcore::sysfs::dev_num_of_path(Path::new(path))
            .ok_or_else(|| format!("{path} is neither a block device nor a regular file"))?;
        self.probe_block(path, dev)
    }

    /// Identity of the block device `dev` reached through `path`.
    pub fn probe_block(&self, path: &str, dev: DevNum) -> Result<SourceIdentity, String> {
        let sys = &self.sys;
        let kname = sys.kname_of(dev).ok_or_else(|| {
            format!(
                "{path} (block device {}:{}) has no entry in sysfs",
                dev.0, dev.1
            )
        })?;
        let node = sys
            .canonical_node(&kname)
            .ok_or_else(|| format!("cannot resolve sysfs entry of {kname}"))?;
        let sectors: u64 = sys
            .attr(&kname, "size")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("cannot read the size of {kname} from sysfs"))?;

        let mut id = SourceIdentity {
            path: path.to_string(),
            canonical_path: std::fs::canonicalize(path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| path.to_string()),
            kernel_name: kname.clone(),
            maj_min: Some(format!("{}:{}", dev.0, dev.1)),
            diskseq: sys.diskseq(&kname),
            size_bytes: sectors.saturating_mul(512),
            read_only: sys.read_only(&kname),
            ..Default::default()
        };

        let is_partition = sys.is_partition(&kname);
        let disk = if is_partition {
            sys.parent_disk(&kname)
                .ok_or_else(|| format!("cannot find the disk of partition {kname}"))?
        } else {
            kname.clone()
        };

        // Kind and the disks the source is stored on
        id.kind = if is_partition {
            id.partition_number = sys.attr(&kname, "partition").and_then(|v| v.parse().ok());
            id.partition_start_sector = sys.attr(&kname, "start").and_then(|v| v.parse().ok());
            SourceKind::Partition
        } else if node.join("dm").is_dir() {
            id.dm_uuid = sys.attr(&kname, "dm/uuid").and_then(|v| sanitize_opt(&v));
            id.dm_name = sys.attr(&kname, "dm/name").and_then(|v| sanitize_opt(&v));
            SourceKind::DeviceMapper {
                crypt_plaintext: id
                    .dm_uuid
                    .as_deref()
                    .is_some_and(|u| u.starts_with("CRYPT-")),
            }
        } else if node.join("md").is_dir() {
            SourceKind::Md
        } else if node.join("loop").is_dir() {
            SourceKind::Loop {
                backing_file: sys
                    .attr(&kname, "loop/backing_file")
                    .and_then(|v| sanitize_opt(&v)),
            }
        } else if node.join("device").exists() {
            SourceKind::Disk
        } else {
            SourceKind::Other
        };
        // S-N1: down to a loop device, never to the disk that holds its
        // backing file (that disk is the host's, not the evidence)
        id.parent_disks = match &id.kind {
            SourceKind::Disk | SourceKind::Other => Vec::new(),
            SourceKind::Partition => vec![format!("/dev/{disk}")],
            _ => sys
                .storage_disks(&kname)
                .into_iter()
                .filter(|d| d != &kname)
                .map(|d| format!("/dev/{d}"))
                .collect(),
        };

        // Sector sizes: partitions have no queue/ of their own
        let queue_of = if is_partition {
            disk.as_str()
        } else {
            kname.as_str()
        };
        let block_size = |attr: &str| {
            sys.attr(queue_of, attr)
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|&v| v > 0)
        };
        id.logical_sector_size = block_size("queue/logical_block_size").unwrap_or_else(|| {
            id.probe_notes
                .push("logical sector size not readable; 512 assumed".into());
            512
        });
        id.physical_sector_size =
            block_size("queue/physical_block_size").unwrap_or(id.logical_sector_size);

        // Hardware identity: the disk itself, or the one disk under a
        // partition or dm/md target. A loop device has none, also under a
        // partition or dm/md target: the disk that holds its backing file is
        // not the evidence
        let single_loop = match id.parent_disks.as_slice() {
            [one] => Some(one.trim_start_matches("/dev/").to_string()).filter(|d| sys.is_loop(d)),
            _ => None,
        };
        let hw = match &id.kind {
            SourceKind::Disk => Some(kname.clone()),
            SourceKind::Other | SourceKind::Loop { .. } => None,
            _ if id.parent_disks.len() == 1 && single_loop.is_none() => {
                Some(id.parent_disks[0].trim_start_matches("/dev/").to_string())
            }
            _ => None,
        };
        if let Some(hw) = &hw {
            if hw != &kname {
                id.hardware_of = Some(hw.clone());
            }
            self.read_hardware(&mut id, hw);
        } else if let SourceKind::Loop { backing_file } = &id.kind {
            id.probe_notes.push(format!(
                "loop device over {}: no hardware model or serial number applies",
                backing_file.as_deref().unwrap_or("an unknown backing file")
            ));
        } else if let Some(lo) = &single_loop {
            id.probe_notes.push(format!(
                "stored on the loop device /dev/{lo} over {}: no hardware model or serial number applies",
                sys.attr(lo, "loop/backing_file")
                    .and_then(|v| sanitize_opt(&v))
                    .as_deref()
                    .unwrap_or("an unknown backing file")
            ));
        } else if !matches!(id.kind, SourceKind::Other) {
            id.probe_notes.push(format!(
                "stored on {} disks; no single model or serial number applies",
                id.parent_disks.len()
            ));
        }

        // udev: the source node (dm names), then the hardware disk if different
        match (self.udev)(path) {
            Ok(props) => {
                if id.dm_uuid.is_none() {
                    id.dm_uuid = props.get("DM_UUID").and_then(|v| sanitize_opt(v));
                }
                if id.dm_name.is_none() {
                    id.dm_name = props.get("DM_NAME").and_then(|v| sanitize_opt(v));
                }
                if hw.as_deref() == Some(kname.as_str()) || (is_partition && hw.is_some()) {
                    apply_hw_udev(&mut id, &props);
                }
            }
            Err(e) => id
                .probe_notes
                .push(format!("udev properties unavailable: {e}")),
        }
        if let Some(hw) = &hw {
            if hw != &kname && !is_partition {
                match (self.udev)(&format!("/dev/{hw}")) {
                    Ok(props) => apply_hw_udev(&mut id, &props),
                    Err(e) => id
                        .probe_notes
                        .push(format!("udev properties of /dev/{hw} unavailable: {e}")),
                }
            }
        }
        id.choose_serial();
        Ok(id)
    }

    /// Model, vendor, firmware, serial candidates, WWN, transport, removable,
    /// hot-plug and rotation of the disk `hw` (sanitised; empty values dropped).
    fn read_hardware(&self, id: &mut SourceIdentity, hw: &str) {
        let sys = &self.sys;
        let Some(hw_node) = sys.canonical_node(hw) else {
            id.probe_notes
                .push(format!("hardware of {hw} not found in sysfs"));
            return;
        };
        let device = std::fs::canonicalize(hw_node.join("device")).ok();
        let dev_attr = |name: &str| -> Option<String> {
            device
                .as_ref()
                .and_then(|d| read_attr(&d.join(name)))
                .and_then(|v| sanitize_opt(&v))
        };
        let is_nvme = hw.starts_with("nvme");

        id.model = dev_attr("model").or_else(|| dev_attr("name"));
        id.vendor = dev_attr("vendor");
        id.firmware_rev = dev_attr("rev")
            .or_else(|| dev_attr("firmware_rev"))
            .or_else(|| dev_attr("fwrev"));

        if let Some(serial) = sys
            .node(hw)
            .and_then(|n| std::fs::read(n.join("device/vpd_pg80")).ok())
            .and_then(|b| parse_vpd_pg80(&b))
        {
            id.add_serial_candidate(&serial, SerialSource::VpdPage80);
        }
        if let Some(serial) = dev_attr("serial") {
            let source = if is_nvme {
                SerialSource::NvmeController
            } else {
                SerialSource::SysfsDeviceSerial
            };
            id.add_serial_candidate(&serial, source);
        }
        // virtio-blk reports the serial of the virtual disk on the disk node
        // itself (/sys/block/vda/serial); lsblk shows it, so the probe must
        // know it too or a selected virtio disk would look swapped
        if let Some(serial) = sys.attr(hw, "serial").and_then(|v| sanitize_opt(&v)) {
            id.add_serial_candidate(&serial, SerialSource::SysfsDeviceSerial);
        }

        // NVMe namespaces carry their own wwid; SCSI/ATA devices have it on the device
        id.wwn = sys
            .attr(hw, "wwid")
            .or_else(|| dev_attr("wwid"))
            .and_then(|w| sanitize_opt(&w))
            .filter(|w| !w.starts_with("t10."));

        let devpath = hw_node.to_string_lossy().into_owned();
        id.transport = transport_from_devpath(&devpath, hw).map(str::to_string);
        id.removable = sys.attr(hw, "removable").as_deref() == Some("1");
        id.hotplug = self.is_hotpluggable(&hw_node);
        id.rotational = match sys.attr(hw, "queue/rotational").as_deref() {
            Some("1") => Some(true),
            Some("0") => Some(false),
            _ => None,
        };
    }

    /// lsblk's HOTPLUG rule: some device above the disk says `removable`
    /// ("removable", not "fixed") in its `removable` attribute.
    fn is_hotpluggable(&self, hw_node: &Path) -> bool {
        let devices = std::fs::canonicalize(self.sys.root().join("devices"))
            .unwrap_or_else(|_| self.sys.root().join("devices"));
        let mut dir: Option<&Path> = hw_node.parent();
        while let Some(d) = dir {
            if !d.starts_with(&devices) || d == devices {
                break;
            }
            if read_attr(&d.join("removable")).as_deref() == Some("removable") {
                return true;
            }
            dir = d.parent();
        }
        false
    }
}

fn apply_hw_udev(id: &mut SourceIdentity, props: &UdevProperties) {
    if let Some(s) = props.get("ID_SERIAL_SHORT") {
        id.add_serial_candidate(s, SerialSource::UdevIdSerialShort);
    }
    if id.wwn.is_none() {
        id.wwn = props
            .get("ID_WWN_WITH_EXTENSION")
            .or_else(|| props.get("ID_WWN"))
            .and_then(|v| sanitize_opt(v));
    }
    if id.transport.is_none() {
        id.transport = props.get("ID_BUS").and_then(|v| sanitize_opt(v)).map(|b| {
            if b == "ata" {
                "sata".into()
            } else {
                b
            }
        });
    }
    if id.model.is_none() {
        id.model = props
            .get("ID_MODEL")
            .and_then(|v| sanitize_opt(&v.replace('_', " ")));
    }
    if id.vendor.is_none() {
        id.vendor = props
            .get("ID_VENDOR")
            .and_then(|v| sanitize_opt(&v.replace('_', " ")));
    }
}

/// Identity of a regular file used as a source (image files, tests).
pub fn probe_file(path: &str) -> Result<SourceIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot inspect {path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} is not a regular file"));
    }
    let canonical = std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());
    Ok(SourceIdentity {
        path: path.to_string(),
        kernel_name: Path::new(&canonical)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default(),
        canonical_path: canonical,
        kind: SourceKind::RegularFile,
        size_bytes: meta.len(),
        logical_sector_size: 512,
        physical_sector_size: 512,
        file_id: Some(format!("{}:{}", meta.dev(), meta.ino())),
        ..Default::default()
    })
}

/// Identity of `path` on this host (sysfs + udevadm).
pub fn probe(path: &str) -> Result<SourceIdentity, String> {
    Prober::host().probe(path)
}

/// `current` is still the device `snapshot` described (see
/// [`SourceIdentity::same_attachment`]).
pub fn same_attachment(current: &SourceIdentity, snapshot: &DeviceIdentity) -> Result<(), String> {
    current.same_attachment(snapshot)
}

/// Name of the source's link in /dev/disk/by-diskseq (R3): `<N>` for a whole
/// device, `<N>-part<P>` for a partition (diskseq is the disk's).
pub fn by_diskseq_name(id: &SourceIdentity) -> Option<String> {
    let seq = id.diskseq?;
    match id.kind {
        SourceKind::RegularFile => None,
        SourceKind::Partition => Some(format!("{seq}-part{}", id.partition_number?)),
        _ => Some(seq.to_string()),
    }
}

/// Path external tools read the source through (R3): the by-diskseq link
/// when it resolves to the pinned major:minor, which a re-attached device
/// under the same name would not; otherwise the device path. `rdev_of`
/// gives the device number of a node (stat), injectable for tests.
pub fn tool_source_path_in(
    id: &SourceIdentity,
    by_diskseq_dir: &Path,
    rdev_of: &dyn Fn(&Path) -> Option<DevNum>,
) -> String {
    let fallback = id.path.clone();
    let (Some(name), Some(pinned)) = (
        by_diskseq_name(id),
        id.maj_min.as_deref().and_then(parse_dev_num),
    ) else {
        return fallback;
    };
    let link: PathBuf = by_diskseq_dir.join(name);
    if rdev_of(&link) == Some(pinned) {
        link.to_string_lossy().into_owned()
    } else {
        fallback
    }
}

/// [`tool_source_path_in`] on this host.
pub fn tool_source_path(id: &SourceIdentity) -> String {
    tool_source_path_in(id, Path::new(BY_DISKSEQ_DIR), &|p| {
        dfcore::sysfs::dev_num_of_path(p)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::sysfs::fake::FakeSysfs;

    const SATA: &str = "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0";
    const USB: &str = "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0";
    const NVME: &str = "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0";

    fn vpd(serial: &str) -> Vec<u8> {
        let mut b = vec![0u8, 0x80, 0, serial.len() as u8 + 4];
        b.extend_from_slice(serial.as_bytes());
        b.extend_from_slice(b"    ");
        b
    }

    fn udev_with(
        props: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Result<UdevProperties, String> {
        move |_| {
            Ok(props
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect())
        }
    }

    fn sata_disk(f: &FakeSysfs) {
        f.add_disk(SATA, "sdb", (8, 16), 1_953_525_168);
        f.set("sdb", "diskseq", "17");
        f.set("sdb", "queue/physical_block_size", "4096");
        f.set("sdb", "queue/rotational", "1");
        f.set_hw(SATA, "model", "WDC WD10EZEX-08W");
        f.set_hw(SATA, "vendor", "ATA     ");
        f.set_hw(SATA, "rev", "1A01");
        f.set_hw(SATA, "wwid", "naa.50014ee2b5a1c3d4");
        f.set_bytes("sdb", "device/vpd_pg80", &vpd("WD-WCC6Y0000001"));
    }

    #[test]
    fn sata_disk_identity_from_sysfs_and_udev() {
        let f = FakeSysfs::new();
        sata_disk(&f);
        let udev = udev_with(&[
            ("ID_SERIAL_SHORT", "WD-WCC6Y0000001"),
            ("ID_BUS", "ata"),
            ("ID_WWN", "0x50014ee2b5a1c3d4"),
        ]);
        let id = Prober::new(f.root(), &udev)
            .probe_block("/dev/sdb", (8, 16))
            .unwrap();
        assert_eq!(id.kernel_name, "sdb");
        assert_eq!(id.maj_min.as_deref(), Some("8:16"));
        assert_eq!(id.diskseq, Some(17));
        assert_eq!(id.kind, SourceKind::Disk);
        assert_eq!(id.size_bytes, 1_953_525_168 * 512);
        assert_eq!(id.logical_sector_size, 512);
        assert_eq!(id.physical_sector_size, 4096);
        assert_eq!(id.model.as_deref(), Some("WDC WD10EZEX-08W"));
        assert_eq!(id.vendor.as_deref(), Some("ATA"));
        assert_eq!(id.firmware_rev.as_deref(), Some("1A01"));
        assert_eq!(id.serial.as_deref(), Some("WD-WCC6Y0000001"));
        assert_eq!(id.serial_source(), Some(SerialSource::VpdPage80));
        assert_eq!(id.serial_candidates.len(), 2);
        assert_eq!(id.wwn.as_deref(), Some("naa.50014ee2b5a1c3d4"));
        assert_eq!(id.transport.as_deref(), Some("sata"));
        assert_eq!(id.rotational, Some(true));
        assert!(!id.removable && !id.hotplug);
        assert_eq!(id.read_only, Some(false));
        assert!(id.parent_disks.is_empty());
        assert_eq!(id.hardware_of, None);
        assert_eq!(id.serial_note(), None);
        assert!(id.probe_notes.is_empty(), "{:?}", id.probe_notes);

        // The probe and an lsblk snapshot of the same disk are the same attachment
        let snapshot = DeviceIdentity {
            path: "/dev/sdb".into(),
            kernel_name: "sdb".into(),
            maj_min: Some("8:16".into()),
            serial: Some("WD-WCC6Y0000001".into()),
            wwn: Some("0x50014ee2b5a1c3d4".into()),
            model: None,
            size: Some((1_953_525_168u64 * 512).to_string()),
            diskseq: Some(17),
        };
        assert_eq!(same_attachment(&id, &snapshot), Ok(()));
    }

    #[test]
    fn partition_reports_its_disk_and_start() {
        let f = FakeSysfs::new();
        sata_disk(&f);
        f.add_partition("sdb", "sdb2", (8, 18), 2, 1_050_624, 1000);
        let id = Prober::sysfs_only(f.root())
            .probe_block("/dev/sdb2", (8, 18))
            .unwrap();
        assert_eq!(id.kind, SourceKind::Partition);
        assert_eq!(id.parent_disks, ["/dev/sdb"]);
        assert_eq!(id.partition_number, Some(2));
        assert_eq!(id.partition_start_sector, Some(1_050_624));
        assert_eq!(id.diskseq, Some(17));
        assert_eq!(id.size_bytes, 512_000);
        assert_eq!(id.physical_sector_size, 4096);
        assert_eq!(id.hardware_of.as_deref(), Some("sdb"));
        assert_eq!(id.serial.as_deref(), Some("WD-WCC6Y0000001"));
        assert!(id.probe_notes.iter().any(|n| n.contains("udev")));
        assert_eq!(by_diskseq_name(&id).as_deref(), Some("17-part2"));
    }

    #[test]
    fn luks_plaintext_on_one_disk_and_lvm_over_two() {
        let f = FakeSysfs::new();
        sata_disk(&f);
        f.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 5000);
        f.add_virtual("dm-0", (254, 0), 4000);
        f.set("dm-0", "dm/uuid", "CRYPT-LUKS2-0123456789abcdef-cryptdata");
        f.set("dm-0", "dm/name", "cryptdata");
        f.stack("dm-0", "sdb1");
        let id = Prober::sysfs_only(f.root())
            .probe_block("/dev/dm-0", (254, 0))
            .unwrap();
        assert_eq!(
            id.kind,
            SourceKind::DeviceMapper {
                crypt_plaintext: true
            }
        );
        assert!(id.kind.label().contains("DECRYPTED"));
        assert_eq!(id.dm_name.as_deref(), Some("cryptdata"));
        assert_eq!(id.parent_disks, ["/dev/sdb"]);
        assert_eq!(id.hardware_of.as_deref(), Some("sdb"));
        assert_eq!(id.serial.as_deref(), Some("WD-WCC6Y0000001"));
        assert_eq!(by_diskseq_name(&id), None); // dm-0 has no diskseq here

        let other = "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0";
        f.add_disk(other, "sdc", (8, 32), 8000);
        f.add_virtual("dm-1", (254, 1), 9000);
        f.set("dm-1", "dm/uuid", "LVM-abcdef");
        f.stack("dm-1", "sdb");
        f.stack("dm-1", "sdc");
        let lvm = Prober::sysfs_only(f.root())
            .probe_block("/dev/dm-1", (254, 1))
            .unwrap();
        assert_eq!(
            lvm.kind,
            SourceKind::DeviceMapper {
                crypt_plaintext: false
            }
        );
        assert_eq!(lvm.parent_disks, ["/dev/sdb", "/dev/sdc"]);
        assert_eq!(lvm.serial, None);
        assert_eq!(lvm.model, None);
        assert!(lvm.probe_notes.iter().any(|n| n.contains("2 disks")));
    }

    #[test]
    fn virtio_disk_serial_and_dm_linear_over_it() {
        const VIRTIO: &str = "pci0000:00/0000:00:05.0/virtio2";
        let f = FakeSysfs::new();
        f.add_disk(VIRTIO, "vdb", (252, 16), 131_072);
        f.set("vdb", "serial", "CFTT-DISK-1");
        f.set("vdb", "diskseq", "4");
        let id = Prober::sysfs_only(f.root())
            .probe_block("/dev/vdb", (252, 16))
            .unwrap();
        assert_eq!(id.kind, SourceKind::Disk);
        assert_eq!(id.transport.as_deref(), Some("virtio"));
        assert_eq!(id.serial.as_deref(), Some("CFTT-DISK-1"));
        assert_eq!(id.serial_source(), Some(SerialSource::SysfsDeviceSerial));

        // dm-linear over the whole disk: the disk's hardware identity
        f.add_virtual("dm-2", (254, 2), 131_072);
        f.set("dm-2", "dm/name", "lin");
        f.set("dm-2", "diskseq", "11");
        f.stack("dm-2", "vdb");
        let dm = Prober::sysfs_only(f.root())
            .probe_block("/dev/mapper/lin", (254, 2))
            .unwrap();
        assert_eq!(
            dm.kind,
            SourceKind::DeviceMapper {
                crypt_plaintext: false
            }
        );
        assert_eq!(dm.parent_disks, ["/dev/vdb"]);
        assert_eq!(dm.hardware_of.as_deref(), Some("vdb"));
        assert_eq!(dm.serial.as_deref(), Some("CFTT-DISK-1"));
        assert_eq!(dm.diskseq, Some(11), "a dm device has its own diskseq");
        assert_eq!(by_diskseq_name(&dm).as_deref(), Some("11"));
    }

    #[test]
    fn loop_devices_have_no_hardware_identity() {
        let f = FakeSysfs::new();
        f.add_virtual("loop0", (7, 0), 2048);
        f.set("loop0", "loop/backing_file", "/images/suspect.img");
        f.set("loop0", "diskseq", "9");
        let id = Prober::sysfs_only(f.root())
            .probe_block("/dev/loop0", (7, 0))
            .unwrap();
        assert_eq!(
            id.kind,
            SourceKind::Loop {
                backing_file: Some("/images/suspect.img".into())
            }
        );
        assert_eq!(id.model, None);
        assert_eq!(id.serial, None);
        assert_eq!(id.hardware_of, None);
        assert!(id.parent_disks.is_empty());
        assert!(id
            .probe_notes
            .iter()
            .any(|n| n.contains("/images/suspect.img")));
        assert_eq!(by_diskseq_name(&id).as_deref(), Some("9"));
    }

    /// A file whose `st_dev` is a real block device number (major != 0):
    /// dfcore resolves a loop device backed by it to that device. A file in
    /// the temporary directory, else this crate's manifest; `None` when both
    /// live on a filesystem with an anonymous device (tmpfs, btrfs).
    fn file_on_a_block_device(tmp: &Path) -> Option<(PathBuf, DevNum)> {
        use std::os::unix::fs::MetadataExt;
        let image = tmp.join("evidence.dd");
        std::fs::write(&image, b"an image file on the host's disk").unwrap();
        [
            image,
            PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
        ]
        .into_iter()
        .find_map(|p| {
            let dev = std::fs::metadata(&p).ok()?.dev() as libc::dev_t;
            let dev = (libc::major(dev) as u32, libc::minor(dev) as u32);
            (dev.0 != 0).then_some((p, dev))
        })
    }

    #[test]
    fn a_mapping_over_a_loop_device_never_takes_the_host_disk_identity() {
        // S-N1: an evidence image file on the host's own disk (nvme0n1),
        // opened as loop0, with a LUKS mapping (dm-0), a kpartx partition
        // (dm-1) and a loop partition (loop0p1) over it. None of them may
        // take the host disk's identity, and nothing may be sent to it
        let tmp = tempfile::tempdir().unwrap();
        let (backing, st_dev) = file_on_a_block_device(tmp.path())
            .unwrap_or_else(|| (tmp.path().join("evidence.dd"), (259, 1)));
        // Device numbers of the fake tree, none equal to the file's
        let mut minor = 200u32;
        let mut fresh = |major: u32| loop {
            minor += 1;
            if (major, minor) != st_dev {
                break (major, minor);
            }
        };
        let (host_disk, loop_dev, dm0, dm1, loop_part) = (
            fresh(st_dev.0),
            fresh(7),
            fresh(254),
            fresh(254),
            fresh(259),
        );
        let f = FakeSysfs::new();
        f.add_disk(NVME, "nvme0n1", host_disk, 1_000_000);
        f.set_hw(NVME, "serial", "HOST-SYSTEM-SSD");
        f.set_hw(NVME, "model", "Host NVMe");
        f.set("nvme0n1", "wwid", "eui.00000000000000aa");
        f.add_partition("nvme0n1", "nvme0n1p1", st_dev, 1, 2048, 900_000);
        f.add_loop("loop0", loop_dev, 4096, &backing.to_string_lossy());
        f.add_partition("loop0", "loop0p1", loop_part, 1, 2048, 1024);
        f.add_virtual("dm-0", dm0, 2000);
        f.set("dm-0", "dm/uuid", "CRYPT-LUKS2-abc-evidence");
        f.stack("dm-0", "loop0");
        f.add_virtual("dm-1", dm1, 1024);
        f.set("dm-1", "dm/name", "loop0p2");
        f.stack("dm-1", "loop0");
        let sys = f.root();
        if file_on_a_block_device(tmp.path()).is_some() {
            // dfcore follows the loop device to the host disk (the
            // destination check needs that); the identity must not
            assert_eq!(
                sys.topology()
                    .backing_disks("dm-0")
                    .into_iter()
                    .collect::<Vec<_>>(),
                ["nvme0n1"]
            );
        }
        assert_eq!(
            sys.storage_disks("dm-0").into_iter().collect::<Vec<_>>(),
            ["loop0"]
        );

        let runner = crate::discovery::runner::ScriptedRunner::new();
        let node_dev = |_: &Path| Some(host_disk);
        let env = crate::discovery::runner::ProbeEnv {
            sys: f.root(),
            dev_dir: PathBuf::from("/nonexistent-dev"),
            node_dev: &node_dev,
            runner: &runner,
        };
        for (path, kname, dev) in [
            ("/dev/dm-0", "dm-0", dm0),
            ("/dev/mapper/loop0p2", "dm-1", dm1),
            ("/dev/loop0p1", "loop0p1", loop_part),
        ] {
            let id = Prober::sysfs_only(f.root()).probe_block(path, dev).unwrap();
            assert_eq!(id.kernel_name, kname);
            assert_eq!(id.parent_disks, ["/dev/loop0"], "{kname}");
            assert_eq!(id.hardware_of, None, "{kname}");
            assert_eq!(id.serial, None, "{kname}");
            assert!(id.serial_candidates.is_empty(), "{kname}");
            assert_eq!(id.model, None, "{kname}");
            assert_eq!(id.wwn, None, "{kname}");
            if kname != "loop0p1" {
                assert!(
                    id.probe_notes
                        .iter()
                        .any(|n| n.starts_with("stored on the loop device /dev/loop0 over ")),
                    "{kname}: {:?}",
                    id.probe_notes
                );
            }
            // No physical disk: capacity and SMART probes send nothing
            let err = crate::discovery::runner::physical_disk(&env, &id).unwrap_err();
            assert!(err.contains("loop device /dev/loop0"), "{kname}: {err}");
            // Write protection: the loop node (the "disk") and the source,
            // never the host disk or its partitions
            let mi = format!(
                "22 1 {}:{} / / rw - ext4 /dev/nvme0n1p1 rw\n",
                st_dev.0, st_dev.1
            );
            let inputs = crate::discovery::writeprotect::decision_inputs(&sys, &id, &mi);
            assert_eq!(
                inputs
                    .disks
                    .iter()
                    .map(|d| d.node.as_str())
                    .collect::<Vec<_>>(),
                ["loop0"],
                "{kname}"
            );
            let decision = crate::discovery::writeprotect::decide(
                crate::models::config::WriteProtectPolicy::Auto,
                &inputs,
            );
            let crate::discovery::writeprotect::WriteProtectDecision::Set { nodes, .. } = decision
            else {
                panic!("{kname}: {decision:?}")
            };
            assert!(nodes.contains(&"loop0".to_string()), "{kname}: {nodes:?}");
            assert!(nodes.contains(&kname.to_string()), "{kname}: {nodes:?}");
            assert!(
                !nodes.iter().any(|n| n.starts_with("nvme")),
                "{kname}: {nodes:?}"
            );
        }
        assert!(runner.calls().is_empty());

        // The loop device itself names no disk either
        let id = Prober::sysfs_only(f.root())
            .probe_block("/dev/loop0", loop_dev)
            .unwrap();
        assert!(id.parent_disks.is_empty(), "{:?}", id.parent_disks);
    }

    #[test]
    fn nvme_namespace_identity() {
        let f = FakeSysfs::new();
        f.add_disk(NVME, "nvme0n1", (259, 0), 2_000_409_264);
        f.set("nvme0n1", "wwid", "eui.0025384b21406566");
        f.set_hw(NVME, "model", "Samsung SSD 990 PRO 1TB                 ");
        f.set_hw(NVME, "serial", "S6Z0NJ0W000000X     ");
        f.set_hw(NVME, "firmware_rev", "4B2QJXD7");
        let id = Prober::sysfs_only(f.root())
            .probe_block("/dev/nvme0n1", (259, 0))
            .unwrap();
        assert_eq!(id.model.as_deref(), Some("Samsung SSD 990 PRO 1TB"));
        assert_eq!(id.serial.as_deref(), Some("S6Z0NJ0W000000X"));
        assert_eq!(id.serial_source(), Some(SerialSource::NvmeController));
        assert_eq!(id.firmware_rev.as_deref(), Some("4B2QJXD7"));
        assert_eq!(id.wwn.as_deref(), Some("eui.0025384b21406566"));
        assert_eq!(id.transport.as_deref(), Some("nvme"));
    }

    #[test]
    fn usb_bridge_hotplug_and_disagreeing_serials() {
        let f = FakeSysfs::new();
        f.add_disk(USB, "sdd", (8, 48), 1000);
        f.set_hw("pci0000:00/0000:00:14.0/usb2/2-1", "removable", "removable");
        f.set_hw(USB, "model", "External\tDrive\u{1b}[0m");
        f.set_hw(USB, "wwid", "t10.JMicron Generic");
        f.set_bytes("sdd", "device/vpd_pg80", &vpd("   "));
        let udev = udev_with(&[("ID_SERIAL_SHORT", "0123456789ABCDEF"), ("ID_BUS", "usb")]);
        let mut id = Prober::new(f.root(), &udev)
            .probe_block("/dev/sdd", (8, 48))
            .unwrap();
        assert_eq!(id.transport.as_deref(), Some("usb"));
        assert!(id.hotplug);
        assert!(!id.removable);
        // Control characters are gone, blank and t10 identifiers dropped
        assert_eq!(id.model.as_deref(), Some("External Drive [0m"));
        assert_eq!(id.wwn, None);
        assert_eq!(id.serial.as_deref(), Some("0123456789ABCDEF"));
        assert_eq!(id.serial_note(), None);
        // smartctl later reads the drive's own serial through the bridge
        id.add_serial_candidate("WD-REAL-DRIVE", SerialSource::SmartctlIdentify);
        assert_eq!(id.serial.as_deref(), Some("WD-REAL-DRIVE"));
        assert!(id.serial_note().unwrap().contains("USB bridge"));
    }

    #[test]
    fn unidentifiable_sources_fail() {
        let f = FakeSysfs::new();
        let p = Prober::sysfs_only(f.root());
        assert!(p
            .probe_block("/dev/sdx", (8, 99))
            .unwrap_err()
            .contains("no entry in sysfs"));
        f.add_disk(SATA, "sde", (8, 64), 10);
        std::fs::remove_file(
            std::fs::canonicalize(f.path().join("class/block/sde"))
                .unwrap()
                .join("size"),
        )
        .unwrap();
        assert!(p
            .probe_block("/dev/sde", (8, 64))
            .unwrap_err()
            .contains("size"));
        let tmp = tempfile::tempdir().unwrap();
        assert!(p
            .probe(&tmp.path().to_string_lossy())
            .unwrap_err()
            .contains("neither a block device nor a regular file"));
        assert!(p.probe("/nonexistent/dfdisk-test").is_err());
    }

    #[test]
    fn regular_file_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("image.raw");
        std::fs::write(&file, vec![0u8; 4096]).unwrap();
        let path = file.to_string_lossy().into_owned();
        let id = Prober::sysfs_only(FakeSysfs::new().root())
            .probe(&path)
            .unwrap();
        assert_eq!(id.kind, SourceKind::RegularFile);
        assert_eq!(id.size_bytes, 4096);
        assert_eq!(id.kernel_name, "image.raw");
        assert!(id.file_id.is_some());
        assert_eq!(by_diskseq_name(&id), None);
        assert_eq!(id.same_attachment_as(&probe_file(&path).unwrap()), Ok(()));
        std::fs::write(&file, vec![0u8; 512]).unwrap();
        assert!(probe_file(&path)
            .unwrap()
            .same_attachment_as(&id)
            .unwrap_err()
            .contains("size"));
    }

    #[test]
    fn tool_source_path_uses_by_diskseq_only_when_it_is_the_pinned_device() {
        let mut id = SourceIdentity {
            path: "/dev/sdb".into(),
            maj_min: Some("8:16".into()),
            diskseq: Some(17),
            ..Default::default()
        };
        let dir = Path::new("/dev/disk/by-diskseq");
        let pinned = |p: &Path| (p == Path::new("/dev/disk/by-diskseq/17")).then_some((8, 16));
        assert_eq!(
            tool_source_path_in(&id, dir, &pinned),
            "/dev/disk/by-diskseq/17"
        );
        // The link now points at another device (re-attached disk): not used
        let moved = |_: &Path| Some((8, 32));
        assert_eq!(tool_source_path_in(&id, dir, &moved), "/dev/sdb");
        let missing = |_: &Path| None;
        assert_eq!(tool_source_path_in(&id, dir, &missing), "/dev/sdb");
        // Partitions use <N>-part<P>
        id.kind = SourceKind::Partition;
        id.partition_number = Some(3);
        id.path = "/dev/sdb3".into();
        id.maj_min = Some("8:19".into());
        let part = |p: &Path| (p == Path::new("/dev/disk/by-diskseq/17-part3")).then_some((8, 19));
        assert_eq!(
            tool_source_path_in(&id, dir, &part),
            "/dev/disk/by-diskseq/17-part3"
        );
        id.diskseq = None;
        assert_eq!(tool_source_path_in(&id, dir, &part), "/dev/sdb3");
    }

    #[test]
    fn helpers() {
        let p =
            parse_udev_properties("ID_SERIAL_SHORT=ABC\nDEVLINKS=/dev/a /dev/b\n\nbroken\n=x\n");
        assert_eq!(p["ID_SERIAL_SHORT"], "ABC");
        assert_eq!(p["DEVLINKS"], "/dev/a /dev/b");
        assert_eq!(p.len(), 2);
        assert_eq!(parse_vpd_pg80(&vpd("SER 1")).as_deref(), Some("SER 1"));
        assert_eq!(parse_vpd_pg80(b"\0\x80\0\x04\0\0\0\0"), None);
        assert_eq!(parse_vpd_pg80(b"plain"), Some("plain".into()));
        assert_eq!(
            transport_from_devpath(&format!("/sys/devices/{USB}"), "sdd"),
            Some("usb")
        );
        assert_eq!(
            transport_from_devpath(&format!("/sys/devices/{SATA}"), "sdb"),
            Some("sata")
        );
        assert_eq!(
            transport_from_devpath("/sys/devices/virtual/block/dm-0", "dm-0"),
            None
        );
    }
}
