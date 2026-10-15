//! The device table of the explorer: every disk and every partition (or
//! other child of a disk) is a selectable source; a selection is keyed by
//! identity (kernel name, serial, WWN, disk sequence number, plus major:minor
//! and size), never by a list index, so a refresh or a hot-plug cannot move it
//! to another device (§16, review C2).

use crate::discovery::devices;
use crate::discovery::safety::is_system_mount;
use crate::models::capacity::CapacityInfo;
use crate::models::device::{format_bytes, BlockDevice, DeviceSafety, Partition};
use crate::models::identity::SourceKind;
use crate::models::text::sanitize_line;

/// Identity of a selectable source as the scan saw it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SelectionKey {
    pub kernel_name: String,
    pub maj_min: Option<String>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub diskseq: Option<u64>,
    pub size_bytes: u64,
}

fn clean(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl SelectionKey {
    pub fn of(dev: &BlockDevice) -> Self {
        Self {
            kernel_name: dev.name.clone(),
            maj_min: clean(&dev.maj_min),
            serial: clean(&dev.serial),
            wwn: clean(&dev.wwn),
            diskseq: dev.diskseq,
            size_bytes: dev.size_bytes,
        }
    }

    /// What differs between `self` (the selection) and `now` (the same
    /// kernel name after a refresh); empty when it is the same device.
    pub fn differences(&self, now: &SelectionKey) -> Vec<String> {
        let mut diffs = Vec::new();
        let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "none".into());
        if self.maj_min != now.maj_min {
            diffs.push(format!(
                "major:minor {} (was {})",
                show(&now.maj_min),
                show(&self.maj_min)
            ));
        }
        if self.serial != now.serial {
            diffs.push(format!(
                "serial {} (was {})",
                show(&now.serial),
                show(&self.serial)
            ));
        }
        if self.wwn != now.wwn {
            diffs.push(format!("WWN {} (was {})", show(&now.wwn), show(&self.wwn)));
        }
        if self.diskseq != now.diskseq {
            let s = |v: Option<u64>| v.map(|n| n.to_string()).unwrap_or_else(|| "none".into());
            diffs.push(format!(
                "disk sequence number {} (was {})",
                s(now.diskseq),
                s(self.diskseq)
            ));
        }
        if self.size_bytes != now.size_bytes {
            diffs.push(format!(
                "size {} bytes (was {} bytes)",
                now.size_bytes, self.size_bytes
            ));
        }
        diffs
    }
}

/// A badge in the device table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// Holds the running system (refused)
    System,
    /// Listed in the dfnix protected-device registry (refused)
    Protected,
    /// Has mounted filesystems (refused until unmounted)
    Mounted,
    /// Read-only at the block layer
    ReadOnly,
    /// Has holders (dm, md, LVM on top)
    InUse,
    /// A capacity probe found a host protected area
    HiddenArea,
    /// A capacity probe found a device configuration overlay
    Dco,
}

impl Badge {
    pub fn label(&self) -> &'static str {
        match self {
            Badge::System => "SYSTEM",
            Badge::Protected => "PROTECTED",
            Badge::Mounted => "MOUNTED",
            Badge::ReadOnly => "RO",
            Badge::InUse => "IN-USE",
            Badge::HiddenArea => "HPA",
            Badge::Dco => "DCO",
        }
    }

    /// The badge of a label of [`devices::badges`].
    pub fn from_label(label: &str) -> Option<Badge> {
        Some(match label {
            "SYSTEM" => Badge::System,
            "PROTECTED" => Badge::Protected,
            "MOUNTED" => Badge::Mounted,
            "RO" => Badge::ReadOnly,
            "IN-USE" => Badge::InUse,
            "HPA" => Badge::HiddenArea,
            "DCO" => Badge::Dco,
            _ => return None,
        })
    }

    /// Short form for narrow tables (the details pane and the help explain
    /// them).
    pub fn short(&self) -> &'static str {
        match self {
            Badge::System => "SYS",
            Badge::Protected => "PROT",
            Badge::Mounted => "MNT",
            Badge::ReadOnly => "RO",
            Badge::InUse => "HOLD",
            Badge::HiddenArea => "HPA",
            Badge::Dco => "DCO",
        }
    }

    /// Badges that make the session refuse the source.
    pub fn refuses(&self) -> bool {
        matches!(self, Badge::System | Badge::Protected | Badge::Mounted)
    }
}

/// One selectable source of the device table.
#[derive(Debug, Clone)]
pub struct SourceRow {
    /// The source as an acquisition request snapshot (a partition is turned
    /// into its own [`BlockDevice`] with the hardware identity of its disk)
    pub device: BlockDevice,
    pub key: SelectionKey,
    /// 0 for a disk, 1 for a partition or other child
    pub depth: u8,
    /// Kernel name of the disk this row belongs to
    pub disk: String,
    /// Mount points in this source's tree, as the scan saw them
    pub mountpoints: Vec<String>,
    pub badges: Vec<Badge>,
    /// Why the dfnix registry protects it
    pub protected: Option<String>,
    /// Critical mounts of a system disk
    pub system_mounts: Vec<String>,
}

impl SourceRow {
    pub fn is_partition(&self) -> bool {
        self.depth > 0
    }

    pub fn has(&self, badge: Badge) -> bool {
        self.badges.contains(&badge)
    }

    /// "SYSTEM MOUNTED RO" for the table.
    pub fn badge_text(&self) -> String {
        self.badges
            .iter()
            .map(Badge::label)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// "SYS MNT RO": the short badge forms.
    pub fn badge_short_text(&self) -> String {
        self.badges
            .iter()
            .map(Badge::short)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Short kind of the source for the table ("disk", "part", "crypt").
    pub fn kind_label(&self) -> String {
        match &self.device.kind {
            SourceKind::Disk => "disk".into(),
            SourceKind::Partition => "part".into(),
            SourceKind::DeviceMapper {
                crypt_plaintext: true,
            } => "crypt".into(),
            SourceKind::DeviceMapper { .. } => "dm".into(),
            SourceKind::Md => "md".into(),
            SourceKind::Loop { .. } => "loop".into(),
            SourceKind::RegularFile => "file".into(),
            SourceKind::Other => "other".into(),
        }
    }

    /// Model (vendor + model) of the disk, sanitised.
    pub fn model(&self) -> String {
        sanitize_line(&self.device.display_name())
    }

    /// Serial as shown (sanitised), "(none)" when the scan saw none.
    pub fn serial(&self) -> String {
        self.device
            .serial
            .as_deref()
            .map(sanitize_line)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "(none)".into())
    }

    pub fn size(&self) -> String {
        format_bytes(self.device.size_bytes)
    }
}

/// A child of `disk` (partition, LUKS mapping, LVM volume, ...) as a source
/// snapshot: its own node, major:minor and size, its own tree of mounts and
/// holders; and the hardware identity (model, serial, WWN) of the disk only
/// when the node is stored on that one disk, as the identity probe reports it
/// for such sources (`discovery::identity`). A node stored on several disks
/// (md RAID, LVM across disks) or on disks the scan did not name gets none:
/// no single drive's serial applies. The disk sequence number is the disk's
/// for a partition (the kernel numbers disks, not partitions) and unknown for
/// a stacked device (dm/md have their own).
pub fn partition_source(disk: &BlockDevice, part: &Partition) -> BlockDevice {
    let lsblk_type = part.kind.as_deref().unwrap_or("part");
    let kind = SourceKind::from_lsblk_type(lsblk_type);
    let is_partition = kind == SourceKind::Partition;
    let on_this_disk_only = match part.parent_disks.as_slice() {
        [] => is_partition,
        [one] => one == &disk.path,
        _ => false,
    };
    let mountpoints = tree_mounts(part);
    let safety = if let Some(system) = mountpoints.iter().find(|m| is_system_mount(m)) {
        DeviceSafety::SystemDisk(vec![system.clone()])
    } else if mountpoints.is_empty() {
        DeviceSafety::Safe
    } else {
        DeviceSafety::Mounted(mountpoints.clone())
    };
    let mut device = BlockDevice {
        name: part.name.clone(),
        path: part.path.clone(),
        size_bytes: part.size_bytes,
        is_read_only: part.is_read_only,
        logical_sector_size: disk.logical_sector_size,
        physical_sector_size: disk.physical_sector_size,
        mountpoints,
        safety,
        maj_min: part.maj_min.clone(),
        kind,
        holders: part.holders.clone(),
        protected: disk.protected.clone(),
        start_sector: part.start_sector,
        ..Default::default()
    };
    if on_this_disk_only {
        device.model = disk.model.clone();
        device.vendor = disk.vendor.clone();
        device.serial = disk.serial.clone();
        device.wwn = disk.wwn.clone();
        device.revision = disk.revision.clone();
        device.bus_type = disk.bus_type.clone();
        device.is_rotational = disk.is_rotational;
        device.is_removable = disk.is_removable;
        device.hotplug = disk.hotplug;
        device.transport = disk.transport.clone();
        device.serial_candidates = disk.serial_candidates.clone();
        device.parent = Some(disk.path.clone());
        device.diskseq = if is_partition { disk.diskseq } else { None };
    } else {
        device.bus_type = "UNKNOWN".into();
    }
    device
}

/// A child's own mount point (lsblk's "[SWAP]" included) and the mounts of
/// its tree as the scan found them.
fn tree_mounts(part: &Partition) -> Vec<String> {
    let mut out: Vec<String> = part.mountpoint.iter().cloned().collect();
    for m in &part.tree_mounts {
        if !out.contains(m) {
            out.push(m.clone());
        }
    }
    out
}

/// Rows of the device table: each disk followed by its children. `capacity`
/// gives the hidden-area state of disks that were probed (by kernel name).
pub fn source_rows(
    devices: &[BlockDevice],
    capacity: &dyn Fn(&str) -> Option<CapacityInfo>,
) -> Vec<SourceRow> {
    let mut rows = Vec::new();
    for disk in devices {
        let system_mounts = match &disk.safety {
            DeviceSafety::SystemDisk(m) => m.clone(),
            _ => Vec::new(),
        };
        // The scan's badges (§16): SYSTEM, PROTECTED, MOUNTED, RO, IN-USE,
        // and HPA / DCO once the examiner had the disk probed
        let probed = capacity(&disk.name);
        let badges: Vec<Badge> = devices::badges(disk, probed.as_ref())
            .into_iter()
            .filter_map(Badge::from_label)
            .collect();
        rows.push(SourceRow {
            device: disk.clone(),
            key: SelectionKey::of(disk),
            depth: 0,
            disk: disk.name.clone(),
            mountpoints: disk.mountpoints.clone(),
            badges,
            protected: disk.protected.clone(),
            system_mounts: system_mounts.clone(),
        });
        for part in &disk.partitions {
            let device = partition_source(disk, part);
            // Its own mount and those of everything stacked on it (a LUKS
            // partition whose mapping is mounted is mounted)
            let mounts = device.mountpoints.clone();
            let critical: Vec<String> = mounts
                .iter()
                .filter(|m| is_system_mount(m))
                .cloned()
                .collect();
            let mut badges = Vec::new();
            // A child of a system disk is shown as such: the session refuses
            // sources on the system disk
            if disk.safety.is_system() || !critical.is_empty() {
                badges.push(Badge::System);
            }
            if disk.protected.is_some() {
                badges.push(Badge::Protected);
            }
            if !mounts.is_empty() {
                badges.push(Badge::Mounted);
            }
            if part.is_read_only {
                badges.push(Badge::ReadOnly);
            }
            if !part.holders.is_empty() {
                badges.push(Badge::InUse);
            }
            rows.push(SourceRow {
                key: SelectionKey::of(&device),
                mountpoints: mounts,
                device,
                depth: 1,
                disk: disk.name.clone(),
                badges,
                protected: disk.protected.clone(),
                system_mounts: if critical.is_empty() {
                    system_mounts.clone()
                } else {
                    critical
                },
            });
        }
    }
    rows
}

/// What became of a selection after a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    /// The same device, now at this row
    Same(usize),
    /// A device of the same kernel name with a different identity
    Changed {
        row: usize,
        differences: Vec<String>,
    },
    /// No device of that kernel name any more
    Gone,
}

/// Find the selection `key` among `rows` (by kernel name, then identity).
pub fn reconcile(key: &SelectionKey, rows: &[SourceRow]) -> Reconciled {
    match rows
        .iter()
        .position(|r| r.key.kernel_name == key.kernel_name)
    {
        None => Reconciled::Gone,
        Some(row) => {
            let differences = key.differences(&rows[row].key);
            if differences.is_empty() {
                Reconciled::Same(row)
            } else {
                Reconciled::Changed { row, differences }
            }
        }
    }
}

/// "The selected source /dev/sdb disappeared" / "... changed: serial ...".
pub fn invalidation_notice(path: &str, how: &Reconciled) -> Option<String> {
    match how {
        Reconciled::Same(_) => None,
        Reconciled::Gone => Some(format!(
            "The selected source {path} disappeared; select a source again."
        )),
        Reconciled::Changed { differences, .. } => Some(format!(
            "The selected source {path} changed: {}; select it again after checking the drive.",
            differences.join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(name: &str, serial: &str, seq: u64) -> BlockDevice {
        BlockDevice {
            name: name.into(),
            path: format!("/dev/{name}"),
            serial: Some(serial.into()),
            maj_min: Some("8:16".into()),
            diskseq: Some(seq),
            size_bytes: 1 << 30,
            model: Some("Disk".into()),
            partitions: vec![Partition {
                name: format!("{name}1"),
                path: format!("/dev/{name}1"),
                size_bytes: 1 << 20,
                maj_min: Some("8:17".into()),
                kind: Some("part".into()),
                start_sector: Some(2048),
                mountpoint: Some("/media/x".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn partitions_are_sources_with_the_disk_hardware_identity() {
        let rows = source_rows(&[disk("sdb", "S1", 7)], &|_| None);
        assert_eq!(rows.len(), 2);
        let part = &rows[1];
        assert!(part.is_partition());
        assert_eq!(part.device.kind, SourceKind::Partition);
        assert_eq!(part.device.serial.as_deref(), Some("S1"));
        assert_eq!(part.device.diskseq, Some(7));
        assert_eq!(part.device.maj_min.as_deref(), Some("8:17"));
        assert_eq!(part.device.parent.as_deref(), Some("/dev/sdb"));
        assert!(part.has(Badge::Mounted));
        assert!(rows[0].has(Badge::Mounted) || rows[0].mountpoints.is_empty());
    }

    #[test]
    fn reconcile_follows_identity_not_position() {
        let before = source_rows(&[disk("sdb", "S1", 7)], &|_| None);
        let key = before[0].key.clone();
        // Another disk appeared in front: same device, new row
        let after = source_rows(&[disk("sda", "S0", 3), disk("sdb", "S1", 7)], &|_| None);
        assert_eq!(reconcile(&key, &after), Reconciled::Same(2));
        // Swapped drive on the same name
        let swapped = source_rows(&[disk("sdb", "S2", 9)], &|_| None);
        match reconcile(&key, &swapped) {
            Reconciled::Changed { row, differences } => {
                assert_eq!(row, 0);
                assert!(differences.iter().any(|d| d.contains("serial S2 (was S1)")));
                assert!(differences.iter().any(|d| d.contains("disk sequence")));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(reconcile(&key, &[]), Reconciled::Gone);
        assert!(invalidation_notice("/dev/sdb", &Reconciled::Gone)
            .unwrap()
            .contains("disappeared"));
    }

    #[test]
    fn badges() {
        let mut d = disk("sdb", "S1", 7);
        d.safety = DeviceSafety::SystemDisk(vec!["/".into()]);
        d.protected = Some("dfnix boot medium".into());
        d.is_read_only = true;
        d.holders = vec!["dm-0".into()];
        // The scan lists the mounts of the disk's whole tree on the disk
        d.mountpoints = vec!["/media/x".into()];
        let rows = source_rows(std::slice::from_ref(&d), &|_| None);
        assert_eq!(rows[0].badge_text(), "SYSTEM PROTECTED MOUNTED RO IN-USE");
        assert!(rows[1].has(Badge::System) && rows[1].has(Badge::Protected));
        // A probed disk: HPA and DCO are told apart
        let probed = |_: &str| {
            Some(CapacityInfo {
                ata: Some(crate::models::capacity::AtaCapacity {
                    hpa_present: Some(false),
                    dco_present: Some(true),
                    ..Default::default()
                }),
                ..CapacityInfo::not_probed(1 << 30, "test")
            })
        };
        let rows = source_rows(&[d], &probed);
        assert!(rows[0].has(Badge::Dco) && !rows[0].has(Badge::HiddenArea));
        // A partition mounted at a dfcore system mount (e.g. the live ISO)
        let mut iso = disk("sdc", "S2", 8);
        iso.partitions[0].mountpoint = Some("/iso".into());
        let rows = source_rows(&[iso], &|_| None);
        assert!(rows[1].has(Badge::System), "{}", rows[1].badge_text());
    }

    #[test]
    fn a_partition_whose_mapping_is_mounted_is_mounted_and_in_use() {
        // sdb1 (LUKS) -> luks-x mounted at /media/x, as Scan::devices() lists it
        let mut d = disk("sdb", "S1", 7);
        d.mountpoints = vec!["/media/x".into()];
        d.safety = DeviceSafety::Mounted(vec!["/media/x".into()]);
        d.holders = vec!["dm-0".into()];
        d.partitions[0].mountpoint = None;
        d.partitions[0].fstype = Some("crypto_LUKS".into());
        d.partitions[0].tree_mounts = vec!["/media/x".into()];
        d.partitions[0].holders = vec!["dm-0".into()];
        d.partitions[0].parent_disks = vec!["/dev/sdb".into()];
        d.partitions.push(Partition {
            name: "luks-x".into(),
            path: "/dev/mapper/luks-x".into(),
            size_bytes: 1 << 19,
            maj_min: Some("254:0".into()),
            kind: Some("crypt".into()),
            mountpoint: Some("/media/x".into()),
            tree_mounts: vec!["/media/x".into()],
            parent_disks: vec!["/dev/sdb".into()],
            ..Default::default()
        });
        let rows = source_rows(&[d], &|_| None);
        let part = &rows[1];
        assert_eq!(part.badge_text(), "MOUNTED IN-USE");
        assert_eq!(part.mountpoints, ["/media/x"]);
        assert_eq!(part.device.holders, ["dm-0"]);
        assert_eq!(
            part.device.safety,
            DeviceSafety::Mounted(vec!["/media/x".into()])
        );
        // The mapping itself, stored on this one disk: the disk's identity
        let crypt = &rows[2];
        assert!(crypt.has(Badge::Mounted) && !crypt.has(Badge::InUse));
        assert_eq!(crypt.device.serial.as_deref(), Some("S1"));
        assert_eq!(crypt.device.parent.as_deref(), Some("/dev/sdb"));
        assert_eq!(crypt.device.diskseq, None, "a dm device has its own");
        // A system mount anywhere in the tree makes the row SYSTEM
        let mut sys = disk("sdc", "S2", 8);
        sys.partitions[0].mountpoint = None;
        sys.partitions[0].tree_mounts = vec!["/".into()];
        let rows = source_rows(&[sys], &|_| None);
        assert!(rows[1].has(Badge::System), "{}", rows[1].badge_text());
        assert_eq!(rows[1].system_mounts, ["/"]);
    }

    #[test]
    fn a_device_on_several_disks_borrows_no_drive_identity() {
        use crate::discovery::identity::Prober;
        use crate::discovery::sysfs::fake::FakeSysfs;
        const VIRTIO_B: &str = "pci0000:00/0000:00:05.0/virtio2";
        const VIRTIO_C: &str = "pci0000:00/0000:00:06.0/virtio3";
        let f = FakeSysfs::new();
        f.add_disk(VIRTIO_B, "vdb", (252, 16), 131_072);
        f.set("vdb", "serial", "DISK-B");
        f.add_partition("vdb", "vdb1", (252, 17), 1, 2048, 100_000);
        f.add_disk(VIRTIO_C, "vdc", (252, 32), 131_072);
        f.set("vdc", "serial", "DISK-C");
        f.add_partition("vdc", "vdc1", (252, 33), 1, 2048, 100_000);
        f.add_virtual("md0", (9, 0), 99_000);
        std::fs::create_dir_all(f.path().join("devices/virtual/block/md0/md")).unwrap();
        f.stack("md0", "vdb1");
        f.stack("md0", "vdc1");
        // What the session probes at the start
        let probed = Prober::sysfs_only(f.root())
            .probe_block("/dev/md0", (9, 0))
            .unwrap();
        assert_eq!(probed.serial, None);

        // The TUI row of md0 under vdb (the scan lists it under both disks)
        let vdb = BlockDevice {
            name: "vdb".into(),
            path: "/dev/vdb".into(),
            serial: Some("DISK-B".into()),
            model: Some("Virtio".into()),
            diskseq: Some(4),
            maj_min: Some("252:16".into()),
            size_bytes: 131_072 * 512,
            ..Default::default()
        };
        let md = Partition {
            name: "md0".into(),
            path: "/dev/md0".into(),
            size_bytes: 99_000 * 512,
            kind: Some("raid1".into()),
            maj_min: Some("9:0".into()),
            parent_disks: vec!["/dev/vdb".into(), "/dev/vdc".into()],
            ..Default::default()
        };
        let row = partition_source(&vdb, &md);
        assert_eq!(row.serial, None, "no single drive's serial");
        assert_eq!(row.model, None);
        assert_eq!(row.parent, None);
        assert!(row.serial_candidates.is_empty());
        // Before, the row carried DISK-B and the start was refused as
        // "source changed ... no serial reported, was DISK-B"
        assert_eq!(probed.same_attachment(&row.device_identity()), Ok(()));

        // A partition always borrows its disk's identity
        let part = Partition {
            name: "vdb1".into(),
            path: "/dev/vdb1".into(),
            kind: Some("part".into()),
            ..Default::default()
        };
        let row = partition_source(&vdb, &part);
        assert_eq!(row.serial.as_deref(), Some("DISK-B"));
        assert_eq!(row.diskseq, Some(4));
    }
}
