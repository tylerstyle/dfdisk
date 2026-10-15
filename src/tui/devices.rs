//! The device table of the explorer: every disk and every partition (or
//! other child of a disk) is a selectable source; a selection is keyed by
//! identity (kernel name, serial, WWN, disk sequence number, plus major:minor
//! and size), never by a list index, so a refresh or a hot-plug cannot move it
//! to another device (§16, review C2).

use crate::discovery::SafetyChecker;
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
    /// A capacity probe found a host protected area or DCO
    HiddenArea,
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
        }
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
/// snapshot: its own node, major:minor and size; the hardware identity
/// (model, serial, WWN) of the disk it is stored on, as the identity probe
/// reports it for such sources. The disk sequence number is the disk's for
/// a partition (the kernel numbers disks, not partitions) and unknown for a
/// stacked device (dm/md have their own).
pub fn partition_source(disk: &BlockDevice, part: &Partition) -> BlockDevice {
    let lsblk_type = part.kind.as_deref().unwrap_or("part");
    let kind = SourceKind::from_lsblk_type(lsblk_type);
    let is_partition = kind == SourceKind::Partition;
    BlockDevice {
        name: part.name.clone(),
        path: part.path.clone(),
        size_bytes: part.size_bytes,
        model: disk.model.clone(),
        vendor: disk.vendor.clone(),
        serial: disk.serial.clone(),
        wwn: disk.wwn.clone(),
        revision: disk.revision.clone(),
        bus_type: disk.bus_type.clone(),
        is_rotational: disk.is_rotational,
        is_removable: disk.is_removable,
        is_read_only: part.is_read_only,
        logical_sector_size: disk.logical_sector_size,
        physical_sector_size: disk.physical_sector_size,
        mountpoints: part.mountpoint.iter().cloned().collect(),
        safety: match &part.mountpoint {
            Some(mp) if SafetyChecker::is_critical_mount(mp) => {
                DeviceSafety::SystemDisk(vec![mp.clone()])
            }
            Some(mp) => DeviceSafety::Mounted(vec![mp.clone()]),
            None => DeviceSafety::Safe,
        },
        maj_min: part.maj_min.clone(),
        diskseq: if is_partition { disk.diskseq } else { None },
        hotplug: disk.hotplug,
        transport: disk.transport.clone(),
        kind,
        protected: disk.protected.clone(),
        parent: Some(disk.path.clone()),
        start_sector: part.start_sector,
        serial_candidates: disk.serial_candidates.clone(),
        ..Default::default()
    }
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
        let mut badges = Vec::new();
        if disk.safety.is_system() {
            badges.push(Badge::System);
        }
        if disk.protected.is_some() {
            badges.push(Badge::Protected);
        }
        if disk.safety.is_mounted() || !disk.mountpoints.is_empty() {
            badges.push(Badge::Mounted);
        }
        if disk.is_read_only {
            badges.push(Badge::ReadOnly);
        }
        if !disk.holders.is_empty() {
            badges.push(Badge::InUse);
        }
        if capacity(&disk.name).is_some_and(|c| c.hidden_area() == Some(true)) {
            badges.push(Badge::HiddenArea);
        }
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
            let mut badges = Vec::new();
            let critical = part
                .mountpoint
                .as_deref()
                .is_some_and(SafetyChecker::is_critical_mount);
            // A child of a system disk is shown as such: the session refuses
            // sources on the system disk
            if disk.safety.is_system() || critical {
                badges.push(Badge::System);
            }
            if disk.protected.is_some() {
                badges.push(Badge::Protected);
            }
            if part.mountpoint.is_some() {
                badges.push(Badge::Mounted);
            }
            if part.is_read_only {
                badges.push(Badge::ReadOnly);
            }
            rows.push(SourceRow {
                key: SelectionKey::of(&device),
                mountpoints: part.mountpoint.iter().cloned().collect(),
                device,
                depth: 1,
                disk: disk.name.clone(),
                badges,
                protected: disk.protected.clone(),
                system_mounts: if critical {
                    part.mountpoint.iter().cloned().collect()
                } else {
                    system_mounts.clone()
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
        let rows = source_rows(&[d], &|_| None);
        assert_eq!(rows[0].badge_text(), "SYSTEM PROTECTED MOUNTED RO IN-USE");
        assert!(rows[1].has(Badge::System) && rows[1].has(Badge::Protected));
    }
}
