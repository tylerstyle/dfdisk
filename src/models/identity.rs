//! Who the source is (§5): the identity probed from sysfs and udev right
//! before an acquisition (see `discovery::identity::probe`), compared with the
//! device the examiner selected and with `--expect-*`, and again at the end.

use crate::models::config::ExpectIdentity;
use crate::models::device::BlockDevice;
use crate::models::text::sanitize_opt;
use dfcore::lsblk::DeviceIdentity;
use serde::{Deserialize, Serialize};

/// What kind of node the source is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceKind {
    /// A whole disk
    #[default]
    Disk,
    /// A partition of a disk (see `parent_disks`, `partition_start_sector`)
    Partition,
    /// A device-mapper target; `crypt_plaintext`: the decrypted view of an
    /// open LUKS/dm-crypt container, not the bytes stored on the disk
    DeviceMapper { crypt_plaintext: bool },
    /// A software RAID (md) array
    Md,
    /// A loop device over `backing_file`
    Loop { backing_file: Option<String> },
    /// A regular file (an image used as source)
    RegularFile,
    /// Any other block device
    Other,
}

impl SourceKind {
    /// Kind of an lsblk TYPE ("disk", "part", "crypt", "lvm", "raid1", "loop", ...).
    pub fn from_lsblk_type(dev_type: &str) -> Self {
        match dev_type {
            "disk" | "mpath" | "rom" => SourceKind::Disk,
            "part" => SourceKind::Partition,
            "crypt" => SourceKind::DeviceMapper {
                crypt_plaintext: true,
            },
            "lvm" | "dm" => SourceKind::DeviceMapper {
                crypt_plaintext: false,
            },
            t if t.starts_with("raid") || t == "md" || t == "linear" => SourceKind::Md,
            "loop" => SourceKind::Loop { backing_file: None },
            _ => SourceKind::Other,
        }
    }

    /// A node whose bytes are those of the physical medium from its start
    /// (ewfacquire `-M physical`); everything else is a logical view.
    pub fn is_whole_disk(&self) -> bool {
        matches!(self, SourceKind::Disk)
    }

    pub fn label(&self) -> String {
        match self {
            SourceKind::Disk => "whole disk".into(),
            SourceKind::Partition => "partition".into(),
            SourceKind::DeviceMapper {
                crypt_plaintext: true,
            } => {
                "device-mapper crypt target (DECRYPTED plaintext view, not the stored bytes)".into()
            }
            SourceKind::DeviceMapper {
                crypt_plaintext: false,
            } => "device-mapper target (logical volume)".into(),
            SourceKind::Md => "software RAID (md) array".into(),
            SourceKind::Loop {
                backing_file: Some(f),
            } => format!("loop device over {f}"),
            SourceKind::Loop { backing_file: None } => "loop device".into(),
            SourceKind::RegularFile => "regular file".into(),
            SourceKind::Other => "block device".into(),
        }
    }
}

/// Where a serial number candidate was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerialSource {
    /// ATA IDENTIFY through smartctl (when SMART ran)
    SmartctlIdentify,
    /// SCSI VPD page 0x80 (unit serial number) in sysfs
    VpdPage80,
    /// NVMe controller `serial` attribute in sysfs
    NvmeController,
    /// Other device `serial` attribute in sysfs (e.g. MMC/SD CID)
    SysfsDeviceSerial,
    /// udev `ID_SERIAL_SHORT`
    UdevIdSerialShort,
    /// lsblk SERIAL of the scan the device was selected from
    Lsblk,
}

impl SerialSource {
    /// Preference, lower first: device-reported > udev > lsblk.
    pub fn rank(&self) -> u8 {
        match self {
            SerialSource::SmartctlIdentify => 0,
            SerialSource::VpdPage80 => 1,
            SerialSource::NvmeController => 2,
            SerialSource::SysfsDeviceSerial => 3,
            SerialSource::UdevIdSerialShort => 10,
            SerialSource::Lsblk => 20,
        }
    }

    /// Read from the device itself rather than from a database.
    pub fn is_device_reported(&self) -> bool {
        self.rank() < 10
    }

    pub fn label(&self) -> &'static str {
        match self {
            SerialSource::SmartctlIdentify => "ATA IDENTIFY (smartctl)",
            SerialSource::VpdPage80 => "SCSI VPD page 0x80",
            SerialSource::NvmeController => "NVMe controller",
            SerialSource::SysfsDeviceSerial => "sysfs device serial",
            SerialSource::UdevIdSerialShort => "udev ID_SERIAL_SHORT",
            SerialSource::Lsblk => "lsblk",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialCandidate {
    pub value: String,
    pub source: SerialSource,
}

/// The identity of an acquisition source. Every string is sanitised (no
/// control characters) and no field holds an empty string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIdentity {
    /// Path as given
    pub path: String,
    /// Path with symlinks resolved
    pub canonical_path: String,
    /// Kernel name (sda, nvme0n1p2, dm-3); the file name for regular files
    pub kernel_name: String,
    /// "major:minor"; `None` for regular files
    pub maj_min: Option<String>,
    /// Disk sequence number (Linux 5.15+), new for every attachment
    pub diskseq: Option<u64>,
    pub kind: SourceKind,
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub firmware_rev: Option<String>,
    /// Preferred serial (see [`SerialSource::rank`])
    pub serial: Option<String>,
    /// Every serial reported, with its source
    pub serial_candidates: Vec<SerialCandidate>,
    pub wwn: Option<String>,
    /// usb, sata, nvme, scsi, mmc, virtio, ...
    pub transport: Option<String>,
    /// Removable media (sysfs `removable`)
    pub removable: bool,
    /// Hot-pluggable attachment (USB, eSATA, ...)
    pub hotplug: bool,
    pub rotational: Option<bool>,
    /// sysfs `ro` of the node when probed
    #[serde(default)]
    pub read_only: Option<bool>,
    /// Whole disks the source is stored on (partition: its disk; dm/md: the
    /// disks behind it); empty for a whole disk
    pub parent_disks: Vec<String>,
    /// Partition number (`partition` attribute), for /dev/disk/by-diskseq links
    #[serde(default)]
    pub partition_number: Option<u32>,
    /// First sector of a partition on its disk, in 512-byte units
    pub partition_start_sector: Option<u64>,
    pub dm_uuid: Option<String>,
    #[serde(default)]
    pub dm_name: Option<String>,
    /// Kernel name of the disk model, vendor, firmware, serial and WWN were
    /// read from, when that is not the source itself (a partition or a dm
    /// target on exactly one disk)
    #[serde(default)]
    pub hardware_of: Option<String>,
    /// Regular files: "st_dev:st_ino"
    #[serde(default)]
    pub file_id: Option<String>,
    /// What could not be read while probing, and other remarks
    #[serde(default)]
    pub probe_notes: Vec<String>,
}

/// Lower-case WWN without "0x", "naa.", "eui." or "nvme." prefixes, so that
/// lsblk ("0x5000c500a1b2c3d4"), sysfs ("naa.5000c500a1b2c3d4") and udev
/// spellings compare equal.
pub fn normalize_wwn(wwn: &str) -> String {
    let w = wwn.trim().to_ascii_lowercase();
    for prefix in ["0x", "naa.", "eui.", "nvme."] {
        if let Some(rest) = w.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    w
}

/// Serial for comparisons: trimmed, inner whitespace kept.
fn serial_key(s: &str) -> String {
    s.trim().to_string()
}

impl SourceIdentity {
    /// Add a serial candidate (sanitised; empty values and exact duplicates
    /// are ignored) and re-choose the preferred serial.
    pub fn add_serial_candidate(&mut self, value: &str, source: SerialSource) {
        // NUL padding and other control characters become spaces and are trimmed
        let Some(value) = sanitize_opt(value) else {
            return;
        };
        if self
            .serial_candidates
            .iter()
            .any(|c| c.source == source && c.value == value)
        {
            return;
        }
        self.serial_candidates
            .push(SerialCandidate { value, source });
        self.choose_serial();
    }

    /// `serial` = the candidate with the best [`SerialSource::rank`].
    pub fn choose_serial(&mut self) {
        self.serial_candidates.sort_by_key(|c| c.source.rank());
        self.serial = self.serial_candidates.first().map(|c| c.value.clone());
    }

    /// Source of the preferred serial.
    pub fn serial_source(&self) -> Option<SerialSource> {
        let serial = self.serial.as_ref()?;
        self.serial_candidates
            .iter()
            .find(|c| &c.value == serial)
            .map(|c| c.source)
    }

    /// "S4GF... (SCSI VPD page 0x80)" or "(none reported)".
    pub fn serial_with_provenance(&self) -> String {
        match (&self.serial, self.serial_source()) {
            (Some(s), Some(src)) => format!("{s} ({})", src.label()),
            (Some(s), None) => s.clone(),
            (None, _) => "(none reported)".into(),
        }
    }

    /// Distinct candidate values, in preference order.
    pub fn distinct_serials(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for c in &self.serial_candidates {
            if !out.iter().any(|v| serial_key(v) == serial_key(&c.value)) {
                out.push(&c.value);
            }
        }
        out
    }

    /// Warning when the sources disagree about the serial: over USB the value
    /// may be the bridge's rather than the drive's.
    pub fn serial_note(&self) -> Option<String> {
        if self.distinct_serials().len() < 2 {
            return None;
        }
        let listing = self
            .serial_candidates
            .iter()
            .map(|c| format!("{}: {}", c.source.label(), c.value))
            .collect::<Vec<_>>()
            .join("; ");
        if self.transport.as_deref() == Some("usb") {
            Some(format!(
                "serial may belong to the USB bridge rather than the drive: the sources disagree ({listing})"
            ))
        } else {
            Some(format!("the serial number sources disagree ({listing})"))
        }
    }

    /// Serial for file names: the preferred serial or "NO_SERIAL".
    pub fn display_serial(&self) -> String {
        self.serial.clone().unwrap_or_else(|| "NO_SERIAL".into())
    }

    /// "Vendor Model" or "Unknown Drive".
    pub fn display_name(&self) -> String {
        match (&self.vendor, &self.model) {
            (Some(v), Some(m)) => format!("{v} {m}"),
            (None, Some(m)) => m.clone(),
            (Some(v), None) => v.clone(),
            (None, None) => "Unknown Drive".into(),
        }
    }

    pub fn is_block_device(&self) -> bool {
        self.kind != SourceKind::RegularFile
    }

    /// The dfcore identity for audit records and the registry.
    pub fn device_identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            path: self.path.clone(),
            kernel_name: self.kernel_name.clone(),
            maj_min: self.maj_min.clone(),
            serial: self.serial.clone(),
            wwn: self.wwn.clone(),
            model: self.model.clone(),
            size: Some(self.size_bytes.to_string()),
            diskseq: self.diskseq,
        }
    }

    /// Is this (just probed) still the device `snapshot` described when it
    /// was selected? Same attachment per dfcore (major:minor, disk sequence
    /// number where both know it, serial / WWN) plus the same size. WWN
    /// spellings are normalised and the snapshot's serial may match any
    /// serial candidate, since a scan and a probe read different sources.
    /// The error lists every difference.
    pub fn same_attachment(&self, snapshot: &DeviceIdentity) -> Result<(), String> {
        let mut diffs = Vec::new();
        if let Some(size) = snapshot.size.as_deref().and_then(|s| s.parse::<u64>().ok()) {
            if size != self.size_bytes {
                diffs.push(format!(
                    "size {} bytes, was {} bytes",
                    self.size_bytes, size
                ));
            }
        }

        if !self.is_block_device() {
            let snap_canon = std::fs::canonicalize(&snapshot.path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| snapshot.path.clone());
            if snap_canon != self.canonical_path {
                diffs.push(format!(
                    "file {} is not the selected {}",
                    self.canonical_path, snapshot.path
                ));
            }
            return finish(diffs);
        }

        // Build the probed side in the snapshot's terms, then let dfcore decide
        let serial_match = snapshot.serial.as_deref().map(|want| {
            self.serial_candidates
                .iter()
                .map(|c| c.value.as_str())
                .chain(self.serial.as_deref())
                .find(|v| serial_key(v) == serial_key(want))
        });
        let current = DeviceIdentity {
            serial: match serial_match {
                Some(Some(v)) => Some(serial_key(v)),
                Some(None) => self.serial.clone(),
                // The snapshot could not see a serial: nothing to compare
                None => None,
            },
            wwn: match (&self.wwn, &snapshot.wwn) {
                (Some(w), Some(_)) => Some(normalize_wwn(w)),
                _ => None,
            },
            ..self.device_identity()
        };
        let reference = DeviceIdentity {
            // lsblk names dm targets by their mapper name, sysfs by dm-N: the
            // node is identified by major:minor, not by either name
            kernel_name: current.kernel_name.clone(),
            serial: snapshot.serial.as_deref().map(serial_key),
            wwn: match (&self.wwn, &snapshot.wwn) {
                (Some(_), Some(w)) => Some(normalize_wwn(w)),
                _ => None,
            },
            ..snapshot.clone()
        };

        if !current.same_attachment(&reference) {
            if snapshot.maj_min.is_none() {
                diffs.push("the selected device has no recorded major:minor".into());
            } else if current.maj_min != reference.maj_min {
                diffs.push(format!(
                    "major:minor {}, was {}",
                    current.maj_min.as_deref().unwrap_or("unknown"),
                    reference.maj_min.as_deref().unwrap_or("unknown")
                ));
            }
            if let (Some(a), Some(b)) = (current.diskseq, reference.diskseq) {
                if a != b {
                    diffs.push(format!("disk sequence number {a}, was {b}"));
                }
            }
            if let (Some(a), Some(b)) = (&current.wwn, &reference.wwn) {
                if a != b {
                    diffs.push(format!("WWN {a}, was {b}"));
                }
            }
            if let Some(want) = &reference.serial {
                if current.serial.as_ref() != Some(want) {
                    diffs.push(match &self.serial {
                        Some(s) => format!("serial {s}, was {want}"),
                        None => format!("no serial reported, was {want}"),
                    });
                }
            }
            if diffs.is_empty() {
                diffs.push("not the same device attachment".into());
            }
        }
        finish(diffs)
    }

    /// [`same_attachment`](Self::same_attachment) against an earlier probe.
    pub fn same_attachment_as(&self, earlier: &SourceIdentity) -> Result<(), String> {
        self.same_attachment(&earlier.device_identity())
    }

    /// Does the source have the serial, WWN and size the examiner expects?
    /// A serial matches any candidate (case-insensitive).
    pub fn check_expectations(&self, expect: &ExpectIdentity) -> Result<(), String> {
        let mut diffs = Vec::new();
        if let Some(want) = &expect.serial {
            let found = self
                .serial_candidates
                .iter()
                .map(|c| c.value.as_str())
                .chain(self.serial.as_deref())
                .any(|v| v.trim().eq_ignore_ascii_case(want.trim()));
            if !found {
                diffs.push(format!(
                    "expected serial {}, the device reports {}",
                    want.trim(),
                    if self.serial_candidates.is_empty() {
                        "none".to_string()
                    } else {
                        self.distinct_serials().join(" / ")
                    }
                ));
            }
        }
        if let Some(want) = &expect.wwn {
            match &self.wwn {
                Some(w) if normalize_wwn(w) == normalize_wwn(want) => {}
                Some(w) => diffs.push(format!("expected WWN {want}, the device reports {w}")),
                None => diffs.push(format!("expected WWN {want}, the device reports none")),
            }
        }
        if let Some(want) = expect.size {
            if want != self.size_bytes {
                diffs.push(format!(
                    "expected {want} bytes, the device has {} bytes",
                    self.size_bytes
                ));
            }
        }
        if diffs.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "the source is not the expected device: {}",
                diffs.join("; ")
            ))
        }
    }

    /// Identity taken from a scan entry without probing (old engines, tests).
    /// Marked in `probe_notes`.
    pub fn from_block_device(dev: &BlockDevice) -> Self {
        let canonical_path = std::fs::canonicalize(&dev.path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| dev.path.clone());
        let is_file = std::fs::metadata(&dev.path)
            .map(|m| m.is_file())
            .unwrap_or(false);
        let mut id = SourceIdentity {
            path: dev.path.clone(),
            canonical_path,
            kernel_name: dev.name.clone(),
            maj_min: dev.maj_min.clone(),
            diskseq: dev.diskseq,
            kind: if is_file {
                SourceKind::RegularFile
            } else {
                dev.kind.clone()
            },
            size_bytes: dev.size_bytes,
            logical_sector_size: dev.logical_sector_size,
            physical_sector_size: dev.physical_sector_size,
            model: dev.model.as_deref().and_then(sanitize_opt),
            vendor: dev.vendor.as_deref().and_then(sanitize_opt),
            firmware_rev: dev.revision.as_deref().and_then(sanitize_opt),
            serial: None,
            serial_candidates: dev.serial_candidates.clone(),
            wwn: dev.wwn.as_deref().and_then(sanitize_opt),
            transport: dev.transport.clone(),
            removable: dev.is_removable,
            hotplug: dev.hotplug,
            rotational: dev.is_rotational,
            read_only: Some(dev.is_read_only),
            parent_disks: dev.parent.iter().cloned().collect(),
            partition_number: None,
            partition_start_sector: dev.start_sector,
            dm_uuid: dev.dm_uuid.clone(),
            dm_name: None,
            hardware_of: None,
            file_id: None,
            probe_notes: vec!["identity taken from the device scan; not re-probed".into()],
        };
        if let Some(s) = &dev.serial {
            id.add_serial_candidate(s, SerialSource::Lsblk);
        }
        id.choose_serial();
        id
    }
}

fn finish(diffs: Vec<String>) -> Result<(), String> {
    if diffs.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "source changed since it was selected: {}",
            diffs.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk() -> SourceIdentity {
        let mut id = SourceIdentity {
            path: "/dev/sdb".into(),
            canonical_path: "/dev/sdb".into(),
            kernel_name: "sdb".into(),
            maj_min: Some("8:16".into()),
            diskseq: Some(42),
            size_bytes: 1_000_204_886_016,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            wwn: Some("naa.5000c500a1b2c3d4".into()),
            transport: Some("sata".into()),
            ..Default::default()
        };
        id.add_serial_candidate("WD-WCC4M0000001", SerialSource::VpdPage80);
        id.add_serial_candidate("WD-WCC4M0000001", SerialSource::UdevIdSerialShort);
        id
    }

    fn snapshot() -> DeviceIdentity {
        DeviceIdentity {
            path: "/dev/sdb".into(),
            kernel_name: "sdb".into(),
            maj_min: Some("8:16".into()),
            serial: Some("WD-WCC4M0000001".into()),
            wwn: Some("0x5000c500a1b2c3d4".into()),
            model: None,
            size: Some("1000204886016".into()),
            diskseq: Some(42),
        }
    }

    #[test]
    fn serial_preference_and_filtering() {
        let mut id = SourceIdentity::default();
        id.add_serial_candidate("  ", SerialSource::VpdPage80);
        id.add_serial_candidate("\0\0", SerialSource::VpdPage80);
        assert!(id.serial_candidates.is_empty());
        assert_eq!(id.serial, None);
        id.add_serial_candidate("LSBLK1", SerialSource::Lsblk);
        assert_eq!(id.serial.as_deref(), Some("LSBLK1"));
        id.add_serial_candidate("UDEV1", SerialSource::UdevIdSerialShort);
        assert_eq!(id.serial.as_deref(), Some("UDEV1"));
        id.add_serial_candidate(" DEV1\n", SerialSource::VpdPage80);
        assert_eq!(id.serial.as_deref(), Some("DEV1"));
        assert_eq!(id.serial_source(), Some(SerialSource::VpdPage80));
        id.add_serial_candidate("ATA1", SerialSource::SmartctlIdentify);
        assert_eq!(id.serial.as_deref(), Some("ATA1"));
        assert_eq!(
            id.serial_with_provenance(),
            "ATA1 (ATA IDENTIFY (smartctl))"
        );
        // Duplicates of value and source are dropped
        id.add_serial_candidate("ATA1", SerialSource::SmartctlIdentify);
        assert_eq!(id.serial_candidates.len(), 4);
        assert!(SerialSource::NvmeController.is_device_reported());
        assert!(!SerialSource::UdevIdSerialShort.is_device_reported());
    }

    #[test]
    fn usb_bridge_note_when_sources_disagree() {
        let mut id = SourceIdentity {
            transport: Some("usb".into()),
            ..Default::default()
        };
        id.add_serial_candidate("DRIVE123", SerialSource::VpdPage80);
        assert_eq!(id.serial_note(), None);
        id.add_serial_candidate("DRIVE123", SerialSource::UdevIdSerialShort);
        assert_eq!(id.serial_note(), None);
        id.add_serial_candidate("BRIDGE9", SerialSource::Lsblk);
        let note = id.serial_note().unwrap();
        assert!(note.contains("USB bridge"), "{note}");
        assert!(
            note.contains("BRIDGE9") && note.contains("DRIVE123"),
            "{note}"
        );
        id.transport = Some("sata".into());
        assert!(!id.serial_note().unwrap().contains("USB"));
    }

    #[test]
    fn same_attachment_accepts_the_same_device_in_other_spellings() {
        assert_eq!(disk().same_attachment(&snapshot()), Ok(()));
        // lsblk saw no serial / WWN: nothing to compare there
        let blind = DeviceIdentity {
            serial: None,
            wwn: None,
            ..snapshot()
        };
        assert_eq!(disk().same_attachment(&blind), Ok(()));
        // Snapshot serial matches a lower-ranked candidate
        let mut usb = disk();
        usb.wwn = None;
        usb.add_serial_candidate("BRIDGE", SerialSource::SmartctlIdentify);
        assert_eq!(usb.serial.as_deref(), Some("BRIDGE"));
        let snap = DeviceIdentity {
            wwn: None,
            ..snapshot()
        };
        assert_eq!(usb.same_attachment(&snap), Ok(()));
        assert_eq!(disk().same_attachment_as(&disk()), Ok(()));
    }

    #[test]
    fn same_attachment_lists_every_difference() {
        let other = DeviceIdentity {
            maj_min: Some("8:32".into()),
            diskseq: Some(43),
            size: Some("500".into()),
            ..snapshot()
        };
        let err = disk().same_attachment(&other).unwrap_err();
        assert!(
            err.starts_with("source changed since it was selected"),
            "{err}"
        );
        assert!(err.contains("major:minor 8:16, was 8:32"), "{err}");
        assert!(err.contains("disk sequence number 42, was 43"), "{err}");
        assert!(
            err.contains("size 1000204886016 bytes, was 500 bytes"),
            "{err}"
        );

        // A swapped disk on the same node: new diskseq
        let swapped = DeviceIdentity {
            diskseq: Some(99),
            ..snapshot()
        };
        assert!(disk().same_attachment(&swapped).unwrap_err().contains("99"));

        // Same node, another drive
        let mut other_drive = disk();
        other_drive.wwn = Some("naa.5000c500ffffffff".into());
        let err = other_drive.same_attachment(&snapshot()).unwrap_err();
        assert!(err.contains("WWN"), "{err}");

        let mut no_wwn = disk();
        no_wwn.wwn = None;
        no_wwn.serial_candidates.clear();
        no_wwn.serial = None;
        let err = no_wwn.same_attachment(&snapshot()).unwrap_err();
        assert!(
            err.contains("no serial reported, was WD-WCC4M0000001"),
            "{err}"
        );

        // Fail closed without a recorded device number
        let unknown = DeviceIdentity {
            maj_min: None,
            ..snapshot()
        };
        assert!(disk()
            .same_attachment(&unknown)
            .unwrap_err()
            .contains("no recorded major:minor"));
    }

    #[test]
    fn expectations_are_checked() {
        let id = disk();
        assert!(id.check_expectations(&ExpectIdentity::default()).is_ok());
        let ok = ExpectIdentity {
            serial: Some("wd-wcc4m0000001".into()),
            wwn: Some("0x5000C500A1B2C3D4".into()),
            size: Some(1_000_204_886_016),
        };
        assert!(id.check_expectations(&ok).is_ok());
        let bad = ExpectIdentity {
            serial: Some("OTHER".into()),
            wwn: Some("eui.1".into()),
            size: Some(1),
        };
        let err = id.check_expectations(&bad).unwrap_err();
        assert!(err.contains("expected serial OTHER"), "{err}");
        assert!(err.contains("expected WWN eui.1"), "{err}");
        assert!(err.contains("expected 1 bytes"), "{err}");
    }

    #[test]
    fn wwn_normalisation() {
        assert_eq!(normalize_wwn("0x5000C500A1B2C3D4"), "5000c500a1b2c3d4");
        assert_eq!(normalize_wwn("naa.5000c500a1b2c3d4"), "5000c500a1b2c3d4");
        assert_eq!(normalize_wwn("eui.0025384B21406566"), "0025384b21406566");
        assert_eq!(normalize_wwn(" abc "), "abc");
    }

    #[test]
    fn kinds() {
        assert_eq!(SourceKind::from_lsblk_type("part"), SourceKind::Partition);
        assert_eq!(
            SourceKind::from_lsblk_type("crypt"),
            SourceKind::DeviceMapper {
                crypt_plaintext: true
            }
        );
        assert_eq!(SourceKind::from_lsblk_type("raid1"), SourceKind::Md);
        assert!(SourceKind::Disk.is_whole_disk());
        assert!(!SourceKind::Partition.is_whole_disk());
        assert!(SourceKind::DeviceMapper {
            crypt_plaintext: true
        }
        .label()
        .contains("DECRYPTED"));
        let v = serde_json::to_value(SourceKind::Loop {
            backing_file: Some("/img".into()),
        })
        .unwrap();
        assert_eq!(v["type"], "loop");
        assert_eq!(v["backing_file"], "/img");
    }

    #[test]
    fn identity_from_a_scan_entry() {
        let dev = BlockDevice {
            name: "sdc".into(),
            path: "/dev/dfdisk-test-nonexistent".into(),
            serial: Some("SER1".into()),
            maj_min: Some("8:32".into()),
            size_bytes: 4096,
            logical_sector_size: 512,
            physical_sector_size: 512,
            ..Default::default()
        };
        let id = SourceIdentity::from_block_device(&dev);
        assert_eq!(id.serial.as_deref(), Some("SER1"));
        assert_eq!(id.serial_source(), Some(SerialSource::Lsblk));
        assert_eq!(id.kind, SourceKind::Disk);
        assert!(!id.probe_notes.is_empty());
        assert_eq!(id.device_identity().size.as_deref(), Some("4096"));
        assert_eq!(id.display_serial(), "SER1");
        assert_eq!(SourceIdentity::default().display_serial(), "NO_SERIAL");
    }
}
