use crate::models::config::SmartPolicy;
use crate::models::identity::{SerialCandidate, SourceKind};
use chrono::{DateTime, Utc};
use dfcore::lsblk::DeviceIdentity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum DeviceSafety {
    /// Safe for acquisition (unmounted, not a system disk)
    #[default]
    Safe,
    /// Has mounted partitions that should be unmounted before acquisition
    Mounted(Vec<String>),
    /// Contains critical OS partitions (root, boot, home, swap, etc.)
    SystemDisk(Vec<String>),
}

impl DeviceSafety {
    pub fn is_system(&self) -> bool {
        matches!(self, DeviceSafety::SystemDisk(_))
    }

    pub fn is_mounted(&self) -> bool {
        matches!(self, DeviceSafety::Mounted(_) | DeviceSafety::SystemDisk(_))
    }

    pub fn status_badge(&self) -> &'static str {
        match self {
            DeviceSafety::Safe => "SAFE",
            DeviceSafety::Mounted(_) => "MOUNTED",
            DeviceSafety::SystemDisk(_) => "SYSTEM (CRITICAL)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Partition {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub mountpoint: Option<String>,
    pub is_read_only: bool,
    /// "major:minor"
    #[serde(default)]
    pub maj_min: Option<String>,
    /// lsblk TYPE ("part", "crypt", "lvm", ...)
    #[serde(default)]
    pub kind: Option<String>,
    /// First sector on the parent disk, 512-byte units
    #[serde(default)]
    pub start_sector: Option<u64>,
}

/// Overall SMART verdict. `Unknown` whenever SMART could not be read; never
/// shown as failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmartHealth {
    Passed,
    Failed,
    #[default]
    Unknown,
}

impl SmartHealth {
    pub fn label(&self) -> &'static str {
        match self {
            SmartHealth::Passed => "PASSED",
            SmartHealth::Failed => "FAILED",
            SmartHealth::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmartInfo {
    #[serde(default)]
    pub health: SmartHealth,
    /// `health == Passed` (kept for older JSON consumers)
    pub passed: bool,
    pub power_on_hours: Option<u64>,
    pub temperature_celsius: Option<i32>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub uncorrectable_errors: Option<u64>,
    /// Percent of rated endurance used (NVMe `percentage_used`, ATA wear attributes)
    pub wear_percentage: Option<u32>,
    pub assessment: String,
}

/// One SMART query of an acquisition source, as recorded in the report (§8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartSnapshot {
    pub policy: SmartPolicy,
    /// argv of the smartctl run
    pub command: Vec<String>,
    pub smartctl_version: Option<String>,
    /// smartctl exit status (a bit mask)
    pub exit_status: Option<i32>,
    pub taken_at: DateTime<Utc>,
    pub summary: SmartInfo,
    /// `<base>.smart-before.json` / `-after.json` holding smartctl's raw output
    pub json_file: Option<String>,
    pub json_sha256: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockDevice {
    pub name: String,
    pub path: String,
    pub devlinks: Vec<String>,
    pub size_bytes: u64,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub revision: Option<String>,
    pub bus_type: String,
    pub is_rotational: Option<bool>,
    /// Removable media (lsblk RM): card readers, optical, floppy
    pub is_removable: bool,
    pub is_read_only: bool,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub partition_table_type: Option<String>,
    pub partitions: Vec<Partition>,
    pub mountpoints: Vec<String>,
    pub safety: DeviceSafety,
    pub smart: Option<SmartInfo>,
    /// "major:minor"
    #[serde(default)]
    pub maj_min: Option<String>,
    /// Disk sequence number (Linux 5.15+)
    #[serde(default)]
    pub diskseq: Option<u64>,
    /// Hot-pluggable attachment (lsblk HOTPLUG: USB, eSATA, ...)
    #[serde(default)]
    pub hotplug: bool,
    /// lsblk TRAN in lower case (usb, sata, nvme, ...)
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub kind: SourceKind,
    /// Devices stacked on this one (dm, md), from sysfs holders
    #[serde(default)]
    pub holders: Vec<String>,
    /// Why the dfnix registry protects this device, if it does
    #[serde(default)]
    pub protected: Option<String>,
    /// Parent disk path of a partition or dm/md device
    #[serde(default)]
    pub parent: Option<String>,
    /// First sector of a partition on its disk, 512-byte units
    #[serde(default)]
    pub start_sector: Option<u64>,
    #[serde(default)]
    pub dm_uuid: Option<String>,
    /// Every serial number seen, with its source
    #[serde(default)]
    pub serial_candidates: Vec<SerialCandidate>,
}

impl BlockDevice {
    pub fn human_size(&self) -> String {
        format_bytes(self.size_bytes)
    }

    pub fn display_name(&self) -> String {
        let vendor = self.vendor.as_deref().unwrap_or("");
        let model = self.model.as_deref().unwrap_or("Unknown Drive");
        if vendor.is_empty() {
            model.trim().to_string()
        } else {
            format!("{} {}", vendor.trim(), model.trim())
        }
    }

    pub fn display_serial(&self) -> String {
        self.serial
            .clone()
            .unwrap_or_else(|| "NO_SERIAL".to_string())
    }

    /// Kind of medium. Hot-pluggable attachment is not removable media: a USB
    /// hard disk is a rotational disk (see [`attachment_str`](Self::attachment_str)).
    pub fn media_type_str(&self) -> &'static str {
        match (self.is_removable, self.is_rotational) {
            (true, _) => "Removable Media",
            (false, Some(true)) => "Rotational HDD",
            (false, Some(false)) => "Solid State (SSD/NVMe/Flash)",
            (false, None) => "Fixed Disk",
        }
    }

    /// "USB, hot-pluggable", "NVME", "SATA".
    pub fn attachment_str(&self) -> String {
        let bus = self
            .transport
            .as_deref()
            .map(str::to_uppercase)
            .unwrap_or_else(|| self.bus_type.clone());
        if self.hotplug {
            format!("{bus}, hot-pluggable")
        } else {
            bus
        }
    }

    /// The dfcore identity of this scan entry (audit records, registry, and
    /// the snapshot a probe is compared with).
    pub fn device_identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            path: self.path.clone(),
            kernel_name: self.name.clone(),
            maj_min: self.maj_min.clone(),
            serial: self.serial.clone().filter(|s| !s.trim().is_empty()),
            wwn: self.wwn.clone().filter(|s| !s.trim().is_empty()),
            model: Some(self.display_name()),
            size: Some(self.size_bytes.to_string()),
            diskseq: self.diskseq,
        }
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1000;
    const MB: u64 = KB * 1000;
    const GB: u64 = MB * 1000;
    const TB: u64 = GB * 1000;

    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    if bytes >= TB {
        format!(
            "{:.2} TB ({:.2} TiB)",
            bytes as f64 / TB as f64,
            bytes as f64 / TIB as f64
        )
    } else if bytes >= GB {
        format!(
            "{:.2} GB ({:.2} GiB)",
            bytes as f64 / GB as f64,
            bytes as f64 / GIB as f64
        )
    } else if bytes >= MB {
        format!(
            "{:.2} MB ({:.2} MiB)",
            bytes as f64 / MB as f64,
            bytes as f64 / MIB as f64
        )
    } else if bytes >= KB {
        format!(
            "{:.2} KB ({:.2} KiB)",
            bytes as f64 / KB as f64,
            bytes as f64 / KIB as f64
        )
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotplug_is_not_removable_media() {
        let usb_hdd = BlockDevice {
            is_rotational: Some(true),
            hotplug: true,
            transport: Some("usb".into()),
            bus_type: "USB".into(),
            ..Default::default()
        };
        assert_eq!(usb_hdd.media_type_str(), "Rotational HDD");
        assert_eq!(usb_hdd.attachment_str(), "USB, hot-pluggable");
        let card = BlockDevice {
            is_removable: true,
            ..Default::default()
        };
        assert_eq!(card.media_type_str(), "Removable Media");
        assert_eq!(BlockDevice::default().media_type_str(), "Fixed Disk");
    }

    #[test]
    fn device_identity_carries_attachment_facts() {
        let dev = BlockDevice {
            name: "sdb".into(),
            path: "/dev/sdb".into(),
            serial: Some("  ".into()),
            maj_min: Some("8:16".into()),
            diskseq: Some(7),
            size_bytes: 512,
            ..Default::default()
        };
        let id = dev.device_identity();
        assert_eq!(id.maj_min.as_deref(), Some("8:16"));
        assert_eq!(id.diskseq, Some(7));
        assert_eq!(id.serial, None);
        assert_eq!(id.size.as_deref(), Some("512"));
        // Older scan JSON without the new fields still loads
        let old = r#"{"name":"sda","path":"/dev/sda","devlinks":[],"size_bytes":1,"model":null,"vendor":null,"serial":null,"wwn":null,"revision":null,"bus_type":"SATA","is_rotational":null,"is_removable":false,"is_read_only":false,"logical_sector_size":512,"physical_sector_size":512,"partition_table_type":null,"partitions":[],"mountpoints":[],"safety":"Safe","smart":null}"#;
        let parsed: BlockDevice = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.kind, SourceKind::Disk);
        assert!(!parsed.hotplug);
    }
}
