use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceSafety {
    /// Safe for acquisition (unmounted, not a system disk)
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

    #[allow(dead_code)]
    pub fn status_badge(&self) -> &'static str {
        match self {
            DeviceSafety::Safe => "SAFE",
            DeviceSafety::Mounted(_) => "MOUNTED",
            DeviceSafety::SystemDisk(_) => "SYSTEM (CRITICAL)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub mountpoint: Option<String>,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartInfo {
    pub passed: bool,
    pub power_on_hours: Option<u64>,
    pub temperature_celsius: Option<i32>,
    pub reallocated_sectors: Option<u64>,
    pub pending_sectors: Option<u64>,
    pub uncorrectable_errors: Option<u64>,
    pub wear_percentage: Option<u32>,
    pub assessment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub is_removable: bool,
    pub is_read_only: bool,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub partition_table_type: Option<String>,
    pub partitions: Vec<Partition>,
    pub mountpoints: Vec<String>,
    pub safety: DeviceSafety,
    pub smart: Option<SmartInfo>,
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

    pub fn media_type_str(&self) -> &'static str {
        match (self.is_rotational, self.is_removable) {
            (_, true) => "Removable Flash/USB",
            (Some(true), false) => "Rotational HDD",
            (Some(false), false) => "Solid State Disk (SSD/NVMe)",
            (None, false) => "Fixed Disk",
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
        format!("{:.2} TB ({:.2} TiB)", bytes as f64 / TB as f64, bytes as f64 / TIB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB ({:.2} GiB)", bytes as f64 / GB as f64, bytes as f64 / GIB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB ({:.2} MiB)", bytes as f64 / MB as f64, bytes as f64 / MIB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB ({:.2} KiB)", bytes as f64 / KB as f64, bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}
