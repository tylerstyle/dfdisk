//! Capacity of the source as the drive reports it, and areas hidden from the
//! operating system (§7, R6): ATA Host Protected Area (HPA) and Device
//! Configuration Overlay (DCO), NVMe namespace size versus capacity. Probing
//! (`hdparm -N`, `hdparm --dco-identify`, `nvme id-ns`) lives in
//! `discovery::capacity`; dfdisk never changes HPA or DCO.

use crate::models::text::format_iec;
use serde::{Deserialize, Serialize};

/// ATA capacity facts (`hdparm -N`, `hdparm --dco-identify`), in sectors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaCapacity {
    /// READ NATIVE MAX ADDRESS
    pub native_max_sectors: Option<u64>,
    /// Current max address (what the OS sees)
    pub current_max_sectors: Option<u64>,
    pub hpa_present: Option<bool>,
    /// Real maximum from DCO IDENTIFY
    pub dco_real_max_sectors: Option<u64>,
    pub dco_present: Option<bool>,
}

/// NVMe namespace facts (`nvme id-ns -o json`), in logical blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeCapacity {
    /// Namespace size
    pub nsze: Option<u64>,
    /// Namespace capacity
    pub ncap: Option<u64>,
    /// Namespace utilisation
    pub nuse: Option<u64>,
    /// Bytes per logical block of the active format
    pub lba_bytes: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityInfo {
    /// Size the kernel reports for the source
    pub reported_bytes: u64,
    /// Device the probe ran against: always the physical disk, also for a
    /// partition or dm source (R6), whose values then describe that disk
    pub probed_device: Option<String>,
    pub ata: Option<AtaCapacity>,
    pub nvme: Option<NvmeCapacity>,
    /// Commands used, e.g. "hdparm -N; hdparm --dco-identify", or why none ran
    pub method: String,
    pub errors: Vec<String>,
}

impl CapacityInfo {
    /// No probe ran (policy, regular file, unsupported transport).
    pub fn not_probed(reported_bytes: u64, reason: impl Into<String>) -> Self {
        Self {
            reported_bytes,
            method: format!("not probed: {}", reason.into()),
            ..Default::default()
        }
    }

    /// `Some(true)`: an HPA or DCO hides sectors; `Some(false)`: probed and
    /// none found; `None`: unknown.
    pub fn hidden_area(&self) -> Option<bool> {
        let ata = self.ata.as_ref()?;
        match (ata.hpa_present, ata.dco_present) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            (Some(false), None) | (None, Some(false)) | (None, None) => None,
        }
    }

    /// Human statements about hidden areas, for warnings and the report.
    pub fn hidden_area_statements(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(ata) = &self.ata {
            if ata.hpa_present == Some(true) {
                match (ata.native_max_sectors, ata.current_max_sectors) {
                    (Some(native), Some(current)) if native > current => out.push(format!(
                        "Host Protected Area: {} sectors ({}) beyond the visible end are hidden",
                        native - current,
                        format_iec((native - current).saturating_mul(512))
                    )),
                    _ => out.push("Host Protected Area present".to_string()),
                }
            }
            if ata.dco_present == Some(true) {
                out.push(match (ata.dco_real_max_sectors, ata.native_max_sectors) {
                    (Some(real), Some(native)) if real > native => format!(
                        "Device Configuration Overlay: {} sectors beyond the native maximum are hidden",
                        real - native
                    ),
                    _ => "Device Configuration Overlay present".to_string(),
                });
            }
        }
        out
    }

    /// One line for the report.
    pub fn summary(&self) -> String {
        let statements = self.hidden_area_statements();
        match self.hidden_area() {
            Some(true) => format!("HIDDEN AREA: {}", statements.join("; ")),
            Some(false) => "no HPA or DCO found".to_string(),
            None => format!("hidden areas unknown ({})", self.method),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_area_states() {
        let none = CapacityInfo::not_probed(1000, "smart policy off");
        assert_eq!(none.hidden_area(), None);
        assert!(none.summary().contains("not probed: smart policy off"));

        let clean = CapacityInfo {
            ata: Some(AtaCapacity {
                native_max_sectors: Some(100),
                current_max_sectors: Some(100),
                hpa_present: Some(false),
                dco_real_max_sectors: Some(100),
                dco_present: Some(false),
            }),
            ..Default::default()
        };
        assert_eq!(clean.hidden_area(), Some(false));
        assert_eq!(clean.summary(), "no HPA or DCO found");

        let hpa = CapacityInfo {
            ata: Some(AtaCapacity {
                native_max_sectors: Some(3000),
                current_max_sectors: Some(1000),
                hpa_present: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(hpa.hidden_area(), Some(true));
        assert!(hpa.summary().contains("2000 sectors"), "{}", hpa.summary());
    }
}
