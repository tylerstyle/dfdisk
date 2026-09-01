use crate::models::{
    case::CaseMetadata,
    config::AcquisitionConfig,
    device::{format_bytes, BlockDevice},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HashResults {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicInfoReport {
    pub tool_name: String,
    pub tool_version: String,
    pub case_metadata: CaseMetadata,
    pub device: BlockDevice,
    pub config: AcquisitionConfig,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub elapsed_seconds: u64,
    pub average_speed_bytes_sec: f64,
    pub bad_sectors_count: u64,
    pub source_hashes: HashResults,
    pub destination_hashes: HashResults,
    pub verification_passed: bool,
    pub generated_files: Vec<String>,
}

impl ForensicInfoReport {
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "================================================================================\n",
        );
        out.push_str("                         DFDISK FORENSIC ACQUISITION REPORT\n");
        out.push_str(
            "================================================================================\n\n",
        );

        // Case Information
        out.push_str("[CASE INFORMATION]\n");
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Case Number", self.case_metadata.case_number
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Location / EA", self.case_metadata.location_ea
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Evidence Number", self.case_metadata.evidence_number
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Authority / Agency", self.case_metadata.authority
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Examiner", self.case_metadata.examiner
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Description", self.case_metadata.description
        ));
        if !self.case_metadata.notes.trim().is_empty() {
            out.push_str(&format!(
                "{:<20}: {}\n",
                "Examiner Notes",
                self.case_metadata.notes.trim()
            ));
        }
        out.push('\n');

        // Source Hardware Specifications
        out.push_str("[SOURCE HARDWARE SPECIFICATIONS]\n");
        out.push_str(&format!("{:<20}: {}\n", "Device Node", self.device.path));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Vendor / Model",
            self.device.display_name()
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Serial Number",
            self.device.display_serial()
        ));
        if let Some(rev) = &self.device.revision {
            out.push_str(&format!("{:<20}: {}\n", "Firmware / Revision", rev));
        }
        if let Some(wwn) = &self.device.wwn {
            out.push_str(&format!("{:<20}: {}\n", "WWN / EUI", wwn));
        }
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Bus Interface", self.device.bus_type
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Media Type",
            self.device.media_type_str()
        ));
        out.push_str(&format!(
            "{:<20}: Logical: {} bytes | Physical: {} bytes\n",
            "Sector Size", self.device.logical_sector_size, self.device.physical_sector_size
        ));
        let total_sectors = if self.device.logical_sector_size > 0 {
            self.device.size_bytes / self.device.logical_sector_size as u64
        } else {
            0
        };
        out.push_str(&format!(
            "{:<20}: {} sectors\n",
            "Total Sectors", total_sectors
        ));
        out.push_str(&format!(
            "{:<20}: {} bytes ({})\n",
            "Total Capacity",
            self.device.size_bytes,
            format_bytes(self.device.size_bytes)
        ));
        if let Some(pt) = &self.device.partition_table_type {
            out.push_str(&format!(
                "{:<20}: {}\n",
                "Partition Scheme",
                pt.to_uppercase()
            ));
        }
        if !self.device.devlinks.is_empty() {
            out.push_str(&format!(
                "{:<20}: {}\n",
                "Device Link", self.device.devlinks[0]
            ));
        }

        // SMART Information
        if let Some(smart) = &self.device.smart {
            out.push_str(&format!(
                "{:<20}: {}\n",
                "SMART Overall",
                if smart.passed {
                    "PASSED"
                } else {
                    "FAILED / WARNING"
                }
            ));
            if let Some(realloc) = smart.reallocated_sectors {
                out.push_str(&format!("{:<20}: {}\n", "Reallocated Sectors", realloc));
            }
            if let Some(pending) = smart.pending_sectors {
                out.push_str(&format!("{:<20}: {}\n", "Pending Sectors", pending));
            }
            if let Some(temp) = smart.temperature_celsius {
                out.push_str(&format!("{:<20}: {} °C\n", "Temperature", temp));
            }
            if let Some(poh) = smart.power_on_hours {
                out.push_str(&format!("{:<20}: {} hours\n", "Power-on Hours", poh));
            }
        }
        out.push('\n');

        // Acquisition Configuration
        out.push_str("[ACQUISITION CONFIGURATION]\n");
        out.push_str(&format!(
            "{:<20}: {} v{}\n",
            "Acquisition Tool", self.tool_name, self.tool_version
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Output Format",
            self.config.format.display_name()
        ));
        out.push_str(&format!(
            "{:<20}: {:?}\n",
            "Compression", self.config.compression
        ));
        out.push_str(&format!(
            "{:<20}: {}\n",
            "Segment Split Size",
            self.config.split_size.display_name()
        ));
        out.push_str(&format!(
            "{:<20}: Retries: {} | Wipe bad sectors: {}\n",
            "Error Handling",
            self.config.error_retries,
            if self.config.wipe_bad_sectors {
                "Yes (Zero-fill)"
            } else {
                "No"
            }
        ));
        out.push('\n');

        // Timestamps & Performance
        out.push_str("[ACQUISITION TIMESTAMPS & PERFORMANCE]\n");
        out.push_str(&format!(
            "{:<20}: {} UTC\n",
            "Started",
            self.started_at.format("%Y-%m-%d %H:%M:%S")
        ));
        out.push_str(&format!(
            "{:<20}: {} UTC\n",
            "Ended",
            self.ended_at.format("%Y-%m-%d %H:%M:%S")
        ));
        let elapsed_formatted = crate::models::telemetry::format_duration(self.elapsed_seconds);
        out.push_str(&format!("{:<20}: {}\n", "Elapsed Time", elapsed_formatted));
        let mbs = self.average_speed_bytes_sec / (1024.0 * 1024.0);
        out.push_str(&format!("{:<20}: {:.2} MB/s\n", "Average Speed", mbs));
        out.push_str(&format!(
            "{:<20}: {} sectors\n",
            "Bad / Error Sectors", self.bad_sectors_count
        ));
        out.push('\n');

        // Cryptographic Hashes & Verification
        out.push_str("[CRYPTOGRAPHIC INTEGRITY & VERIFICATION]\n");
        if let Some(h) = &self.source_hashes.md5 {
            out.push_str(&format!("{:<20}: {}\n", "Source MD5", h));
        }
        if let Some(h) = &self.source_hashes.sha1 {
            out.push_str(&format!("{:<20}: {}\n", "Source SHA-1", h));
        }
        if let Some(h) = &self.source_hashes.sha256 {
            out.push_str(&format!("{:<20}: {}\n", "Source SHA-256", h));
        }
        out.push('\n');

        if let Some(h) = &self.destination_hashes.md5 {
            out.push_str(&format!("{:<20}: {}\n", "Image MD5", h));
        }
        if let Some(h) = &self.destination_hashes.sha1 {
            out.push_str(&format!("{:<20}: {}\n", "Image SHA-1", h));
        }
        if let Some(h) = &self.destination_hashes.sha256 {
            out.push_str(&format!("{:<20}: {}\n", "Image SHA-256", h));
        }
        out.push('\n');

        let status_str = if self.verification_passed {
            "VERIFIED - ALL HASHES MATCH (Acquisition Integrity Confirmed)"
        } else {
            "WARNING - HASH MISMATCH OR VERIFICATION INCOMPLETE"
        };
        out.push_str(&format!("{:<20}: {}\n", "Verification Result", status_str));

        if !self.generated_files.is_empty() {
            out.push_str("\n[GENERATED EVIDENCE FILES]\n");
            for f in &self.generated_files {
                out.push_str(&format!(" - {}\n", f));
            }
        }

        out.push_str(
            "================================================================================\n",
        );
        out
    }
}
