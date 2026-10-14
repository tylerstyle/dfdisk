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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VerificationStatus {
    /// Source and destination hashes strictly match
    Verified,
    /// Hashes were computed for both source and destination, but do not match
    Mismatch,
    /// Damaged media rescue: live source hashing not possible due to bad sectors; destination image hashes recorded
    DamagedMedia,
    /// Verification failed due to read/write errors or incomplete execution
    Failed,
    /// Verification was not requested or skipped
    #[default]
    NotVerified,
    /// Acquisition stopped before the end of the source; the image and its
    /// hashes cover only the bytes that were read
    Incomplete,
}

pub use crate::models::config::HashSelection;

/// Compare source and destination digests for the selected algorithms only.
/// Digests that were not selected are ignored, so disabling an algorithm can
/// never produce a mismatch. A selected digest missing on either side fails.
pub fn compare_selected(
    selection: HashSelection,
    source: &HashResults,
    destination: &HashResults,
) -> VerificationStatus {
    let pairs = [
        (selection.md5, &source.md5, &destination.md5),
        (selection.sha1, &source.sha1, &destination.sha1),
        (selection.sha256, &source.sha256, &destination.sha256),
    ];
    let mut compared = 0;
    let mut missing = false;
    for (selected, s, d) in pairs {
        if !selected {
            continue;
        }
        match (s, d) {
            (Some(s), Some(d)) if !s.eq_ignore_ascii_case(d) => {
                return VerificationStatus::Mismatch
            }
            (Some(_), Some(_)) => compared += 1,
            _ => missing = true,
        }
    }
    if missing || compared == 0 {
        VerificationStatus::Failed
    } else {
        VerificationStatus::Verified
    }
}

/// Why and where an acquisition stopped before the end of the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncompleteAcquisition {
    pub bytes_acquired: u64,
    pub expected_bytes: u64,
    pub reason: String,
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
    #[serde(default)]
    pub verification_status: VerificationStatus,
    pub generated_files: Vec<String>,
    /// Hash of the audit-log record written when this acquisition started; the
    /// matching "finished" record carries this report's SHA-256
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_anchor: Option<String>,
    /// How read errors were actually handled, when it differs from what the
    /// configuration's retry / wipe settings would suggest
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_handling_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<IncompleteAcquisition>,
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
        match &self.error_handling_note {
            Some(note) => out.push_str(&format!("{:<20}: {}\n", "Error Handling", note)),
            None => out.push_str(&format!(
                "{:<20}: Retries: {} | Wipe bad sectors: {}\n",
                "Error Handling",
                self.config.error_retries,
                if self.config.wipe_bad_sectors {
                    "Yes (Zero-fill)"
                } else {
                    "No"
                }
            )),
        }
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

        if let Some(inc) = &self.incomplete {
            out.push_str("[ACQUISITION RESULT]\n");
            out.push_str(&format!("{:<20}: INCOMPLETE\n", "Status"));
            out.push_str(&format!(
                "{:<20}: {} of {} bytes ({})\n",
                "Acquired",
                inc.bytes_acquired,
                inc.expected_bytes,
                format_bytes(inc.bytes_acquired)
            ));
            out.push_str(&format!("{:<20}: {}\n", "Stopped Because", inc.reason));
            out.push_str(&format!(
                "{:<20}: The image holds source bytes 0..{} only; nothing was zero-filled and all hashes below cover only that range.\n",
                "Note", inc.bytes_acquired
            ));
            out.push('\n');
        }

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

        let status_str = match self.verification_status {
            VerificationStatus::Verified => {
                "VERIFIED - ALL HASHES MATCH (Acquisition Integrity Confirmed)"
            }
            VerificationStatus::DamagedMedia => {
                "WARNING - HASH MISMATCH OR VERIFICATION INCOMPLETE (Damaged Media / Unreadable Sectors Present)"
            }
            VerificationStatus::Mismatch => {
                "CRITICAL ERROR - HASH MISMATCH (Evidence Invalidation / Cryptographic Disparity)"
            }
            VerificationStatus::Failed => {
                "WARNING - HASH MISMATCH OR VERIFICATION INCOMPLETE (Verification Failed)"
            }
            VerificationStatus::Incomplete => {
                "INCOMPLETE - ACQUISITION STOPPED EARLY (Image covers only the acquired range)"
            }
            VerificationStatus::NotVerified => {
                if self.verification_passed {
                    "VERIFIED - ALL HASHES MATCH (Acquisition Integrity Confirmed)"
                } else {
                    "WARNING - HASH MISMATCH OR VERIFICATION INCOMPLETE"
                }
            }
        };
        out.push_str(&format!("{:<20}: {}\n", "Verification Result", status_str));
        if let Some(anchor) = &self.audit_anchor {
            out.push_str(&format!(
                "{:<20}: {} (dfnix audit log)\n",
                "Audit Anchor", anchor
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_status_rendering() {
        let mut report = ForensicInfoReport {
            tool_name: "dfdisk".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            case_metadata: CaseMetadata::default(),
            device: BlockDevice::default(),
            config: AcquisitionConfig::default(),
            started_at: Utc::now(),
            ended_at: Utc::now(),
            elapsed_seconds: 10,
            average_speed_bytes_sec: 1000.0,
            bad_sectors_count: 0,
            source_hashes: HashResults::default(),
            destination_hashes: HashResults::default(),
            verification_passed: true,
            verification_status: VerificationStatus::Verified,
            generated_files: vec![],
            audit_anchor: None,
            error_handling_note: None,
            incomplete: None,
        };

        assert!(report.render_text().contains("VERIFIED - ALL HASHES MATCH"));

        report.verification_status = VerificationStatus::DamagedMedia;
        report.verification_passed = false;
        let txt = report.render_text();
        assert!(txt.contains("WARNING - HASH MISMATCH OR VERIFICATION INCOMPLETE (Damaged Media"));

        report.verification_status = VerificationStatus::Mismatch;
        assert!(report
            .render_text()
            .contains("CRITICAL ERROR - HASH MISMATCH"));
    }

    #[test]
    fn test_incomplete_rendering_never_claims_zero_fill() {
        let config = AcquisitionConfig {
            wipe_bad_sectors: true,
            ..Default::default()
        };
        let report = ForensicInfoReport {
            tool_name: "dfdisk (raw engine)".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            case_metadata: CaseMetadata::default(),
            device: BlockDevice::default(),
            config,
            started_at: Utc::now(),
            ended_at: Utc::now(),
            elapsed_seconds: 1,
            average_speed_bytes_sec: 1.0,
            bad_sectors_count: 0,
            source_hashes: HashResults::default(),
            destination_hashes: HashResults::default(),
            verification_passed: false,
            verification_status: VerificationStatus::Incomplete,
            generated_files: vec![],
            audit_anchor: None,
            error_handling_note: Some("None (stops at first read error)".to_string()),
            incomplete: Some(IncompleteAcquisition {
                bytes_acquired: 3584,
                expected_bytes: 5120,
                reason: "Input/output error at byte offset 3584".to_string(),
            }),
        };
        let txt = report.render_text();
        assert!(!txt.contains("Zero-fill"), "{txt}");
        assert!(txt.contains("INCOMPLETE"));
        assert!(txt.contains("3584 of 5120 bytes"));
        assert!(txt.contains("byte offset 3584"));
        assert!(txt.contains("None (stops at first read error)"));
    }

    fn h(md5: Option<&str>, sha1: Option<&str>, sha256: Option<&str>) -> HashResults {
        HashResults {
            md5: md5.map(str::to_string),
            sha1: sha1.map(str::to_string),
            sha256: sha256.map(str::to_string),
        }
    }

    #[test]
    fn test_compare_selected_ignores_unselected_digests() {
        let all = HashSelection {
            md5: true,
            sha1: true,
            sha256: true,
        };
        let no_sha1 = HashSelection {
            md5: true,
            sha1: false,
            sha256: true,
        };
        let no_sha256 = HashSelection {
            md5: true,
            sha1: true,
            sha256: false,
        };

        let src = h(Some("aa"), None, Some("cc"));
        // Destination carries an extra SHA-1 (e.g. recomputed by ewfverify): not a mismatch
        let dst = h(Some("AA"), Some("bb"), Some("cc"));
        assert_eq!(
            compare_selected(no_sha1, &src, &dst),
            VerificationStatus::Verified
        );

        let src = h(Some("aa"), Some("bb"), None);
        let dst = h(Some("aa"), Some("bb"), Some("zz"));
        assert_eq!(
            compare_selected(no_sha256, &src, &dst),
            VerificationStatus::Verified
        );

        // Selected but missing on one side
        assert_eq!(
            compare_selected(all, &src, &dst),
            VerificationStatus::Failed
        );
        // Real disagreement
        let dst = h(Some("aa"), Some("XX"), None);
        assert_eq!(
            compare_selected(no_sha256, &src, &dst),
            VerificationStatus::Mismatch
        );
        // Nothing selected is never a pass
        assert_eq!(
            compare_selected(HashSelection::default(), &src, &src),
            VerificationStatus::Failed
        );
    }
}
