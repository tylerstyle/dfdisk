use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaseMetadata {
    pub case_number: String,
    pub location_ea: String,
    pub evidence_number: String,
    pub authority: String,
    pub examiner: String,
    pub description: String,
    pub notes: String,
}

impl CaseMetadata {
    /// Returns the effective case number (or default fallback if empty)
    pub fn effective_case(&self) -> &str {
        let t = self.case_number.trim();
        if t.is_empty() {
            "CASE001"
        } else {
            t
        }
    }

    /// Returns the effective location/EA (or default fallback if empty)
    pub fn effective_ea(&self) -> &str {
        let t = self.location_ea.trim();
        if t.is_empty() {
            "01"
        } else {
            t
        }
    }

    /// Returns the effective evidence number (or default fallback if empty)
    pub fn effective_evidence(&self) -> &str {
        let t = self.evidence_number.trim();
        if t.is_empty() {
            "cf01"
        } else {
            t
        }
    }

    /// Returns the effective authority (or default fallback if empty)
    #[allow(dead_code)]
    pub fn effective_authority(&self) -> &str {
        let t = self.authority.trim();
        if t.is_empty() {
            "Law Enforcement / DFIR Unit"
        } else {
            t
        }
    }

    /// Returns the effective examiner (or default fallback if empty)
    pub fn effective_examiner(&self) -> &str {
        let t = self.examiner.trim();
        if t.is_empty() {
            "Forensic Examiner"
        } else {
            t
        }
    }

    /// Returns the effective description
    pub fn effective_description<'a>(&'a self, fallback: &'a str) -> &'a str {
        let t = self.description.trim();
        if t.is_empty() {
            fallback
        } else {
            t
        }
    }

    /// Sanitizes the case number (e.g. "VG12345/26" -> "vg12345_26")
    pub fn sanitized_case(&self) -> String {
        sanitize_token(self.effective_case()).to_lowercase()
    }

    /// Formats the location / EA (e.g. "01" -> "ea01", "ea02" -> "ea02")
    pub fn formatted_ea(&self) -> String {
        let clean = sanitize_token(self.effective_ea()).to_lowercase();
        if clean.starts_with("ea") {
            clean
        } else {
            format!("ea{}", clean)
        }
    }

    /// Formats the evidence number (e.g. "CF01" -> "cf01")
    pub fn formatted_evidence(&self) -> String {
        sanitize_token(self.effective_evidence()).to_lowercase()
    }

    /// Generates the standard forensic base filename:
    /// e.g. "vg12345_26_ea01_cf01_SERIALNUMBER"
    pub fn generate_base_filename(&self, serial: &str) -> String {
        let case = self.sanitized_case();
        let ea = self.formatted_ea();
        let ev = self.formatted_evidence();
        let clean_serial = sanitize_serial(serial);

        format!("{}_{}_{}_{}", case, ea, ev, clean_serial)
    }

    /// Generates full filename with extension (e.g. "vg12345_26_ea01_cf01_SERIALNUMBER.e01")
    pub fn generate_filename(&self, serial: &str, extension: &str) -> String {
        let base = self.generate_base_filename(serial);
        let ext = extension.trim_start_matches('.');
        format!("{}.{}", base, ext)
    }
}

fn sanitize_token(input: &str) -> String {
    let mut out = String::new();
    for c in input.chars() {
        if c.is_alphanumeric() {
            out.push(c);
        } else if (c == '/' || c == '-' || c == '_' || c == '.' || c == ' ')
            && (!out.ends_with('_') && !out.is_empty())
        {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn sanitize_serial(serial: &str) -> String {
    let s = serial.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("unknown") || s.eq_ignore_ascii_case("no_serial") {
        "NOSERIAL".to_string()
    } else {
        let cleaned = s
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_uppercase();

        if cleaned.is_empty() {
            "NOSERIAL".to_string()
        } else {
            cleaned
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filename_generation() {
        let meta = CaseMetadata {
            case_number: "VG12345/26".to_string(),
            location_ea: "01".to_string(),
            evidence_number: "cf01".to_string(),
            authority: "Police".to_string(),
            examiner: "Investigator".to_string(),
            description: "Test".to_string(),
            notes: "".to_string(),
        };

        assert_eq!(
            meta.generate_filename("S4GFNX0T501075", "e01"),
            "vg12345_26_ea01_cf01_S4GFNX0T501075.e01"
        );
        assert_eq!(
            meta.generate_filename("S4GFNX0T501075", "info"),
            "vg12345_26_ea01_cf01_S4GFNX0T501075.info"
        );
    }

    #[test]
    fn test_sanitize_serial_fallbacks() {
        assert_eq!(sanitize_serial(""), "NOSERIAL");
        assert_eq!(sanitize_serial("   "), "NOSERIAL");
        assert_eq!(sanitize_serial("###"), "NOSERIAL");
        assert_eq!(sanitize_serial("___"), "NOSERIAL");
        assert_eq!(sanitize_serial("!@#$%^&*()"), "NOSERIAL");
        assert_eq!(sanitize_serial("unknown"), "NOSERIAL");
        assert_eq!(sanitize_serial("UNKNOWN"), "NOSERIAL");
        assert_eq!(sanitize_serial("no_serial"), "NOSERIAL");
        assert_eq!(sanitize_serial("NO_SERIAL"), "NOSERIAL");
        assert_eq!(sanitize_serial("S4GFNX0T501075"), "S4GFNX0T501075");
        assert_eq!(sanitize_serial("wd-wcc 4m/123"), "WD-WCC_4M_123");
    }

    #[test]
    fn test_case_metadata_defaults() {
        let meta = CaseMetadata::default();
        assert_eq!(meta.effective_case(), "CASE001");
        assert_eq!(meta.effective_ea(), "01");
        assert_eq!(meta.effective_evidence(), "cf01");
        assert_eq!(meta.formatted_ea(), "ea01");
        assert_eq!(meta.formatted_evidence(), "cf01");
        assert_eq!(
            meta.generate_base_filename("###"),
            "case001_ea01_cf01_NOSERIAL"
        );
    }

    #[test]
    fn test_case_naming_and_serial_adversarial_stress() {
        let edge_serials = [
            "",
            "   ",
            "unknown",
            "UNKNOWN",
            "no_serial",
            "NO_SERIAL",
            "!!!",
            "---",
            "___",
            "/dev/sda",
            "🚀🔒🛡️",
            "SN#123-456_789.abc",
            "München_Festplatte_01",
            "硬盘_9999",
            "   ___---___   ",
        ];

        for serial in edge_serials {
            let meta = CaseMetadata {
                case_number: "2026/CRIME/01".to_string(),
                location_ea: "EA-1".to_string(),
                evidence_number: "EVD#99".to_string(),
                authority: "BKA".to_string(),
                examiner: "Müller".to_string(),
                description: "Forensic image".to_string(),
                notes: "".to_string(),
            };

            let base = meta.generate_base_filename(serial);
            assert!(!base.is_empty(), "Base filename must never be empty");
            assert!(!base.contains(' '), "Base filename must not contain spaces");
            assert!(
                !base.contains('/'),
                "Base filename must not contain slashes"
            );

            let full = meta.generate_filename(serial, "e01");
            assert!(
                full.ends_with(".e01"),
                "Full filename must have correct extension"
            );
        }

        // Adversarial case metadata fields (all pure punctuation or whitespace)
        let meta_adversarial = CaseMetadata {
            case_number: "///...---___".to_string(),
            location_ea: "???!!!".to_string(),
            evidence_number: "   ".to_string(),
            authority: "".to_string(),
            examiner: "".to_string(),
            description: "".to_string(),
            notes: "".to_string(),
        };
        let base_adv = meta_adversarial.generate_base_filename("___");
        assert_eq!(base_adv, "unknown_eaunknown_cf01_NOSERIAL");
        let full_adv = meta_adversarial.generate_filename("___", ".raw");
        assert_eq!(full_adv, "unknown_eaunknown_cf01_NOSERIAL.raw");
    }
}
