//! Case metadata, its sanitisation for E01 headers and reports, and the
//! forensic file naming convention `{case}_{ea}_{evidence}_{serial}`, e.g.
//! "VG12345/26" + "01" + "cf01" + "EXS970A0004192" →
//! `vg12345_26_ea01_cf01_EXS970A0004192`.
//!
//! No placeholder ever becomes a recorded value: an empty field is "(not
//! provided)" in reports and omitted from E01 headers. The one default is the
//! EA/location number "01", a numbering convention rather than a placeholder.

use crate::models::text::sanitize_line;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// How reports show an optional case field that was left empty.
pub const NOT_PROVIDED: &str = "(not provided)";

/// EA / location number used when none is given (numbering convention).
pub const DEFAULT_EA: &str = "01";

/// Longest file name (in bytes) common filesystems accept.
pub const MAX_FILENAME_BYTES: usize = 255;

/// Every suffix dfdisk (or a tool it runs) appends to an acquisition's base
/// name. The longest of them decides whether a base name fits the 255-byte
/// file name limit. `.verify-<UTC>.txt` is the addendum of a re-verification.
pub const OUTPUT_SUFFIXES: &[&str] = &[
    ".E01",
    ".E99",
    ".EAA",
    ".raw",
    ".map",
    ".map.bak",
    ".info",
    ".info.tmp",
    ".info.json",
    ".info.json.tmp",
    ".info.reserve",
    ".info.session-999",
    ".pieces.tsv",
    ".pieces.tsv.tmp",
    ".identity.json",
    ".identity.json.tmp",
    ".smart-before.json",
    ".smart-after.json",
    ".ewfacquire.log",
    ".verify-20260101T000000Z.txt",
];

/// Length in bytes of the longest entry of [`OUTPUT_SUFFIXES`].
pub fn longest_output_suffix() -> usize {
    OUTPUT_SUFFIXES.iter().map(|s| s.len()).max().unwrap_or(0)
}

/// Refuse (never truncate) a base name that would make some output file name
/// longer than 255 bytes once `longest_suffix` bytes are appended.
pub fn check_filename_length(base: &str, longest_suffix: usize) -> Result<(), String> {
    let total = base.len() + longest_suffix;
    if total <= MAX_FILENAME_BYTES {
        return Ok(());
    }
    Err(format!(
        "The output base name is {} bytes long; with the longest suffix dfdisk writes ({} bytes) a file name would be {} bytes, more than the {}-byte limit. Shorten the case number, EA or evidence number: file names are never truncated.",
        base.len(),
        longest_suffix,
        total,
        MAX_FILENAME_BYTES
    ))
}

/// A header or report value: control characters (tab and newline included)
/// become single spaces, the value is trimmed and NFC-normalised.
pub fn sanitize_header(raw: &str) -> String {
    sanitize_line(raw).nfc().collect()
}

/// [`sanitize_header`], `None` when nothing is left.
pub fn header_value(raw: &str) -> Option<String> {
    Some(sanitize_header(raw)).filter(|v| !v.is_empty())
}

/// The value, or "(not provided)".
pub fn or_not_provided(value: Option<String>) -> String {
    value.unwrap_or_else(|| NOT_PROVIDED.to_string())
}

/// JSON form of an optional case field: an empty value is `null` (not `""`),
/// and `null` or a missing key reads back as empty. Text reports show
/// "(not provided)" instead.
mod empty_as_null {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &str, s: S) -> Result<S::Ok, S::Error> {
        if value.is_empty() {
            s.serialize_none()
        } else {
            s.serialize_some(value)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
    }
}

/// Case and chain-of-custody values. In JSON (the `.info.json` report), an
/// empty optional field is `null`; required fields are always strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseMetadata {
    /// Required
    pub case_number: String,
    /// EA / location number; "01" when empty
    #[serde(default, with = "empty_as_null")]
    pub location_ea: String,
    /// Required
    pub evidence_number: String,
    #[serde(default, with = "empty_as_null")]
    pub authority: String,
    /// Required
    pub examiner: String,
    #[serde(default, with = "empty_as_null")]
    pub description: String,
    #[serde(default, with = "empty_as_null")]
    pub notes: String,
    /// Chain of custody: number of the evidence seal
    #[serde(default, with = "empty_as_null")]
    pub seal_number: String,
    /// Chain of custody: when the evidence was seized (free text)
    #[serde(default, with = "empty_as_null")]
    pub seizure_time: String,
    /// Chain of custody: where the evidence was seized
    #[serde(default, with = "empty_as_null")]
    pub seizure_location: String,
}

impl CaseMetadata {
    /// Every acquisition records a case number, an evidence number and an
    /// examiner. The error names all missing fields and their CLI flags.
    pub fn validate_required(&self) -> Result<(), String> {
        let missing: Vec<&str> = [
            (self.effective_case(), "case number (--case)"),
            (self.effective_evidence(), "evidence number (--evidence)"),
            (self.effective_examiner(), "examiner (--examiner)"),
        ]
        .into_iter()
        .filter(|(value, _)| value.is_none())
        .map(|(_, name)| name)
        .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Required case information missing: {}. Every acquisition records them; nothing is filled in for you.",
                missing.join(", ")
            ))
        }
    }

    pub fn effective_case(&self) -> Option<String> {
        header_value(&self.case_number)
    }

    pub fn effective_evidence(&self) -> Option<String> {
        header_value(&self.evidence_number)
    }

    pub fn effective_examiner(&self) -> Option<String> {
        header_value(&self.examiner)
    }

    /// EA / location, "01" when empty (numbering convention, see module docs).
    pub fn effective_ea(&self) -> String {
        header_value(&self.location_ea).unwrap_or_else(|| DEFAULT_EA.to_string())
    }

    pub fn effective_authority(&self) -> Option<String> {
        header_value(&self.authority)
    }

    pub fn effective_description(&self) -> Option<String> {
        header_value(&self.description)
    }

    pub fn effective_notes(&self) -> Option<String> {
        header_value(&self.notes)
    }

    pub fn effective_seal_number(&self) -> Option<String> {
        header_value(&self.seal_number)
    }

    pub fn effective_seizure_time(&self) -> Option<String> {
        header_value(&self.seizure_time)
    }

    pub fn effective_seizure_location(&self) -> Option<String> {
        header_value(&self.seizure_location)
    }

    /// The values that are recorded: every field sanitised, the EA filled with
    /// its default, empty optional fields left empty.
    pub fn sanitized(&self) -> CaseMetadata {
        CaseMetadata {
            case_number: sanitize_header(&self.case_number),
            location_ea: self.effective_ea(),
            evidence_number: sanitize_header(&self.evidence_number),
            authority: sanitize_header(&self.authority),
            examiner: sanitize_header(&self.examiner),
            description: sanitize_header(&self.description),
            notes: sanitize_header(&self.notes),
            seal_number: sanitize_header(&self.seal_number),
            seizure_time: sanitize_header(&self.seizure_time),
            seizure_location: sanitize_header(&self.seizure_location),
        }
    }

    /// Report rows: (label, value or "(not provided)"), in report order.
    pub fn report_rows(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Case Number", or_not_provided(self.effective_case())),
            ("Location / EA", self.effective_ea()),
            (
                "Evidence Number",
                or_not_provided(self.effective_evidence()),
            ),
            ("Examiner", or_not_provided(self.effective_examiner())),
            (
                "Authority / Agency",
                or_not_provided(self.effective_authority()),
            ),
            ("Description", or_not_provided(self.effective_description())),
            ("Seal Number", or_not_provided(self.effective_seal_number())),
            (
                "Seized At (time)",
                or_not_provided(self.effective_seizure_time()),
            ),
            (
                "Seized At (place)",
                or_not_provided(self.effective_seizure_location()),
            ),
            ("Examiner Notes", or_not_provided(self.effective_notes())),
        ]
    }

    /// Notes for the E01 header (`ewfacquire -N`): the fields the E01 header
    /// has no own field for (authority, EA, seal, seizure) and the notes, only
    /// those provided, so the image and the .info record the same values.
    pub fn ewf_header_notes(&self) -> Option<String> {
        let parts: Vec<String> = [
            ("Authority", self.effective_authority()),
            ("EA", Some(self.effective_ea())),
            ("Seal", self.effective_seal_number()),
            ("Seized at", self.effective_seizure_time()),
            ("Seized in", self.effective_seizure_location()),
            ("Notes", self.effective_notes()),
        ]
        .into_iter()
        .filter_map(|(label, value)| value.map(|v| format!("{label}: {v}")))
        .collect();
        Some(parts.join("; ")).filter(|s| !s.is_empty())
    }

    /// Case number as a file name token (e.g. "VG12345/26" -> "vg12345_26").
    pub fn sanitized_case(&self) -> String {
        sanitize_token(&self.case_number).to_lowercase()
    }

    /// EA as a file name token ("01" -> "ea01", "ea02" -> "ea02").
    pub fn formatted_ea(&self) -> String {
        let clean = sanitize_token(&self.effective_ea()).to_lowercase();
        if clean.starts_with("ea") {
            clean
        } else {
            format!("ea{}", clean)
        }
    }

    /// Evidence number as a file name token ("CF01" -> "cf01").
    pub fn formatted_evidence(&self) -> String {
        sanitize_token(&self.evidence_number).to_lowercase()
    }

    /// The forensic base file name `{case}_{ea}_{evidence}_{serial}`, e.g.
    /// "vg12345_26_ea01_cf01_EXS970A0004192". Tokens are NFC-normalised; an
    /// empty or unusable token reads "unknown" (serial: "NOSERIAL"). For
    /// previews; acquisitions use [`base_filename_checked`](Self::base_filename_checked).
    pub fn generate_base_filename(&self, serial: &str) -> String {
        format!(
            "{}_{}_{}_{}",
            self.sanitized_case(),
            self.formatted_ea(),
            self.formatted_evidence(),
            sanitize_serial(serial)
        )
    }

    /// Base name plus extension (e.g. "vg12345_26_ea01_cf01_EXS970A0004192.e01").
    pub fn generate_filename(&self, serial: &str, extension: &str) -> String {
        let base = self.generate_base_filename(serial);
        let ext = extension.trim_start_matches('.');
        format!("{}.{}", base, ext)
    }

    /// The base name of an acquisition: required fields present and every
    /// output file name within 255 bytes, or the reason why not.
    pub fn base_filename_checked(&self, serial: &str) -> Result<String, String> {
        self.validate_required()?;
        let base = self.generate_base_filename(serial);
        check_filename_length(&base, longest_output_suffix())?;
        Ok(base)
    }
}

fn sanitize_token(input: &str) -> String {
    let normalized: String = sanitize_line(input).nfc().collect();
    let mut out = String::new();
    for c in normalized.chars() {
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
    let s: String = sanitize_line(serial).nfc().collect();
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

    fn full() -> CaseMetadata {
        CaseMetadata {
            case_number: "VG12345/26".to_string(),
            location_ea: "01".to_string(),
            evidence_number: "cf01".to_string(),
            authority: "Police".to_string(),
            examiner: "Investigator".to_string(),
            description: "Test".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_filename_generation() {
        let meta = full();
        assert_eq!(
            meta.generate_filename("EXS970A0004192", "e01"),
            "vg12345_26_ea01_cf01_EXS970A0004192.e01"
        );
        assert_eq!(
            meta.generate_filename("EXS970A0004192", "info"),
            "vg12345_26_ea01_cf01_EXS970A0004192.info"
        );
        assert_eq!(
            meta.base_filename_checked("EXS970A0004192").unwrap(),
            "vg12345_26_ea01_cf01_EXS970A0004192"
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
        assert_eq!(sanitize_serial("EXS970A0004192"), "EXS970A0004192");
        assert_eq!(sanitize_serial("wd-wcc 4m/123"), "WD-WCC_4M_123");
    }

    #[test]
    fn empty_case_invents_nothing() {
        let meta = CaseMetadata::default();
        assert_eq!(meta.effective_case(), None);
        assert_eq!(meta.effective_evidence(), None);
        assert_eq!(meta.effective_examiner(), None);
        assert_eq!(meta.effective_authority(), None);
        assert_eq!(meta.effective_description(), None);
        // The EA number is a numbering convention, not a placeholder
        assert_eq!(meta.effective_ea(), "01");
        assert_eq!(meta.formatted_ea(), "ea01");
        let err = meta.validate_required().unwrap_err();
        assert!(err.contains("case number (--case)"), "{err}");
        assert!(err.contains("evidence number (--evidence)"), "{err}");
        assert!(err.contains("examiner (--examiner)"), "{err}");
        assert!(meta.base_filename_checked("X").is_err());
        // Names never contain made-up case values
        assert_eq!(
            meta.generate_base_filename("###"),
            "unknown_ea01_unknown_NOSERIAL"
        );
        for (label, value) in meta.report_rows() {
            if label == "Location / EA" {
                assert_eq!(value, "01");
            } else {
                assert_eq!(value, NOT_PROVIDED, "{label}");
            }
        }
        assert_eq!(meta.ewf_header_notes().as_deref(), Some("EA: 01"));
    }

    #[test]
    fn whitespace_only_required_fields_are_missing() {
        let meta = CaseMetadata {
            case_number: " \t ".into(),
            evidence_number: "E1".into(),
            examiner: "\n".into(),
            ..Default::default()
        };
        let err = meta.validate_required().unwrap_err();
        assert!(err.contains("case number") && err.contains("examiner"));
        assert!(!err.contains("evidence number"));
        assert!(full().validate_required().is_ok());
    }

    #[test]
    fn header_values_are_single_line_trimmed_and_nfc() {
        assert_eq!(sanitize_header("  Case\t1\r\nline2  "), "Case 1 line2");
        assert_eq!(sanitize_header("e\u{301}"), "\u{e9}");
        assert_eq!(sanitize_header("\u{1b}[2Jcleared"), "[2Jcleared");
        assert_eq!(header_value(" \t\n"), None);
        let meta = CaseMetadata {
            examiner: "M\u{fc}ller\tJ.".into(),
            notes: "a\nb".into(),
            ..full()
        };
        let s = meta.sanitized();
        assert_eq!(s.examiner, "Müller J.");
        assert_eq!(s.notes, "a b");
        assert_eq!(s.location_ea, "01");
        assert_eq!(s.seal_number, "");
    }

    #[test]
    fn filename_tokens_are_nfc_normalised() {
        let composed = CaseMetadata {
            case_number: "Caf\u{e9}".into(),
            evidence_number: "\u{c4}1".into(),
            ..full()
        };
        let decomposed = CaseMetadata {
            case_number: "Cafe\u{301}".into(),
            evidence_number: "A\u{308}1".into(),
            ..full()
        };
        assert_eq!(
            composed.generate_base_filename("S\u{e9}R"),
            decomposed.generate_base_filename("Se\u{301}R")
        );
        assert_eq!(composed.sanitized_case(), "caf\u{e9}");
        assert_eq!(decomposed.formatted_evidence(), "\u{e4}1");
    }

    #[test]
    fn empty_optional_fields_serialise_as_null() {
        let meta = CaseMetadata {
            authority: "Police".into(),
            ..full()
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["authority"], "Police");
        assert_eq!(json["case_number"], "VG12345/26");
        assert!(json["notes"].is_null());
        assert!(json["seal_number"].is_null());
        assert_eq!(serde_json::from_value::<CaseMetadata>(json).unwrap(), meta);
        // Required fields stay strings even when empty; null optional fields
        // and missing keys read back as empty
        let empty = serde_json::to_value(CaseMetadata::default()).unwrap();
        assert_eq!(empty["case_number"], "");
        assert!(empty["location_ea"].is_null());
        let parsed: CaseMetadata = serde_json::from_str(
            r#"{"case_number":"C","evidence_number":"E","examiner":"X","notes":null}"#,
        )
        .unwrap();
        assert_eq!(parsed.notes, "");
        assert_eq!(parsed.authority, "");
    }

    #[test]
    fn chain_of_custody_fields_reach_reports_and_e01_notes() {
        let meta = CaseMetadata {
            seal_number: "S-0042".into(),
            seizure_time: "2026-10-14 09:30 local".into(),
            seizure_location: "Office 3".into(),
            notes: "Laptop drive".into(),
            ..full()
        };
        let rows = meta.report_rows();
        assert!(rows.contains(&("Seal Number", "S-0042".to_string())));
        assert!(rows.contains(&("Seized At (place)", "Office 3".to_string())));
        assert_eq!(
            meta.ewf_header_notes().as_deref(),
            Some("Authority: Police; EA: 01; Seal: S-0042; Seized at: 2026-10-14 09:30 local; Seized in: Office 3; Notes: Laptop drive")
        );
        // Old JSON without the new fields still loads
        let old = r#"{"case_number":"C","location_ea":"01","evidence_number":"E","authority":"","examiner":"X","description":"","notes":""}"#;
        let parsed: CaseMetadata = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.seal_number, "");
    }

    #[test]
    fn file_names_are_refused_not_truncated() {
        let longest = longest_output_suffix();
        assert_eq!(longest, ".verify-20260101T000000Z.txt".len());
        let fits = "a".repeat(MAX_FILENAME_BYTES - longest);
        assert!(check_filename_length(&fits, longest).is_ok());
        let err = check_filename_length(&format!("{fits}b"), longest).unwrap_err();
        assert!(err.contains("never truncated"), "{err}");
        assert!(err.contains("256 bytes"), "{err}");
        // Multi-byte characters count in bytes
        let meta = CaseMetadata {
            case_number: "\u{786c}".repeat(80),
            ..full()
        };
        assert!(meta.base_filename_checked("SER").is_err());
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
            "tab\tnew\nline",
        ];

        for serial in edge_serials {
            let meta = CaseMetadata {
                case_number: "2026/CRIME/01".to_string(),
                location_ea: "EA-1".to_string(),
                evidence_number: "EVD#99".to_string(),
                authority: "BKA".to_string(),
                examiner: "Müller".to_string(),
                description: "Forensic image".to_string(),
                ..Default::default()
            };

            let base = meta.generate_base_filename(serial);
            assert!(!base.is_empty(), "Base filename must never be empty");
            assert!(!base.contains(' '), "Base filename must not contain spaces");
            assert!(
                !base.contains('/'),
                "Base filename must not contain slashes"
            );
            assert!(!base.chars().any(char::is_control), "{base:?}");

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
            ..Default::default()
        };
        let base_adv = meta_adversarial.generate_base_filename("___");
        assert_eq!(base_adv, "unknown_eaunknown_unknown_NOSERIAL");
        let full_adv = meta_adversarial.generate_filename("___", ".raw");
        assert_eq!(full_adv, "unknown_eaunknown_unknown_NOSERIAL.raw");
    }
}
