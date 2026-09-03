#![allow(unused_imports, dead_code)]

#[path = "../src/models/mod.rs"]
mod models;

use models::case::CaseMetadata;

#[test]
fn test_evidence_filename_generation_format() {
    let meta = CaseMetadata {
        case_number: "CASE-2026/01".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "cf01".to_string(),
        authority: "DFIR Unit".to_string(),
        examiner: "Special Agent Smith".to_string(),
        description: "Seized NVMe Drive".to_string(),
        notes: "Acquired at scene".to_string(),
    };

    let base = meta.generate_base_filename("WD-WCC4M123456");
    assert_eq!(base, "case_2026_01_ea01_cf01_WD-WCC4M123456");

    // Extensions: E01, raw, info, leading dot trimming
    assert_eq!(
        meta.generate_filename("WD-WCC4M123456", "e01"),
        "case_2026_01_ea01_cf01_WD-WCC4M123456.e01"
    );
    assert_eq!(
        meta.generate_filename("WD-WCC4M123456", ".raw"),
        "case_2026_01_ea01_cf01_WD-WCC4M123456.raw"
    );
    assert_eq!(
        meta.generate_filename("WD-WCC4M123456", "info"),
        "case_2026_01_ea01_cf01_WD-WCC4M123456.info"
    );

    // If ea already starts with "ea", it should not be duplicated
    let meta_ea = CaseMetadata {
        case_number: "C1".to_string(),
        location_ea: "ea02".to_string(),
        evidence_number: "hd01".to_string(),
        ..Default::default()
    };
    assert_eq!(meta_ea.generate_base_filename("S123"), "c1_ea02_hd01_S123");
}

#[test]
fn test_sanitization_special_characters_and_spaces() {
    let meta = CaseMetadata {
        case_number: "Case #2026 / Sub-Dept . A".to_string(),
        location_ea: "Room 101 / Shelf B".to_string(),
        evidence_number: "Device (Mobile) #42".to_string(),
        ..Default::default()
    };

    let base = meta.generate_base_filename("WD WCC 4M 123");

    // Must not contain spaces, slashes, hashes, or parentheses
    assert!(
        !base.contains(' '),
        "Filename must not contain spaces: {}",
        base
    );
    assert!(
        !base.contains('/'),
        "Filename must not contain slashes: {}",
        base
    );
    assert!(
        !base.contains('#'),
        "Filename must not contain hashes: {}",
        base
    );
    assert!(
        !base.contains('('),
        "Filename must not contain parentheses: {}",
        base
    );
    assert!(
        !base.contains(')'),
        "Filename must not contain parentheses: {}",
        base
    );

    // Metadata tokens (case, ea, evidence) must have consecutive separators collapsed
    assert!(meta.sanitized_case().contains("case_2026_sub_dept_a"));
    assert!(!meta.sanitized_case().contains("__"));
    assert!(meta.formatted_ea().contains("earoom_101_shelf_b"));
    assert!(!meta.formatted_ea().contains("__"));
    assert!(meta.formatted_evidence().contains("device_mobile_42"));
    assert!(!meta.formatted_evidence().contains("__"));

    // Case number must be lowercase, serial uppercase
    assert!(base.starts_with("case_2026_sub_dept_a_"));
    assert!(base.ends_with("_WD_WCC_4M_123"));
}

#[test]
fn test_fallback_to_noserial_on_punctuation_only() {
    let punctuation_serials = [
        "",
        "   ",
        "\t\n",
        "###",
        "___",
        "!@#$%^&*()",
        "???///\\\\",
        "...",
        "_ _ _",
        "unknown",
        "UNKNOWN",
        "Unknown",
        "no_serial",
        "NO_SERIAL",
        "No_Serial",
    ];

    let meta = CaseMetadata {
        case_number: "VG100".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "cf01".to_string(),
        ..Default::default()
    };

    for serial in &punctuation_serials {
        let base = meta.generate_base_filename(serial);
        assert!(
            base.ends_with("_NOSERIAL"),
            "Serial '{}' must fall back to '_NOSERIAL', got: '{}'",
            serial,
            base
        );
    }
}

#[test]
fn test_multibyte_international_utf8() {
    let international_cases = [
        // German umlauts
        (
            "München-2026",
            "Asservat-ÄÖÜ",
            "Beweis-01",
            "Platte-München",
        ),
        // Cyrillic
        (
            "Дело-2026-99",
            "Кабинет-04",
            "Улика-01",
            "Диск-Серийный-123",
        ),
        // CJK (Chinese / Japanese)
        ("案件2026", "保管室01", "证据A1", "硬盘SN8888"),
        // Arabic
        ("قضية-2026", "موقع-01", "دليل-01", "قرص-12345"),
        // Emoji & Symbols
        ("Case-🚀-01", "EA-🔒", "EV-🛡️", "SERIAL-🎯-999"),
    ];

    for (c, ea, ev, s) in international_cases {
        let meta = CaseMetadata {
            case_number: c.to_string(),
            location_ea: ea.to_string(),
            evidence_number: ev.to_string(),
            authority: "International DFIR".to_string(),
            examiner: "Examiner Müller".to_string(),
            description: "Cross-border forensic acquisition".to_string(),
            notes: "".to_string(),
        };

        // Generation must not panic
        let base = meta.generate_base_filename(s);
        let full = meta.generate_filename(s, "E01");

        assert!(!base.is_empty(), "Base filename must not be empty");
        assert!(
            !base.contains('/'),
            "Base filename must not contain slashes"
        );
        assert!(!base.contains(' '), "Base filename must not contain spaces");
        assert!(full.ends_with(".E01"), "Full filename must end with .E01");

        // Length in characters should be consistent
        assert!(base.chars().count() > 0);
    }
}

#[test]
fn test_metadata_defaults() {
    let default_meta = CaseMetadata::default();

    assert_eq!(default_meta.effective_case(), "CASE001");
    assert_eq!(default_meta.effective_ea(), "01");
    assert_eq!(default_meta.effective_evidence(), "cf01");
    assert_eq!(
        default_meta.effective_authority(),
        "Law Enforcement / DFIR Unit"
    );
    assert_eq!(default_meta.effective_examiner(), "Forensic Examiner");
    assert_eq!(
        default_meta.effective_description("Fallback Device"),
        "Fallback Device"
    );

    assert_eq!(default_meta.sanitized_case(), "case001");
    assert_eq!(default_meta.formatted_ea(), "ea01");
    assert_eq!(default_meta.formatted_evidence(), "cf01");

    let base = default_meta.generate_base_filename("");
    assert_eq!(base, "case001_ea01_cf01_NOSERIAL");
}
