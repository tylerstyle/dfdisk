#![allow(unused_imports, dead_code)]

#[path = "../src/models/mod.rs"]
mod models;

#[path = "../src/engines/mod.rs"]
mod engines;

use chrono::Utc;
use engines::ewf::verify_ewf_hashes;
use models::{
    case::CaseMetadata,
    config::AcquisitionConfig,
    device::{BlockDevice, DeviceSafety},
    info_report::{ForensicInfoReport, HashResults},
};

#[test]
fn test_verify_ewf_hashes_comprehensive_matrix() {
    let md5_good = "5eb63bbbe01eeed093cb22bb8f5acdc3".to_string();
    let md5_bad = "00000000000000000000000000000000".to_string();
    let sha1_good = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed".to_string();
    let sha1_bad = "1111111111111111111111111111111111111111".to_string();
    let sha256_good =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string();
    let sha256_bad = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

    // 1. Dual-hash default scenario:
    // Source has MD5 + SHA-1 + SHA-256 (computed via MultiHasher)
    // Destination has MD5 + SHA-256 (ewfacquire default dual-hash)
    let source_default = HashResults {
        md5: Some(md5_good.clone()),
        sha1: Some(sha1_good.clone()),
        sha256: Some(sha256_good.clone()),
    };
    let dest_default = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: Some(sha256_good.clone()),
    };
    assert!(
        verify_ewf_hashes(&source_default, &dest_default),
        "Standard dual-hash default scenario must pass verification"
    );

    // 2. All 3 hashes match
    let dest_all_match = HashResults {
        md5: Some(md5_good.clone()),
        sha1: Some(sha1_good.clone()),
        sha256: Some(sha256_good.clone()),
    };
    assert!(verify_ewf_hashes(&source_default, &dest_all_match));

    // 3. Case insensitivity (lowercase vs uppercase hex)
    let dest_uppercase = HashResults {
        md5: Some(md5_good.to_uppercase()),
        sha1: None,
        sha256: Some(sha256_good.to_uppercase()),
    };
    assert!(
        verify_ewf_hashes(&source_default, &dest_uppercase),
        "Hash comparison must be ASCII case-insensitive"
    );

    // 4. Single hash match scenarios
    let source_md5_only = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: None,
    };
    let dest_md5_only = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: None,
    };
    assert!(verify_ewf_hashes(&source_md5_only, &dest_md5_only));

    let source_sha256_only = HashResults {
        md5: None,
        sha1: None,
        sha256: Some(sha256_good.clone()),
    };
    let dest_sha256_only = HashResults {
        md5: None,
        sha1: None,
        sha256: Some(sha256_good.clone()),
    };
    assert!(verify_ewf_hashes(&source_sha256_only, &dest_sha256_only));

    // 5. Mismatch scenarios
    // MD5 mismatch
    let dest_md5_mismatch = HashResults {
        md5: Some(md5_bad),
        sha1: None,
        sha256: Some(sha256_good.clone()),
    };
    assert!(
        !verify_ewf_hashes(&source_default, &dest_md5_mismatch),
        "Must fail when MD5 mismatches"
    );

    // SHA-256 mismatch
    let dest_sha256_mismatch = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: Some(sha256_bad),
    };
    assert!(
        !verify_ewf_hashes(&source_default, &dest_sha256_mismatch),
        "Must fail when SHA-256 mismatches"
    );

    // SHA-1 mismatch
    let dest_sha1_mismatch = HashResults {
        md5: Some(md5_good.clone()),
        sha1: Some(sha1_bad),
        sha256: Some(sha256_good.clone()),
    };
    assert!(
        !verify_ewf_hashes(&source_default, &dest_sha1_mismatch),
        "Must fail when SHA-1 mismatches"
    );

    // 6. Empty / None scenarios (rejection of tautological None == None match)
    let all_none_1 = HashResults::default();
    let all_none_2 = HashResults::default();
    assert!(
        !verify_ewf_hashes(&all_none_1, &all_none_2),
        "All None hashes must NEVER pass verification"
    );
    assert!(
        !verify_ewf_hashes(&source_default, &all_none_2),
        "Destination with no hashes must not pass"
    );
    assert!(
        !verify_ewf_hashes(&all_none_1, &dest_default),
        "Source with no hashes must not pass"
    );

    // 7. Destination missing in source
    let source_no_sha1 = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: Some(sha256_good),
    };
    let dest_has_sha1 = HashResults {
        md5: Some(md5_good),
        sha1: Some(sha1_good),
        sha256: None,
    };
    assert!(
        !verify_ewf_hashes(&source_no_sha1, &dest_has_sha1),
        "Must fail when destination expects SHA-1 but source does not have it"
    );
}

#[test]
fn test_truthful_forensic_reporting_damaged_media_rescue() {
    let dest_hashes = HashResults {
        md5: Some("79054025255fb1a26e4bc422aef54eb4".to_string()),
        sha1: None,
        sha256: Some(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
        ),
    };

    let bad_sectors = 142;
    let report = ForensicInfoReport {
        tool_name: "dfdisk (ddrescue engine)".to_string(),
        tool_version: "0.1.1".to_string(),
        case_metadata: CaseMetadata {
            case_number: "CRIME-2026/RESQ".to_string(),
            location_ea: "EA-01".to_string(),
            evidence_number: "BAD-DISK-01".to_string(),
            authority: "State Police Forensic Lab".to_string(),
            examiner: "Forensic Specialist".to_string(),
            description: "Damaged HDD with bad sectors".to_string(),
            notes: "DDRescue resilient pass".to_string(),
        },
        device: BlockDevice {
            name: "sdd".to_string(),
            path: "/dev/sdd".to_string(),
            devlinks: vec![],
            size_bytes: 500107862016,
            model: Some("Damaged Western Digital".to_string()),
            vendor: Some("WDC".to_string()),
            serial: Some("WD-WCC4M0000000".to_string()),
            wwn: None,
            revision: None,
            bus_type: "SATA".to_string(),
            is_rotational: Some(true),
            is_removable: false,
            is_read_only: false,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            partition_table_type: Some("gpt".to_string()),
            partitions: vec![],
            mountpoints: vec![],
            safety: DeviceSafety::Safe,
            smart: None,
        },
        config: AcquisitionConfig {
            rescue_mode: true,
            error_retries: 3,
            wipe_bad_sectors: true,
            ..Default::default()
        },
        started_at: Utc::now(),
        ended_at: Utc::now(),
        elapsed_seconds: 7200,
        average_speed_bytes_sec: 69459425.0,
        bad_sectors_count: bad_sectors,
        // Crucial forensic truthfulness:
        // Source hashes over damaged media CANNOT be genuinely computed.
        // Therefore source_hashes must be None, and verification_passed must be false.
        source_hashes: HashResults::default(),
        destination_hashes: dest_hashes.clone(),
        verification_passed: false,
        generated_files: vec![
            "crime_2026_resq_eaea_01_bad_disk_01_WD-WCC4M0000000.raw".to_string(),
            "crime_2026_resq_eaea_01_bad_disk_01_WD-WCC4M0000000.map".to_string(),
        ],
    };

    // 1. Assert structured integrity
    assert!(report.source_hashes.md5.is_none());
    assert!(report.source_hashes.sha1.is_none());
    assert!(report.source_hashes.sha256.is_none());

    assert_eq!(report.destination_hashes.md5, dest_hashes.md5);
    assert_eq!(report.destination_hashes.sha256, dest_hashes.sha256);

    assert!(!report.verification_passed);
    assert_eq!(report.bad_sectors_count, 142);

    // 2. Render and verify court certificate text
    let cert_text = report.render_text();

    // Must warn that verification is incomplete due to media damage
    assert!(
        cert_text.contains("WARNING - HASH MISMATCH OR VERIFICATION INCOMPLETE"),
        "Court certificate must explicitly flag incomplete verification on damaged media"
    );

    // Must NEVER claim complete verification
    assert!(
        !cert_text.contains("VERIFIED - ALL HASHES MATCH"),
        "Court certificate must NOT claim verified match over damaged sectors"
    );

    // Must truthfully report bad sector count
    assert!(
        cert_text.contains("142 sectors"),
        "Certificate must state bad sector count"
    );

    // Must show Image hashes but omit Source hashes
    assert!(cert_text.contains("Image MD5"));
    assert!(cert_text.contains("Image SHA-256"));
    assert!(!cert_text.contains("Source MD5"));
    assert!(!cert_text.contains("Source SHA-1"));
    assert!(!cert_text.contains("Source SHA-256"));
}
