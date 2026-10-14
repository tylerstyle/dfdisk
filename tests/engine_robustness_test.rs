mod common;

use common::{audit_sandbox, file_device};
use dfdisk::engines;
use dfdisk::models::{
    self,
    case::CaseMetadata,
    config::{AcquisitionConfig, EffectiveConfig, EngineKind},
    identity::SourceIdentity,
    info_report::{compare_digests, ForensicInfoReport, HashResults, HashSelection},
    outcome::{Outcome, RangeKind, VerificationResult},
};

fn verified(sel: HashSelection, src: &HashResults, dst: &HashResults) -> bool {
    compare_digests(sel, src, dst, "test").is_matched()
}

fn is_mismatch(r: VerificationResult) -> bool {
    matches!(r, VerificationResult::Mismatched { .. })
}

fn is_failed(r: VerificationResult) -> bool {
    matches!(r, VerificationResult::Failed { .. })
}

#[test]
fn test_compare_digests_comprehensive_matrix() {
    let md5_good = "5eb63bbbe01eeed093cb22bb8f5acdc3".to_string();
    let md5_bad = "00000000000000000000000000000000".to_string();
    let sha1_good = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed".to_string();
    let sha1_bad = "1111111111111111111111111111111111111111".to_string();
    let sha256_good =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string();
    let sha256_bad = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

    let all = HashSelection {
        md5: true,
        sha1: true,
        sha256: true,
    };
    let md5_sha256 = HashSelection {
        md5: true,
        sha1: false,
        sha256: true,
    };
    let md5_only = HashSelection {
        md5: true,
        sha1: false,
        sha256: false,
    };
    let sha256_only = HashSelection {
        md5: false,
        sha1: false,
        sha256: true,
    };

    let source_all = HashResults {
        md5: Some(md5_good.clone()),
        sha1: Some(sha1_good.clone()),
        sha256: Some(sha256_good.clone()),
    };
    let dest_md5_sha256 = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: Some(sha256_good.clone()),
    };

    // 1. Only the selected digests are compared
    assert!(verified(md5_sha256, &source_all, &dest_md5_sha256));
    assert!(verified(all, &source_all, &source_all));
    // A selected digest the image lacks is a failure, not a pass
    assert!(is_failed(compare_digests(
        all,
        &source_all,
        &dest_md5_sha256,
        "t"
    )));

    // 2. Case insensitivity (lowercase vs uppercase hex)
    let dest_uppercase = HashResults {
        md5: Some(md5_good.to_uppercase()),
        sha1: None,
        sha256: Some(sha256_good.to_uppercase()),
    };
    assert!(verified(md5_sha256, &source_all, &dest_uppercase));

    // 3. Single digest selections
    assert!(verified(md5_only, &source_all, &dest_md5_sha256));
    assert!(verified(sha256_only, &source_all, &dest_md5_sha256));

    // 4. Mismatches in any selected digest
    let dest_md5_mismatch = HashResults {
        md5: Some(md5_bad),
        sha1: None,
        sha256: Some(sha256_good.clone()),
    };
    assert!(is_mismatch(compare_digests(
        md5_sha256,
        &source_all,
        &dest_md5_mismatch,
        "t"
    )));
    let dest_sha256_mismatch = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: Some(sha256_bad),
    };
    assert!(is_mismatch(compare_digests(
        md5_sha256,
        &source_all,
        &dest_sha256_mismatch,
        "t"
    )));
    let dest_sha1_mismatch = HashResults {
        md5: Some(md5_good.clone()),
        sha1: Some(sha1_bad),
        sha256: Some(sha256_good.clone()),
    };
    assert!(is_mismatch(compare_digests(
        all,
        &source_all,
        &dest_sha1_mismatch,
        "t"
    )));
    // ...but a mismatch in an unselected digest is ignored
    assert!(verified(md5_sha256, &source_all, &dest_sha1_mismatch));

    // 5. Never a tautological pass
    let none = HashResults::default();
    assert!(!verified(all, &none, &none));
    assert!(!verified(all, &source_all, &none));
    assert!(!verified(all, &none, &source_all));
    assert!(!verified(
        HashSelection::default(),
        &source_all,
        &source_all
    ));

    // 6. Disabling SHA-1 while the image still reports one is not a mismatch
    let source_no_sha1 = HashResults {
        md5: Some(md5_good.clone()),
        sha1: None,
        sha256: Some(sha256_good),
    };
    let dest_has_sha1 = HashResults {
        md5: Some(md5_good),
        sha1: Some(sha1_good),
        sha256: source_no_sha1.sha256.clone(),
    };
    assert!(verified(md5_sha256, &source_no_sha1, &dest_has_sha1));
}

#[test]
fn test_truthful_forensic_reporting_damaged_media_rescue() {
    let image_hashes = HashResults {
        md5: Some("79054025255fb1a26e4bc422aef54eb4".to_string()),
        sha1: None,
        sha256: Some(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
        ),
    };
    let device = file_device(
        std::path::Path::new("/dev/dfdisk-test-sdd"),
        500107862016,
        Some("WD-WCC4M0000000"),
    );
    let source = SourceIdentity::from_block_device(&device);
    let config = AcquisitionConfig {
        rescue_mode: true,
        error_retries: 3,
        split_size: models::config::SplitSize::None,
        ..Default::default()
    };
    let case = CaseMetadata {
        case_number: "CRIME-2026/RESQ".to_string(),
        location_ea: "EA-01".to_string(),
        evidence_number: "BAD-DISK-01".to_string(),
        authority: "State Police Forensic Lab".to_string(),
        examiner: "Forensic Specialist".to_string(),
        description: "Damaged HDD with bad sectors".to_string(),
        notes: "DDRescue resilient pass".to_string(),
        ..Default::default()
    };
    let mut report = ForensicInfoReport::new(
        EngineKind::Rescue,
        &case,
        source.clone(),
        EffectiveConfig::build(&config, Some(&source)),
    );
    report.bytes_acquired = report.expected_bytes;
    // 142 bad sectors (ddrescue '-' areas) are zeros in the image
    report
        .read_errors
        .push_sectors(1_000_000, 100, RangeKind::Substituted);
    report
        .read_errors
        .push_sectors(2_000_000, 42, RangeKind::Substituted);
    report.image_hashes = image_hashes.clone();
    report.verification.result = VerificationResult::NotPossible {
        reason: "ddrescue computes no digest while reading".into(),
    };
    report.apply_classification();

    // 1. Structured truthfulness: no acquisition digest is invented
    assert!(report.acquisition_hashes.is_empty());
    assert_eq!(report.image_hashes, image_hashes);
    assert_eq!(report.outcome, Outcome::CompletedWithReadErrors);
    assert_eq!(report.exit_code, 7);
    assert_eq!(report.read_errors.substituted_sectors(), 142);

    // 2. The report says what the digests describe
    let cert_text = report.render_text();
    assert!(
        !cert_text.contains("ALL HASHES MATCH"),
        "Court certificate must NOT claim a verified match over damaged sectors"
    );
    assert!(cert_text.contains("COMPLETED WITH READ ERRORS (exit code 7)"));
    assert!(
        cert_text
            .contains("142 sectors (71 KiB) in 2 ranges were unreadable and replaced by zeros"),
        "{cert_text}"
    );
    assert!(cert_text.contains("not the original medium"));
    assert!(cert_text.contains("(none: no digest was computed while reading the source)"));
    assert!(cert_text.contains("MD5     : 79054025255fb1a26e4bc422aef54eb4"));
}

#[tokio::test]
async fn test_raw_acquisition_end_to_end() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let temp_dir = tmp.path();

    let source_disk = temp_dir.join("virtual_source.bin");
    let test_data = vec![0x42u8; 2 * 1024 * 1024]; // 2 MB of test data
    std::fs::write(&source_disk, &test_data).unwrap();

    let device = file_device(&source_disk, test_data.len() as u64, Some("VT10001"));

    let case = CaseMetadata {
        case_number: "CASE2026-RAW".to_string(),
        location_ea: "LOC01".to_string(),
        evidence_number: "EV01".to_string(),
        authority: "Federal Cybercrime Unit".to_string(),
        examiner: "Forensic Specialist".to_string(),
        description: "Test Raw Acquisition".to_string(),
        notes: "Automated verification test".to_string(),
        ..Default::default()
    };

    let out_dir = temp_dir.join("evidence_output");
    let config = AcquisitionConfig {
        format: models::config::ImageFormat::Raw,
        output_dir: out_dir.clone(),
        calc_md5: true,
        calc_sha1: true,
        calc_sha256: true,
        ..Default::default()
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel(50);
    let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    tokio::spawn(async move { while rx.recv().await.is_some() {} });

    let report = engines::raw::RawAcquireEngine::run_acquisition(device, case, config, tx, abort)
        .await
        .expect("RAW acquisition must succeed");

    assert_eq!(report.outcome, Outcome::Verified);
    assert_eq!(report.exit_code, 0);
    assert!(report.read_errors.is_empty());
    assert!(report.verification.result.is_matched());
    assert_eq!(report.acquisition_hashes.md5, report.image_hashes.md5);
    assert_eq!(report.acquisition_hashes.sha1, report.image_hashes.sha1);
    assert_eq!(report.acquisition_hashes.sha256, report.image_hashes.sha256);

    let cert_text = report.render_text();
    assert!(cert_text.contains("VERIFIED - ALL HASHES MATCH"));
    assert!(cert_text.contains("DFDISK FORENSIC ACQUISITION REPORT"));

    // Verify written raw file exists and matches source
    let expected_raw = std::path::PathBuf::from(&report.image_files[0]);
    assert!(expected_raw.exists());
    let written = std::fs::read(&expected_raw).unwrap();
    assert_eq!(written, test_data);

    // Both reports exist, and the JSON twin says the same
    let expected_info = expected_raw.with_extension("info");
    assert!(expected_info.exists());
    let json = std::fs::read_to_string(expected_raw.with_extension("info.json")).unwrap();
    let back = ForensicInfoReport::from_json(&json).unwrap();
    assert_eq!(back.outcome, Outcome::Verified);
    assert_eq!(
        std::fs::read_to_string(&expected_info).unwrap(),
        back.render_text()
    );
}

#[tokio::test]
async fn test_raw_acquisition_abort_reactivity() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let temp_dir = tmp.path();

    let source_disk = temp_dir.join("virtual_source.bin");
    let test_data = vec![0xaau8; 10 * 1024 * 1024]; // 10 MB
    std::fs::write(&source_disk, &test_data).unwrap();

    let device = file_device(&source_disk, test_data.len() as u64, Some("VT10002"));

    let case = CaseMetadata {
        case_number: "CASE-ABORT".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "CF01".to_string(),
        authority: "DFIR Unit".to_string(),
        examiner: "Examiner".to_string(),
        description: "Test Abort".to_string(),
        notes: "".to_string(),
        ..Default::default()
    };

    let out_dir = temp_dir.join("evidence_output");
    let config = AcquisitionConfig {
        format: models::config::ImageFormat::Raw,
        output_dir: out_dir.clone(),
        ..Default::default()
    };

    let (tx, _rx) = tokio::sync::mpsc::channel(50);
    let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Trigger abort flag immediately
    abort.store(true, std::sync::atomic::Ordering::Relaxed);

    let res =
        engines::raw::RawAcquireEngine::run_acquisition(device, case, config, tx, abort).await;

    assert!(res.is_err(), "Must return Err on abort");
    let err_msg = res.unwrap_err();
    assert!(err_msg.contains("aborted by user"));
}

#[tokio::test]
async fn test_raw_acquisition_destination_exists_refusal() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let temp_dir = tmp.path();

    let source_disk = temp_dir.join("source.bin");
    std::fs::write(&source_disk, b"sample source data").unwrap();

    let out_dir = temp_dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let case = CaseMetadata {
        case_number: "CASE01".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "CF01".to_string(),
        authority: "DFIR".to_string(),
        examiner: "Examiner".to_string(),
        description: "Test".to_string(),
        notes: "".to_string(),
        ..Default::default()
    };
    let device = file_device(&source_disk, 18, Some("SER001"));
    let config = AcquisitionConfig {
        format: models::config::ImageFormat::Raw,
        output_dir: out_dir.clone(),
        ..Default::default()
    };

    // Pre-create the destination raw file
    let expected_dest = out_dir.join(case.generate_filename(&device.display_serial(), "raw"));
    std::fs::write(&expected_dest, b"already existing file").unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(50);
    let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let res =
        engines::raw::RawAcquireEngine::run_acquisition(device, case, config, tx, abort).await;

    assert!(res.is_err(), "Must fail if destination RAW already exists");
    let err = res.unwrap_err();
    assert!(err.contains("already exists"), "Error was: {}", err);
}

#[tokio::test]
async fn test_raw_acquisition_source_destination_collision() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let temp_dir = tmp.path();

    let out_dir = temp_dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let case = CaseMetadata {
        case_number: "CASE01".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "CF01".to_string(),
        authority: "DFIR".to_string(),
        examiner: "Examiner".to_string(),
        description: "Test".to_string(),
        notes: "".to_string(),
        ..Default::default()
    };
    let serial = "COLLIDE01";
    let target_filename = case.generate_filename(serial, "raw");
    let source_disk = out_dir.join(&target_filename);
    std::fs::write(
        &source_disk,
        b"precious evidence data that must not be truncated",
    )
    .unwrap();

    let device = file_device(&source_disk, 51, Some(serial));
    let config = AcquisitionConfig {
        format: models::config::ImageFormat::Raw,
        output_dir: out_dir.clone(),
        ..Default::default()
    };

    let (tx, _rx) = tokio::sync::mpsc::channel(50);
    let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let res =
        engines::raw::RawAcquireEngine::run_acquisition(device, case, config, tx, abort).await;

    assert!(res.is_err(), "Must fail when destination matches source");
    // Ensure the source file was NOT truncated to 0 bytes!
    let data = std::fs::read(&source_disk).unwrap();
    assert_eq!(data, b"precious evidence data that must not be truncated");
}

#[tokio::test]
async fn test_raw_acquisition_incomplete_size_mismatch() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let temp_dir = tmp.path();

    let source_disk = temp_dir.join("truncated_source.bin");
    std::fs::write(&source_disk, b"short data").unwrap(); // 10 bytes

    let out_dir = temp_dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let case = CaseMetadata {
        case_number: "CASE01".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "CF01".to_string(),
        authority: "DFIR".to_string(),
        examiner: "Examiner".to_string(),
        description: "Test".to_string(),
        notes: "".to_string(),
        ..Default::default()
    };
    let device = file_device(&source_disk, 1000, Some("SER_MISMATCH"));
    let config = AcquisitionConfig {
        format: models::config::ImageFormat::Raw,
        output_dir: out_dir.clone(),
        ..Default::default()
    };

    let (tx, _rx) = tokio::sync::mpsc::channel(50);
    let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let res =
        engines::raw::RawAcquireEngine::run_acquisition(device, case, config, tx, abort).await;

    assert!(
        res.is_err(),
        "Must fail when bytes copied != expected device size"
    );
    let err = res.unwrap_err();
    assert!(err.contains("Acquisition incomplete"), "Error was: {}", err);
}

#[tokio::test]
async fn test_rescue_stale_files_refusal_without_resume() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let temp_dir = tmp.path();

    let source_disk = temp_dir.join("source.bin");
    std::fs::write(&source_disk, b"source").unwrap();

    let out_dir = temp_dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let case = CaseMetadata {
        case_number: "CASE01".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "CF01".to_string(),
        authority: "DFIR".to_string(),
        examiner: "Examiner".to_string(),
        description: "Test".to_string(),
        notes: "".to_string(),
        ..Default::default()
    };
    let device = file_device(&source_disk, 6, Some("RESCUE001"));
    let config = AcquisitionConfig {
        format: models::config::ImageFormat::E01,
        compression: models::config::CompressionLevel::Fast,
        split_size: models::config::SplitSize::TwoGb,
        output_dir: out_dir.clone(),
        rescue_mode: true,
        resume: false,
        ..Default::default()
    };

    // Pre-create existing mapfile
    let base_name = case.generate_base_filename(&device.display_serial());
    let existing_map = out_dir.join(format!("{}.map", base_name));
    std::fs::write(&existing_map, b"# ddrescue mapfile\n").unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel(50);
    let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let res =
        engines::rescue::RescueAcquireEngine::run_rescue(device, case, config, tx, abort).await;

    assert!(
        res.is_err(),
        "Must refuse to silently overwrite or reuse existing mapfile without --resume"
    );
    let err = res.unwrap_err();
    assert!(err.contains("already exists"), "Error was: {}", err);
}
