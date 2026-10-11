#![allow(unused_imports, dead_code)]

#[path = "../src/models/mod.rs"]
mod models;

#[path = "../src/engines/mod.rs"]
mod engines;

use digest::Digest;
use models::{
    case::CaseMetadata,
    config::{AcquisitionConfig, ImageFormat},
    device::{BlockDevice, DeviceSafety},
    info_report::VerificationStatus,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dfdisk_integrity_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("out")).unwrap();
    dir
}

fn case() -> CaseMetadata {
    CaseMetadata {
        case_number: "CASE42".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "CF01".to_string(),
        authority: "DFIR".to_string(),
        examiner: "Examiner".to_string(),
        description: "Integrity test".to_string(),
        notes: "".to_string(),
    }
}

fn file_device(path: &Path, size_bytes: u64, serial: Option<&str>) -> BlockDevice {
    BlockDevice {
        name: "test_dev".to_string(),
        path: path.to_string_lossy().to_string(),
        devlinks: vec![],
        size_bytes,
        model: Some("Test".to_string()),
        vendor: Some("Test".to_string()),
        serial: serial.map(str::to_string),
        wwn: None,
        revision: None,
        bus_type: "Virtual".to_string(),
        is_rotational: Some(false),
        is_removable: false,
        is_read_only: false,
        logical_sector_size: 512,
        physical_sector_size: 512,
        partition_table_type: None,
        partitions: vec![],
        mountpoints: vec![],
        safety: DeviceSafety::Safe,
        smart: None,
    }
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}

fn channel() -> (
    tokio::sync::mpsc::Sender<models::telemetry::ProgressTelemetry>,
    tokio::sync::mpsc::Receiver<models::telemetry::ProgressTelemetry>,
) {
    tokio::sync::mpsc::channel(1000)
}

fn have_libewf() -> bool {
    std::process::Command::new("ewfacquire")
        .arg("-V")
        .output()
        .is_ok()
        && std::process::Command::new("ewfverify")
            .arg("-V")
            .output()
            .is_ok()
}

// ---------------------------------------------------------------------------
// RAW: truthful reporting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn raw_short_source_keeps_partial_image_and_reports_incomplete() {
    let dir = scratch("raw_incomplete");
    let src = dir.join("src.bin");
    std::fs::write(&src, sample(10)).unwrap();
    let out = dir.join("out");
    let config = AcquisitionConfig {
        format: ImageFormat::Raw,
        output_dir: out.clone(),
        wipe_bad_sectors: true,
        ..Default::default()
    };
    let device = file_device(&src, 1000, Some("SHORT01"));
    let raw = out.join(case().generate_filename("SHORT01", "raw"));
    let info = out.join(case().generate_filename("SHORT01", "info"));

    let (tx, _rx) = channel();
    let err = engines::raw::RawAcquireEngine::run_acquisition(
        device,
        case(),
        config,
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap_err();
    assert!(err.contains("Acquisition incomplete"), "{err}");
    assert!(err.contains("10 of 1000 bytes"), "{err}");

    assert_eq!(
        std::fs::read(&raw).unwrap(),
        sample(10),
        "partial image must be kept"
    );
    let text =
        std::fs::read_to_string(&info).expect("report must be written for partial acquisitions");
    assert!(text.contains("INCOMPLETE"), "{text}");
    assert!(text.contains("10 of 1000 bytes"), "{text}");
    assert!(!text.contains("Zero-fill"), "{text}");
    assert!(text.contains(engines::raw::RAW_ERROR_HANDLING), "{text}");
    assert!(!text.contains("VERIFIED - ALL HASHES MATCH"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn raw_complete_report_states_real_error_handling() {
    let dir = scratch("raw_complete");
    let data = sample(64 * 1024);
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let config = AcquisitionConfig {
        format: ImageFormat::Raw,
        output_dir: dir.join("out"),
        calc_sha1: false,
        ..Default::default()
    };
    let (tx, _rx) = channel();
    let report = engines::raw::RawAcquireEngine::run_acquisition(
        file_device(&src, data.len() as u64, Some("FULL01")),
        case(),
        config,
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    // Disabling SHA-1 must not turn into a mismatch
    assert_eq!(report.verification_status, VerificationStatus::Verified);
    assert!(report.source_hashes.sha1.is_none());
    assert_eq!(
        report.source_hashes.sha256,
        Some(hex::encode(sha2::Sha256::digest(&data)))
    );
    let text = report.render_text();
    assert!(!text.contains("Zero-fill"), "{text}");
    assert!(report.incomplete.is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// E01: overwrite protection and single-pass digests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ewf_refuses_existing_segment_before_running_ewfacquire() {
    let dir = scratch("ewf_exists");
    let src = dir.join("src.bin");
    std::fs::write(&src, sample(4096)).unwrap();
    let out = dir.join("out");
    let base = case().generate_base_filename("NO_SERIAL");
    let existing = out.join(format!("{}.E01", base));
    std::fs::write(&existing, b"earlier acquisition of another drive").unwrap();

    let config = AcquisitionConfig {
        output_dir: out.clone(),
        ..Default::default()
    };
    let (tx, _rx) = channel();
    let err = engines::ewf::EwfAcquireEngine::run_acquisition(
        file_device(&src, 4096, None),
        case(),
        config,
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap_err();

    assert!(err.contains("already exists"), "{err}");
    assert!(err.contains("no serial number"), "{err}");
    assert_eq!(
        std::fs::read(&existing).unwrap(),
        b"earlier acquisition of another drive"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

async fn run_ewf(
    tag: &str,
    calc_sha1: bool,
    calc_sha256: bool,
) -> Option<(Vec<u8>, models::info_report::ForensicInfoReport)> {
    if !have_libewf() {
        eprintln!("skipping: ewfacquire/ewfverify not installed");
        return None;
    }
    let dir = scratch(tag);
    let data = sample(2 * 1024 * 1024);
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let config = AcquisitionConfig {
        output_dir: dir.join("out"),
        calc_sha1,
        calc_sha256,
        ..Default::default()
    };
    let (tx, mut rx) = channel();
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let report = engines::ewf::EwfAcquireEngine::run_acquisition(
        file_device(
            &src,
            data.len() as u64,
            Some(&format!("EWF{}", tag.to_uppercase())),
        ),
        case(),
        config,
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();
    let _ = drain.await;
    let _ = std::fs::remove_dir_all(&dir);
    Some((data, report))
}

#[tokio::test]
async fn ewf_all_digests_in_one_pass_verify() {
    let Some((data, report)) = run_ewf("all", true, true).await else {
        return;
    };
    assert_eq!(report.verification_status, VerificationStatus::Verified);
    assert_eq!(
        report.source_hashes.md5,
        Some(hex::encode(md5::Md5::digest(&data)))
    );
    assert_eq!(
        report.source_hashes.sha1,
        Some(hex::encode(sha1::Sha1::digest(&data)))
    );
    assert_eq!(
        report.source_hashes.sha256,
        Some(hex::encode(sha2::Sha256::digest(&data)))
    );
    assert_eq!(report.source_hashes.sha1, report.destination_hashes.sha1);
}

#[tokio::test]
async fn ewf_without_sha1_has_no_false_mismatch() {
    let Some((data, report)) = run_ewf("nosha1", false, true).await else {
        return;
    };
    assert_eq!(report.verification_status, VerificationStatus::Verified);
    assert!(report.source_hashes.sha1.is_none());
    assert_eq!(
        report.source_hashes.sha256,
        Some(hex::encode(sha2::Sha256::digest(&data)))
    );
}

#[tokio::test]
async fn ewf_without_sha256_has_no_false_mismatch() {
    let Some((_, report)) = run_ewf("nosha256", true, false).await else {
        return;
    };
    assert_eq!(report.verification_status, VerificationStatus::Verified);
    assert!(report.source_hashes.sha256.is_none());
}

// ---------------------------------------------------------------------------
// Destination-on-source against this host's real block devices
// ---------------------------------------------------------------------------

fn dev_node_for(dev: engines::preflight::DevNum) -> Option<PathBuf> {
    std::fs::read_dir("/dev")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| engines::preflight::source_device(p) == Some(dev))
}

#[test]
fn image_on_the_source_disk_is_refused_on_this_host() {
    let dir = std::env::temp_dir();
    let Some(dev) = engines::preflight::backing_device_of_path(&dir) else {
        eprintln!("skipping: temp dir is not on a block device");
        return;
    };
    let Some(node) = dev_node_for(dev) else {
        eprintln!("skipping: no /dev node for {}:{}", dev.0, dev.1);
        return;
    };
    let err = engines::preflight::ensure_destination_not_on_source(&node.to_string_lossy(), &dir)
        .unwrap_err();
    assert!(err.contains("Critical Safety Error"), "{err}");

    // The whole disk that partition sits on must be refused as well
    let topo = engines::preflight::BlockTopology::default();
    if let Some(name) = topo.name_of(dev) {
        for disk in topo.backing_disks(&name) {
            let disk_node = Path::new("/dev").join(&disk);
            if disk_node.exists() {
                let err = engines::preflight::ensure_destination_not_on_source(
                    &disk_node.to_string_lossy(),
                    &dir,
                )
                .unwrap_err();
                assert!(err.contains(&disk), "{err}");
            }
        }
    }
}
