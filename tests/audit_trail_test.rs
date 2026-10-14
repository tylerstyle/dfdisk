//! Acquisitions leave a verifiable trail in the dfnix audit log, and the report
//! and the log point at each other. Own test binary: it sets DFNIX_AUDIT_LOG.

use dfdisk::engines;
use dfdisk::models::{
    case::CaseMetadata,
    config::{AcquisitionConfig, ImageFormat},
    device::{BlockDevice, DeviceSafety},
};
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn device(path: &std::path::Path, size: u64) -> BlockDevice {
    BlockDevice {
        name: "audit_dev".into(),
        path: path.to_string_lossy().into(),
        size_bytes: size,
        model: Some("Audit".into()),
        serial: Some("AUDIT01".into()),
        bus_type: "Virtual".into(),
        is_rotational: Some(false),
        logical_sector_size: 512,
        physical_sector_size: 512,
        safety: DeviceSafety::Safe,
        ..Default::default()
    }
}

fn case() -> CaseMetadata {
    CaseMetadata {
        case_number: "AUDIT".into(),
        location_ea: "01".into(),
        evidence_number: "A01".into(),
        authority: "DFIR".into(),
        examiner: "Examiner".into(),
        description: "Audit trail".into(),
        notes: "".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn acquisition_report_and_audit_log_anchor_each_other() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let log = dir.join("audit.jsonl");
    std::env::set_var("DFNIX_AUDIT_LOG", &log);
    std::env::set_var("DFNIX_PROTECTED_FILE", dir.join("protected.json"));

    let src = dir.join("src.bin");
    std::fs::write(&src, vec![7u8; 8192]).unwrap();
    let config = AcquisitionConfig {
        format: ImageFormat::Raw,
        output_dir: dir.join("out"),
        ..Default::default()
    };
    let (tx, _rx) = tokio::sync::mpsc::channel(1000);
    let report = engines::raw::RawAcquireEngine::run_acquisition(
        device(&src, 8192),
        case(),
        config.clone(),
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    // Second run collides with the first: refused, and recorded as such
    let (tx, _rx) = tokio::sync::mpsc::channel(1000);
    let refused = engines::raw::RawAcquireEngine::run_acquisition(
        device(&src, 8192),
        case(),
        config,
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    assert!(refused.is_err());

    let state = dfcore::audit::verify(&log).unwrap();
    assert_eq!(state.records, 4);
    let records: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let actions: Vec<_> = records
        .iter()
        .map(|r| {
            (
                r["action"].as_str().unwrap(),
                r["outcome"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        actions,
        [
            ("acquisition_started", "ok"),
            ("acquisition_finished", "ok"),
            ("acquisition_started", "ok"),
            ("acquisition_finished", "refused"),
        ]
    );

    // The report names the record its acquisition started with ...
    let anchor = report.audit_anchor.clone().unwrap();
    assert_eq!(records[0]["hash"], anchor);
    assert_eq!(records[0]["device"]["serial"], "AUDIT01");
    // ... and the finished record holds the report's own digest
    let info = std::fs::read(
        dir.join("out")
            .join(case().generate_filename("AUDIT01", "info")),
    )
    .unwrap();
    assert_eq!(
        records[1]["details"]["report_sha256"],
        hex::encode(Sha256::digest(&info))
    );
    assert!(String::from_utf8_lossy(&info).contains(&anchor));
    assert_eq!(
        records[1]["details"]["source_hashes"]["sha256"],
        hex::encode(Sha256::digest(vec![7u8; 8192]))
    );

    // The case directory carries a verifiable copy of the log as of the successful
    // acquisition (audit-<boot_id>.jsonl); the refused second run wrote nothing there
    let exported: Vec<_> = std::fs::read_dir(dir.join("out"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name.starts_with("audit-") && name.ends_with(".jsonl")
        })
        .collect();
    assert_eq!(exported.len(), 1, "{exported:?}");
    let copy = &exported[0];
    let copied = dfcore::audit::verify(copy).unwrap();
    assert_eq!(copied.records, 2);
    assert_eq!(copied.head, records[1]["hash"].as_str().unwrap());
    let head = std::fs::read_to_string(copy.with_extension("head")).unwrap();
    assert!(head.starts_with(&copied.head), "{head}");
}
