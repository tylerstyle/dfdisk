#![allow(unused_imports, dead_code)]

//! Acquisitions leave a verifiable trail in the dfnix audit log, and the report
//! and the log point at each other. Own test binary: it sets DFNIX_AUDIT_LOG.

#[path = "../src/models/mod.rs"]
mod models;

#[path = "../src/engines/mod.rs"]
mod engines;

use models::{
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
        devlinks: vec![],
        size_bytes: size,
        model: Some("Audit".into()),
        vendor: None,
        serial: Some("AUDIT01".into()),
        wwn: None,
        revision: None,
        bus_type: "Virtual".into(),
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

fn case() -> CaseMetadata {
    CaseMetadata {
        case_number: "AUDIT".into(),
        location_ea: "01".into(),
        evidence_number: "A01".into(),
        authority: "DFIR".into(),
        examiner: "Examiner".into(),
        description: "Audit trail".into(),
        notes: "".into(),
    }
}

#[tokio::test]
async fn acquisition_report_and_audit_log_anchor_each_other() {
    let dir = std::env::temp_dir().join(format!("dfdisk_audit_trail_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.jsonl");
    std::env::set_var("DFNIX_AUDIT_LOG", &log);

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

    let _ = std::fs::remove_dir_all(&dir);
}
