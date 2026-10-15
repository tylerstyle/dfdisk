//! An E01 stores whole 512-byte sectors only: a source whose size is not a
//! multiple of 512 bytes (a regular image file) is refused as a usage error
//! before anything is written or recorded, by `acquire` and by `check`.
//! (Measured with libewf 20231119 and 20140816: ewfacquire would hash all
//! bytes but store only the whole sectors, and the image would not verify.)
//! No tool runs, so these tests need no libewf.

mod common;

use common::{audit_sandbox, case, file_device};
use dfdisk::engines::session::{self, AcquisitionRequest, HostSystem, StopFlags};
use dfdisk::engines::ErrorKind;
use dfdisk::models::config::{AcquisitionConfig, EngineKind};
use dfdisk::models::telemetry::ProgressTelemetry;

const ODD: usize = 3_000_000;

fn request(dir: &std::path::Path, engine: EngineKind) -> AcquisitionRequest {
    let src = dir.join("odd.img");
    std::fs::write(&src, vec![0x5au8; ODD]).unwrap();
    let config = AcquisitionConfig {
        allow_tmpfs: true,
        ..AcquisitionConfig::for_engine(engine, dir.join("out"))
    };
    AcquisitionRequest::new(file_device(&src, ODD as u64, Some("ODD1")), case(), config)
}

#[tokio::test]
async fn e01_of_a_source_without_whole_sectors_is_refused_before_writing() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let req = request(tmp.path(), EngineKind::Ewf);
    let out = req.config.output_dir.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressTelemetry>(100);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let err = session::run_with(&HostSystem, req, tx, StopFlags::new())
        .await
        .unwrap_err();
    let _ = drain.await;
    assert_eq!(err.kind, ErrorKind::Usage);
    assert_eq!(err.exit_code(), 2);
    assert!(
        err.message
            .contains("192 bytes more than 5859 whole 512-byte sectors"),
        "{err}"
    );
    assert!(!out.exists(), "nothing may be written");
    // Usage errors are not audited (decision 2)
    let log = std::fs::read_to_string(audit_sandbox().join("audit.jsonl")).unwrap_or_default();
    assert!(
        !log.contains(&*tmp.path().to_string_lossy()),
        "a usage error was recorded"
    );

    let report = session::check(request(tmp.path(), EngineKind::Ewf)).await;
    assert_eq!(report.exit_code(), 2, "{}", report.render_text());
    assert!(!out.exists());
}

#[tokio::test]
async fn raw_of_the_same_source_is_not_refused_for_its_size() {
    audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let report = session::check(request(tmp.path(), EngineKind::Raw)).await;
    assert!(
        !report.render_text().contains("whole 512-byte sectors"),
        "{}",
        report.render_text()
    );
}
