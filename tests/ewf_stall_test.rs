//! E-1: a source that ends before its probed size while it stays attached
//! (here a regular file truncated during the acquisition; the fakedev shim
//! slows ewfacquire's reads) makes ewfacquire wait for data forever. The
//! E01 engine notices that it makes no progress, checks the source, and
//! stops ewfacquire itself: INCOMPLETE, "source lost at offset X", not a
//! hang and not an abort.
//!
//! Own test binary: it lowers the engine's process-wide stall limit.
//! Runs when libewf and a C compiler exist; with DFDISK_REQUIRE_TOOLS=1 a
//! missing tool fails it.

mod common;
mod support;

use common::{audit_sandbox, case, file_device};
use dfdisk::engines::ewf::SOURCE_STALL_SECS;
use dfdisk::engines::session::{self, AcquisitionRequest, HostSystem, StopFlags};
use dfdisk::models::config::{AcquisitionConfig, EngineKind};
use dfdisk::models::outcome::Outcome;
use dfdisk::models::telemetry::{AcquisitionStatus, ProgressTelemetry};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const MIB: u64 = 1024 * 1024;

#[tokio::test]
async fn a_source_that_ends_early_stops_ewfacquire_instead_of_hanging() {
    audit_sandbox();
    let Some(fake) = support::fakedev() else {
        return;
    };
    SOURCE_STALL_SECS.store(2, Ordering::SeqCst);
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src.img");
    let data: Vec<u8> = (0..4 * MIB).map(|i| (i * 13 % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();
    // 60 ms per read: the 4 MiB take several seconds
    fake.configure(&src, &[("FAKEDEV_DELAY_US", "60000")]);
    let out = tmp.path().join("out");
    let config = AcquisitionConfig {
        allow_tmpfs: true,
        ..AcquisitionConfig::for_engine(EngineKind::Ewf, &out)
    };
    let request =
        AcquisitionRequest::new(file_device(&src, 4 * MIB, Some("SHRINK1")), case(), config);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressTelemetry>(1000);
    let shrink = src.clone();
    let drain = tokio::spawn(async move {
        let mut done = false;
        while let Some(t) = rx.recv().await {
            if !done && t.status == AcquisitionStatus::Acquiring {
                done = true;
                let path = shrink.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(MIB)
                        .unwrap();
                });
            }
        }
    });
    let started = Instant::now();
    let result = session::run_with(&HostSystem, request, tx, StopFlags::default()).await;
    let _ = drain.await;
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "the acquisition hung for {:?}",
        started.elapsed()
    );
    let report = result.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Incomplete,
        "{}",
        report.render_text()
    );
    assert_eq!(report.exit_code, 6);
    let reason = report.stop_reason.clone().unwrap_or_default();
    assert!(reason.starts_with("source lost at offset "), "{reason}");
    assert!(
        reason.contains(
            "the source has 1048576 bytes now, 4194304 bytes when the acquisition started"
        ),
        "{reason}"
    );
    assert!(report.bytes_acquired < 4 * MIB);
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.starts_with("dfdisk stopped ewfacquire")),
        "{:?}",
        report.notes
    );
    assert!(!report.image_files.is_empty(), "the segments are kept");
}
