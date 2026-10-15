mod common;
mod support;

use common::{audit_sandbox, case, file_device, sample, scratch};
use dfdisk::{
    engines::{
        self,
        session::{self, AcquisitionRequest},
        AcquisitionError, ErrorKind,
    },
    models::{
        self,
        config::{AcquisitionConfig, EngineKind},
        device::BlockDevice,
        info_report::ForensicInfoReport,
        outcome::Outcome,
    },
};
use digest::Digest;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Run the session on this host (regular-file sources only), draining progress.
async fn run(
    device: BlockDevice,
    config: AcquisitionConfig,
) -> Result<ForensicInfoReport, AcquisitionError> {
    audit_sandbox();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<models::telemetry::ProgressTelemetry>(1000);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let r = session::run(
        AcquisitionRequest::new(device, case(), config),
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let _ = drain.await;
    r
}

/// Engine defaults for a test destination (which may be a tmpfs).
fn config(engine: EngineKind, out: &Path) -> AcquisitionConfig {
    AcquisitionConfig {
        allow_tmpfs: true,
        ..AcquisitionConfig::for_engine(engine, out)
    }
}

// ---------------------------------------------------------------------------
// RAW: truthful reporting through the session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_source_that_changed_size_since_it_was_selected_is_refused() {
    let tmp = scratch();
    let dir = tmp.path();
    let src = dir.join("src.bin");
    std::fs::write(&src, sample(10)).unwrap();
    let out = dir.join("out").join("new");
    // Selected as 1000 bytes, now 10: not the device the examiner chose
    let err = run(
        file_device(&src, 1000, Some("SHORT01")),
        config(EngineKind::Raw, &out),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Refused);
    assert_eq!(err.exit_code(), 3);
    assert!(
        err.message.contains("size 10 bytes, was 1000 bytes"),
        "{err}"
    );
    assert!(!out.exists(), "nothing may be written");
}

#[tokio::test]
async fn raw_complete_report_states_real_error_handling() {
    let tmp = scratch();
    let dir = tmp.path();
    let data = sample(64 * 1024);
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let config = AcquisitionConfig {
        calc_sha1: false,
        ..config(EngineKind::Raw, &dir.join("out"))
    };
    let report = run(file_device(&src, data.len() as u64, Some("FULL01")), config)
        .await
        .unwrap();

    // Disabling SHA-1 must not turn into a mismatch
    assert_eq!(report.outcome, Outcome::Verified);
    assert_eq!(report.exit_code, 0);
    assert!(report.acquisition_hashes.sha1.is_none());
    assert_eq!(
        report.acquisition_hashes.sha256,
        Some(hex::encode(sha2::Sha256::digest(&data)))
    );
    let text = report.render_text();
    assert!(!text.contains("Zero-fill"), "{text}");
    assert!(text.contains(engines::raw::RAW_ERROR_HANDLING), "{text}");
    assert!(report.stop_reason.is_none());
    // A regular file: probed, not write-protected, no capacity/SMART probes
    assert_eq!(
        report.source.kind,
        dfdisk::models::identity::SourceKind::RegularFile
    );
    assert!(!report.write_protection.as_ref().unwrap().set_by_dfdisk);
    assert!(report.smart_before.is_none());
    assert_eq!(report.identity_check.end_ok, Some(true));
}

// ---------------------------------------------------------------------------
// E01: overwrite protection and single-pass digests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ewf_refuses_existing_segment_before_running_ewfacquire() {
    let tmp = scratch();
    let dir = tmp.path();
    let src = dir.join("src.bin");
    std::fs::write(&src, sample(4096)).unwrap();
    let out = dir.join("out");
    let base = case().generate_base_filename("NO_SERIAL");
    let existing = out.join(format!("{}.E01", base));
    std::fs::write(&existing, b"earlier acquisition of another drive").unwrap();

    let err = run(file_device(&src, 4096, None), config(EngineKind::Ewf, &out))
        .await
        .unwrap_err();
    assert!(err.is_refusal());
    assert!(err.message.contains("already exists"), "{err}");
    assert!(err.message.contains("no serial number"), "{err}");
    assert_eq!(
        std::fs::read(&existing).unwrap(),
        b"earlier acquisition of another drive"
    );
}

async fn run_ewf(
    tag: &str,
    calc_sha1: bool,
    calc_sha256: bool,
) -> Option<(Vec<u8>, models::info_report::ForensicInfoReport)> {
    // Skips without libewf; fails instead when DFDISK_REQUIRE_TOOLS=1
    if !support::tool_available(&["ewfacquire", "ewfverify"]) {
        return None;
    }
    let tmp = scratch();
    let dir = tmp.path();
    let data = sample(2 * 1024 * 1024);
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let config = AcquisitionConfig {
        calc_sha1,
        calc_sha256,
        ..config(EngineKind::Ewf, &dir.join("out"))
    };
    let report = run(
        file_device(
            &src,
            data.len() as u64,
            Some(&format!("EWF{}", tag.to_uppercase())),
        ),
        config,
    )
    .await
    .unwrap();
    Some((data, report))
}

#[tokio::test]
async fn ewf_all_digests_in_one_pass_verify() {
    let Some((data, report)) = run_ewf("all", true, true).await else {
        return;
    };
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    assert_eq!(
        report.acquisition_hashes.md5,
        Some(hex::encode(md5::Md5::digest(&data)))
    );
    assert_eq!(
        report.acquisition_hashes.sha1,
        Some(hex::encode(sha1::Sha1::digest(&data)))
    );
    assert_eq!(
        report.acquisition_hashes.sha256,
        Some(hex::encode(sha2::Sha256::digest(&data)))
    );
    assert_eq!(report.acquisition_hashes.sha1, report.image_hashes.sha1);
}

#[tokio::test]
async fn ewf_without_sha1_has_no_false_mismatch() {
    let Some((data, report)) = run_ewf("nosha1", false, true).await else {
        return;
    };
    assert_eq!(report.outcome, Outcome::Verified);
    assert!(report.acquisition_hashes.sha1.is_none());
    assert_eq!(
        report.acquisition_hashes.sha256,
        Some(hex::encode(sha2::Sha256::digest(&data)))
    );
}

#[tokio::test]
async fn ewf_without_sha256_has_no_false_mismatch() {
    let Some((_, report)) = run_ewf("nosha256", true, false).await else {
        return;
    };
    assert_eq!(report.outcome, Outcome::Verified);
    assert!(report.acquisition_hashes.sha256.is_none());
}

// ---------------------------------------------------------------------------
// Destination-on-source against this host's real block devices
// ---------------------------------------------------------------------------

fn dev_node_for(dev: dfcore::sysfs::DevNum) -> Option<PathBuf> {
    std::fs::read_dir("/dev")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| dfcore::sysfs::source_device(p) == Some(dev))
}

#[test]
fn image_on_the_source_disk_is_refused_on_this_host() {
    let dir = std::env::temp_dir();
    let Some(dev) = dfcore::sysfs::backing_device_of_path(&dir) else {
        eprintln!("skipping: temp dir is not on a block device");
        return;
    };
    let Some(node) = dev_node_for(dev) else {
        eprintln!("skipping: no /dev node for {}:{}", dev.0, dev.1);
        return;
    };
    let err = engines::preflight::ensure_destination_not_on_source(&node.to_string_lossy(), &dir)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Critical Safety Error"), "{err}");

    // The whole disk that partition sits on must be refused as well
    let topo = dfcore::sysfs::BlockTopology::default();
    if let Some(name) = topo.name_of(dev) {
        for disk in topo.backing_disks(&name) {
            let disk_node = Path::new("/dev").join(&disk);
            if disk_node.exists() {
                let err = engines::preflight::ensure_destination_not_on_source(
                    &disk_node.to_string_lossy(),
                    &dir,
                )
                .unwrap_err()
                .to_string();
                assert!(err.contains(&disk), "{err}");
            }
        }
    }
}
