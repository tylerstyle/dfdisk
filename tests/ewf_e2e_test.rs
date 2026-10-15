//! E01 acquisitions end to end through the real session and the real libewf
//! tools, with read errors injected by the fakedev shim (tests/support):
//! ewfacquire sees a regular image file as a block device whose reads fail
//! with EIO at chosen offsets, or from an offset on (a dying source).
//!
//! These run when libewf and a C compiler exist; with DFDISK_REQUIRE_TOOLS=1 a
//! missing tool fails them. They never touch a host disk.

mod common;
mod support;

use common::{audit_sandbox, case, file_device};
use dfdisk::engines::session::{self, AcquisitionRequest, HostSystem, StopFlags};
use dfdisk::engines::AcquisitionError;
use dfdisk::models::config::{AcquisitionConfig, EngineKind, EngineSettings};
use dfdisk::models::info_report::{sha256_file, ForensicInfoReport};
use dfdisk::models::outcome::{Outcome, RangeKind, VerificationResult};
use dfdisk::models::telemetry::{AcquisitionStatus, ProgressTelemetry};
use digest::Digest;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MIB: u64 = 1024 * 1024;
const SIZE: u64 = 4 * MIB;

/// Incompressible, reproducible content.
fn content(len: u64, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Run {
    _tmp: tempfile::TempDir,
    data: Vec<u8>,
    src: PathBuf,
    out: PathBuf,
    result: Result<ForensicInfoReport, AcquisitionError>,
}

/// Acquire a 4 MiB fake device with these shim settings through the session.
async fn acquire(serial: &str, shim: &[(&str, &str)], stop: Option<StopFlags>) -> Option<Run> {
    audit_sandbox();
    let fake = support::fakedev()?;
    let tmp = tempfile::tempdir().unwrap();
    let data = content(SIZE, serial.len() as u64 * 7919 + 13);
    let src = tmp.path().join("src.img");
    std::fs::write(&src, &data).unwrap();
    fake.configure(&src, shim);
    let out = tmp.path().join("out");
    let config = AcquisitionConfig {
        allow_tmpfs: true,
        ..AcquisitionConfig::for_engine(EngineKind::Ewf, &out)
    };
    let request = AcquisitionRequest::new(file_device(&src, SIZE, Some(serial)), case(), config);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressTelemetry>(1000);
    let stop = stop.unwrap_or_default();
    let trigger = stop.clone();
    let abort_after_start = shim.iter().any(|(k, _)| *k == "FAKEDEV_DELAY_US");
    let out_dir = out.clone();
    let drain = tokio::spawn(async move {
        let mut started = false;
        while let Some(t) = rx.recv().await {
            if abort_after_start && !started && t.status == AcquisitionStatus::Acquiring {
                started = true;
                let flags = trigger.clone();
                let dir = out_dir.clone();
                tokio::spawn(async move {
                    // Once ewfacquire has written its first segment (a fixed
                    // delay raced with a slow start under load), then 1 s more
                    for _ in 0..1500 {
                        let written = std::fs::read_dir(&dir).is_ok_and(|rd| {
                            rd.flatten().any(|e| {
                                e.file_name().to_string_lossy().ends_with(".E01")
                                    && e.metadata().is_ok_and(|m| m.len() > 0)
                            })
                        });
                        if written {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    flags.abort.store(true, std::sync::atomic::Ordering::SeqCst);
                });
            }
        }
    });
    let result = session::run_with(&HostSystem, request, tx, stop).await;
    let _ = drain.await;
    Some(Run {
        _tmp: tmp,
        data,
        src,
        out,
        result,
    })
}

fn md5(data: &[u8]) -> String {
    hex::encode(md5::Md5::digest(data))
}

fn read_files(report: &ForensicInfoReport) -> (String, serde_json::Value) {
    let dir = Path::new(&report.output_dir);
    let text = std::fs::read_to_string(dir.join(format!("{}.info", report.base_name))).unwrap();
    let json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join(format!("{}.info.json", report.base_name))).unwrap(),
    )
    .unwrap();
    (text, json)
}

fn json_ranges(json: &serde_json::Value) -> Vec<(u64, u64, String)> {
    json["read_errors"]["ranges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["offset"].as_u64().unwrap(),
                r["length"].as_u64().unwrap(),
                r["kind"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// A row of the text report's read-error table: "# offset length sectors".
fn has_text_range(text: &str, offset: u64, length: u64) -> bool {
    text.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() >= 4 && f[1] == offset.to_string() && f[2] == length.to_string()
    })
}

#[tokio::test]
async fn one_bad_sector_is_completed_with_read_errors_exit_7() {
    let Some(run) = acquire("BAD1", &[("FAKEDEV_BAD", "1048576:512")], None).await else {
        return;
    };
    let report = run.result.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::CompletedWithReadErrors,
        "{} / {:?}",
        report.outcome_reason,
        report.notes
    );
    assert_eq!(report.exit_code, 7);
    assert_eq!(report.bytes_acquired, SIZE);
    assert_eq!(report.stop_reason, None);
    let ranges: Vec<(u64, u64, RangeKind)> = report
        .read_errors
        .ranges
        .iter()
        .map(|r| (r.offset, r.length, r.kind))
        .collect();
    assert_eq!(ranges, vec![(MIB, 512, RangeKind::Substituted)]);
    assert_eq!(report.read_errors.source, "ewfacquire output + ewfinfo -e");
    // ewfacquire's list and the image's list agree (both parsed, any libewf)
    assert!(
        !report.notes.iter().any(|n| n.contains("differ")),
        "{:?}",
        report.notes
    );

    // The digests describe the stream with the zero-filled sector, and the
    // image re-read reproduces them
    let mut substituted = run.data.clone();
    substituted[MIB as usize..MIB as usize + 512].fill(0);
    assert_eq!(report.acquisition_hashes.md5, Some(md5(&substituted)));
    assert_ne!(report.acquisition_hashes.md5, Some(md5(&run.data)));
    assert!(
        matches!(
            report.verification.result,
            VerificationResult::Matched { .. }
        ),
        "{:?}",
        report.verification
    );
    assert_eq!(report.image_hashes.md5, report.acquisition_hashes.md5);

    // Both report files state the exact range and never "ALL HASHES MATCH"
    let (text, json) = read_files(&report);
    assert!(!text.contains("ALL HASHES MATCH"), "{text}");
    assert!(text.contains("COMPLETED WITH READ ERRORS"), "{text}");
    assert!(has_text_range(&text, MIB, 512), "{text}");
    assert_eq!(json["outcome"], "completed_with_read_errors");
    assert_eq!(json["exit_code"], 7);
    assert_eq!(
        json_ranges(&json),
        vec![(MIB, 512, "substituted".to_string())]
    );

    // What ran, and the log of ewfacquire as an auxiliary file
    let log = report
        .auxiliary_files
        .iter()
        .find(|f| f.path.ends_with(".ewfacquire.log"))
        .expect("the ewfacquire log is listed");
    assert_eq!(log.sha256, sha256_file(Path::new(&log.path)).unwrap());
    let ewfacquire = report
        .provenance
        .commands
        .iter()
        .find(|c| c.argv[0] == "ewfacquire")
        .unwrap();
    assert!(ewfacquire.argv.windows(2).any(|w| w == ["-g", "1"]));
    assert!(ewfacquire.argv.windows(2).any(|w| w[0] == "-l"));
    // The default retry count is ewfacquire's own: no -r (ewfacquire
    // 20140807 crashes on any -r), and the report says so
    assert!(
        !ewfacquire.argv.iter().any(|a| a == "-r"),
        "{:?}",
        ewfacquire.argv
    );
    assert!(
        text.contains("2 (ewfacquire's default; -r not given)"),
        "{text}"
    );
    for tool in ["ewfacquire", "ewfinfo", "ewfverify"] {
        assert!(
            report.provenance.commands.iter().any(|c| c.argv[0] == tool),
            "{tool} not recorded"
        );
        assert!(
            report.provenance.tools[tool].starts_with(tool),
            "{:?}",
            report.provenance.tools
        );
    }
    let EngineSettings::Ewf(s) = &report.effective_config.settings else {
        panic!()
    };
    assert_eq!((s.error_granularity_sectors, s.retries), (1, 2));
    assert!(s.retries_default);
}

#[tokio::test]
async fn clean_fake_device_is_verified() {
    let Some(run) = acquire("CLEAN1", &[], None).await else {
        return;
    };
    let report = run.result.unwrap();
    assert_eq!(report.outcome, Outcome::Verified, "{:?}", report.notes);
    assert_eq!(report.exit_code, 0);
    assert!(report.read_errors.is_empty());
    assert_eq!(report.acquisition_hashes.md5, Some(md5(&run.data)));
    let (text, _) = read_files(&report);
    assert!(text.contains("ALL HASHES MATCH"));
}

#[tokio::test]
async fn source_dying_mid_run_is_incomplete() {
    // Every read from 1 MiB on fails and the node disappears: ewfacquire
    // stops with FAILURE
    let Some(run) = acquire(
        "DIE1",
        &[("FAKEDEV_DIE_AT", "1048576"), ("FAKEDEV_VANISH", "1")],
        None,
    )
    .await
    else {
        return;
    };
    let report = run.result.unwrap();
    assert_eq!(report.outcome, Outcome::Incomplete, "{:?}", report.notes);
    assert_eq!(report.exit_code, 6);
    let reason = report.stop_reason.clone().unwrap();
    assert!(
        reason.starts_with("source lost during the acquisition"),
        "{reason}"
    );
    assert_eq!(report.identity_check.end_ok, Some(false));
    assert!(!run.src.exists());
    assert!(!report.image_files.is_empty(), "the segments are kept");
    let (text, json) = read_files(&report);
    assert!(!text.contains("ALL HASHES MATCH"));
    assert!(text.contains("INCOMPLETE"));
    assert_eq!(json["exit_code"], 6);
}

#[tokio::test]
async fn source_lost_after_zero_filling_to_the_end_is_incomplete() {
    // ewfacquire zero-fills everything from 1 MiB on and completes; the
    // source is gone afterwards
    let Some(run) = acquire(
        "LOST1",
        &[("FAKEDEV_DIE_AT", "1048576"), ("FAKEDEV_VANISH_AFTER", "1")],
        None,
    )
    .await
    else {
        return;
    };
    let report = run.result.unwrap();
    assert_eq!(report.outcome, Outcome::Incomplete);
    assert_eq!(report.exit_code, 6);
    assert!(report
        .stop_reason
        .as_deref()
        .unwrap()
        .starts_with("source lost at offset 1048576 (1 MiB)"));
    assert_eq!(report.bytes_acquired, MIB);
    let (text, json) = read_files(&report);
    assert_eq!(
        json_ranges(&json),
        vec![(MIB, 3 * MIB, "unread".to_string())]
    );
    assert!(has_text_range(&text, MIB, 3 * MIB), "{text}");
    assert!(!text.contains("ALL HASHES MATCH"));
}

#[tokio::test]
async fn a_source_smaller_after_zero_filling_to_the_end_is_lost_there() {
    // E-NEW-2: ewfacquire zero-fills everything from 1 MiB on and completes;
    // afterwards the source is still there but has only 1 MiB. The zeros
    // are not source data, and no note says the source was still present
    let Some(run) = acquire(
        "SHRUNK1",
        &[
            ("FAKEDEV_DIE_AT", "1048576"),
            ("FAKEDEV_SHRINK_AFTER", "1048576"),
        ],
        None,
    )
    .await
    else {
        return;
    };
    let report = run.result.unwrap();
    assert_eq!(report.outcome, Outcome::Incomplete);
    assert!(run.src.exists());
    assert_eq!(std::fs::metadata(&run.src).unwrap().len(), MIB);
    let reason = report.stop_reason.clone().unwrap();
    assert!(
        reason.starts_with(
            "source lost at offset 1048576 (1 MiB): the source has 1048576 bytes now, 4194304 bytes when the acquisition started"
        ),
        "{reason}"
    );
    assert_eq!(report.bytes_acquired, MIB);
    assert!(
        !report.notes.iter().any(|n| n.contains("still present")),
        "{:?}",
        report.notes
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("after the source was lost or became smaller")),
        "{:?}",
        report.notes
    );
    let (_, json) = read_files(&report);
    assert_eq!(
        json_ranges(&json),
        vec![(MIB, 3 * MIB, "unread".to_string())]
    );
}

#[tokio::test]
async fn medium_failing_to_the_end_while_attached_is_read_errors() {
    let Some(run) = acquire("TAIL1", &[("FAKEDEV_DIE_AT", "1048576")], None).await else {
        return;
    };
    let report = run.result.unwrap();
    assert_eq!(report.outcome, Outcome::CompletedWithReadErrors);
    assert_eq!(report.exit_code, 7);
    let (_, json) = read_files(&report);
    assert_eq!(
        json_ranges(&json),
        vec![(MIB, 3 * MIB, "substituted".to_string())]
    );
    assert!(run.src.exists());
    assert!(
        report.notes.iter().any(|n| n.contains(
            "the source was still present afterwards, with at least the 4194304 bytes it had at the start"
        )),
        "{:?}",
        report.notes
    );
}

#[tokio::test]
async fn abort_keeps_the_segments_and_reports_aborted() {
    // 128 slow reads (about 6 s); the test aborts 1 s after ewfacquire wrote
    // its first segment
    let Some(run) = acquire(
        "ABORT1",
        &[("FAKEDEV_DELAY_US", "50000")],
        Some(StopFlags::new()),
    )
    .await
    else {
        return;
    };
    let report = run.result.unwrap();
    assert_eq!(report.outcome, Outcome::Aborted, "{:?}", report.notes);
    assert_eq!(report.exit_code, 8);
    assert!(report.aborted);
    assert!(!report.image_files.is_empty());
    for f in &report.image_files {
        assert!(Path::new(f).exists(), "{f} was deleted");
    }
    assert_eq!(Path::new(&report.output_dir), run.out);
    let ewfacquire = report
        .provenance
        .commands
        .iter()
        .find(|c| c.argv[0] == "ewfacquire")
        .unwrap();
    assert!(
        ewfacquire.stop.as_deref().unwrap_or("").contains("SIGINT"),
        "{ewfacquire:?}"
    );
    assert!(report.notes.iter().any(|n| n.contains("not finalized")));
    let (text, _) = read_files(&report);
    assert!(text.contains("ABORTED"));
    assert!(!text.contains("ALL HASHES MATCH"));
}
