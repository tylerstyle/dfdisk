//! End-to-end RAW acquisitions with real read errors at the system-call
//! level: a small LD_PRELOAD library (compiled with `cc` at test time) makes
//! `pread64` fail with EIO on chosen byte ranges of the source file (the
//! whole request fails, as a block device read over a bad sector does), or
//! with ENODEV from a chosen offset on (the device is gone). The session and
//! the engine run unchanged in a child test process: O_DIRECT reads, sector
//! salvage, the read-error table, the verdict and the reports.
//!
//! Without a C compiler the tests are skipped, unless DFDISK_REQUIRE_TOOLS=1
//! (package builds), where they fail.

mod common;

use common::{audit_sandbox, case, file_device, sample};
use dfdisk::engines::session::{self, AcquisitionRequest};
use dfdisk::models::config::{AcquisitionConfig, OnReadError};
use dfdisk::models::info_report::{ForensicInfoReport, HashResults};
use dfdisk::models::outcome::{Outcome, RangeKind, VerificationResult};
use digest::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const SHIM_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int is_target(int fd) {
    const char *t = getenv("DFDISK_SHIM_FILE");
    if (!t) return 0;
    char p[64], buf[4096];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(p, buf, sizeof buf - 1);
    if (n < 0) return 0;
    buf[n] = 0;
    return strcmp(buf, t) == 0;
}

/* DFDISK_SHIM_BAD="off:len,off:len": EIO for a request touching a range.
   DFDISK_SHIM_LOST="off": ENODEV for a request reaching off or beyond. */
static int failure(off_t off, size_t count) {
    off_t end = off + (off_t)count;
    const char *lost = getenv("DFDISK_SHIM_LOST");
    if (lost && end > atoll(lost)) return ENODEV;
    const char *s = getenv("DFDISK_SHIM_BAD");
    while (s && *s) {
        char *colon;
        long long b = strtoll(s, &colon, 10);
        if (*colon != ':') break;
        char *next;
        long long l = strtoll(colon + 1, &next, 10);
        if (off < b + l && end > b) return EIO;
        s = (*next == ',') ? next + 1 : NULL;
    }
    return 0;
}

ssize_t pread64(int fd, void *buf, size_t count, off_t off) {
    static ssize_t (*real)(int, void *, size_t, off_t);
    if (!real) real = dlsym(RTLD_NEXT, "pread64");
    if (count > 0 && is_target(fd)) {
        int e = failure(off, count);
        if (e) { errno = e; return -1; }
    }
    return real(fd, buf, count, off);
}

ssize_t pread(int fd, void *buf, size_t count, off_t off) {
    return pread64(fd, buf, count, off);
}
"#;

const CHILD: &str = "child_runs_one_scenario";
const MIB: u64 = 1 << 20;

fn require_tools() -> bool {
    std::env::var("DFDISK_REQUIRE_TOOLS").is_ok_and(|v| v == "1")
}

/// Compile the shim into `dir`; `None` (skip) without a C compiler.
fn build_shim(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("eio_shim.c");
    let lib = dir.join("eio_shim.so");
    std::fs::write(&src, SHIM_C).unwrap();
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    match Command::new(&cc)
        .args(["-shared", "-fPIC", "-O1", "-o"])
        .arg(&lib)
        .arg(&src)
        .arg("-ldl")
        .output()
    {
        Ok(o) if o.status.success() => Some(lib),
        Ok(o) => panic!(
            "{cc} failed to build the test shim: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) if require_tools() => {
            panic!("DFDISK_REQUIRE_TOOLS=1 but no C compiler ({cc}): {e}")
        }
        Err(e) => {
            eprintln!("skipping: no C compiler ({cc}): {e}");
            None
        }
    }
}

struct Scenario<'a> {
    name: &'a str,
    size: usize,
    policy: OnReadError,
    bad: &'a str,
    lost: Option<u64>,
}

/// Run `scenario` in a child test process with the shim preloaded; returns
/// the source data and the report the child wrote.
fn run_scenario(s: &Scenario) -> Option<(Vec<u8>, ForensicInfoReport, tempfile::TempDir)> {
    let tmp = tempfile::tempdir().unwrap();
    let shim = build_shim(tmp.path())?;
    let data = sample(s.size);
    let src = tmp.path().join("source.bin");
    std::fs::write(&src, &data).unwrap();
    let src = std::fs::canonicalize(&src).unwrap();
    let out = tmp.path().join("out");
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([CHILD, "--exact", "--nocapture", "--test-threads=1"])
        .env("LD_PRELOAD", &shim)
        .env("DFDISK_SHIM_FILE", &src)
        .env("DFDISK_SHIM_BAD", s.bad)
        .env("DFDISK_EIO_SCENARIO", s.name)
        .env("DFDISK_EIO_SOURCE", &src)
        .env("DFDISK_EIO_OUT", &out)
        .env(
            "DFDISK_EIO_POLICY",
            match s.policy {
                OnReadError::Stop => "stop",
                OnReadError::ZeroFill => "zero-fill",
            },
        );
    if let Some(l) = s.lost {
        cmd.env("DFDISK_SHIM_LOST", l.to_string());
    }
    let o = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        stdout.contains("CHILD RAN"),
        "the child did not run:\n{stdout}"
    );
    let json = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(".info.json"))
        .expect("a report");
    let report = ForensicInfoReport::from_json(&std::fs::read_to_string(&json).unwrap()).unwrap();
    let text = std::fs::read_to_string(json.with_extension("")).unwrap();
    assert_eq!(text, report.render_text());
    Some((data, report, tmp))
}

/// The child: one acquisition through the session, with the shim active.
#[tokio::test]
async fn child_runs_one_scenario() {
    let Ok(name) = std::env::var("DFDISK_EIO_SCENARIO") else {
        return; // only meaningful in the child process
    };
    audit_sandbox();
    let src = PathBuf::from(std::env::var("DFDISK_EIO_SOURCE").unwrap());
    let out = PathBuf::from(std::env::var("DFDISK_EIO_OUT").unwrap());
    let policy = match std::env::var("DFDISK_EIO_POLICY").unwrap().as_str() {
        "zero-fill" => OnReadError::ZeroFill,
        _ => OnReadError::Stop,
    };
    let config = AcquisitionConfig {
        allow_tmpfs: true,
        on_read_error: policy,
        piece_size: Some(MIB),
        verify_source: true,
        ..AcquisitionConfig::raw(&out)
    };
    let size = std::fs::metadata(&src).unwrap().len();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1000);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let report = session::run(
        AcquisitionRequest::new(file_device(&src, size, Some("EIO01")), case(), config),
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap_or_else(|e| panic!("{name}: the session failed: {e}"));
    let _ = drain.await;
    println!("CHILD RAN {name}: {}", report.outcome.label());
}

fn digests(data: &[u8]) -> HashResults {
    HashResults {
        md5: Some(hex::encode(md5::Md5::digest(data))),
        sha1: Some(hex::encode(sha1::Sha1::digest(data))),
        sha256: Some(hex::encode(sha2::Sha256::digest(data))),
    }
}

fn ranges(r: &ForensicInfoReport) -> Vec<(u64, u64, RangeKind)> {
    r.read_errors
        .ranges
        .iter()
        .map(|x| (x.offset, x.length, x.kind))
        .collect()
}

#[test]
fn one_bad_sector_zero_filled_is_completed_with_read_errors() {
    let bad_at = MIB + 4096;
    let Some((data, report, _tmp)) = run_scenario(&Scenario {
        name: "zero-fill-one-sector",
        size: (3 * MIB) as usize,
        policy: OnReadError::ZeroFill,
        bad: &format!("{bad_at}:512"),
        lost: None,
    }) else {
        return;
    };
    assert_eq!(
        report.outcome,
        Outcome::CompletedWithReadErrors,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 7);
    assert_eq!(report.bytes_acquired, data.len() as u64);
    assert_eq!(ranges(&report), [(bad_at, 512, RangeKind::Substituted)]);
    assert_eq!(report.read_errors.substituted_sectors(), 1);

    // The image is the source with exactly that sector zeroed, and the
    // digests (stream and re-read) describe that image
    let mut expected = data.clone();
    expected[bad_at as usize..bad_at as usize + 512].fill(0);
    let image = std::fs::read(&report.image_files[0]).unwrap();
    assert!(image == expected, "only the bad sector differs");
    assert_eq!(report.acquisition_hashes, digests(&expected));
    assert_eq!(report.image_hashes, digests(&expected));
    assert!(report.verification.result.is_matched());
    // A second read cannot reproduce a stream with substitutions
    assert!(matches!(
        report.verification.source_reread,
        Some(VerificationResult::NotPossible { .. })
    ));
    let text = report.render_text();
    assert!(!text.contains("ALL HASHES MATCH"), "{text}");
    assert!(text.contains("COMPLETED WITH READ ERRORS"), "{text}");
    assert!(text.contains(&bad_at.to_string()), "{text}");
    // The pieces: the second piece holds the zeroed sector
    assert_eq!(report.piecewise.as_ref().unwrap().count, 3);
}

#[test]
fn stop_policy_ends_at_the_bad_sector_and_is_incomplete() {
    let bad_at = 2 * MIB + 512 * 7;
    let Some((data, report, _tmp)) = run_scenario(&Scenario {
        name: "stop-one-sector",
        size: (3 * MIB) as usize,
        policy: OnReadError::Stop,
        bad: &format!("{bad_at}:512"),
        lost: None,
    }) else {
        return;
    };
    assert_eq!(
        report.outcome,
        Outcome::Incomplete,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 6);
    assert_eq!(report.bytes_acquired, bad_at);
    let stop = report.stop_reason.as_deref().unwrap();
    assert!(
        stop.starts_with(&format!(
            "read error at byte offset {bad_at} (sector {})",
            bad_at / 512
        )),
        "{stop}"
    );
    assert_eq!(
        ranges(&report),
        [(bad_at, data.len() as u64 - bad_at, RangeKind::Unread)]
    );
    let image = std::fs::read(&report.image_files[0]).unwrap();
    assert!(
        image == data[..bad_at as usize],
        "everything before the bad sector"
    );
    assert_eq!(report.acquisition_hashes, digests(&image));
    assert!(
        report.verification.result.is_matched(),
        "the partial image verifies"
    );
    assert!(!report.render_text().contains("ALL HASHES MATCH"));
}

#[test]
fn several_damaged_areas_are_listed_exactly() {
    let Some((data, report, _tmp)) = run_scenario(&Scenario {
        name: "zero-fill-ranges",
        size: (4 * MIB) as usize,
        policy: OnReadError::ZeroFill,
        bad: "0:1024,1049600:4096,4193792:512",
        lost: None,
    }) else {
        return;
    };
    assert_eq!(report.outcome, Outcome::CompletedWithReadErrors);
    assert_eq!(
        ranges(&report),
        [
            (0, 1024, RangeKind::Substituted),
            (1_049_600, 4096, RangeKind::Substituted),
            (4_193_792, 512, RangeKind::Substituted),
        ]
    );
    assert_eq!(report.read_errors.substituted_sectors(), 2 + 8 + 1);
    assert_eq!(report.bytes_acquired, data.len() as u64);
}

#[test]
fn a_device_that_disappears_is_source_lost_and_incomplete() {
    let lost = 2 * MIB;
    let Some((data, report, _tmp)) = run_scenario(&Scenario {
        name: "lost",
        size: (4 * MIB) as usize,
        policy: OnReadError::ZeroFill,
        bad: "",
        lost: Some(lost),
    }) else {
        return;
    };
    assert_eq!(
        report.outcome,
        Outcome::Incomplete,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 6);
    assert_eq!(report.bytes_acquired, lost);
    let stop = report.stop_reason.as_deref().unwrap();
    assert!(
        stop.starts_with(&format!("source lost at byte offset {lost}")),
        "{stop}"
    );
    assert_eq!(
        ranges(&report),
        [(lost, data.len() as u64 - lost, RangeKind::Unread)]
    );
    let image = std::fs::read(&report.image_files[0]).unwrap();
    assert!(image == data[..lost as usize]);
}
