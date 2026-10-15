//! Rescue acquisitions end to end through the session on this host, with the
//! real GNU ddrescue on regular files. Bad areas come from ddrescue's own test
//! mode: a wrapper named `ddrescue` first in PATH adds the options listed in
//! `<source>.ddrescue-args` (e.g. `-H map`, `--no-trim`, `-Z rate`) and runs
//! the real ddrescue. The tests run when ddrescue is installed and fail
//! without it when DFDISK_REQUIRE_TOOLS=1.

mod common;

use common::{audit_sandbox, case, file_device, sample, scratch};
use dfdisk::engines::session::{self, AcquisitionRequest};
use dfdisk::engines::{rescue, AcquisitionError, ErrorKind};
use dfdisk::models::config::AcquisitionConfig;
use dfdisk::models::device::BlockDevice;
use dfdisk::models::info_report::{sha256_file, ForensicInfoReport};
use dfdisk::models::outcome::{Outcome, RangeKind, VerificationResult};
use dfdisk::models::telemetry::ProgressTelemetry;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const MIB: usize = 1 << 20;
const TESTMODE_BAD_MIDDLE: &str = "tests/fixtures/ddrescue/testmode_bad_middle.map";
const TESTMODE_4MIB: &str = "tests/fixtures/ddrescue/testmode_4mib.map";

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}

/// Put the test-mode wrapper first in PATH (once per test binary). `false`
/// when ddrescue is not installed and tools are not required.
fn ddrescue_wrapper() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        audit_sandbox();
        let Some(real) = find_in_path("ddrescue") else {
            assert!(
                std::env::var_os("DFDISK_REQUIRE_TOOLS").is_none(),
                "DFDISK_REQUIRE_TOOLS is set but ddrescue is not installed"
            );
            eprintln!("ddrescue not installed: rescue end-to-end tests skipped");
            return false;
        };
        let dir = tempfile::Builder::new()
            .prefix("dfdisk-ddrescue-wrapper-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap()
            .keep();
        let script = dir.join("ddrescue");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 # test wrapper: options from <infile>.ddrescue-args, then the real ddrescue\n\
                 REAL='{}'\n\
                 n=$#\n\
                 if [ $n -lt 3 ]; then exec \"$REAL\" \"$@\"; fi\n\
                 eval \"infile=\\${{$((n-2))}}\"\n\
                 if [ -f \"$infile.ddrescue-args\" ]; then set -- $(cat \"$infile.ddrescue-args\") \"$@\"; fi\n\
                 exec \"$REAL\" \"$@\"\n",
                real.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![dir];
        paths.extend(std::env::split_paths(&path));
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
        true
    })
}

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// A regular-file source with `len` bytes and ddrescue test options.
fn source(dir: &Path, len: usize, ddrescue_args: Option<String>) -> (PathBuf, Vec<u8>) {
    let data = sample(len);
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    if let Some(args) = ddrescue_args {
        std::fs::write(dir.join("src.bin.ddrescue-args"), args).unwrap();
    }
    (src, data)
}

fn rescue_config(out: &Path) -> AcquisitionConfig {
    AcquisitionConfig {
        allow_tmpfs: true,
        error_retries: 0,
        ..AcquisitionConfig::rescue(out)
    }
}

/// Run the session; with `abort_when_mapped`, abort shortly after ddrescue
/// wrote its map into that directory (a fixed delay raced with a slow
/// session start under load: an abort before ddrescue wrote anything is an
/// error, not a report).
async fn run_with_abort(
    device: BlockDevice,
    config: AcquisitionConfig,
    abort_when_mapped: Option<PathBuf>,
) -> Result<ForensicInfoReport, AcquisitionError> {
    audit_sandbox();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressTelemetry>(1000);
    let drain = tokio::spawn(async move {
        let mut t = ProgressTelemetry::default();
        while let Some(u) = rx.recv().await {
            t.apply_update(u);
        }
        t
    });
    let abort = Arc::new(AtomicBool::new(false));
    if let Some(dir) = abort_when_mapped {
        let flag = abort.clone();
        tokio::spawn(async move {
            for _ in 0..1500 {
                let mapped = std::fs::read_dir(&dir).is_ok_and(|rd| {
                    rd.flatten().any(|e| {
                        e.file_name().to_string_lossy().ends_with(".map")
                            && e.metadata().is_ok_and(|m| m.len() > 0)
                    })
                });
                if mapped {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            flag.store(true, Ordering::SeqCst);
        });
    }
    let r = session::run(AcquisitionRequest::new(device, case(), config), tx, abort).await;
    let _ = drain.await;
    r
}

async fn run(
    device: BlockDevice,
    config: AcquisitionConfig,
) -> Result<ForensicInfoReport, AcquisitionError> {
    run_with_abort(device, config, None).await
}

fn image_of(report: &ForensicInfoReport) -> Vec<u8> {
    std::fs::read(&report.image_files[0]).unwrap()
}

fn ddrescue_argv(report: &ForensicInfoReport) -> Vec<String> {
    report
        .provenance
        .commands
        .iter()
        .find(|c| c.argv[0] == rescue::DDRESCUE)
        .expect("the ddrescue command is recorded")
        .argv
        .clone()
}

/// The "acquisition_finished" audit record of `report`.
fn finished_record(report: &ForensicInfoReport) -> serde_json::Value {
    let log = std::fs::read_to_string(audit_sandbox().join("audit.jsonl")).unwrap();
    let report_file = Path::new(&report.output_dir)
        .join(format!("{}.info", report.base_name))
        .to_string_lossy()
        .into_owned();
    log.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|r| r["action"] == "acquisition_finished")
        .find(|r| r["details"]["report_file"] == report_file.as_str())
        .expect("a finished record for the report")
}

#[tokio::test]
async fn a_clean_rescue_is_complete_but_unverified_without_a_second_read() {
    if !ddrescue_wrapper() {
        return;
    }
    let tmp = scratch();
    let (src, data) = source(tmp.path(), MIB, None);
    let out = tmp.path().join("out");
    let report = run(
        file_device(&src, MIB as u64, Some("CLEAN01")),
        rescue_config(&out),
    )
    .await
    .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::CompleteUnverified,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 9);
    assert!(report.read_errors.is_empty());
    assert_eq!(report.read_errors.source, "ddrescue mapfile");
    assert_eq!(report.bytes_acquired, MIB as u64);
    assert!(
        report.acquisition_hashes.is_empty(),
        "ddrescue computes no digest"
    );
    assert_eq!(image_of(&report), data);
    assert!(matches!(
        report.verification.result,
        VerificationResult::NotPossible { .. }
    ));
    let text = report.render_text();
    assert!(
        text.contains("COMPLETE, NOT VERIFIED (exit code 9)"),
        "{text}"
    );
    assert!(!text.contains("ALL HASHES MATCH"), "{text}");
    assert!(text.contains("GNU ddrescue"), "{text}");

    // Map and identity record are listed with their digests, here and in the audit record
    let base = Path::new(&report.output_dir).join(&report.base_name);
    let map = PathBuf::from(format!("{}.map", base.display()));
    let identity = PathBuf::from(format!("{}.identity.json", base.display()));
    for f in [&map, &identity] {
        let digest = sha256_file(f).unwrap();
        assert!(
            report
                .auxiliary_files
                .iter()
                .any(|a| Path::new(&a.path) == f && a.sha256 == digest),
            "{f:?} {:?}",
            report.auxiliary_files
        );
    }
    let record = finished_record(&report);
    let aux = record["details"]["auxiliary_files"].as_array().unwrap();
    assert!(aux
        .iter()
        .any(|a| a["path"] == map.to_string_lossy().as_ref()
            && a["sha256"] == sha256_file(&map).unwrap().as_str()));
    let rec = rescue::read_identity_record(&identity).unwrap();
    assert_eq!(rec.identity.canonical_path, report.source.canonical_path);
    assert_eq!(rec.identity.size_bytes, MIB as u64);

    // What ran: no -d for a regular file, no -I on a first start, the version recorded
    let argv = ddrescue_argv(&report);
    assert!(
        !argv.contains(&"-d".to_string()) && !argv.contains(&"-I".to_string()),
        "{argv:?}"
    );
    assert!(argv.windows(2).any(|w| w == ["-b", "512"]), "{argv:?}");
    assert!(report.provenance.tools["ddrescue"].starts_with("GNU ddrescue"));

    // --verify-source: the second read matches the image -> verified
    let tmp = scratch();
    let (src, _) = source(tmp.path(), MIB, None);
    let config = AcquisitionConfig {
        verify_source: true,
        ..rescue_config(&tmp.path().join("out"))
    };
    let report = run(file_device(&src, MIB as u64, Some("CLEAN02")), config)
        .await
        .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 0);
    assert!(report.render_text().contains("ALL HASHES MATCH"));
}

#[tokio::test]
async fn bad_sectors_from_the_map_are_substituted_and_never_verified() {
    if !ddrescue_wrapper() {
        return;
    }
    let tmp = scratch();
    let args = format!("-H {}", fixture(TESTMODE_BAD_MIDDLE).display());
    let (src, data) = source(tmp.path(), MIB, Some(args));
    let config = AcquisitionConfig {
        verify_source: true,
        ..rescue_config(&tmp.path().join("out"))
    };
    let report = run(file_device(&src, MIB as u64, Some("BAD01")), config)
        .await
        .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::CompletedWithReadErrors,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 7);
    let ranges: Vec<_> = report
        .read_errors
        .ranges
        .iter()
        .map(|r| (r.offset, r.length, r.kind))
        .collect();
    assert_eq!(
        ranges,
        vec![
            (0x10000, 0x400, RangeKind::Substituted),
            (0x90000, 0x200, RangeKind::Substituted)
        ]
    );
    assert_eq!(report.read_errors.substituted_sectors(), 3);
    assert_eq!(report.bytes_acquired, MIB as u64);
    // The image holds zeros there and the source everywhere else
    let image = image_of(&report);
    assert_eq!(image.len(), MIB);
    for (offset, length, _) in &ranges {
        let (o, l) = (*offset as usize, *length as usize);
        assert!(image[o..o + l].iter().all(|b| *b == 0));
        assert!(data[o..o + l].iter().any(|b| *b != 0));
    }
    assert_eq!(image[..0x10000], data[..0x10000]);
    assert_eq!(image[0x10400..0x90000], data[0x10400..0x90000]);
    assert_eq!(image[0x90200..], data[0x90200..]);
    // The second read is skipped: it cannot reproduce substituted sectors
    assert!(matches!(
        report.verification.source_reread,
        Some(VerificationResult::NotPossible { .. })
    ));
    let text = report.render_text();
    assert!(!text.contains("ALL HASHES MATCH"), "{text}");
    assert!(
        text.contains("3 sectors (1.50 KiB) in 2 ranges were unreadable and replaced by zeros"),
        "{text}"
    );
    assert!(
        text.contains("bad-sector 1.50 KiB (1536 bytes) in 2 areas"),
        "{text}"
    );
    let record = finished_record(&report);
    assert_eq!(record["details"]["exit_code"], 7);
}

#[tokio::test]
async fn areas_left_unfinished_make_the_rescue_incomplete() {
    if !ddrescue_wrapper() {
        return;
    }
    let tmp = scratch();
    let args = format!("--no-trim -H {}", fixture(TESTMODE_BAD_MIDDLE).display());
    let (src, _) = source(tmp.path(), MIB, Some(args));
    let report = run(
        file_device(&src, MIB as u64, Some("TRIM01")),
        rescue_config(&tmp.path().join("out")),
    )
    .await
    .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Incomplete,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 6);
    // Two non-trimmed blocks of 64 KiB around the bad sectors: not read, not substituted
    assert_eq!(report.read_errors.unread_bytes(), 0x20000);
    assert_eq!(report.read_errors.substituted_bytes(), 0);
    assert_eq!(report.bytes_acquired, (MIB - 0x20000) as u64);
    let text = report.render_text();
    assert!(text.contains("run the rescue again"), "{text}");
    assert!(
        text.contains("non-trimmed 128 KiB (131072 bytes)"),
        "{text}"
    );
}

#[tokio::test]
async fn an_aborted_rescue_resumes_with_its_sessions_listed() {
    if !ddrescue_wrapper() {
        return;
    }
    let tmp = scratch();
    let size = 4 * MIB;
    // 256 KiB/s: the 4 MiB source takes 16 s; abort 0.5 s after the map
    // appears
    let args = format!("-Z 262144 -H {}", fixture(TESTMODE_4MIB).display());
    let (src, data) = source(tmp.path(), size, Some(args));
    let out = tmp.path().join("out");
    let device = file_device(&src, size as u64, Some("RESUME01"));
    let report = run_with_abort(device.clone(), rescue_config(&out), Some(out.clone()))
        .await
        .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Aborted,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 8);
    assert!(report.read_errors.unread_bytes() > 0);
    let cmd = report
        .provenance
        .commands
        .iter()
        .find(|c| c.argv[0] == rescue::DDRESCUE)
        .unwrap();
    assert!(
        cmd.stop.as_deref().unwrap_or("").contains("SIGINT"),
        "{cmd:?}"
    );
    let map = out.join(format!("{}.map", report.base_name));
    let saved = std::fs::read_to_string(&map).unwrap();
    assert!(
        saved.contains("?"),
        "ddrescue saved a map with untried areas:\n{saved}"
    );
    let first_map_sha = sha256_file(&map).unwrap();
    assert!(report
        .auxiliary_files
        .iter()
        .any(|a| a.sha256 == first_map_sha));

    // Resume at full speed: the rest is read, the earlier report is kept
    std::fs::write(
        tmp.path().join("src.bin.ddrescue-args"),
        format!("-H {}", fixture(TESTMODE_4MIB).display()),
    )
    .unwrap();
    let config = AcquisitionConfig {
        resume: true,
        ..rescue_config(&out)
    };
    let resumed = run(device, config).await.unwrap();
    assert_eq!(
        resumed.outcome,
        Outcome::CompletedWithReadErrors,
        "{}",
        resumed.outcome_reason
    );
    assert_eq!(resumed.exit_code, 7);
    assert_eq!(resumed.bytes_acquired, size as u64);
    assert_eq!(resumed.read_errors.substituted_bytes(), 0x10000);
    assert_eq!(resumed.read_errors.ranges[0].offset, 0x100000);
    let image = image_of(&resumed);
    assert_eq!(image[..0x100000], data[..0x100000]);
    assert_eq!(image[0x110000..], data[0x110000..]);
    assert!(ddrescue_argv(&resumed).contains(&"-I".to_string()));

    assert_eq!(resumed.resume_sessions.len(), 1);
    let s = &resumed.resume_sessions[0];
    assert_eq!(s.session, 1);
    assert_eq!(s.outcome, Some(Outcome::Aborted));
    let kept = out.join(format!("{}.info.session-1", resumed.base_name));
    assert_eq!(Path::new(&s.report_file), kept);
    assert_eq!(
        std::fs::read_to_string(&kept).unwrap(),
        report.render_text()
    );
    assert_eq!(
        s.report_sha256.as_deref(),
        Some(sha256_file(&kept).unwrap().as_str())
    );
    let kept_json = out.join(format!("{}.info.session-1.json", resumed.base_name));
    assert_eq!(
        ForensicInfoReport::from_json(&std::fs::read_to_string(kept_json).unwrap())
            .unwrap()
            .outcome,
        Outcome::Aborted
    );
    let notes = resumed.notes.join("\n");
    assert!(
        notes.contains("the source matches the identity recorded at the first start"),
        "{notes}"
    );
    // R-6: the identity record is the one the previous report lists
    let identity = out.join(format!("{}.identity.json", resumed.base_name));
    let identity_sha = sha256_file(&identity).unwrap();
    assert!(
        notes.contains(&format!(
            "(SHA-256 {identity_sha}) is the one the report of the last session"
        )),
        "{notes}"
    );
    assert!(
        notes.contains(&format!(
            "(SHA-256 {first_map_sha}) is the map the report of session 1 lists"
        )),
        "{notes}"
    );
    let text = resumed.render_text();
    assert!(text.contains("Earlier Session 1"), "{text}");
    assert!(text.contains("Resumed"), "{text}");
}

/// R-2: a session killed after ddrescue wrote data but before it saved its
/// map leaves source data in areas the map lists as not tried; when the
/// resumed session finds them unreadable, ddrescue marks them bad and never
/// writes them. The report says bad sectors are zeros in the image: dfdisk
/// makes that true.
#[tokio::test]
async fn bad_areas_hold_zeros_after_a_killed_session_is_resumed() {
    if !ddrescue_wrapper() {
        return;
    }
    let tmp = scratch();
    let (src, data) = source(tmp.path(), MIB, None);
    let out = tmp.path().join("out");
    let device = file_device(&src, MIB as u64, Some("KILLED01"));
    let first = run(device.clone(), rescue_config(&out)).await.unwrap();
    assert_eq!(first.outcome, Outcome::CompleteUnverified);
    // The map as a killed session can leave it: the image holds the data of
    // these areas, the map lists them as not tried
    let map = out.join(format!("{}.map", first.base_name));
    std::fs::write(
        &map,
        "# Mapfile. Created by GNU ddrescue version 1.30\n\
         # current_pos  current_status  current_pass\n\
         0x00010000     ?               1\n\
         #      pos        size  status\n\
         0x00000000  0x00010000  +\n\
         0x00010000  0x00000400  ?\n\
         0x00010400  0x0007FC00  +\n\
         0x00090000  0x00000200  ?\n\
         0x00090200  0x0006FE00  +\n",
    )
    .unwrap();
    assert_eq!(image_of(&first), data, "the image holds the whole source");
    // Now these areas cannot be read
    std::fs::write(
        tmp.path().join("src.bin.ddrescue-args"),
        format!("-H {}", fixture(TESTMODE_BAD_MIDDLE).display()),
    )
    .unwrap();
    let config = AcquisitionConfig {
        resume: true,
        ..rescue_config(&out)
    };
    let resumed = run(device.clone(), config).await.unwrap();
    assert_eq!(
        resumed.outcome,
        Outcome::CompletedWithReadErrors,
        "{}",
        resumed.outcome_reason
    );
    let saved = std::fs::read_to_string(&map).unwrap();
    assert!(
        saved.contains("0x00010000  0x00000400  -"),
        "ddrescue marked the area bad:\n{saved}"
    );
    let image = image_of(&resumed);
    assert_eq!(image.len(), MIB);
    assert!(image[0x10000..0x10400].iter().all(|b| *b == 0));
    assert!(image[0x90000..0x90200].iter().all(|b| *b == 0));
    assert_eq!(image[..0x10000], data[..0x10000]);
    assert_eq!(image[0x10400..0x90000], data[0x10400..0x90000]);
    assert_eq!(image[0x90200..], data[0x90200..]);
    let notes = resumed.notes.join("\n");
    assert!(
        notes.contains("dfdisk wrote zeros over the 2 bad-sector areas of the map inside the image (1536 bytes)"),
        "{notes}"
    );
    assert!(
        notes.contains("3 sectors (512-byte) held other data before"),
        "{notes}"
    );
    // The digests describe the zeros
    let mut expected = data.clone();
    expected[0x10000..0x10400].fill(0);
    expected[0x90000..0x90200].fill(0);
    assert_eq!(
        resumed.image_hashes.md5.as_deref(),
        Some(hex::encode(<md5::Md5 as md5::Digest>::digest(&expected)).as_str())
    );

    // S-N3: the source data the zeros replaced is kept in the files of
    // session 2 (the first session's report is kept as session 1), listed
    // with their SHA-256
    let bin = out.join(format!("{}.zeroed-2.bin", resumed.base_name));
    let tsv = out.join(format!("{}.zeroed-2.tsv", resumed.base_name));
    let mut kept = data[0x10000..0x10400].to_vec();
    kept.extend_from_slice(&data[0x90000..0x90200]);
    assert_eq!(std::fs::read(&bin).unwrap(), kept);
    let sha = |b: &[u8]| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b));
    assert_eq!(
        std::fs::read_to_string(&tsv).unwrap(),
        format!(
            "{}\n65536\t1024\t0\t{}\n589824\t512\t1024\t{}\n",
            rescue::ZEROED_TSV_HEADER,
            sha(&data[0x10000..0x10400]),
            sha(&data[0x90000..0x90200])
        )
    );
    for f in [&bin, &tsv] {
        let listed = resumed
            .auxiliary_files
            .iter()
            .find(|a| Path::new(&a.path) == f.as_path())
            .unwrap_or_else(|| panic!("{} not listed", f.display()));
        assert_eq!(listed.sha256, sha(&std::fs::read(f).unwrap()));
    }
    assert!(
        notes.contains(&format!(
            "their bytes are kept in {}.zeroed-2.bin",
            resumed.base_name
        )),
        "{notes}"
    );
    let text = std::fs::read_to_string(out.join(format!("{}.info", resumed.base_name))).unwrap();
    assert!(
        text.contains(&format!(".zeroed-2.bin (SHA-256 {})", sha(&kept))),
        "{text}"
    );

    // A further resume accepts the kept files and never touches them
    let config = AcquisitionConfig {
        resume: true,
        ..rescue_config(&out)
    };
    let again = run(device, config).await.unwrap();
    assert_eq!(again.outcome, Outcome::CompletedWithReadErrors);
    assert_eq!(std::fs::read(&bin).unwrap(), kept);
    assert!(!out
        .join(format!("{}.zeroed-3.bin", resumed.base_name))
        .exists());
}

#[tokio::test]
async fn a_resume_on_another_source_is_refused_before_anything_is_written() {
    if !ddrescue_wrapper() {
        return;
    }
    let tmp = scratch();
    let (src, _) = source(tmp.path(), MIB, None);
    let out = tmp.path().join("out");
    let device = file_device(&src, MIB as u64, Some("SWAP01"));
    let first = run(device.clone(), rescue_config(&out)).await.unwrap();
    assert_eq!(first.outcome, Outcome::CompleteUnverified);
    let base = first.base_name.clone();
    let snapshot = |dir: &Path| {
        let mut v: Vec<(String, String)> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    sha256_file(&e.path()).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let before = snapshot(&out);
    let resume = AcquisitionConfig {
        resume: true,
        ..rescue_config(&out)
    };

    // Another file of the same size at the same path (a new inode)
    let other = tmp.path().join("other.bin");
    std::fs::write(&other, vec![0xEEu8; MIB]).unwrap();
    std::fs::rename(&other, &src).unwrap();
    let e = run(device.clone(), resume.clone()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused, "{e}");
    assert_eq!(e.exit_code(), 3);
    assert!(
        e.message.contains("not the device this rescue started on"),
        "{e}"
    );
    assert!(e.message.contains("another file at the same path"), "{e}");
    assert_eq!(snapshot(&out), before, "a refused resume changes nothing");

    // Another size
    std::fs::write(&src, vec![0xEEu8; 2 * MIB]).unwrap();
    let bigger = file_device(&src, 2 * MIB as u64, Some("SWAP01"));
    let e = run(bigger, resume.clone()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused, "{e}");
    assert!(
        e.message.contains("size 2097152 bytes, was 1048576 bytes"),
        "{e}"
    );
    assert_eq!(snapshot(&out), before);

    // R-6: an identity record changed after the last report (here: the same
    // content re-serialised) is not trusted
    std::fs::write(&src, vec![0xEEu8; MIB]).unwrap();
    let record = out.join(format!("{base}.identity.json"));
    let original = std::fs::read_to_string(&record).unwrap();
    let value: serde_json::Value = serde_json::from_str(&original).unwrap();
    std::fs::write(&record, serde_json::to_string(&value).unwrap()).unwrap();
    let changed = snapshot(&out);
    let e = run(device.clone(), resume.clone()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused, "{e}");
    assert!(e.message.contains("changed or replaced"), "{e}");
    assert_eq!(snapshot(&out), changed, "a refused resume changes nothing");
    std::fs::write(&record, original).unwrap();

    // No identity record: the map cannot be tied to any source
    std::fs::remove_file(out.join(format!("{base}.identity.json"))).unwrap();
    std::fs::write(&src, vec![0xEEu8; MIB]).unwrap();
    let e = run(device, resume).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused, "{e}");
    assert!(e.message.contains("does not exist"), "{e}");
}
