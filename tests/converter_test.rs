//! Conversions with real libewf (§13 Converter, review H3): verified RAW to
//! E01 and E01 to RAW, split inputs, refusals before anything is written,
//! case values from the source report, inherited read errors and verdicts,
//! mismatch detection, aborts that stop the tool.
//!
//! The tests need ewfacquire/ewfexport/ewfinfo/ewfverify on PATH; without
//! them they are skipped, unless DFDISK_REQUIRE_TOOLS=1 (then they fail).

mod common;

use dfdisk::engines::converter::{convert_with, ConvertEnv, ConverterTools, FileFlush};
use dfdisk::engines::ErrorKind;
use dfdisk::models::case::CaseMetadata;
use dfdisk::models::config::{
    AcquisitionConfig, CompressionLevel, EffectiveConfig, EngineKind, SplitSize,
};
use dfdisk::models::conversion::{ConversionReport, ConversionRequest, ConversionTarget};
use dfdisk::models::identity::SourceIdentity;
use dfdisk::models::info_report::{ForensicInfoReport, HashResults};
use dfdisk::models::outcome::{exit_code, Outcome, RangeKind, ReadErrorTable, VerificationResult};
use dfdisk::models::protection::RegistryPresence;
use dfdisk::signals::StopFlags;
use md5::Digest;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;

fn have_libewf() -> bool {
    let ok = ["ewfacquire", "ewfexport", "ewfinfo", "ewfverify"]
        .iter()
        .all(|t| {
            std::process::Command::new(t)
                .arg("-V")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        });
    if !ok && std::env::var("DFDISK_REQUIRE_TOOLS").as_deref() == Ok("1") {
        panic!("DFDISK_REQUIRE_TOOLS=1 but the libewf tools are not installed");
    }
    if !ok {
        eprintln!("skipping: libewf tools (ewfacquire/ewfexport/ewfinfo/ewfverify) not installed");
    }
    ok
}

/// Absolute path of `tool` on PATH.
fn which(tool: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|d| d.join(tool))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("{tool} not on PATH"))
}

/// Deterministic pseudo-random bytes (incompressible, fast).
fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn md5_hex(bytes: &[u8]) -> String {
    hex::encode(md5::Md5::digest(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    src: PathBuf,
    out: PathBuf,
    env: ConvertEnv,
}

fn fixture() -> Fixture {
    common::audit_sandbox();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let src = root.join("src");
    let out = root.join("out");
    std::fs::create_dir_all(&src).unwrap();
    let env = ConvertEnv {
        tools: ConverterTools::default(),
        audit_log: root.join("audit.jsonl"),
        registry: RegistryPresence::Absent,
        mountinfo: None,
        grace: Duration::from_secs(15),
        export_audit: false,
        flush: FileFlush::default(),
    };
    Fixture {
        _tmp: tmp,
        root,
        src,
        out,
        env,
    }
}

fn case() -> CaseMetadata {
    CaseMetadata {
        case_number: "CASE42".into(),
        evidence_number: "CF01".into(),
        examiner: "Examiner".into(),
        description: "converter test".into(),
        ..Default::default()
    }
}

/// A request for a test destination (which may be on tmpfs).
fn request(source: &Path, target: ConversionTarget, out: &Path) -> ConversionRequest {
    ConversionRequest {
        allow_tmpfs: true,
        ..ConversionRequest::new(source, target, out)
    }
}

async fn run(
    env: &ConvertEnv,
    req: ConversionRequest,
    stop: StopFlags,
) -> Result<ConversionReport, dfdisk::engines::AcquisitionError> {
    let (tx, mut rx) = mpsc::channel(64);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let r = convert_with(env, req, tx, stop).await;
    let _ = drain.await;
    r
}

fn audit_actions(log: &Path) -> Vec<Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Abort `stop` once `file` exists with more than `min_len` bytes (at most
/// 30 s later): a fixed delay raced with a slow tool start under load, and an
/// abort before the tool wrote anything is (correctly) an error, not a report.
fn abort_once_written(stop: &StopFlags, file: PathBuf, min_len: u64) {
    let flag = stop.clone();
    tokio::spawn(async move {
        for _ in 0..1500 {
            if std::fs::metadata(&file).is_ok_and(|m| m.len() > min_len) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        flag.abort.store(true, std::sync::atomic::Ordering::SeqCst);
    });
}

fn ewfinfo(image: &Path) -> String {
    let out = std::process::Command::new("ewfinfo")
        .arg(image)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// A dfdisk acquisition report for `image` (as a RAW engine run would write).
fn acquisition_report(
    image: &Path,
    content: &[u8],
    outcome_setup: impl FnOnce(&mut ForensicInfoReport),
) -> PathBuf {
    let dir = image.parent().unwrap();
    let identity = SourceIdentity {
        path: "/dev/sdx".into(),
        canonical_path: "/dev/sdx".into(),
        kernel_name: "sdx".into(),
        size_bytes: content.len() as u64,
        logical_sector_size: 512,
        physical_sector_size: 512,
        ..Default::default()
    };
    let config = AcquisitionConfig::raw(dir);
    let effective = EffectiveConfig::build(&config, Some(&identity));
    let mut r = ForensicInfoReport::new(EngineKind::Raw, &case(), identity, effective);
    r.base_name = "x".into();
    r.output_dir = dir.to_string_lossy().into_owned();
    r.image_files = vec![image.to_string_lossy().into_owned()];
    r.bytes_acquired = content.len() as u64;
    r.acquisition_hashes = HashResults {
        md5: Some(md5_hex(content)),
        sha1: None,
        sha256: Some(sha256_hex(content)),
    };
    r.image_hashes = r.acquisition_hashes.clone();
    r.verification.result = VerificationResult::Matched {
        method: "image re-read".into(),
    };
    outcome_setup(&mut r);
    r.apply_classification();
    let path = dir.join("x.info.json");
    std::fs::write(&path, r.to_json()).unwrap();
    path
}

#[tokio::test]
async fn raw_to_e01_is_verified_against_dfdisks_own_hash() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(3 << 20, 1);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    req.split_size = SplitSize::Custom(1 << 20);
    let mut env = f.env.clone();
    env.export_audit = true;
    let r = run(&env, req, StopFlags::new()).await.unwrap();

    assert_eq!(r.outcome, Outcome::Verified, "{}", r.render_text());
    assert_eq!(r.exit_code(), exit_code::VERIFIED);
    assert_eq!(r.expected_bytes, content.len() as u64);
    assert_eq!(r.bytes_converted, content.len() as u64);
    assert!(r.output_files.len() >= 3, "{:?}", r.output_files);
    assert!(r.output_files[0].ends_with("x.E01"));
    assert_eq!(
        r.source_hashes.md5.as_deref(),
        Some(md5_hex(&content).as_str())
    );
    assert_eq!(r.output_hashes.md5, r.source_hashes.md5);
    assert_eq!(
        r.output_hashes.sha256.as_deref(),
        Some(sha256_hex(&content).as_str())
    );
    assert!(r
        .comparisons
        .iter()
        .any(|c| c.independent && c.result.is_matched()));
    assert!(r.source_report.is_none());
    assert!(r.notes.iter().any(|n| n.contains("no acquisition report")));

    // Reports next to the output, JSON round trip, digests of the written files
    assert_eq!(r.report_file, f.out.join("x.conversion.info"));
    let json = std::fs::read_to_string(&r.report_json_file).unwrap();
    let back = ConversionReport::from_json(&json).unwrap();
    assert_eq!(back.outcome, Outcome::Verified);
    assert_eq!(
        r.report_json_sha256.as_deref(),
        Some(sha256_hex(json.as_bytes()).as_str())
    );
    let text = std::fs::read_to_string(&r.report_file).unwrap();
    assert!(
        text.contains("VERIFIED - ALL COMPARED DIGESTS MATCH"),
        "{text}"
    );
    assert!(!f.out.join("x.conversion.info.reserve").exists());
    assert!(r
        .auxiliary_files
        .iter()
        .any(|a| a.path.ends_with("x.conversion.log")));
    // Every command is in the report, with tool versions
    let argv0: Vec<&str> = r
        .provenance
        .commands
        .iter()
        .map(|c| c.argv[0].as_str())
        .collect();
    assert!(
        argv0.contains(&"ewfacquire") && argv0.contains(&"ewfverify"),
        "{argv0:?}"
    );
    // Reading a file needs no retries, and ewfacquire 20140807 (Ubuntu
    // 22.04) crashes on any -r: the conversion never gives it
    for c in r
        .provenance
        .commands
        .iter()
        .filter(|c| c.argv[0] == "ewfacquire")
    {
        assert!(!c.argv.iter().any(|a| a == "-r"), "{:?}", c.argv);
    }
    assert!(r
        .provenance
        .tools
        .get("ewfacquire")
        .is_some_and(|v| v.contains("ewfacquire")));

    // The E01 header records the case values, and no libewf placeholder
    let info = ewfinfo(&r.output_files[0]);
    assert!(info.contains("Case number:\t\tCASE42"), "{info}");
    assert!(info.contains("Examiner name:\t\tExaminer"), "{info}");
    assert!(info.contains("Converted by dfdisk"), "{info}");
    for placeholder in ["case_number", "examiner_name", "evidence_number"] {
        assert!(!info.contains(placeholder), "{info}");
    }

    // Audit: started (anchor) and finished with the report digests
    let records = audit_actions(&env.audit_log);
    let actions: Vec<&str> = records
        .iter()
        .map(|r| r["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, vec!["conversion_started", "conversion_finished"]);
    let anchor = records[0]["hash"].as_str().unwrap();
    assert_eq!(r.audit.anchor.as_deref(), Some(anchor));
    assert_eq!(records[1]["details"]["anchor"].as_str(), Some(anchor));
    assert_eq!(records[1]["details"]["exit_code"], 0);
    assert_eq!(
        records[1]["details"]["report_sha256"].as_str(),
        r.report_sha256.as_deref()
    );
    // The audit log copy in the output directory
    assert!(r
        .audit
        .export_file
        .as_deref()
        .is_some_and(|p| Path::new(p).exists()));
}

#[tokio::test]
async fn split_raw_input_is_converted_completely() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data((1 << 20) * 3 + 512 * 7, 2);
    for (i, chunk) in content.chunks(1 << 20).enumerate() {
        std::fs::write(f.src.join(format!("x.{:03}", i + 1)), chunk).unwrap();
    }
    let mut req = request(&f.src.join("x.001"), ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let r = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert_eq!(r.outcome, Outcome::Verified, "{}", r.render_text());
    assert_eq!(r.source_files.len(), 4);
    assert_eq!(r.bytes_converted, content.len() as u64);
    assert_eq!(
        r.output_hashes.md5.as_deref(),
        Some(md5_hex(&content).as_str())
    );
    assert!(r.source_format.contains("split RAW image (4 segments)"));
    // The command named every segment, in order
    let acquire = r
        .provenance
        .commands
        .iter()
        .find(|c| c.argv[0] == "ewfacquire")
        .unwrap();
    let tail: Vec<&str> = acquire.argv[acquire.argv.len() - 4..]
        .iter()
        .map(|a| a.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(tail, vec!["x.001", "x.002", "x.003", "x.004"]);

    // A gap in the set refuses before anything is written
    std::fs::rename(f.src.join("x.003"), f.src.join("x.005")).unwrap();
    let out2 = f.root.join("out2");
    let mut req = request(&f.src.join("x.001"), ConversionTarget::E01, &out2);
    req.case = Some(case());
    let e = run(&f.env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
    assert!(e.message.contains("x.003 is missing"), "{e}");
    assert!(!out2.exists());
}

#[tokio::test]
async fn existing_output_is_refused_before_any_tool_runs() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(1 << 20, 3)).unwrap();
    std::fs::create_dir_all(&f.out).unwrap();
    // Another spelling of the output name (exFAT/NTFS/vfat are case-insensitive)
    std::fs::write(f.out.join("X.e01"), b"earlier evidence").unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let e = run(&f.env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused);
    assert!(e.message.contains("Refusing to overwrite"), "{e}");
    assert_eq!(
        std::fs::read(f.out.join("X.e01")).unwrap(),
        b"earlier evidence"
    );
    assert_eq!(files_in(&f.out), vec!["X.e01"]);
    // T8: the refusal is in the audit log, and nothing else
    let records = audit_actions(&f.env.audit_log);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["action"], "conversion_refused");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(records[0]["details"]["exit_code"], 3);
    assert_eq!(records[0]["details"]["base_name"], "x");
    assert!(records[0]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("Refusing to overwrite"));

    // E01 to RAW: an existing RAW (here the image the E01 was made from) refuses too
    let mut req = request(&raw, ConversionTarget::E01, &f.src);
    req.case = Some(case());
    let r = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert_eq!(r.outcome, Outcome::Verified);
    let req = request(&f.src.join("x.E01"), ConversionTarget::Raw, &f.src);
    let e = run(&f.env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused);
    assert!(e.message.contains("x.raw"), "{e}");
}

#[tokio::test]
async fn size_not_a_multiple_of_512_and_missing_case_values_are_usage_errors() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let raw = f.src.join("odd.raw");
    std::fs::write(&raw, data(1_000_000, 4)).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let e = run(&f.env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
    assert_eq!(e.exit_code(), exit_code::USAGE);
    assert!(e.message.contains("not a multiple of 512"), "{e}");
    assert!(e.message.contains("silently drop the last 64 bytes"), "{e}");
    assert!(!f.out.exists());

    let raw = f.src.join("even.raw");
    std::fs::write(&raw, data(1 << 20, 4)).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(CaseMetadata {
        case_number: "C1".into(),
        ..Default::default()
    });
    let e = run(&f.env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
    assert!(e.message.contains("evidence number (--evidence)"), "{e}");
    assert!(e.message.contains("examiner (--examiner)"), "{e}");
    assert!(!f.out.exists());
    assert!(audit_actions(&f.env.audit_log).is_empty());

    // Converting an E01 "to E01", or a RAW "to RAW"
    let e = run(
        &f.env,
        request(&raw, ConversionTarget::Raw, &f.out),
        StopFlags::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
}

#[tokio::test]
async fn case_values_and_digests_come_from_the_acquisition_report() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(2 << 20, 5);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let report = acquisition_report(&raw, &content, |_| {});
    // No case values given: they come from x.info.json
    let r = run(
        &f.env,
        request(&raw, ConversionTarget::E01, &f.out),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(r.outcome, Outcome::Verified, "{}", r.render_text());
    assert_eq!(r.case_metadata.case_number, "CASE42");
    assert_eq!(r.case_metadata.examiner, "Examiner");
    assert!(
        r.case_sources[0].contains("x.info.json"),
        "{:?}",
        r.case_sources
    );
    let src = r.source_report.as_ref().unwrap();
    assert_eq!(src.path, report);
    assert_eq!(src.outcome, Outcome::Verified);
    assert_eq!(
        src.sha256,
        dfdisk::models::info_report::sha256_file(&report).unwrap()
    );
    // The report's digests are the reference (no own hash of the RAW needed)
    assert!(r.comparisons[0].reference.contains("x.info.json"));
    assert!(r.comparisons[0].result.is_matched());
    // Medium facts of the report: a whole disk, fixed
    assert_eq!(r.settings.media_flags.as_deref(), Some("physical"));
    let info = ewfinfo(&r.output_files[0]);
    assert!(info.contains("Evidence number:\tCF01"), "{info}");
    assert!(info.contains("x.info.json: VERIFIED"), "{info}");

    // A report that does not describe the image, given explicitly: usage error
    let other = f.src.join("other.raw");
    std::fs::write(&other, &content).unwrap();
    let mut req = request(&other, ConversionTarget::E01, &f.root.join("out2"));
    req.source_report = Some(report);
    let e = run(&f.env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
    assert!(e.message.contains("does not list other.raw"), "{e}");
}

#[tokio::test]
async fn read_errors_and_verdicts_of_the_source_acquisition_are_inherited() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(1 << 20, 6);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();

    // Substituted sectors in the acquisition: never VERIFIED, exit 7
    acquisition_report(&raw, &content, |r| {
        let mut t = ReadErrorTable::new(512, "raw engine");
        t.push(4096, 1024, RangeKind::Substituted);
        r.read_errors = t;
    });
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("o1"));
    req.notes = vec!["Rescue read-error summary from the CLI".into()];
    let r = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert_eq!(
        r.outcome,
        Outcome::CompletedWithReadErrors,
        "{}",
        r.render_text()
    );
    assert_eq!(r.exit_code, exit_code::READ_ERRORS);
    assert_eq!(r.read_errors.substituted_bytes(), 1024);
    assert!(r.verification.is_matched());
    let text = std::fs::read_to_string(&r.report_file).unwrap();
    assert!(!text.contains("ALL COMPARED DIGESTS MATCH"), "{text}");
    let info = ewfinfo(&r.output_files[0]);
    assert!(
        info.contains("2 sectors (1 KiB) in 1 range unreadable"),
        "{info}"
    );
    assert!(
        info.contains("Rescue read-error summary from the CLI"),
        "{info}"
    );

    // A rescue that was never verified against the medium: exit 9, not 0
    acquisition_report(&raw, &content, |r| {
        r.engine = EngineKind::Rescue;
        r.acquisition_hashes = HashResults::default();
        r.verification.result = VerificationResult::NotPossible {
            reason: "ddrescue computes no digest".into(),
        };
    });
    let r = run(
        &f.env,
        request(&raw, ConversionTarget::E01, &f.root.join("o2")),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        r.outcome,
        Outcome::CompleteUnverified,
        "{}",
        r.render_text()
    );
    assert_eq!(r.exit_code, exit_code::UNVERIFIED);
    assert!(r.comparisons[0].result.is_matched());
    assert!(
        r.outcome_reason.contains("never verified"),
        "{}",
        r.outcome_reason
    );

    // C-3: an acquisition whose verification found a mismatch or failed:
    // a matching conversion is not a verified copy of the medium
    for (n, result) in [
        VerificationResult::Mismatched {
            method: "second read of the source".into(),
            details: "source changed or unstable: MD5 differs".into(),
        },
        VerificationResult::Failed {
            reason: "the second source read failed: EIO".into(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let label = match &result {
            VerificationResult::Mismatched { .. } => "HASH MISMATCH",
            _ => "VERIFICATION FAILED",
        };
        acquisition_report(&raw, &content, |r| r.verification.result = result);
        let r = run(
            &f.env,
            request(&raw, ConversionTarget::E01, &f.root.join(format!("c3-{n}"))),
            StopFlags::new(),
        )
        .await
        .unwrap();
        let text = r.render_text();
        assert_eq!(r.outcome, Outcome::CompleteUnverified, "{text}");
        assert_eq!(r.exit_code, exit_code::UNVERIFIED);
        assert!(r.comparisons[0].result.is_matched(), "{text}");
        assert!(
            r.outcome_reason
                .contains("not confirmed to reproduce its medium"),
            "{}",
            r.outcome_reason
        );
        assert!(r.outcome_reason.contains(label), "{}", r.outcome_reason);
        assert!(!text.contains("ALL COMPARED DIGESTS MATCH"), "{text}");
    }

    // An incomplete acquisition: the converted image is incomplete too
    acquisition_report(&raw, &content, |r| {
        r.expected_bytes = 4 << 20;
        r.stop_reason = Some("source lost at offset 1048576".into());
    });
    let r = run(
        &f.env,
        request(&raw, ConversionTarget::E01, &f.root.join("o3")),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(r.outcome, Outcome::Incomplete, "{}", r.render_text());
    assert_eq!(r.exit_code, exit_code::INCOMPLETE);
    assert!(r.stop_reason.as_deref().unwrap().contains("source lost"));
}

#[tokio::test]
async fn an_image_changed_since_its_acquisition_is_a_mismatch() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(1 << 20, 7);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    acquisition_report(&raw, &content, |_| {});
    let mut tampered = content.clone();
    tampered[1000] ^= 0xff;
    std::fs::write(&raw, &tampered).unwrap();
    let r = run(
        &f.env,
        request(&raw, ConversionTarget::E01, &f.out),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(r.outcome, Outcome::Mismatch, "{}", r.render_text());
    assert_eq!(r.exit_code, exit_code::MISMATCH);
    let VerificationResult::Mismatched { details, .. } = &r.verification else {
        panic!("{:?}", r.verification)
    };
    assert!(details.contains(&md5_hex(&content)), "{details}");
}

#[tokio::test]
async fn e01_to_raw_is_verified_against_the_stored_digests() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data((3 << 20) + 4096, 8);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("e01"));
    req.case = Some(case());
    req.split_size = SplitSize::Custom(1 << 20);
    req.compression = CompressionLevel::Best;
    let made = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert!(made.output_files.len() >= 3);

    // Any segment of the family may be given; every segment is read
    let r = run(
        &f.env,
        request(&made.output_files[1], ConversionTarget::Raw, &f.out),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(r.outcome, Outcome::Verified, "{}", r.render_text());
    assert_eq!(r.source_files.len(), made.output_files.len());
    assert!(r.source.ends_with("x.E01"));
    let out = std::fs::read(f.out.join("x.raw")).unwrap();
    assert_eq!(out, content);
    assert_eq!(
        r.output_hashes.md5.as_deref(),
        Some(md5_hex(&content).as_str())
    );
    // Stored MD5 in the E01 and the conversion report of the E01 both compared
    assert!(r
        .comparisons
        .iter()
        .filter(|c| c.independent)
        .all(|c| c.result.is_matched()));
    assert!(r
        .comparisons
        .iter()
        .any(|c| c.reference.contains("stored in x.E01")));
    assert!(r
        .comparisons
        .iter()
        .any(|c| c.reference.contains("x.conversion.info.json")));
    // Case values from the E01's conversion report and header
    assert_eq!(r.case_metadata.case_number, "CASE42");
    // ewfexport's own .raw.info is an auxiliary file
    assert!(r
        .auxiliary_files
        .iter()
        .any(|a| a.path.ends_with("x.raw.info")));
}

/// A wrapper around a real tool: runs it, then runs `after` (shell).
fn wrapper(dir: &Path, tool: &str, after: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let real = which(tool);
    let path = dir.join(format!("wrapped-{tool}"));
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n\"{}\" \"$@\"\nrc=$?\n{after}\nexit $rc\n",
            real.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[tokio::test]
async fn a_raw_output_that_differs_from_the_e01_is_a_mismatch() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(1 << 20, 9);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.src);
    req.case = Some(case());
    run(&f.env, req, StopFlags::new()).await.unwrap();

    // ewfexport "succeeds", then a byte of its output changes on disk
    let out_raw = f.out.join("x.raw");
    let mut env = f.env.clone();
    env.tools.ewfexport = wrapper(
        &f.root,
        "ewfexport",
        &format!(
            "printf 'TAMPEREDTAMPERED' | dd of=\"{}\" bs=1 seek=4242 conv=notrunc 2>/dev/null",
            out_raw.display()
        ),
    )
    .into();
    let mut req = request(&f.src.join("x.E01"), ConversionTarget::Raw, &f.out);
    req.case = Some(case());
    let r = run(&env, req, StopFlags::new()).await.unwrap();
    assert_eq!(r.outcome, Outcome::Mismatch, "{}", r.render_text());
    assert_eq!(r.exit_code, exit_code::MISMATCH);
    assert!(r
        .comparisons
        .iter()
        .any(|c| c.independent && matches!(c.result, VerificationResult::Mismatched { .. })));
}

#[tokio::test]
async fn read_errors_stored_in_the_e01_are_inherited_by_the_raw_output() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(1 << 20, 10);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("e01"));
    req.case = Some(case());
    run(&f.env, req, StopFlags::new()).await.unwrap();
    std::fs::remove_file(f.root.join("e01/x.conversion.info.json")).unwrap();

    // ewfinfo's error list as an E01 with an unreadable range shows it
    let mut env = f.env.clone();
    env.tools.ewfinfo = wrapper(
        &f.root,
        "ewfinfo",
        "printf 'Read errors during acquiry:\\n\\ttotal number: 1\\n\\tat sector(s): 8 - 15 (number: 8)\\n\\n'",
    )
    .into();
    let r = run(
        &env,
        request(&f.root.join("e01/x.E01"), ConversionTarget::Raw, &f.out),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        r.outcome,
        Outcome::CompletedWithReadErrors,
        "{}",
        r.render_text()
    );
    assert_eq!(r.exit_code, exit_code::READ_ERRORS);
    assert_eq!(r.read_errors.ranges.len(), 1);
    assert_eq!(r.read_errors.ranges[0].offset, 4096);
    assert_eq!(r.read_errors.ranges[0].length, 4096);
    assert!(r.verification.is_matched());
    assert!(
        r.case_sources[0].contains("E01 header"),
        "{:?}",
        r.case_sources
    );

    // An error list dfdisk cannot locate: no conversion, nothing written
    let mut env = f.env.clone();
    env.tools.ewfinfo = wrapper(
        &f.root,
        "ewfinfo",
        "printf 'Read errors during acquiry\\n\\ttotal number: 2\\n\\tat sector(s): 8 - 15 number: 8\\n\\n'",
    )
    .into();
    let out2 = f.root.join("out2");
    let e = run(
        &env,
        request(&f.root.join("e01/x.E01"), ConversionTarget::Raw, &out2),
        StopFlags::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Failed);
    assert!(e.message.contains("cannot locate"), "{e}");
    assert!(!out2.exists());
}

#[tokio::test]
async fn abort_stops_ewfacquire_and_reports_aborted() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    // Incompressible data with best compression: long enough to abort
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(192 << 20, 11)).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    req.compression = CompressionLevel::Best;
    let stop = StopFlags::new();
    abort_once_written(&stop, f.out.join("x.E01"), 0);
    let started = std::time::Instant::now();
    let r = run(&f.env, req, stop).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(r.outcome, Outcome::Aborted, "{}", r.render_text());
    assert_eq!(r.exit_code, exit_code::ABORTED);
    let acquire = r
        .provenance
        .commands
        .iter()
        .find(|c| c.argv[0] == "ewfacquire")
        .unwrap();
    assert!(
        acquire
            .stop
            .as_deref()
            .is_some_and(|s| s.contains("SIGINT")),
        "{acquire:?}"
    );
    assert!(r
        .notes
        .iter()
        .any(|n| n.contains("partial and must not be used")));
    let records = audit_actions(&f.env.audit_log);
    assert_eq!(records.last().unwrap()["details"]["outcome"], "aborted");
    // Nothing of ewfacquire is still running
    let out = std::process::Command::new("pgrep")
        .args(["-f", &f.out.join("x").to_string_lossy()])
        .output();
    if let Ok(o) = out {
        assert!(
            o.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&o.stdout)
        );
    }
}

/// libewf 20140816 (the Debian/Ubuntu ewf-tools line) is the one on PATH.
fn legacy_libewf() -> bool {
    std::process::Command::new("ewfexport")
        .arg("-V")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("20140816"))
}

/// What every conversion of a corrupted E01 must state (C-1), on both
/// libewf lines: 20231119's ewfexport fails, 20140816's writes zeros for
/// what it cannot read and ends with SUCCESS.
fn assert_corrupted_e01_conversion(r: &ConversionReport, out_raw: &Path) {
    let text = r.render_text();
    assert_eq!(r.outcome, Outcome::Incomplete, "{text}");
    assert_eq!(r.exit_code, exit_code::INCOMPLETE);
    let stop = r.stop_reason.clone().unwrap_or_default();
    assert!(stop.contains("\"Is corrupted: yes\""), "{stop}");
    assert!(
        !text.contains("The whole source image was converted"),
        "{text}"
    );
    assert!(r.bytes_converted < r.expected_bytes, "{text}");
    assert!(!text.contains("100.0%"), "{text}");
    assert!(
        !text.contains("stores no digest of its media data"),
        "{text}"
    );
    if legacy_libewf() {
        // Zeros for the missing part, listed with their positions
        assert!(r.conversion_errors.unread_bytes() > 0, "{text}");
        assert!(stop.contains("ewfexport could not read"), "{stop}");
        assert!(text.contains("[READ ERRORS OF THIS CONVERSION]"), "{text}");
        assert_eq!(
            r.bytes_converted + r.conversion_errors.unread_bytes(),
            r.expected_bytes,
            "{text}"
        );
        let out = std::fs::read(out_raw).unwrap();
        for range in &r.conversion_errors.ranges {
            let (a, b) = (range.offset as usize, range.end() as usize);
            assert!(out[a..b.min(out.len())].iter().all(|x| *x == 0));
        }
    }
}

/// C-1: a chunk whose checksum does not match is exported as stored (both
/// libewf lines report it under "Read errors during export"); the report
/// lists it and never calls it zeros or converted.
#[tokio::test]
async fn a_chunk_that_fails_its_checksum_is_listed_not_converted() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(1 << 20, 26);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("e01"));
    req.case = Some(case());
    req.compression = CompressionLevel::None;
    run(&f.env, req, StopFlags::new()).await.unwrap();
    let e01 = f.root.join("e01").join("x.E01");
    // Overwrite 8 bytes of chunk data (uncompressed E01, past the headers)
    {
        use std::os::unix::fs::FileExt;
        let file = std::fs::OpenOptions::new().write(true).open(&e01).unwrap();
        file.write_all_at(b"XXXXXXXX", 300_000).unwrap();
    }
    let alone = f.root.join("alone");
    std::fs::create_dir_all(&alone).unwrap();
    std::fs::copy(&e01, alone.join("x.E01")).unwrap();
    let mut req = request(&alone.join("x.E01"), ConversionTarget::Raw, &f.out);
    req.case = Some(case());
    let r = run(&f.env, req, StopFlags::new()).await.unwrap();
    let text = r.render_text();
    assert_eq!(r.outcome, Outcome::Incomplete, "{text}");
    assert_eq!(r.conversion_errors.ranges.len(), 1, "{text}");
    assert_eq!(r.conversion_errors.unread_bytes(), 64 * 512);
    assert_eq!(r.bytes_converted, (1 << 20) - 64 * 512);
    let stop = r.stop_reason.clone().unwrap();
    assert!(stop.contains("could not read 64 sectors"), "{stop}");
    assert!(stop.contains("zeros or unchecked data"), "{stop}");
    assert!(!text.contains("zero-filled"), "{text}");
    // The output holds the data as stored, not zeros
    let out = std::fs::read(f.out.join("x.raw")).unwrap();
    assert_eq!(out.len(), 1 << 20);
    assert!(out[288 * 1024..320 * 1024].iter().any(|b| *b != 0));
}

/// C-4: an E01 made from a rescue (as --rescue-to-e01 does) records its
/// zero-filled sectors only in its header notes; converted back without the
/// reports that list them, the output must not pass for a verified copy.
#[tokio::test]
async fn zero_filled_sectors_recorded_only_in_the_e01_notes_are_never_verified() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let mut content = data(1 << 20, 23);
    content[4096..5120].fill(0);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let report_json = acquisition_report(&raw, &content, |r| {
        r.engine = EngineKind::Rescue;
        r.acquisition_hashes = HashResults::default();
        let mut t = ReadErrorTable::new(512, "ddrescue mapfile");
        t.push(4096, 1024, RangeKind::Substituted);
        r.read_errors = t;
        r.verification.result = VerificationResult::NotPossible {
            reason: "ddrescue computes no digest".into(),
        };
    });
    let rescue =
        ForensicInfoReport::from_json(&std::fs::read_to_string(&report_json).unwrap()).unwrap();
    assert_eq!(rescue.outcome, Outcome::CompletedWithReadErrors);
    let e01_dir = f.root.join("e01");
    let mut req = request(&raw, ConversionTarget::E01, &e01_dir);
    req.notes = dfdisk::engines::converter::rescue_notes(&rescue, &report_json);
    req.source_report = Some(report_json.clone());
    let made = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert_eq!(made.outcome, Outcome::CompletedWithReadErrors);
    let e01 = e01_dir.join("x.E01");
    let info = ewfinfo(&e01);
    assert!(info.contains("Zero-filled sectors of the rescue"), "{info}");

    // Next to its conversion report: the ranges are inherited from it
    let r = run(
        &f.env,
        request(&e01, ConversionTarget::Raw, &f.root.join("with")),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        r.outcome,
        Outcome::CompletedWithReadErrors,
        "{}",
        r.render_text()
    );
    assert_eq!(r.read_errors.substituted_bytes(), 1024);

    // Alone: never VERIFIED, and the report does not say "none recorded"
    let alone = f.root.join("alone");
    std::fs::create_dir_all(&alone).unwrap();
    std::fs::copy(&e01, alone.join("x.E01")).unwrap();
    let r = run(
        &f.env,
        request(&alone.join("x.E01"), ConversionTarget::Raw, &f.out),
        StopFlags::new(),
    )
    .await
    .unwrap();
    let text = r.render_text();
    assert_eq!(r.outcome, Outcome::CompleteUnverified, "{text}");
    assert_eq!(r.exit_code, exit_code::UNVERIFIED);
    assert!(r.comparisons[0].result.is_matched(), "{text}");
    assert!(
        r.outcome_reason.contains("header notes"),
        "{}",
        r.outcome_reason
    );
    assert!(!text.contains("none recorded"), "{text}");
    assert!(
        text.contains("its header notes (written by dfdisk) state: 2 sectors (1 KiB) in 1 range unreadable in the acquisition, zeros in this image; Zero-filled sectors of the rescue (ddrescue mapfile, 512 bytes each): 8-9"),
        "{text}"
    );
}

/// fsync fails for output images (`.E01` segments, the `.raw` output).
fn failing_image_sync(path: &Path, f: &std::fs::File) -> std::io::Result<()> {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if ext.starts_with('e') || ext == "raw" {
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    } else {
        f.sync_all()
    }
}

/// Eviction from the page cache fails for every file.
fn failing_evict(_: &Path, _: &std::fs::File) -> std::io::Result<()> {
    Err(std::io::Error::from_raw_os_error(libc::EINVAL))
}

/// T1: an output image that cannot be fsynced is not verified (exit 4), and
/// no method text claims an fsync or an eviction that failed.
#[tokio::test]
async fn an_output_that_cannot_be_flushed_is_never_verified() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(1 << 20, 25);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let mut env = f.env.clone();
    env.flush.sync = failing_image_sync;
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("e01"));
    req.case = Some(case());
    let r = run(&env, req, StopFlags::new()).await.unwrap();
    let text = r.render_text();
    assert_eq!(r.outcome, Outcome::VerificationFailed, "{text}");
    assert_eq!(r.exit_code, exit_code::FAILED);
    let VerificationResult::Failed { reason } = &r.verification else {
        panic!("{:?}", r.verification)
    };
    assert!(
        reason.contains("could not be flushed durably to the destination"),
        "{reason}"
    );
    assert!(reason.contains("x.E01"), "{reason}");
    assert!(!r
        .verification_method
        .contains("fsync and page-cache eviction"));
    assert!(!text.contains("after fsync and"), "{text}");

    // E01 to RAW: the RAW output (of an E01 converted without trouble)
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("good"));
    req.case = Some(case());
    let good = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert_eq!(good.outcome, Outcome::Verified, "{}", good.render_text());
    let made = f.root.join("good").join("x.E01");
    let r = run(
        &env,
        request(&made, ConversionTarget::Raw, &f.out),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        r.outcome,
        Outcome::VerificationFailed,
        "{}",
        r.render_text()
    );
    assert!(!r.verification_method.contains("page-cache eviction"));

    // Eviction alone fails: verified, but the method says the re-read may
    // have come from memory
    let mut env = f.env.clone();
    env.flush.evict = failing_evict;
    let r = run(
        &env,
        request(&made, ConversionTarget::Raw, &f.root.join("evict")),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(r.outcome, Outcome::Verified, "{}", r.render_text());
    assert!(
        r.verification_method
            .contains("so the re-read may have come from memory"),
        "{}",
        r.verification_method
    );
}

/// C-5: a report the caller found next to the image (not the examiner's
/// --report) that describes another image of the same base name is ignored
/// with a note; the converter then finds the image's own report.
#[tokio::test]
async fn a_report_found_by_the_caller_for_another_image_is_ignored() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(1 << 20, 24);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    // A rescue next to its E01 (as --rescue-to-e01 leaves it): x.info.json
    // lists x.raw, x.conversion.info.json lists x.E01
    let rescue_json = acquisition_report(&raw, &content, |r| {
        r.engine = EngineKind::Rescue;
        r.acquisition_hashes = HashResults::default();
        r.verification.result = VerificationResult::NotPossible {
            reason: "ddrescue computes no digest".into(),
        };
    });
    let made = run(
        &f.env,
        request(&raw, ConversionTarget::E01, &f.src),
        StopFlags::new(),
    )
    .await
    .unwrap();
    assert_eq!(made.outcome, Outcome::CompleteUnverified);
    let e01 = f.src.join("x.E01");

    // As the CLI found it (`<stem>.info.json` next to the image)
    let mut req = request(&e01, ConversionTarget::Raw, &f.out);
    req.source_report = Some(rescue_json.clone());
    req.source_report_auto = true;
    let r = run(&f.env, req, StopFlags::new()).await.unwrap();
    let used = r.source_report.as_ref().expect("the E01's own report");
    assert!(
        used.path.ends_with("x.conversion.info.json"),
        "{}",
        r.render_text()
    );
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("x.info.json was not used: it does not list x.E01")),
        "{:?}",
        r.notes
    );

    // Given by the examiner: it must describe the image
    let mut req = request(&e01, ConversionTarget::Raw, &f.root.join("given"));
    req.source_report = Some(rescue_json);
    let e = run(&f.env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage, "{e}");
    assert!(e.message.contains("does not list x.E01"), "{e}");
}

#[tokio::test]
async fn an_e01_missing_its_last_segment_is_never_converted_whole() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    let content = data(3 << 20, 21);
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, &content).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("e01"));
    req.case = Some(case());
    req.split_size = SplitSize::Custom(1 << 20);
    req.compression = CompressionLevel::None;
    let made = run(&f.env, req, StopFlags::new()).await.unwrap();
    let segments = made.output_files.len();
    assert!(segments >= 4, "{:?}", made.output_files);
    // The family without its last segment, and without its reports
    let copy = f.root.join("copy");
    std::fs::create_dir_all(&copy).unwrap();
    for seg in &made.output_files[..segments - 1] {
        std::fs::copy(seg, copy.join(seg.file_name().unwrap())).unwrap();
    }
    let mut req = request(&copy.join("x.E01"), ConversionTarget::Raw, &f.out);
    req.case = Some(case());
    let r = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert_eq!(r.source_files.len(), segments - 1);
    assert_corrupted_e01_conversion(&r, &f.out.join("x.raw"));
    if legacy_libewf() {
        // Not "stores no digest": the digests are in the missing segment
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("which is missing or was never written")),
            "{:?}",
            r.notes
        );
    }
}

#[tokio::test]
async fn an_aborted_e01_is_never_converted_whole() {
    if !have_libewf() {
        return;
    }
    let f = fixture();
    // Incompressible data with best compression: long enough to abort
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(96 << 20, 22)).unwrap();
    let mut req = request(&raw, ConversionTarget::E01, &f.root.join("e01"));
    req.case = Some(case());
    req.compression = CompressionLevel::Best;
    let stop = StopFlags::new();
    // Abort once ewfacquire has written a few MiB
    abort_once_written(&stop, f.root.join("e01").join("x.E01"), 4 << 20);
    let made = run(&f.env, req, stop).await.unwrap();
    assert_eq!(made.outcome, Outcome::Aborted, "{}", made.render_text());
    // The unfinalized E01 alone, away from its report
    let alone = f.root.join("alone");
    std::fs::create_dir_all(&alone).unwrap();
    std::fs::copy(&made.output_files[0], alone.join("x.E01")).unwrap();
    assert!(ewfinfo(&alone.join("x.E01")).contains("Is corrupted:\t\tyes"));
    let mut req = request(&alone.join("x.E01"), ConversionTarget::Raw, &f.out);
    req.case = Some(case());
    let r = run(&f.env, req, StopFlags::new()).await.unwrap();
    assert_corrupted_e01_conversion(&r, &f.out.join("x.raw"));
}

#[tokio::test]
async fn abort_escalates_when_the_tool_ignores_sigint() {
    use std::os::unix::fs::PermissionsExt;
    common::audit_sandbox();
    let f = fixture();
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(1 << 20, 12)).unwrap();
    // A stand-in ewfacquire that writes a segment, ignores SIGINT and sleeps
    let pidfile = f.root.join("pid");
    let fake = f.root.join("fake-ewfacquire");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\n[ \"$1\" = -V ] && {{ echo 'fake-ewfacquire 0'; exit 0; }}\ntrap '' INT\necho $$ > \"{}\"\nwhile [ $# -gt 0 ]; do [ \"$1\" = -t ] && target=$2; shift; done\necho partial > \"$target.E01\"\nsleep 60\n",
            pidfile.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut env = f.env.clone();
    env.tools.ewfacquire = fake.into();
    env.grace = Duration::from_millis(300);
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let stop = StopFlags::new();
    abort_once_written(&stop, f.out.join("x.E01"), 0);
    let started = std::time::Instant::now();
    let r = run(&env, req, stop).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(r.outcome, Outcome::Aborted);
    assert_eq!(r.output_files, vec![f.out.join("x.E01")]);
    let cmd = r
        .provenance
        .commands
        .iter()
        .find(|c| c.argv[0].ends_with("fake-ewfacquire"))
        .unwrap();
    assert!(
        cmd.stop.as_deref().is_some_and(|s| s.contains("SIGTERM")),
        "{cmd:?}"
    );
    let pid = std::fs::read_to_string(&pidfile).unwrap();
    assert!(
        !Path::new(&format!("/proc/{}", pid.trim())).exists(),
        "the tool is still running"
    );
}

#[tokio::test]
async fn abort_before_the_first_write_writes_nothing() {
    common::audit_sandbox();
    let f = fixture();
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(1 << 20, 13)).unwrap();
    let mut env = f.env.clone();
    // Never reached: the abort comes first
    env.tools.ewfacquire = "/nonexistent/ewfacquire".into();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let stop = StopFlags::new();
    stop.abort.store(true, std::sync::atomic::Ordering::SeqCst);
    let e = run(&env, req, stop).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Aborted);
    assert!(!f.out.exists());
    assert!(audit_actions(&env.audit_log).is_empty());
}

#[tokio::test]
async fn a_tool_that_cannot_run_leaves_nothing_but_the_audit_record() {
    common::audit_sandbox();
    let f = fixture();
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(1 << 20, 14)).unwrap();
    let mut env = f.env.clone();
    env.tools.ewfacquire = "/nonexistent/ewfacquire".into();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let e = run(&env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Failed);
    assert!(e.message.contains("cannot run ewfacquire"), "{e}");
    // Reservation and the created directory are gone
    assert!(!f.out.exists());
    let records = audit_actions(&env.audit_log);
    let actions: Vec<&str> = records
        .iter()
        .map(|r| r["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, vec!["conversion_started", "conversion_finished"]);
    assert_eq!(records[1]["details"]["error_kind"], "failed");
}

#[tokio::test]
async fn a_destination_in_memory_is_refused_unless_allowed() {
    common::audit_sandbox();
    let f = fixture();
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(1 << 20, 15)).unwrap();
    let mut env = f.env.clone();
    let root = std::fs::canonicalize(&f.root).unwrap();
    env.mountinfo = Some(format!(
        "22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n90 22 0:55 / {} rw - tmpfs tmpfs rw\n",
        root.display()
    ));
    let mut req = ConversionRequest::new(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let e = run(&env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused);
    assert!(e.message.contains("--allow-tmpfs"), "{e}");
    assert!(!f.out.exists());
    // T8: recorded as "conversion_refused" (no libewf needed)
    let records = audit_actions(&env.audit_log);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["action"], "conversion_refused");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(records[0]["details"]["error_kind"], "refused");
    assert!(records[0]["details"]["target"]
        .as_str()
        .unwrap()
        .ends_with("x.E01"));
    assert!(dfcore::audit::verify(&env.audit_log).is_ok());
    // A usage error is not recorded
    let mut req = ConversionRequest::new(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    req.split_size = SplitSize::Custom(4096);
    let e = run(&env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage, "{e}");
    assert_eq!(audit_actions(&env.audit_log).len(), 1);
}

#[tokio::test]
async fn an_unwritable_audit_log_refuses_on_dfnix_only() {
    common::audit_sandbox();
    let f = fixture();
    let raw = f.src.join("x.raw");
    std::fs::write(&raw, data(1 << 20, 16)).unwrap();
    let mut env = f.env.clone();
    std::fs::write(f.root.join("file"), b"not a directory").unwrap();
    env.audit_log = f.root.join("file/audit.jsonl");
    env.registry = RegistryPresence::Present;
    env.tools.ewfacquire = "/nonexistent/ewfacquire".into();
    let mut req = request(&raw, ConversionTarget::E01, &f.out);
    req.case = Some(case());
    let e = run(&env, req, StopFlags::new()).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::Refused, "{e}");
    assert!(e.message.contains("audit log"), "{e}");
    assert!(!f.out.exists());
}
