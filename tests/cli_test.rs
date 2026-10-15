//! The `dfdisk` binary end to end: help texts, argument validation, device
//! resolution, exit codes, JSON output, `check`, `verify`. Sources are
//! regular files; the audit log and registry live in a sandbox; tools that
//! would touch host disks (lsblk, udevadm, smartctl) are mocks on PATH.

use md5::{Digest, Md5};
use sha2::Sha256;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod support;

const BIN: &str = env!("CARGO_BIN_EXE_dfdisk");

/// Scratch directory of this test binary for the audit log and registry.
fn sandbox() -> &'static Path {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("dfdisk-cli-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap()
            .keep()
    })
}

/// Mock lsblk/udevadm/smartctl: nothing the binary runs touches host disks.
fn mock_path() -> &'static str {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let dir = sandbox().join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        for (tool, script) in [
            ("lsblk", "#!/bin/sh\necho '{\"blockdevices\": []}'\n"),
            ("udevadm", "#!/bin/sh\nexit 1\n"),
            ("smartctl", "#!/bin/sh\necho '{}'\nexit 2\n"),
        ] {
            let p = dir.join(tool);
            std::fs::write(&p, script).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        )
    })
}

/// The dfdisk binary with its audit log and registry in the sandbox and the
/// mock tools first on PATH.
fn dfdisk() -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env("DFNIX_AUDIT_LOG", sandbox().join("audit.jsonl"))
        .env("DFNIX_PROTECTED_FILE", sandbox().join("protected.json"))
        .env("PATH", mock_path());
    cmd
}

fn run(args: &[&str]) -> Output {
    dfdisk().args(args).output().unwrap()
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// A scratch directory below the target dir (the acquisitions pass
/// --allow-tmpfs in case that is a tmpfs).
fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("dfdisk-cli-run-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 % 251) as u8).collect()
}

/// `acquire <src> --format raw -o <out>` with the case flags the CFTT test
/// uses, plus `extra`.
fn acquire_raw(src: &Path, out: &Path, evidence: &str, extra: &[&str]) -> Output {
    let mut args = vec![
        "acquire".to_string(),
        src.to_string_lossy().into_owned(),
        "--format".into(),
        "raw".into(),
        "-o".into(),
        out.to_string_lossy().into_owned(),
        "-C".into(),
        "CLI-1".into(),
        "-E".into(),
        evidence.into(),
        "--examiner".into(),
        "Tester".into(),
        "--allow-tmpfs".into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    dfdisk().args(&args).output().unwrap()
}

fn files_ending(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.to_string_lossy().ends_with(suffix))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Version and help
// ---------------------------------------------------------------------------

#[test]
fn version_names_both_revisions() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    let (stdout, _) = text(&output);
    assert!(stdout.starts_with("dfdisk "), "{stdout}");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    assert!(stdout.contains("dfdisk git revision: "), "{stdout}");
    assert!(stdout.contains("dfcore "), "{stdout}");

    let short = run(&["-V"]);
    assert!(short.status.success());
    assert_eq!(
        text(&short).0,
        format!("dfdisk {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_documents_commands_and_exit_codes() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag]);
        assert!(output.status.success());
        let (stdout, _) = text(&output);
        for word in [
            "Usage:", "acquire", "check", "unmount", "verify", "convert", "list", "tui",
        ] {
            assert!(stdout.contains(word), "{flag}: {word}\n{stdout}");
        }
        for code in [
            "0  verified",
            "1  internal error",
            "2  usage error",
            "3  refused",
            "4  failed",
            "5  hash mismatch",
            "6  incomplete",
            "7  completed with read errors",
            "8  aborted",
            "9  complete but not verified",
        ] {
            assert!(stdout.contains(code), "{flag}: {code}\n{stdout}");
        }
    }
}

#[test]
fn acquire_help_documents_every_flag_and_the_required_fields() {
    let (stdout, _) = text(&run(&["acquire", "--help"]));
    assert!(
        stdout.contains(
            "Usage: dfdisk acquire [OPTIONS] --case <CASE> --evidence <EVIDENCE> --examiner <EXAMINER> --output-dir <DIR> <DEVICE>"
        ),
        "{stdout}"
    );
    for flag in [
        "-C, --case",
        "-E, --evidence",
        "-e, --examiner",
        "-o, --output-dir",
        "--ea",
        "--authority",
        "-D, --description",
        "-N, --notes",
        "--seal",
        "--seized-at",
        "--seized-location",
        "--format",
        "--digests",
        "--compression",
        "--split",
        "--piece-size",
        "--rescue",
        "--resume",
        "--rescue-to-e01",
        "-r, --retries",
        "--error-granularity",
        "--on-read-error",
        "--verify-source",
        "--smart",
        "--write-protect",
        "--allow-tmpfs",
        "--allow-low-space",
        "--refuse-hidden-areas",
        "--expect-serial",
        "--expect-wwn",
        "--expect-size",
        "--auto-unmount",
        "--json",
        "-v, --verbose",
        "Exit codes:",
        "SIGHUP",
        "second SIGINT",
        "1, 2, 8, 5, 4, 3, 6, 7, 9, 0",
        // 4 is a verdict too (VERIFICATION FAILED)
        "verdict of the report (0, 4-9;",
    ] {
        assert!(stdout.contains(flag), "{flag}\n{stdout}");
    }
    // No placeholder defaults for case values
    for placeholder in ["CASE001", "cf01]", "Forensic Examiner", "Law Enforcement"] {
        assert!(!stdout.contains(placeholder), "{placeholder}");
    }
    // No override for holders: a holder claims the source exclusively
    assert!(!stdout.contains("--allow-holders"), "{stdout}");
}

#[test]
fn every_command_help_documents_its_flags_and_exit_codes() {
    for (cmd, needles) in [
        ("list", &["--json", "--smart"][..]),
        (
            "check",
            &[
                "<DEVICE>",
                "--case",
                "--output-dir",
                "--json",
                "Exit codes:",
                "3  refused",
            ],
        ),
        ("unmount", &["<DEVICE>", "--json", "Exit codes:", "audit"]),
        (
            "verify",
            &[
                "<IMAGE>",
                "--md5",
                "--sha1",
                "--sha256",
                "--report",
                "--pieces",
                "--json",
                "9  digests computed, but nothing to compare",
            ],
        ),
        (
            "convert",
            &[
                "<SOURCE>",
                "--to",
                "--output-dir",
                "--case",
                "--evidence",
                "--examiner",
                "--compression",
                "--split",
                "--report",
                "--json",
                "Exit codes",
            ],
        ),
    ] {
        let output = run(&[cmd, "--help"]);
        assert!(output.status.success(), "{cmd}");
        let (stdout, _) = text(&output);
        for n in needles {
            assert!(stdout.contains(n), "{cmd}: {n}\n{stdout}");
        }
    }
}

// ---------------------------------------------------------------------------
// Argument validation (exit 2)
// ---------------------------------------------------------------------------

#[test]
fn convert_help_names_the_tool_that_writes_raw() {
    let (stdout, _) = text(&run(&["convert", "--help"]));
    assert!(
        stdout.contains("convert --to raw writes it with ewfexport"),
        "{stdout}"
    );
    assert!(!stdout.contains("native engine"), "{stdout}");
}

#[test]
fn missing_or_invalid_arguments_are_usage_errors() {
    // Required case fields and destination: no defaults
    let output = run(&["acquire", "/dev/null"]);
    assert_eq!(output.status.code(), Some(2));
    let (_, stderr) = text(&output);
    for name in ["--case", "--evidence", "--examiner", "--output-dir"] {
        assert!(stderr.contains(name), "{name}: {stderr}");
    }
    let base = ["x", "-o", "o", "-C", "c", "-E", "e", "-e", "x"];
    let with = |cmd: &str, extra: &[&'static str]| -> Vec<String> {
        std::iter::once(cmd)
            .chain(base)
            .chain(extra.iter().copied())
            .map(String::from)
            .collect()
    };
    let mut cases: Vec<Vec<String>> = vec![
        vec!["acquire".into()],
        vec!["convert".into()],
        vec!["verify".into()],
        vec!["check".into(), "x".into()],
        vec!["unmount".into()],
        vec!["--unsupported-forensic-flag".into()],
        vec![
            "verify".into(),
            "x.raw".into(),
            "--md5".into(),
            "a".into(),
            "--report".into(),
            "x.info.json".into(),
        ],
    ];
    for extra in [
        &["--format", "invalid"][..],
        &["--split", "3G"],
        &["--compression", "max"],
        &["--expect-size", "1.5G"],
        &["--piece-size", "huge"],
        &["--on-read-error", "ignore"],
    ] {
        cases.push(with("acquire", extra));
        cases.push(with("check", extra));
    }
    for args in cases {
        let output = dfdisk().args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {:?}",
            text(&output)
        );
    }
}

#[test]
fn inconsistent_options_are_refused_before_anything_happens() {
    let tmp = scratch();
    let src = tmp.path().join("evidence.bin");
    std::fs::write(&src, sample(64 * 1024)).unwrap();
    let out = tmp.path().join("out");
    for (extra, needle) in [
        (&["--compression", "best"][..], "--compression"),
        (
            &["--rescue", "--on-read-error", "zero-fill"],
            "--on-read-error",
        ),
        (&["--resume"], "--resume"),
        (&["--piece-size", "1000"], "piece size"),
        (&["--rescue", "-r", "300"], "retries"),
    ] {
        let output = acquire_raw(&src, &out, "E1", extra);
        let (stdout, stderr) = text(&output);
        assert_eq!(output.status.code(), Some(2), "{extra:?}: {stdout}{stderr}");
        assert!(stderr.contains(needle), "{extra:?}: {stderr}");
        assert_eq!(stderr.matches("Error (USAGE ERROR)").count(), 1, "{stderr}");
    }
    assert!(!out.exists(), "nothing was written");

    // A blank required value
    let output = dfdisk()
        .args([
            "acquire",
            &src.to_string_lossy(),
            "-o",
            &out.to_string_lossy(),
            "-C",
            " ",
            "-E",
            "E1",
            "-e",
            "Tester",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output).1.contains("case number (--case)"));
    assert!(!out.exists());
}

// ---------------------------------------------------------------------------
// Device resolution
// ---------------------------------------------------------------------------

#[test]
fn sources_that_do_not_exist_or_are_no_source_are_usage_errors() {
    let tmp = scratch();
    let out = tmp.path().join("out");
    let output = acquire_raw(Path::new("/nonexistent/device/path/12345"), &out, "E1", &[]);
    assert_eq!(output.status.code(), Some(2));
    let (_, stderr) = text(&output);
    assert_eq!(
        stderr.matches("not found").count(),
        1,
        "printed once: {stderr}"
    );

    let output = acquire_raw(tmp.path(), &out, "E1", &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output)
        .1
        .contains("neither a block device nor a regular file"));

    // A character device is no source either
    let output = acquire_raw(Path::new("/dev/null"), &out, "E1", &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!out.exists());
}

#[test]
fn bare_names_are_devices_and_ambiguity_is_refused() {
    let tmp = scratch();
    let out = tmp.path().join("out");
    let base = [
        "-o",
        out.to_str().unwrap(),
        "-C",
        "C",
        "-E",
        "E",
        "-e",
        "X",
        "--format",
        "raw",
    ];
    // ./null and /dev/null: ambiguous (review H7)
    std::fs::write(tmp.path().join("null"), sample(4096)).unwrap();
    let output = dfdisk()
        .current_dir(tmp.path())
        .args(["acquire", "null"])
        .args(base)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let (_, stderr) = text(&output);
    assert!(stderr.contains("ambiguous"), "{stderr}");
    assert!(stderr.contains("./null"), "{stderr}");

    // Only ./name: a bare name never means a file
    std::fs::write(tmp.path().join("evidence.dd"), sample(4096)).unwrap();
    let output = dfdisk()
        .current_dir(tmp.path())
        .args(["acquire", "evidence.dd"])
        .args(base)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output).1.contains("./evidence.dd"));

    // The same rules in `check` and `unmount`
    let output = dfdisk()
        .current_dir(tmp.path())
        .args(["check", "null"])
        .args(base)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let output = dfdisk()
        .current_dir(tmp.path())
        .args(["unmount", "null"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!out.exists());
}

#[test]
fn unmount_refuses_regular_files() {
    let tmp = scratch();
    let f = tmp.path().join("image.dd");
    std::fs::write(&f, sample(512)).unwrap();
    let output = run(&["unmount", f.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output).1.contains("block devices"));
}

// ---------------------------------------------------------------------------
// Acquisition exit codes and output
// ---------------------------------------------------------------------------

#[test]
fn acquisition_exit_codes_follow_the_outcome() {
    let tmp = scratch();
    let src = tmp.path().join("evidence.bin");
    std::fs::write(&src, sample(256 * 1024)).unwrap();
    let out = tmp.path().join("out");

    // Verified: exit 0, reports written, the verdict last on stdout
    let first = acquire_raw(&src, &out, "E1", &[]);
    let (stdout, stderr) = text(&first);
    assert_eq!(first.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("VERIFIED (exit code 0)"), "{stdout}");
    assert!(stdout.contains("VERIFIED - ALL HASHES MATCH"), "{stdout}");
    assert!(stdout.contains("[+] Source      : "), "{stdout}");
    assert!(stderr.contains("[*] "), "phases on stderr: {stderr}");
    assert_eq!(files_ending(&out, ".info.json").len(), 1);
    let raw = files_ending(&out, ".raw");
    assert_eq!(raw.len(), 1);
    assert_eq!(std::fs::read(&raw[0]).unwrap(), sample(256 * 1024));
    // No serial is made up for a file: the file name says NOSERIAL
    assert!(
        raw[0]
            .to_string_lossy()
            .ends_with("cli_1_ea01_e1_NOSERIAL.raw"),
        "{raw:?}"
    );

    // The same acquisition again: refused, exit 3, nothing overwritten
    let second = acquire_raw(&src, &out, "E1", &[]);
    assert_eq!(second.status.code(), Some(3));
    let (_, stderr) = text(&second);
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_eq!(stderr.matches("Error (REFUSED)").count(), 1, "{stderr}");

    // An identity expectation that does not hold: refused, nothing written
    let other = tmp.path().join("out2");
    let refused = acquire_raw(&src, &other, "E2", &["--expect-size", "1M"]);
    assert_eq!(refused.status.code(), Some(3));
    assert!(text(&refused).1.contains("not the expected device"));
    assert!(!other.exists());
    // ... and with the right size it runs
    let ok = acquire_raw(&src, &other, "E2", &["--expect-size", "256K"]);
    assert_eq!(ok.status.code(), Some(0), "{:?}", text(&ok));
}

#[test]
fn json_output_is_the_report_and_nothing_else() {
    let tmp = scratch();
    let src = tmp.path().join("evidence.bin");
    std::fs::write(&src, sample(128 * 1024)).unwrap();
    let out = tmp.path().join("out");
    let output = acquire_raw(
        &src,
        &out,
        "J1",
        &["--json", "--seal", "S-1", "--digests", "sha256,md5"],
    );
    let (stdout, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let file = std::fs::read_to_string(&files_ending(&out, ".info.json")[0]).unwrap();
    assert_eq!(
        stdout.trim_end(),
        file.trim_end(),
        "stdout is the .info.json"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 2);
    assert_eq!(v["outcome"], "verified");
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["case_metadata"]["seal_number"], "S-1");
    assert_eq!(v["case_metadata"]["authority"], serde_json::Value::Null);
    assert_eq!(
        v["effective_config"]["digests"],
        serde_json::json!(["MD5", "SHA256"])
    );
    assert!(
        v["acquisition_hashes"]["sha1"].is_null(),
        "only what was selected"
    );
    // Human text and the verdict on stderr
    assert!(stderr.contains("VERIFIED (exit code 0)"), "{stderr}");
    assert!(stderr.contains("[+] Source"), "{stderr}");

    // Errors with --json: a JSON error document on stdout, the message on stderr
    let output = acquire_raw(Path::new("/nonexistent/x"), &out, "J2", &["--json"]);
    assert_eq!(output.status.code(), Some(2));
    let (stdout, stderr) = text(&output);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 1, "{v}");
    assert_eq!(v["error"]["kind"], "usage");
    assert_eq!(v["error"]["exit_code"], 2);
    assert!(stderr.contains("Error (USAGE ERROR)"), "{stderr}");
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

#[test]
fn check_writes_nothing_and_reports_readiness() {
    let tmp = scratch();
    let src = tmp.path().join("evidence.bin");
    std::fs::write(&src, sample(64 * 1024)).unwrap();
    let out = tmp.path().join("case/out");
    let check = |extra: &[&str]| {
        let mut args = vec![
            "check".to_string(),
            src.to_string_lossy().into_owned(),
            "-o".into(),
            out.to_string_lossy().into_owned(),
            "-C".into(),
            "K".into(),
            "-E".into(),
            "E1".into(),
            "-e".into(),
            "X".into(),
            "--format".into(),
            "raw".into(),
            "--allow-tmpfs".into(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        dfdisk().args(&args).output().unwrap()
    };
    let output = check(&["--json"]);
    let (stdout, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 1, "{v}");
    assert_eq!(v["ready"], true, "{v}");
    assert_eq!(v["problems"], serde_json::json!([]));
    assert_eq!(v["base_name"], "k_ea01_e1_NOSERIAL");
    assert!(!tmp.path().join("case").exists(), "check wrote nothing");

    let output = check(&[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output).0.contains("READY"));

    // Problems are listed, with the exit code of the first
    let output = check(&["--expect-size", "1M"]);
    assert_eq!(output.status.code(), Some(3));
    let (stdout, _) = text(&output);
    assert!(stdout.contains("NOT READY"), "{stdout}");
    assert!(stdout.contains("not the expected device"), "{stdout}");
    let output = check(&["--resume"]);
    assert_eq!(output.status.code(), Some(2), "{:?}", text(&output));
    assert!(!tmp.path().join("case").exists());

    // I3: without ewfacquire on PATH an E01 is not READY (exit 4), and
    // acquire fails before anything is written or recorded
    let only_mocks = sandbox().join("bin");
    let mut args: Vec<String> = [
        "check",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-C",
        "K",
        "-E",
        "E1",
        "-e",
        "X",
        "--format",
        "e01",
        "--allow-tmpfs",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let output = dfdisk()
        .env("PATH", &only_mocks)
        .args(&args)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(4), "{stdout}\n{stderr}");
    assert!(stdout.contains("ewfacquire"), "{stdout}");
    args[0] = "acquire".into();
    let log_before = std::fs::read_to_string(sandbox().join("audit.jsonl")).unwrap_or_default();
    let output = dfdisk()
        .env("PATH", &only_mocks)
        .args(&args)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(4), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("Error (FAILED)") && stderr.contains("ewfacquire"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Starting"),
        "nothing claims a start: {stderr}"
    );
    assert!(!stderr.contains("ACQUIRING"), "nothing started: {stderr}");
    assert!(!tmp.path().join("case").exists());
    let log_after = std::fs::read_to_string(sandbox().join("audit.jsonl")).unwrap_or_default();
    assert!(
        !log_after[log_before.len()..].contains(&src.to_string_lossy().into_owned()),
        "no audit record for this run"
    );
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

#[test]
fn verify_exit_codes() {
    let tmp = scratch();
    let image = tmp.path().join("verify_test.bin");
    let payload = b"CRIME_SCENE_FORENSIC_ACQUISITION_VERIFICATION_PAYLOAD_2026";
    std::fs::write(&image, payload).unwrap();
    let md5 = hex::encode(Md5::digest(payload));
    let sha256 = hex::encode(Sha256::digest(payload));
    let img = image.to_str().unwrap();

    let ok = run(&["verify", img, "--md5", &md5, "--sha256", &sha256]);
    assert_eq!(ok.status.code(), Some(0), "{:?}", text(&ok));
    let (stdout, _) = text(&ok);
    assert!(stdout.contains("VERIFICATION RESULT: PASSED"), "{stdout}");
    assert!(stdout.contains("[+] MD5 MATCH"), "{stdout}");

    let bad = run(&["verify", img, "--md5", "00000000000000000000000000000000"]);
    assert_eq!(bad.status.code(), Some(5));
    let (stdout, _) = text(&bad);
    assert!(stdout.contains("MISMATCH"), "{stdout}");
    assert!(stdout.contains("VERIFICATION RESULT: FAILED"), "{stdout}");

    // Nothing to compare: never "PASSED" (decision 1: exit 9)
    let nothing = run(&["verify", img]);
    assert_eq!(nothing.status.code(), Some(9), "{:?}", text(&nothing));
    let (stdout, _) = text(&nothing);
    assert!(stdout.contains("NOT VERIFIED"), "{stdout}");
    assert!(!stdout.contains("PASSED"), "{stdout}");

    // --json
    let json = run(&["verify", img, "--sha256", &sha256, "--json"]);
    assert_eq!(json.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_str(&text(&json).0).unwrap();
    assert_eq!(v["schema_version"], 1, "{v}");
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["verification"]["result"]["status"], "matched");
    assert!(v["verification"]["pieces"].is_null());

    // Missing image: usage
    let missing = run(&["verify", "/nonexistent/image.raw", "--md5", &md5]);
    assert_eq!(missing.status.code(), Some(2));

    // A malformed digest is a usage error (exit 2), never a mismatch, and
    // writes no addendum (T5)
    let addenda = || {
        std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".verify-"))
            .count()
    };
    let before = addenda();
    for (flag, bad) in [
        ("--md5", "xyz"),
        ("--md5", &md5[..31]),
        ("--sha1", md5.as_str()),
        ("--sha256", "zz"),
    ] {
        let o = run(&["verify", img, flag, bad]);
        let (_, stderr) = text(&o);
        assert_eq!(o.status.code(), Some(2), "{flag} {bad}: {stderr}");
        assert!(stderr.contains("hexadecimal digits"), "{stderr}");
    }
    assert_eq!(addenda(), before, "no addendum for a usage error");
    // Upper case and surrounding blanks are fine
    let upper = run(&["verify", img, "--md5", &format!(" {} ", md5.to_uppercase())]);
    assert_eq!(upper.status.code(), Some(0), "{:?}", text(&upper));

    // --pieces does not apply to EWF images
    std::fs::write(
        tmp.path().join("x.pieces.tsv"),
        "index\toffset\tlength\tsha256\n",
    )
    .unwrap();
    let ewf = run(&[
        "verify",
        tmp.path().join("x.E01").to_str().unwrap(),
        "--pieces",
        tmp.path().join("x.pieces.tsv").to_str().unwrap(),
    ]);
    assert_eq!(ewf.status.code(), Some(2));

    // An addendum per verification and an audit record
    let addenda = std::fs::read_dir(tmp.path())
        .unwrap()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with("verify_test.verify-") && n.ends_with(".txt")
        })
        .count();
    assert!(addenda >= 1, "no verification addendum written");
    let log = std::fs::read_to_string(sandbox().join("audit.jsonl")).unwrap();
    assert!(log.contains("\"image_verification\""));
}

#[test]
fn verify_records_absolute_paths_for_a_relative_image() {
    // I6: the addendum, the JSON result and the audit record never carry
    // the relative path that was typed
    let tmp = scratch();
    std::fs::create_dir(tmp.path().join("case")).unwrap();
    std::fs::write(tmp.path().join("case/rel.raw"), b"relative").unwrap();
    let o = dfdisk()
        .current_dir(tmp.path())
        .args(["verify", "case/rel.raw", "--json"])
        .output()
        .unwrap();
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(9), "{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let image = v["verification"]["image"].as_str().unwrap();
    assert!(Path::new(image).is_absolute(), "{image}");
    assert!(image.ends_with("case/rel.raw"), "{image}");
    let log = std::fs::read_to_string(sandbox().join("audit.jsonl")).unwrap();
    let record: serde_json::Value = log
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|r| r["action"] == "image_verification")
        .find(|r| {
            r["details"]["image"]
                .as_str()
                .is_some_and(|i| i.ends_with("case/rel.raw"))
        })
        .expect("a record of this verification");
    assert!(Path::new(record["details"]["image"].as_str().unwrap()).is_absolute());
}

#[test]
fn verify_takes_the_expected_digests_from_a_report() {
    let tmp = scratch();
    let src = tmp.path().join("evidence.bin");
    std::fs::write(&src, sample(64 * 1024)).unwrap();
    let out = tmp.path().join("out");
    let acq = acquire_raw(&src, &out, "R1", &["--piece-size", "off"]);
    assert_eq!(acq.status.code(), Some(0), "{:?}", text(&acq));
    let report = files_ending(&out, ".info.json").remove(0);
    let image = files_ending(&out, ".raw").remove(0);
    let ok = run(&[
        "verify",
        image.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert_eq!(ok.status.code(), Some(0), "{:?}", text(&ok));
    // Tampered image: mismatch
    let mut data = std::fs::read(&image).unwrap();
    data[100] ^= 0xff;
    std::fs::write(&image, data).unwrap();
    let bad = run(&[
        "verify",
        image.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert_eq!(bad.status.code(), Some(5), "{:?}", text(&bad));
}

// ---------------------------------------------------------------------------
// list, convert
// ---------------------------------------------------------------------------

#[test]
fn list_json_structure() {
    // Names and device numbers no host has (major 511 is unassigned), so
    // the scan finds no sysfs entry, mount or device link of the real host
    let tmp = scratch();
    let lsblk = tmp.path().join("lsblk");
    std::fs::write(
        &lsblk,
        r#"#!/bin/sh
cat << 'EOF'
{"blockdevices": [{"name": "nvme97n1", "path": "/dev/nvme97n1", "maj:min": "511:96",
  "size": 1000204886016, "type": "disk", "model": "Example NVMe 1TB", "vendor": "Example",
  "serial": "S5GXNF0R123456", "tran": "nvme", "mountpoints": [null],
  "children": [{"name": "nvme97n1p1", "path": "/dev/nvme97n1p1", "maj:min": "511:97",
    "size": 536870912, "type": "part", "fstype": "vfat", "mountpoints": [null]}]}]}
EOF
"#,
    )
    .unwrap();
    std::fs::set_permissions(&lsblk, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", tmp.path().display(), mock_path());

    let output = dfdisk()
        .args(["list", "--json"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{:?}", text(&output));
    let v: serde_json::Value = serde_json::from_str(&text(&output).0).unwrap();
    assert_eq!(v["schema_version"], 1, "{v}");
    assert!(v.get("registry").is_some(), "{v}");
    let devices = v["devices"].as_array().expect("an array of devices");
    assert_eq!(devices.len(), 1);
    let d = &devices[0];
    for field in [
        "name",
        "path",
        "kernel_name",
        "transport",
        "serial",
        "serial_candidates",
        "maj_min",
        "kind",
        "holders",
        "mountpoints",
        "system",
        "badges",
        "children",
    ] {
        assert!(d.get(field).is_some(), "{field}: {d}");
    }
    assert_eq!(d["size_bytes"], 1000204886016u64);
    assert_eq!(d["maj_min"], "511:96");
    assert_eq!(d["serial"], "S5GXNF0R123456");
    assert_eq!(d["transport"], "nvme");
    assert_eq!(d["children"][0]["maj_min"], "511:97");
    assert_eq!(d["children"][0]["path"], "/dev/nvme97n1p1");
    // No SMART in a scan (section 8)
    assert!(d.get("smart").is_none(), "{d}");

    let output = dfdisk().args(["list"]).env("PATH", &path).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let (stdout, _) = text(&output);
    assert!(stdout.contains("S5GXNF0R123456"), "{stdout}");
    assert!(stdout.contains("/dev/nvme97n1p1"), "{stdout}");
}

#[test]
fn convert_option_errors_are_usage_errors() {
    let tmp = scratch();
    let src = tmp.path().join("img.raw");
    std::fs::write(&src, sample(4096)).unwrap();
    let out = tmp.path().join("out");
    let output = run(&[
        "convert",
        src.to_str().unwrap(),
        "--to",
        "raw",
        "-o",
        out.to_str().unwrap(),
        "--compression",
        "best",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output).1.contains("E01 target only"));
    assert!(!out.exists());
}

#[test]
fn verify_pieces_finds_the_changed_piece() {
    let tmp = scratch();
    let image = tmp.path().join("pieces.raw");
    let data = sample(3 << 20);
    std::fs::write(&image, &data).unwrap();
    let tsv = tmp.path().join("pieces.pieces.tsv");
    let mut rows = String::from("index\toffset\tlength\tsha256\n");
    for (i, chunk) in data.chunks(1 << 20).enumerate() {
        rows.push_str(&format!(
            "{i}\t{}\t{}\t{}\n",
            i << 20,
            chunk.len(),
            hex::encode(Sha256::digest(chunk))
        ));
    }
    std::fs::write(&tsv, rows).unwrap();
    let sha256 = hex::encode(Sha256::digest(&data));
    let verify = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            image.to_str().unwrap(),
            "--pieces",
            tsv.to_str().unwrap(),
            "--json",
        ];
        args.extend_from_slice(extra);
        let o = run(&args);
        let v: serde_json::Value = serde_json::from_str(&text(&o).0).unwrap();
        (o.status.code(), v)
    };
    // The pieces alone are a comparison: exit 0, never a stub's 4
    let (code, v) = verify(&[]);
    assert_eq!(code, Some(0), "the pieces were the comparison: {v}");
    let pieces = &v["verification"]["pieces"];
    assert_eq!(pieces["pieces_checked"], 3, "{v}");
    assert_eq!(pieces["mismatch_count"], 0, "{v}");
    assert_eq!(pieces["covered_bytes"], 3 << 20, "{v}");
    assert_eq!(v["verification"]["result"]["status"], "matched", "{v}");
    assert!(
        v["verification"]["method"]
            .as_str()
            .unwrap()
            .contains("piecewise SHA-256 (3 pieces"),
        "{v}"
    );
    // The addendum names the piece check
    let addendum = v["verification"]["addendum"].as_str().unwrap();
    let text = std::fs::read_to_string(addendum).unwrap();
    assert!(text.contains("Pieces File"), "{text}");
    let (code, _) = verify(&["--sha256", &sha256]);
    assert_eq!(code, Some(0));

    // One changed byte in the second piece: a mismatch even when the
    // whole-image digest is not given
    let mut bad = data.clone();
    bad[(1 << 20) + 5] ^= 0x55;
    std::fs::write(&image, &bad).unwrap();
    let (code, v) = verify(&[]);
    assert_eq!(code, Some(5), "{v}");
    let pieces = &v["verification"]["pieces"];
    assert_eq!(pieces["mismatch_count"], 1, "{v}");
    assert_eq!(pieces["mismatches"][0]["index"], 1, "{v}");
    assert!(
        v["verification"]["result"]["details"]
            .as_str()
            .unwrap()
            .contains("piece 1 (bytes 1048576-2097151)"),
        "{v}"
    );

    // A pieces file that does not cover the whole image is a mismatch
    std::fs::write(&image, [data.as_slice(), b"tail"].concat()).unwrap();
    let (code, v) = verify(&[]);
    assert_eq!(code, Some(5), "{v}");
    assert!(
        v["verification"]["result"]["details"]
            .as_str()
            .unwrap()
            .contains("4 bytes after the last piece"),
        "{v}"
    );
}

// ---------------------------------------------------------------------------
// --rescue-to-e01 with the real GNU ddrescue and libewf
// ---------------------------------------------------------------------------

/// A clean rescue with --verify-source converted to E01 in the same
/// directory: both verdicts VERIFIED (exit 0), the conversion report names
/// the rescue report by path and digest, no file of the rescue is touched.
/// A second run refuses (never overwrites), and so does a resume while the
/// E01 of the earlier image is there.
#[test]
fn rescue_to_e01_converts_next_to_the_rescue() {
    if !support::tool_available(&["ddrescue", "ewfacquire", "ewfverify", "ewfinfo"]) {
        return;
    }
    let tmp = scratch();
    let src = tmp.path().join("evidence.bin");
    std::fs::write(&src, sample(1 << 20)).unwrap();
    let out = tmp.path().join("out");
    let rescue = |extra: &[&str]| {
        let mut args = vec![
            "acquire",
            src.to_str().unwrap(),
            "--rescue",
            "--rescue-to-e01",
            "--verify-source",
            "-o",
            out.to_str().unwrap(),
            "-C",
            "CLI-1",
            "-E",
            "R2E",
            "--examiner",
            "Tester",
            "--allow-tmpfs",
            "--allow-low-space",
            "--json",
        ];
        args.extend_from_slice(extra);
        dfdisk().args(&args).output().unwrap()
    };
    let o = rescue(&[]);
    let (stdout, stderr) = text(&o);
    assert_eq!(o.status.code(), Some(0), "{stderr}\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 1, "{v}");
    assert_eq!(v["acquisition"]["outcome"], "verified", "{v}");
    assert_eq!(v["conversion"]["outcome"], "verified", "{v}");
    assert_eq!(v["exit_code"], 0);
    let base = v["acquisition"]["base_name"].as_str().unwrap().to_string();

    // Everything in one directory, nothing in a subdirectory
    let names: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for suffix in [
        ".raw",
        ".map",
        ".info",
        ".info.json",
        ".identity.json",
        ".E01",
        ".conversion.info",
        ".conversion.info.json",
    ] {
        assert!(
            names.contains(&format!("{base}{suffix}")),
            "{base}{suffix} missing: {names:?}"
        );
    }
    assert!(
        std::fs::read_dir(&out)
            .unwrap()
            .flatten()
            .all(|e| e.path().is_file()),
        "{names:?}"
    );

    // The conversion report references the rescue report by path and digest
    let rescue_json = out.join(format!("{base}.info.json"));
    let conv: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out.join(format!("{base}.conversion.info.json"))).unwrap(),
    )
    .unwrap();
    let reference = &conv["source_report"];
    assert_eq!(
        reference["path"],
        rescue_json.to_string_lossy().as_ref(),
        "{conv}"
    );
    assert_eq!(
        reference["sha256"],
        hex::encode(Sha256::digest(std::fs::read(&rescue_json).unwrap())),
        "{conv}"
    );
    assert_eq!(reference["engine"], "rescue", "{conv}");
    // The rescue's image digest is what the E01 holds
    let image = std::fs::read(out.join(format!("{base}.raw"))).unwrap();
    assert_eq!(image, sample(1 << 20));
    assert_eq!(
        conv["output_hashes"]["md5"].as_str().map(str::to_lowercase),
        Some(hex::encode(Md5::digest(&image))),
        "{conv}"
    );

    // Never overwritten: the same run again is refused
    let o = rescue(&[]);
    assert_eq!(o.status.code(), Some(3), "{:?}", text(&o));
    // A resume would change the image the E01 was made from: refused while
    // the conversion's files are there
    let o = rescue(&["--resume"]);
    assert_eq!(o.status.code(), Some(3), "{:?}", text(&o));
    assert!(text(&o).1.contains(".E01"), "{:?}", text(&o));

    // C-5: the E01 back to RAW. The rescue report next to it lists
    // <base>.raw, not <base>.E01: found automatically it is ignored with a
    // note (not a usage error); given with --report it is refused
    let e01 = out.join(format!("{base}.E01"));
    let back = tmp.path().join("back");
    let convert = |extra: &[&str]| {
        let mut args = vec![
            "convert",
            e01.to_str().unwrap(),
            "--to",
            "raw",
            "-o",
            back.to_str().unwrap(),
            "--allow-tmpfs",
            "--json",
        ];
        args.extend_from_slice(extra);
        dfdisk().args(&args).output().unwrap()
    };
    let o = convert(&["--report", rescue_json.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{:?}", text(&o));
    assert!(text(&o).1.contains("does not list"), "{:?}", text(&o));
    let o = convert(&[]);
    let (stdout, stderr) = text(&o);
    assert_ne!(o.status.code(), Some(2), "{stderr}\n{stdout}");
    let conv: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        conv["notes"].as_array().unwrap().iter().any(|n| n
            .as_str()
            .unwrap()
            .contains("was not used: it does not list")),
        "{conv}"
    );
}
