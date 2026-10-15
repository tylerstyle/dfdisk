//! The CLI end to end against a fake session host: flags -> request ->
//! session -> printed report and exit code, for every outcome (§2), plus
//! the option mapping and the `--rescue-to-e01` planning. No host disk is
//! touched: the source is a regular file, the engine and the verification
//! are closures.

use super::acquire::*;
use super::args::{AcquireArgs, Cli, Commands};
use super::console::Console;
use super::resolve::file_device;
use crate::discovery::sysfs::SysRoot;
use crate::engines::preflight::DestinationFacts;
use crate::engines::process::StopControl;
use crate::engines::session::{
    AcquisitionRequest, EngineContext, EngineOutput, SessionHost, SwapEntry,
};
use crate::engines::AcquisitionError;
use crate::models::capacity::CapacityInfo;
use crate::models::config::{
    CompressionLevel, EngineKind, OnReadError, SmartPolicy, SplitSize, WriteProtectPolicy,
};
use crate::models::device::SmartSnapshot;
use crate::models::identity::SourceIdentity;
use crate::models::info_report::{ForensicInfoReport, HashResults};
use crate::models::outcome::{Outcome, RangeKind, ReadErrorTable, VerificationResult};
use crate::models::protection::WriteProtection;
use crate::models::provenance::{ClockInfo, ProvenanceRecorder, TimedatectlInfo, ToolProvenance};
use crate::signals::AbortController;
use clap::Parser;
use digest::Digest;
use futures::future::BoxFuture;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

const SIZE: u64 = 64 * 1024;

fn sample() -> Vec<u8> {
    (0..SIZE).map(|i| (i * 7 % 253) as u8).collect()
}

fn hashes(data: &[u8]) -> HashResults {
    HashResults {
        md5: Some(hex::encode(md5::Md5::digest(data))),
        sha1: Some(hex::encode(sha1::Sha1::digest(data))),
        sha256: Some(hex::encode(sha2::Sha256::digest(data))),
    }
}

/// What the fake engine and verification do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Verified,
    ReadErrors,
    Incomplete,
    Mismatch,
    VerifyFails,
    NothingToCompare,
    Aborted,
}

struct FakeHost {
    tmp: tempfile::TempDir,
    scenario: Scenario,
    probe_error: Option<String>,
}

impl FakeHost {
    fn new(scenario: Scenario) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("source.img"), sample()).unwrap();
        std::fs::create_dir_all(tmp.path().join("sys")).unwrap();
        Self {
            tmp,
            scenario,
            probe_error: None,
        }
    }

    fn source(&self) -> PathBuf {
        self.tmp.path().join("source.img")
    }

    fn out(&self) -> PathBuf {
        self.tmp.path().join("case")
    }

    fn log(&self) -> PathBuf {
        self.tmp.path().join("audit.jsonl")
    }

    fn args(&self, extra: &[&str]) -> AcquireArgs {
        let mut argv: Vec<String> = [
            "dfdisk",
            "acquire",
            &self.source().to_string_lossy(),
            "-o",
            &self.out().to_string_lossy(),
            "-C",
            "CLI-7",
            "-E",
            "HD01",
            "--examiner",
            "Test Examiner",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        argv.extend(extra.iter().map(|s| s.to_string()));
        match Cli::try_parse_from(argv).unwrap().command {
            Some(Commands::Acquire(a)) => a,
            other => panic!("{other:?}"),
        }
    }

    fn request(&self, args: &AcquireArgs) -> AcquisitionRequest {
        let config = config_from_options(&args.options).unwrap();
        AcquisitionRequest::new(
            file_device(&self.source(), SIZE),
            case_from_args(&args.case),
            config,
        )
    }

    fn engine(&self, ctx: &EngineContext) -> Result<EngineOutput, AcquisitionError> {
        let data = sample();
        let image = ctx.output_path(".raw");
        let mut out = EngineOutput {
            bytes_acquired: SIZE,
            expected_bytes: SIZE,
            acquisition_hashes: hashes(&data),
            image_files: vec![image.clone()],
            ..Default::default()
        };
        match self.scenario {
            Scenario::ReadErrors => {
                let mut t = ReadErrorTable::new(512, "fake engine");
                t.push(4096, 1024, RangeKind::Substituted);
                out.read_errors = t;
            }
            Scenario::Incomplete => {
                out.bytes_acquired = SIZE / 2;
                out.stop_reason = Some("unreadable sector at offset 32768".into());
            }
            Scenario::Aborted => {
                // A signal arrived while the engine ran: the controller's flag
                ctx.abort.store(true, Ordering::SeqCst);
                out.bytes_acquired = SIZE / 4;
                out.aborted = true;
            }
            _ => {}
        }
        std::fs::write(&image, &data[..out.bytes_acquired as usize])?;
        Ok(out)
    }

    fn verification(&self, out: &EngineOutput) -> (VerificationResult, HashResults) {
        let method = "fake re-read".to_string();
        match self.scenario {
            Scenario::Mismatch => (
                VerificationResult::Mismatched {
                    method,
                    details: "MD5 differs".into(),
                },
                HashResults::default(),
            ),
            Scenario::VerifyFails => (
                VerificationResult::Failed {
                    reason: "the image could not be read".into(),
                },
                HashResults::default(),
            ),
            Scenario::NothingToCompare => (
                VerificationResult::NotPossible {
                    reason: "nothing to compare".into(),
                },
                out.acquisition_hashes.clone(),
            ),
            _ => (
                VerificationResult::Matched { method },
                out.acquisition_hashes.clone(),
            ),
        }
    }
}

impl SessionHost for FakeHost {
    fn find_tool(&self, program: &str) -> Option<PathBuf> {
        Some(PathBuf::from("/fake/bin").join(program))
    }

    fn probe_identity(&self, path: &str) -> Result<SourceIdentity, String> {
        match &self.probe_error {
            Some(e) => Err(e.clone()),
            None => crate::discovery::identity::probe_file(path),
        }
    }

    fn sysfs(&self) -> SysRoot {
        SysRoot::new(self.tmp.path().join("sys"))
    }

    fn mountinfo(&self) -> Result<String, String> {
        Ok(String::new())
    }

    fn swaps(&self) -> Result<Vec<SwapEntry>, String> {
        Ok(Vec::new())
    }

    fn registry(&self) -> Result<Option<dfcore::protected::Registry>, String> {
        Ok(None)
    }

    fn lsblk(&self) -> Result<Vec<dfcore::lsblk::FlatDevice>, String> {
        Ok(Vec::new())
    }

    fn open_source(&self, identity: &SourceIdentity) -> Result<File, AcquisitionError> {
        Ok(File::open(&identity.path)?)
    }

    fn destination(&self, output_dir: &Path) -> io::Result<DestinationFacts> {
        Ok(DestinationFacts {
            output_dir: output_dir.to_path_buf(),
            existing_ancestor: dfcore::sysfs::existing_ancestor(output_dir),
            ancestor_is_dir: true,
            mount_point: Some("/".into()),
            fs_type: Some("ext4".into()),
            mount_source: Some("/dev/fake1".into()),
            read_only_mount: false,
            free_bytes: Some(10 << 30),
            backing_device: None,
        })
    }

    fn tool_source_path(&self, identity: &SourceIdentity) -> String {
        identity.path.clone()
    }

    fn enforce_write_protection(
        &self,
        _identity: &SourceIdentity,
        _wp: &mut WriteProtection,
    ) -> Result<(), String> {
        Ok(())
    }

    fn capacity<'a>(
        &'a self,
        identity: &'a SourceIdentity,
        _control: &'a StopControl,
        _recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, CapacityInfo> {
        Box::pin(async move { CapacityInfo::not_probed(identity.size_bytes, "fake") })
    }

    fn smart<'a>(
        &'a self,
        _identity: &'a SourceIdentity,
        _policy: SmartPolicy,
        _json_file: Option<&'a Path>,
        _control: &'a StopControl,
        _recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, Option<SmartSnapshot>> {
        Box::pin(async { None })
    }

    fn clock(&self) -> BoxFuture<'static, ClockInfo> {
        Box::pin(async {
            ClockInfo::from_parts(
                chrono::Utc::now(),
                &TimedatectlInfo {
                    ntp_synchronized: Some(true),
                    ..Default::default()
                },
                Some("UTC".into()),
                Some(0),
                Some("+00:00".into()),
            )
        })
    }

    fn provenance(&self) -> ToolProvenance {
        ToolProvenance::default()
    }

    fn tool_versions<'a>(&'a self, _tools: Vec<String>) -> BoxFuture<'a, BTreeMap<String, String>> {
        Box::pin(async { BTreeMap::new() })
    }

    fn audit_log(&self) -> PathBuf {
        self.log()
    }

    fn export_audit(&self, log: &Path, dir: &Path) -> Result<PathBuf, String> {
        dfcore::audit::export_for_boot(log, dir, "testboot")
            .map(|i| i.jsonl)
            .map_err(|e| format!("{e:#}"))
    }

    fn acquire<'a>(
        &'a self,
        ctx: &'a EngineContext,
    ) -> BoxFuture<'a, Result<EngineOutput, AcquisitionError>> {
        Box::pin(async move { self.engine(ctx) })
    }

    fn verify<'a>(
        &'a self,
        _ctx: &'a EngineContext,
        out: &'a EngineOutput,
    ) -> BoxFuture<'a, (VerificationResult, HashResults)> {
        Box::pin(async move { self.verification(out) })
    }
}

fn run_options(args: &AcquireArgs) -> RunOptions {
    RunOptions {
        verbose: false,
        e01: E01Settings::from_options(&args.options),
    }
}

/// Run `acquire` with `extra` flags on `host` the way `run_command` does:
/// (exit code, stdout, stderr).
async fn acquire_on(host: &FakeHost, extra: &[&str], json: bool) -> (i32, String, String) {
    let args = host.args(extra);
    let request = host.request(&args);
    let (console, out, err) = Console::capture(json);
    let controller = AbortController::new();
    let result = execute_acquisition(
        host,
        request,
        run_options(&args),
        &controller,
        &mut None,
        &console,
    )
    .await;
    let code = super::finish(&console, result);
    (code, out.text(), err.text())
}

fn info_json(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().ends_with(".info.json"))
        .expect("a report")
        .path()
}

#[tokio::test]
async fn every_outcome_maps_to_its_exit_code() {
    for (scenario, code, label) in [
        (Scenario::Verified, 0, "VERIFIED"),
        (Scenario::ReadErrors, 7, "COMPLETED WITH READ ERRORS"),
        (Scenario::Incomplete, 6, "INCOMPLETE"),
        (Scenario::Mismatch, 5, "HASH MISMATCH"),
        (Scenario::VerifyFails, 4, "VERIFICATION FAILED"),
        (Scenario::NothingToCompare, 9, "COMPLETE, NOT VERIFIED"),
        (Scenario::Aborted, 8, "ABORTED"),
    ] {
        let host = FakeHost::new(scenario);
        let (got, stdout, stderr) = acquire_on(&host, &["--format", "raw"], false).await;
        assert_eq!(got, code, "{scenario:?}\n{stdout}\n{stderr}");
        assert!(
            stdout.contains(&format!("{label} (exit code {code})")),
            "{scenario:?}: {stdout}"
        );
        // The report text is on stdout, "ALL HASHES MATCH" only when verified
        assert!(stdout.contains("Report: "), "{stdout}");
        assert_eq!(
            stdout.contains("ALL HASHES MATCH"),
            scenario == Scenario::Verified,
            "{scenario:?}: {stdout}"
        );
        let report = ForensicInfoReport::from_json(
            &std::fs::read_to_string(info_json(&host.out())).unwrap(),
        )
        .unwrap();
        assert_eq!(report.exit_code, code, "{scenario:?}");
    }
}

#[tokio::test]
async fn json_prints_exactly_the_info_json_on_stdout() {
    let host = FakeHost::new(Scenario::ReadErrors);
    let (code, stdout, stderr) = acquire_on(&host, &["--format", "raw"], true).await;
    assert_eq!(code, 7, "{stderr}");
    let file = std::fs::read_to_string(info_json(&host.out())).unwrap();
    assert_eq!(stdout.trim_end(), file.trim_end(), "stdout is the report");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 2);
    assert_eq!(v["outcome"], "completed_with_read_errors");
    assert_eq!(v["exit_code"], 7);
    assert_eq!(v["case_metadata"]["case_number"], "CLI-7");
    // Human text went to stderr
    assert!(
        stderr.contains("COMPLETED WITH READ ERRORS (exit code 7)"),
        "{stderr}"
    );
}

#[tokio::test]
async fn refusals_and_usage_errors_are_printed_once_with_their_code() {
    let mut host = FakeHost::new(Scenario::Verified);
    host.probe_error = Some("no such device".into());
    let (code, stdout, stderr) = acquire_on(&host, &["--format", "raw"], false).await;
    assert_eq!(code, 3, "{stderr}");
    assert_eq!(stderr.matches("Error (REFUSED)").count(), 1, "{stderr}");
    assert!(stderr.contains("no such device"), "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!host.out().exists(), "nothing written for a refusal");

    // --json: the error as JSON on stdout as well
    let (code, stdout, _) = acquire_on(&host, &["--format", "raw"], true).await;
    assert_eq!(code, 3);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["error"]["kind"], "refused");
    assert_eq!(v["error"]["exit_code"], 3);

    // Usage: a required field that is blank (the session validates too)
    let host = FakeHost::new(Scenario::Verified);
    let mut args = host.args(&["--format", "raw"]);
    args.case.examiner = "  ".into();
    let request = host.request(&args);
    let (console, _out, err) = Console::capture(false);
    let r = execute_acquisition(
        &host,
        request,
        run_options(&args),
        &AbortController::new(),
        &mut None,
        &console,
    )
    .await;
    assert_eq!(super::finish(&console, r), 2);
    assert!(
        err.text().contains("examiner (--examiner)"),
        "{}",
        err.text()
    );
}

#[tokio::test]
async fn an_abort_before_the_start_writes_nothing() {
    let host = FakeHost::new(Scenario::Verified);
    let args = host.args(&["--format", "raw"]);
    let controller = AbortController::new();
    controller.handle(crate::signals::SignalKind::Interrupt);
    let (console, ..) = Console::capture(false);
    let r = execute_acquisition(
        &host,
        host.request(&args),
        run_options(&args),
        &controller,
        &mut None,
        &console,
    )
    .await;
    assert_eq!(super::finish(&console, r), 8);
    assert!(!host.out().exists());
}

#[tokio::test]
async fn an_incomplete_rescue_is_not_converted() {
    let host = FakeHost::new(Scenario::Incomplete);
    let (code, stdout, stderr) = acquire_on(
        &host,
        &["--rescue", "--rescue-to-e01", "--split", "4G"],
        true,
    )
    .await;
    assert_eq!(code, 6, "{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["acquisition"]["outcome"], "incomplete");
    assert_eq!(v["acquisition"]["engine"], "rescue");
    assert!(v["conversion"].is_null());
    assert!(v["conversion_error"].is_null());
    assert!(
        v["conversion_skipped"]
            .as_str()
            .unwrap()
            .contains("--resume"),
        "{v}"
    );
    assert_eq!(v["exit_code"], 6);
    // The rescue report announces the conversion
    assert_eq!(
        v["acquisition"]["effective_config"]["settings"]["rescue"]["rescue_to_e01"], true,
        "{v}"
    );
    assert!(std::fs::read_dir(host.out())
        .unwrap()
        .flatten()
        .all(|e| !e.file_name().to_string_lossy().contains(".conversion.")));
    assert!(stderr.contains("no conversion"), "{stderr}");
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(argv)
}

fn acquire(extra: &[&str]) -> Result<AcquireArgs, clap::Error> {
    let mut argv = vec![
        "dfdisk", "acquire", "/dev/sdx", "-o", "/cases/x", "-C", "C1", "-E", "E1", "-e", "Ex",
    ];
    argv.extend_from_slice(extra);
    parse(&argv).map(|c| match c.command {
        Some(Commands::Acquire(a)) => a,
        other => panic!("{other:?}"),
    })
}

#[test]
fn required_arguments_have_no_defaults() {
    use clap::error::ErrorKind as Clap;
    for missing in [
        &[
            "dfdisk", "acquire", "/dev/sdx", "-o", "/x", "-E", "E1", "-e", "Ex",
        ][..],
        &[
            "dfdisk", "acquire", "/dev/sdx", "-o", "/x", "-C", "C1", "-e", "Ex",
        ],
        &[
            "dfdisk", "acquire", "/dev/sdx", "-o", "/x", "-C", "C1", "-E", "E1",
        ],
        &[
            "dfdisk", "acquire", "/dev/sdx", "-C", "C1", "-E", "E1", "-e", "Ex",
        ],
        &[
            "dfdisk", "check", "/dev/sdx", "-C", "C1", "-E", "E1", "-e", "Ex",
        ],
        &["dfdisk", "convert", "x.raw", "--to", "e01"],
    ] {
        let e = parse(missing).unwrap_err();
        assert_eq!(e.kind(), Clap::MissingRequiredArgument, "{missing:?}");
        assert_eq!(e.exit_code(), 2);
    }
    // The long examiner flag and the short flags the CFTT test uses
    let a = parse(&[
        "dfdisk",
        "acquire",
        "/dev/sdx",
        "-o",
        "/x",
        "-C",
        "C1",
        "-E",
        "E1",
        "--examiner",
        "Ex",
    ])
    .unwrap();
    assert!(matches!(a.command, Some(Commands::Acquire(_))));
    // Blank values are refused by the case model (usage, exit 2)
    let mut args = acquire(&[]).unwrap();
    args.case.case = " ".into();
    args.case.evidence = String::new();
    let config = config_from_options(&args.options).unwrap();
    let e = validate_acquisition(&config, &case_from_args(&args.case)).unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.message.contains("case number (--case)"), "{e}");
    assert!(e.message.contains("evidence number (--evidence)"), "{e}");
}

#[test]
fn defaults_map_onto_the_e01_configuration() {
    let a = acquire(&[]).unwrap();
    let c = config_from_options(&a.options).unwrap();
    assert_eq!(c.engine(), EngineKind::Ewf);
    assert_eq!(c.compression, CompressionLevel::Fast);
    assert_eq!(c.split_size, SplitSize::TwoGb);
    assert!(c.calc_md5 && c.calc_sha1 && c.calc_sha256);
    assert_eq!(c.error_retries, 2);
    assert_eq!(c.smart, SmartPolicy::Basic);
    assert_eq!(c.write_protect, WriteProtectPolicy::Auto);
    assert!(c.expect.is_empty());
    assert_eq!(c.output_dir, PathBuf::from("/cases/x"));
    assert!(c.validate().is_ok());
    let case = case_from_args(&a.case);
    assert_eq!(case.location_ea, "", "EA \"01\" comes from the model");
    assert_eq!(case.effective_ea(), "01");
    assert_eq!(case.authority, "");
    // A relative output directory becomes absolute (the report records it)
    let mut rel = acquire(&[]).unwrap();
    rel.options.output_dir = PathBuf::from("case");
    assert!(config_from_options(&rel.options)
        .unwrap()
        .output_dir
        .is_absolute());
}

#[test]
fn every_new_flag_reaches_the_configuration() {
    let a = acquire(&[
        "--format",
        "raw",
        "--digests",
        "sha256",
        "--on-read-error",
        "zero-fill",
        "--piece-size",
        "64M",
        "--verify-source",
        "--smart",
        "full",
        "--write-protect",
        "off",
        "--allow-tmpfs",
        "--allow-low-space",
        "--refuse-hidden-areas",
        "--expect-serial",
        "S123",
        "--expect-wwn",
        "0x5000c500a1b2c3d4",
        "--expect-size",
        "1G",
        "--seal",
        "SEAL-9",
        "--seized-at",
        "2026-10-01 10:00",
        "--seized-location",
        "Office 3",
        "--ea",
        "02",
        "--authority",
        "Agency",
        "-D",
        "laptop disk",
        "-N",
        "note",
    ])
    .unwrap();
    let c = config_from_options(&a.options).unwrap();
    assert_eq!(c.engine(), EngineKind::Raw);
    assert!(!c.calc_md5 && !c.calc_sha1 && c.calc_sha256);
    assert_eq!(c.on_read_error, OnReadError::ZeroFill);
    assert_eq!(c.piece_size, Some(64 << 20));
    assert!(c.verify_source);
    assert_eq!(c.smart, SmartPolicy::Full);
    assert_eq!(c.write_protect, WriteProtectPolicy::Off);
    assert!(c.allow_tmpfs && c.allow_low_space && c.refuse_hidden_areas);
    // --allow-holders is gone (a holder claims the source; it could never apply)
    let e = Cli::try_parse_from([
        "dfdisk",
        "acquire",
        "/dev/sdx",
        "-o",
        "/tmp/x",
        "-C",
        "C",
        "-E",
        "E",
        "-e",
        "X",
        "--allow-holders",
    ])
    .unwrap_err();
    assert!(
        e.use_stderr(),
        "an unknown argument is a usage error (exit 2)"
    );
    assert_eq!(c.expect.serial.as_deref(), Some("S123"));
    assert_eq!(c.expect.wwn.as_deref(), Some("0x5000c500a1b2c3d4"));
    assert_eq!(c.expect.size, Some(1 << 30));
    assert_eq!(c.split_size, SplitSize::None);
    assert!(c.validate().is_ok(), "{:?}", c.validate());
    let case = case_from_args(&a.case);
    assert_eq!(case.seal_number, "SEAL-9");
    assert_eq!(case.seizure_time, "2026-10-01 10:00");
    assert_eq!(case.seizure_location, "Office 3");
    assert_eq!(case.location_ea, "02");
    assert_eq!(case.authority, "Agency");
    assert_eq!(case.description, "laptop disk");
    assert_eq!(case.notes, "note");

    let a = acquire(&["--format", "raw", "--piece-size", "off"]).unwrap();
    assert_eq!(config_from_options(&a.options).unwrap().piece_size, None);

    let a = acquire(&[
        "--compression",
        "best",
        "--split",
        "none",
        "-r",
        "7",
        "--error-granularity",
        "8",
        "--digests",
        "sha1",
    ])
    .unwrap();
    let c = config_from_options(&a.options).unwrap();
    assert_eq!(c.compression, CompressionLevel::Best);
    assert_eq!(c.split_size, SplitSize::None);
    assert_eq!(c.error_retries, 7);
    assert_eq!(c.ewf_error_granularity, Some(8));
    assert!(c.validate().is_ok());

    let a = acquire(&["--rescue", "--resume", "--rescue-to-e01", "--split", "4G"]).unwrap();
    let c = config_from_options(&a.options).unwrap();
    assert_eq!(c.engine(), EngineKind::Rescue);
    assert!(c.resume && c.rescue_to_e01);
    assert_eq!(
        c.split_size,
        SplitSize::None,
        "the rescue image is one file"
    );
    assert!(c.validate().is_ok());
    assert_eq!(
        E01Settings::from_options(&a.options),
        E01Settings {
            compression: CompressionLevel::Fast,
            split_size: SplitSize::FourGb,
            ..Default::default()
        }
    );
}

#[test]
fn flags_for_another_engine_are_usage_errors() {
    for (flags, needle) in [
        (
            &["--format", "raw", "--compression", "best"][..],
            "--compression",
        ),
        (&["--format", "raw", "--split", "4G"], "--split"),
        (&["--rescue", "--split", "4G"], "--split"),
        (&["--format", "raw", "-r", "3"], "--retries"),
        (&["--on-read-error", "stop"], "--on-read-error"),
        (
            &["--rescue", "--on-read-error", "zero-fill"],
            "--on-read-error",
        ),
        (&["--piece-size", "1G"], "--piece-size"),
        (&["--rescue", "--format", "e01"], "--rescue-to-e01"),
    ] {
        let a = acquire(flags).unwrap();
        let e = config_from_options(&a.options).unwrap_err();
        assert_eq!(e.exit_code(), 2, "{flags:?}");
        assert!(e.message.contains(needle), "{flags:?}: {e}");
    }
    // Rules of the configuration itself
    for flags in [
        &["--resume"][..],
        &["--rescue-to-e01"],
        &["--format", "raw", "--error-granularity", "8"],
        &["-r", "256"],
        &["--format", "raw", "--piece-size", "1000"],
        &["--format", "raw", "--digests", ""],
    ] {
        let Ok(a) = acquire(flags) else {
            continue; // clap refused the value itself (also exit 2)
        };
        let c = config_from_options(&a.options).unwrap();
        let e = validate_acquisition(&c, &case_from_args(&a.case)).unwrap_err();
        assert_eq!(e.exit_code(), 2, "{flags:?}");
    }
    // Values clap itself refuses
    for flags in [
        &["--expect-size", "1.5G"][..],
        &["--piece-size", "huge"],
        &["--smart", "always"],
        &["--write-protect", "maybe"],
        &["--digests", "crc32"],
    ] {
        assert!(acquire(flags).is_err(), "{flags:?}");
    }
}

#[test]
fn exit_code_severity() {
    assert_eq!(more_severe(0, 9), 9);
    assert_eq!(more_severe(9, 7), 7);
    assert_eq!(more_severe(7, 4), 4);
    assert_eq!(more_severe(4, 5), 5);
    assert_eq!(more_severe(5, 8), 8);
    assert_eq!(more_severe(3, 6), 3);
    assert_eq!(more_severe(0, 0), 0);
    assert_eq!(
        more_severe(42, 0),
        42,
        "unknown codes count as internal errors"
    );
    for (i, a) in SEVERITY_ORDER.iter().enumerate() {
        for b in &SEVERITY_ORDER[i..] {
            assert_eq!(more_severe(*a, *b), *a);
            assert_eq!(more_severe(*b, *a), *a);
        }
    }
}

fn rescue_report(outcome: Outcome, ranges: u64) -> ForensicInfoReport {
    use crate::models::config::{AcquisitionConfig, EffectiveConfig};
    let case = crate::models::case::CaseMetadata {
        case_number: "C".into(),
        evidence_number: "E".into(),
        examiner: "X".into(),
        ..Default::default()
    };
    let config = AcquisitionConfig::rescue("/cases/x");
    let mut r = ForensicInfoReport::new(
        EngineKind::Rescue,
        &case,
        SourceIdentity::default(),
        EffectiveConfig::build(&config, None),
    );
    r.outcome = outcome;
    r.exit_code = outcome.exit_code();
    r.output_dir = "/cases/x".into();
    r.base_name = "c_ea01_e_SER".into();
    r.image_files = vec!["/cases/x/c_ea01_e_SER.raw".into()];
    let mut t = ReadErrorTable::new(512, "ddrescue mapfile");
    for i in 0..ranges {
        t.push(i << 20, 4096, RangeKind::Substituted);
    }
    r.read_errors = t;
    r
}

#[test]
fn rescue_to_e01_converts_complete_rescues_only() {
    let case = crate::models::case::CaseMetadata::default();
    let e01 = E01Settings {
        compression: CompressionLevel::Best,
        split_size: SplitSize::FourGb,
        allow_tmpfs: false,
        allow_low_space: true,
    };
    for outcome in [
        Outcome::Verified,
        Outcome::CompleteUnverified,
        Outcome::CompletedWithReadErrors,
    ] {
        let req = plan_conversion(&rescue_report(outcome, 2), &case, e01).unwrap();
        assert_eq!(req.source, PathBuf::from("/cases/x/c_ea01_e_SER.raw"));
        assert_eq!(
            req.output_dir,
            PathBuf::from("/cases/x"),
            "next to the rescue"
        );
        assert!(req.allow_low_space && !req.allow_tmpfs);
        assert_eq!(
            req.source_report,
            Some(PathBuf::from("/cases/x/c_ea01_e_SER.info.json"))
        );
        assert_eq!(req.compression, CompressionLevel::Best);
        assert_eq!(req.split_size, SplitSize::FourGb);
        assert!(req.case.is_some());
        assert_eq!(req.notes.len(), 1, "the zero-filled ranges");
    }
    for outcome in [
        Outcome::Incomplete,
        Outcome::Aborted,
        Outcome::Mismatch,
        Outcome::VerificationFailed,
    ] {
        let reason = plan_conversion(&rescue_report(outcome, 0), &case, e01).unwrap_err();
        assert!(reason.contains(outcome.label()), "{reason}");
    }
    let mut no_image = rescue_report(Outcome::Verified, 0);
    no_image.image_files.clear();
    assert!(plan_conversion(&no_image, &case, e01).is_err());
    assert_eq!(ConversionStep::Skipped("x".into()).exit_code(), 0);
    // I2: after a written rescue, a conversion that could not start is
    // FAILED (4), never 2 or 3 ("nothing was written")
    assert_eq!(
        ConversionStep::Failed(AcquisitionError::refused("x")).exit_code(),
        4
    );
    assert_eq!(
        ConversionStep::Failed(AcquisitionError::usage("x")).exit_code(),
        4
    );
    assert_eq!(
        ConversionStep::Failed(AcquisitionError::aborted("x")).exit_code(),
        8
    );
    assert_eq!(
        ConversionStep::Failed(AcquisitionError::failed("x")).exit_code(),
        4
    );
}

#[test]
fn rescue_notes_list_the_zero_filled_ranges() {
    // The converter states the source, the rescue verdict and the read-error
    // summary itself; the CLI adds only the ranges
    let json = Path::new("/cases/x/c_ea01_e_SER.info.json");
    let notes = rescue_notes(&rescue_report(Outcome::CompletedWithReadErrors, 2), json);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains("ddrescue mapfile, 512 bytes each"),
        "{notes:?}"
    );
    assert!(notes[0].contains("0-7, 2048-2055"), "{notes:?}");
    let notes = rescue_notes(&rescue_report(Outcome::CompletedWithReadErrors, 25), json);
    assert!(
        notes[0].contains("and 5 more ranges (see c_ea01_e_SER.info.json)"),
        "{notes:?}"
    );
    assert!(rescue_notes(&rescue_report(Outcome::CompleteUnverified, 0), json).is_empty());
}

#[test]
fn the_selection_summary_is_sanitised() {
    use crate::cli::resolve::ResolvedSource;
    use crate::models::device::BlockDevice;
    let dev = BlockDevice {
        path: "/dev/sdx".into(),
        model: Some("Evil\x1b[2JDisk".into()),
        serial: Some("SER\nIAL".into()),
        maj_min: Some("8:16".into()),
        size_bytes: 1 << 30,
        ..Default::default()
    };
    let source = ResolvedSource::Block {
        path: "/dev/disk/by-id/usb-x".into(),
        dev: (8, 16),
    };
    let lines = selection_lines(
        &dev,
        &source,
        &crate::models::config::AcquisitionConfig::ewf("/cases/x"),
        "c_ea01_e_SER_IAL",
    )
    .join("\n");
    assert!(!lines.contains('\x1b'), "{lines}");
    assert!(lines.contains("serial SER IAL"), "{lines}");
    assert!(
        lines.contains("given as    : /dev/disk/by-id/usb-x"),
        "{lines}"
    );
    assert!(lines.contains("major:minor : 8:16"), "{lines}");
    assert!(lines.contains("1073741824 bytes (1 GiB)"), "{lines}");
}

#[tokio::test]
async fn a_panic_exits_1_not_101() {
    // T6: the documented internal-error code, with the result of a run that
    // did not panic passed through unchanged
    assert_eq!(super::exit_code_or_internal_error(async { 7 }).await, 7);
    let code = super::exit_code_or_internal_error(async {
        if std::hint::black_box(true) {
            panic!("injected for the test");
        }
        0
    })
    .await;
    assert_eq!(code, crate::models::outcome::exit_code::INTERNAL_ERROR);
    let code = super::exit_code_or_internal_error(async {
        let v: Vec<u8> = Vec::new();
        i32::from(v[std::hint::black_box(3)])
    })
    .await;
    assert_eq!(code, 1);
}

#[test]
fn argument_errors_are_json_when_the_command_line_asks_for_json() {
    // I-J1: the parser failed, so the command line is read without it
    use clap::Parser;
    let argv = |a: &[&str]| -> Vec<std::ffi::OsString> {
        std::iter::once("dfdisk")
            .chain(a.iter().copied())
            .map(Into::into)
            .collect()
    };
    for (args, json) in [
        (&["verify", "x.raw", "--md5", "xyz", "--json"][..], true),
        (&["convert", "--json", "--bogus"][..], true),
        (&["list", "-j", "--bogus"][..], true),
        (&["list", "-sj"][..], true),
        (&["verify", "x.raw", "--md5", "xyz"][..], false),
        // -j is list's short flag only; after "--" nothing is an option
        (&["acquire", "-j"][..], false),
        (&["verify", "--bogus", "--", "--json"][..], false),
    ] {
        let a = argv(args);
        assert_eq!(super::wants_json(&a), json, "{args:?}");
        let err = Cli::try_parse_from(&a).map(|_| ()).unwrap_err();
        let doc = super::usage_error_document(&a, &err.render().to_string());
        assert_eq!(doc.is_some(), json, "{args:?}");
        if let Some(doc) = doc {
            let v: serde_json::Value = serde_json::from_str(&doc).unwrap();
            assert_eq!(v["schema_version"], 1);
            assert_eq!(v["error"]["kind"], "usage");
            assert_eq!(v["error"]["exit_code"], 2);
            let m = v["error"]["message"].as_str().unwrap();
            assert!(!m.starts_with("error:") && !m.contains('\n'), "{m}");
        }
    }
}
