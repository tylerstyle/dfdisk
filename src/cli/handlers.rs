//! `dfdisk list`, `unmount`, `verify` and `convert` (§15). `acquire` and
//! `check` live in [`crate::cli::acquire`].

use crate::cli::acquire::{compression_of, split_of};
use crate::cli::args::{CliImageFormat, ConvertArgs, ListArgs, UnmountArgs, VerifyArgs};
use crate::cli::console::{progress_line, Console, ProgressPrinter};
use crate::cli::drive::{drive, with_signals, Activity};
use crate::cli::resolve::{resolve_argument, ResolvedSource};
use crate::discovery::devices::{self, Scan};
use crate::discovery::{identity, safety, smart, DeviceScanner};
use crate::engines::converter;
use crate::engines::verify::{
    self, CheckStatus, ExpectedHashes, ImageVerification, VerifyEvent, VerifyOptions,
};
use crate::engines::AcquisitionError;
use crate::models::case::CaseMetadata;
use crate::models::config::SmartPolicy;
use crate::models::conversion::{ConversionRequest, ConversionTarget};
use crate::models::device::BlockDevice;
use crate::models::identity::SourceKind;
use crate::models::info_report::INFO_JSON_SUFFIX;
use crate::models::outcome::{exit_code, Outcome, VerificationResult};
use crate::models::telemetry::{AcquisitionStatus, PhaseProgress, ProgressTelemetry};
use crate::models::text::{format_iec, sanitize_line};
use crate::signals::{AbortController, SignalListener};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// `dfdisk list [--json] [--smart]`: one lsblk + sysfs scan (nothing is
/// sent to any device); `--json` prints the scan's listing (schema 1,
/// partitions and stacked devices nested in `children`).
pub async fn handle_list(args: ListArgs, console: &Console) -> Result<i32, AcquisitionError> {
    let scan = tokio::task::spawn_blocking(DeviceScanner::scan)
        .await
        .map_err(|e| AcquisitionError::failed(format!("the device scan stopped: {e}")))?
        .map_err(|e| AcquisitionError::failed(format!("cannot list the block devices: {e}")))?;
    if console.json() {
        let mut list = scan.listing();
        if args.smart {
            list.attach_smart(&scan, SmartPolicy::Basic).await;
        }
        console.data(
            &serde_json::to_string_pretty(&list)
                .map_err(|e| AcquisitionError::failed(e.to_string()))?,
        );
        return Ok(exit_code::VERIFIED);
    }
    let mut devices = scan.devices();
    if args.smart {
        add_smart(&scan, &mut devices).await;
    }
    for note in &scan.notes {
        console.note(&format!("[!] {}", sanitize_line(note)));
    }
    console.data(&device_table(&devices, args.smart));
    Ok(exit_code::VERIFIED)
}

/// SMART summary of every whole disk, queried on demand (§8: never part of a
/// scan; `-n standby` does not wake a sleeping disk). Inaccessible SMART
/// stays UNKNOWN.
async fn add_smart(scan: &Scan, devices: &mut [BlockDevice]) {
    let jobs = devices
        .iter()
        .enumerate()
        .filter(|(_, d)| d.kind == SourceKind::Disk)
        .filter_map(|(i, d)| {
            let node = scan.nodes.iter().find(|n| n.device.path == d.path)?;
            let id = node.identity.clone();
            Some(async move { (i, smart::query_on_demand(&id, SmartPolicy::Basic).await) })
        })
        .collect::<Vec<_>>();
    for (i, snap) in futures::future::join_all(jobs).await {
        if let Some(s) = snap {
            devices[i].smart = Some(s.summary);
        }
    }
}

/// The state badges of a device (the scan's: SYSTEM, PROTECTED, MOUNTED,
/// RO, IN-USE), or "-".
pub fn badges(dev: &BlockDevice) -> String {
    let b = devices::badges(dev, None);
    if b.is_empty() {
        "-".into()
    } else {
        b.join(" ")
    }
}

/// A table cell: sanitised, padded to `width`, shortened with "..." when
/// longer.
fn cell(s: &str, width: usize) -> String {
    let clean = sanitize_line(s);
    let n = clean.chars().count();
    if n <= width {
        format!("{clean:<width$}")
    } else if width <= 3 {
        clean.chars().take(width).collect()
    } else {
        let mut t: String = clean.chars().take(width - 3).collect();
        t.push_str("...");
        t
    }
}

/// The human device table: disks with their partitions and stacked devices
/// below them. Serial numbers are never shortened (they identify evidence).
pub fn device_table(devices: &[BlockDevice], with_smart: bool) -> String {
    let mut out = format!(
        "{:<22} {:<16} {:<24} {:<22} {:>10}  {:<9} {}\n",
        "DEVICE",
        "TYPE/BUS",
        "MODEL",
        "SERIAL",
        "SIZE",
        "MAJ:MIN",
        if with_smart { "STATE / SMART" } else { "STATE" }
    );
    for d in devices {
        let mut state = badges(d);
        if with_smart {
            let smart = d
                .smart
                .as_ref()
                .map(|s| s.health.label())
                .unwrap_or("not queried");
            state = format!("{state} / {smart}");
        }
        let serial = sanitize_line(d.serial.as_deref().unwrap_or("(none)"));
        out.push_str(&format!(
            "{} {} {} {:<22} {:>10}  {} {}\n",
            cell(&d.path, 22),
            cell(&d.attachment_str(), 16),
            cell(&d.display_name(), 24),
            serial,
            format_iec(d.size_bytes),
            cell(d.maj_min.as_deref().unwrap_or("?"), 9),
            state
        ));
        if let Some(reason) = &d.protected {
            out.push_str(&format!(
                "    protected by the dfnix registry: {}\n",
                sanitize_line(reason)
            ));
        }
        if let crate::models::device::DeviceSafety::SystemDisk(reasons) = &d.safety {
            if !reasons.is_empty() {
                out.push_str(&format!(
                    "    running system: {}\n",
                    sanitize_line(&reasons.join("; "))
                ));
            }
        }
        for p in &d.partitions {
            let mut state = Vec::new();
            if let Some(m) = &p.mountpoint {
                state.push(format!("mounted at {}", sanitize_line(m)));
            }
            if p.is_read_only {
                state.push("RO".into());
            }
            let fs = [p.fstype.as_deref(), p.label.as_deref()]
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!(
                "  {} {} {} {:>10}  {} {}\n",
                cell(&p.path, 20),
                cell(p.kind.as_deref().unwrap_or("part"), 16),
                cell(&fs, 47),
                format_iec(p.size_bytes),
                cell(p.maj_min.as_deref().unwrap_or("?"), 9),
                if state.is_empty() {
                    "-".to_string()
                } else {
                    state.join(", ")
                }
            ));
        }
    }
    out.push_str(
        "\nAcquire with: dfdisk acquire <DEVICE> -o <DIR> --case <CASE> --evidence <EVIDENCE> --examiner <NAME>\n",
    );
    out
}

// ---------------------------------------------------------------------------
// unmount
// ---------------------------------------------------------------------------

/// `dfdisk unmount <device>`: the audited unmount of the source tree (§10).
pub async fn handle_unmount(args: UnmountArgs, console: &Console) -> Result<i32, AcquisitionError> {
    let source = resolve_argument(&args.device)?;
    let path = match &source {
        ResolvedSource::Block { path, .. } => path.to_string_lossy().into_owned(),
        ResolvedSource::File { path, .. } => {
            return Err(AcquisitionError::usage(format!(
                "{} is a regular file; unmount works on block devices",
                path.display()
            )))
        }
    };
    let probe_path = path.clone();
    let id = tokio::task::spawn_blocking(move || identity::probe(&probe_path))
        .await
        .map_err(|e| AcquisitionError::failed(format!("the device probe stopped: {e}")))?
        .map_err(|e| {
            AcquisitionError::refused(format!("{path} cannot be identified; refusing: {e}"))
        })?;
    let device = id.path.clone();
    let result = tokio::task::spawn_blocking(move || safety::unmount_source_tree(&id))
        .await
        .map_err(|e| AcquisitionError::failed(format!("the unmount stopped: {e}")))??;
    if console.json() {
        console.data(
            &serde_json::to_string_pretty(&json!({
                "device": device,
                "mounts_before": result.mounts_before,
                "unmounted": result.unmounted,
                "holders": result.holders,
                "audit_record": result.audit_hash,
                "audit_error": result.audit_error,
                "notes": result.notes,
            }))
            .unwrap_or_default(),
        );
        for n in &result.notes {
            console.note(&format!("[!] {}", sanitize_line(n)));
        }
        return Ok(exit_code::VERIFIED);
    }
    if result.unmounted.is_empty() {
        console.data(&format!("[+] Nothing of {device} was mounted"));
    }
    for m in &result.unmounted {
        console.data(&format!("[+] Unmounted {}", sanitize_line(m)));
    }
    // The notes name the holders left open (dfdisk does not close them)
    for n in &result.notes {
        console.data(&format!("[!] {}", sanitize_line(n)));
    }
    match (&result.audit_hash, &result.audit_error) {
        (Some(h), _) => console.data(&format!("[+] Audit record: {h}")),
        (None, Some(e)) => console.data(&format!(
            "[!] The unmount was NOT recorded in the audit log: {}",
            sanitize_line(e)
        )),
        (None, None) => {}
    }
    Ok(exit_code::VERIFIED)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn progress_interval(console: &Console) -> Duration {
    if console.progress_redraws() {
        Duration::from_millis(250)
    } else {
        Duration::from_secs(30)
    }
}

fn verify_progress(done: u64, total: u64, speed: f64) -> ProgressTelemetry {
    ProgressTelemetry {
        status: AcquisitionStatus::Verifying,
        verify_progress: Some(PhaseProgress {
            bytes_done: done,
            total_bytes: total,
            percentage: if total > 0 {
                done as f64 * 100.0 / total as f64
            } else {
                0.0
            },
            speed_bps: speed,
        }),
        ..Default::default()
    }
}

/// The last line of `dfdisk verify`: PASSED only when something was
/// compared and everything matched (exit 0); nothing compared is exit 9
/// (decision 1), never a pass.
pub fn verify_verdict(v: &ImageVerification) -> String {
    match &v.result {
        VerificationResult::Matched { .. } if v.exit_code == exit_code::VERIFIED => {
            "VERIFICATION RESULT: PASSED (every expected value matches)".to_string()
        }
        VerificationResult::Mismatched { .. } => {
            "VERIFICATION RESULT: FAILED (HASH MISMATCH)".to_string()
        }
        VerificationResult::Failed { reason } => format!("VERIFICATION RESULT: FAILED ({reason})"),
        _ => "VERIFICATION RESULT: NOT VERIFIED (digests computed, nothing to compare against)"
            .to_string(),
    }
}

/// `dfdisk verify <image> [--md5 ..] [--report <info.json>] [--pieces <tsv>]`.
/// One verification ([`verify::verify_image`]) covers the digests and the
/// pieces file: both are in its verdict, its exit code, the addendum and the
/// audit record.
pub async fn handle_verify(
    args: VerifyArgs,
    controller: &AbortController,
    listener: &mut Option<SignalListener>,
    console: &Console,
) -> Result<i32, AcquisitionError> {
    let expected = match &args.report {
        Some(report) => ExpectedHashes::from_report_json(report)?,
        None => ExpectedHashes::given(args.md5.clone(), args.sha1.clone(), args.sha256.clone()),
    };
    let ewf = verify::is_ewf_image_file(&args.image);
    console.say(&format!(
        "[*] Verifying {} ({})",
        args.image.display(),
        if ewf {
            "EWF, re-read by ewfverify"
        } else {
            "hashed by dfdisk"
        }
    ));
    if !expected.is_empty() {
        console.say(&format!("    expected digests from {}", expected.source));
    }
    let mut options = VerifyOptions::recorded();
    if let Some(tsv) = &args.pieces {
        console.say(&format!("    pieces file {}", tsv.display()));
        options = options.with_pieces(tsv.clone());
    }

    let stop = controller.stop_flags();
    let interval = progress_interval(console);
    let mut last = None::<Instant>;
    let verification = with_signals(
        verify::verify_image(
            &args.image,
            &expected,
            &options,
            &stop,
            |event| match event {
                VerifyEvent::Progress(p) => {
                    if last.is_none_or(|l| l.elapsed() >= interval) {
                        last = Some(Instant::now());
                        if let Some(line) = progress_line(&verify_progress(
                            p.bytes_hashed,
                            p.total_bytes,
                            p.speed_bps,
                        )) {
                            console.progress(&line);
                        }
                    }
                }
                VerifyEvent::ToolOutput(line) => console.note(&format!("[ewfverify] {line}")),
            },
        ),
        listener,
        console,
        Activity::Verification,
    )
    .await;
    console.end_progress();
    let v = verification?;
    let code = v.exit_code;
    let verdict = verify_verdict(&v);

    if console.json() {
        console.data(
            &serde_json::to_string_pretty(&json!({
                "verification": v,
                "exit_code": code,
            }))
            .unwrap_or_default(),
        );
        console.note(&verdict);
        return Ok(code);
    }
    console.data(&v.render_text());
    for c in &v.checks {
        let line = match c.status {
            CheckStatus::Match => format!("  [+] {} MATCH", c.algorithm.label()),
            CheckStatus::Mismatch => format!(
                "  [!] {} MISMATCH! Expected: {}",
                c.algorithm.label(),
                c.expected
            ),
            CheckStatus::NotComputed => format!(
                "  [!] {} NOT COMPUTED! Expected: {}",
                c.algorithm.label(),
                c.expected
            ),
        };
        console.data(&line);
    }
    if let Some(p) = &v.pieces {
        let mark = if p.all_match() { "+" } else { "!" };
        console.data(&format!("  [{mark}] Pieces: {}", p.details(20)));
    }
    for w in &v.warnings {
        console.note(&format!("[!] WARNING: {w}"));
    }
    if let Some(a) = &v.addendum {
        console.data(&format!("[+] Verification addendum: {}", a.display()));
    }
    console.data(&format!("\n{verdict}\nExit code: {code}"));
    Ok(code)
}

// ---------------------------------------------------------------------------
// convert
// ---------------------------------------------------------------------------

/// `<base>.info.json` next to an image `<base>.<ext>` (`.raw`, `.001`,
/// `.E01`), if it exists.
pub fn report_next_to(image: &Path) -> Option<PathBuf> {
    let stem = image.file_stem()?.to_string_lossy().into_owned();
    let candidate = image.with_file_name(format!("{stem}{INFO_JSON_SUFFIX}"));
    candidate.is_file().then_some(candidate)
}

/// The conversion the flags describe. Only an explicit `--report` becomes
/// the request's `source_report` (and must list the source image); a report
/// next to the source is found by the converter itself, which uses it when
/// it lists the image and otherwise ignores it with a note (C-5: the
/// `<base>.info.json` of a rescue lists `<base>.raw`, not the `<base>.E01`
/// made from it).
pub fn conversion_request(args: &ConvertArgs) -> Result<ConversionRequest, AcquisitionError> {
    let target = match args.to {
        CliImageFormat::E01 => ConversionTarget::E01,
        CliImageFormat::Raw => ConversionTarget::Raw,
    };
    if target == ConversionTarget::Raw && (args.compression.is_some() || args.split.is_some()) {
        return Err(AcquisitionError::usage(
            "--compression and --split apply to an E01 target only",
        ));
    }
    let c = &args.case;
    let case = c.any().then(|| {
        let opt = |v: &Option<String>| v.clone().unwrap_or_default();
        CaseMetadata {
            case_number: opt(&c.case),
            location_ea: opt(&c.ea),
            evidence_number: opt(&c.evidence),
            authority: opt(&c.authority),
            examiner: opt(&c.examiner),
            description: opt(&c.description),
            notes: opt(&c.notes),
            seal_number: opt(&c.seal),
            seizure_time: opt(&c.seized_at),
            seizure_location: opt(&c.seized_location),
        }
    });
    let output_dir = std::path::absolute(&args.output_dir).map_err(|e| {
        AcquisitionError::usage(format!(
            "invalid output directory {}: {e}",
            args.output_dir.display()
        ))
    })?;
    if let Some(r) = &args.report {
        if !r.is_file() {
            return Err(AcquisitionError::usage(format!(
                "report not found: {}",
                r.display()
            )));
        }
    }
    if target == ConversionTarget::Raw && args.allow_low_space {
        return Err(AcquisitionError::usage(
            "--allow-low-space applies to an E01 target only (a RAW output needs the full size)",
        ));
    }
    Ok(ConversionRequest {
        case,
        compression: compression_of(args.compression),
        split_size: split_of(args.split),
        source_report: args.report.clone(),
        allow_tmpfs: args.allow_tmpfs,
        allow_low_space: args.allow_low_space,
        ..ConversionRequest::new(args.source.clone(), target, output_dir)
    })
}

/// `dfdisk convert <source> --to e01|raw -o <dir>`.
pub async fn handle_convert(
    args: ConvertArgs,
    controller: &AbortController,
    listener: &mut Option<SignalListener>,
    console: &Console,
) -> Result<i32, AcquisitionError> {
    let req = conversion_request(&args)?;
    console.say(&format!(
        "[*] Converting {} to {} in {}",
        req.source.display(),
        match req.target {
            ConversionTarget::E01 => "E01",
            ConversionTarget::Raw => "RAW",
        },
        req.output_dir.display()
    ));
    match &req.source_report {
        Some(r) => console.say(&format!("    source report: {}", r.display())),
        None => {
            if let Some(r) = report_next_to(&req.source) {
                console.say(&format!(
                    "    source report: {} (used if it lists the source image)",
                    r.display()
                ));
            }
        }
    }
    let (tx, rx) = mpsc::channel(256);
    let mut printer = ProgressPrinter::new(console, false);
    let report = drive(
        converter::convert(req, tx, controller.stop_flags()),
        rx,
        listener,
        console,
        &mut printer,
        Activity::Conversion,
    )
    .await?;
    if console.json() {
        console.data(&serde_json::to_string_pretty(&report).map_err(|e| {
            AcquisitionError::failed(format!("cannot serialise the conversion report: {e}"))
        })?);
        return Ok(report.exit_code());
    }
    if let Ok(text) = std::fs::read_to_string(&report.report_file) {
        console.data(&text);
    }
    let mark = if report.outcome == Outcome::Verified {
        "+"
    } else {
        "!"
    };
    for line in report.verdict_lines() {
        console.data(&format!("[{mark}] {line}"));
    }
    for f in &report.output_files {
        console.data(&format!("    image  : {}", f.display()));
    }
    console.data(&format!("    report : {}", report.report_file.display()));
    console.data(&format!(
        "             {}",
        report.report_json_file.display()
    ));
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::device::{DeviceSafety, Partition};

    #[test]
    fn device_table_shows_full_serials_partitions_and_badges() {
        let devices = vec![BlockDevice {
            name: "sdb".into(),
            path: "/dev/sdb".into(),
            model: Some("Very Long Model Name Of A USB Bridge Disk".into()),
            serial: Some("WD-WCC4E1234567890ABCDEFGH".into()),
            size_bytes: 1 << 30,
            maj_min: Some("8:16".into()),
            transport: Some("usb".into()),
            hotplug: true,
            safety: DeviceSafety::Mounted(vec!["/media/x".into()]),
            mountpoints: vec!["/media/x".into()],
            protected: Some("dfnix boot medium".into()),
            is_read_only: true,
            holders: vec!["dm-0".into()],
            partitions: vec![Partition {
                name: "sdb1".into(),
                path: "/dev/sdb1".into(),
                size_bytes: 1 << 29,
                fstype: Some("ext4".into()),
                mountpoint: Some("/media/x".into()),
                maj_min: Some("8:17".into()),
                kind: Some("part".into()),
                ..Default::default()
            }],
            ..Default::default()
        }];
        let t = device_table(&devices, true);
        assert!(t.contains("WD-WCC4E1234567890ABCDEFGH"), "{t}");
        assert!(
            t.contains("PROTECTED MOUNTED RO IN-USE / not queried"),
            "{t}"
        );
        assert!(t.contains("/dev/sdb1"), "{t}");
        assert!(t.contains("mounted at /media/x"), "{t}");
        assert!(t.contains("protected by the dfnix registry"), "{t}");
        let system = BlockDevice {
            safety: DeviceSafety::SystemDisk(vec!["/dev/sda2 mounted at /".into()]),
            ..devices[0].clone()
        };
        let t2 = device_table(&[system], false);
        assert!(
            t2.contains("running system: /dev/sda2 mounted at /"),
            "{t2}"
        );
        assert!(t.contains("1 GiB"), "{t}");
        assert_eq!(badges(&BlockDevice::default()), "-");
    }

    #[test]
    fn conversion_requests_from_flags() {
        use crate::cli::args::{Cli, Commands};
        use clap::Parser;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("c_ea01_e1_SER.raw");
        std::fs::write(&src, vec![0u8; 512]).unwrap();
        std::fs::write(tmp.path().join("c_ea01_e1_SER.info.json"), b"{}").unwrap();
        let parse = |extra: &[&str]| {
            let mut argv = vec![
                "dfdisk".to_string(),
                "convert".into(),
                src.to_string_lossy().into_owned(),
                "-o".into(),
                "out".into(),
            ];
            argv.extend(extra.iter().map(|s| s.to_string()));
            match Cli::try_parse_from(argv).unwrap().command {
                Some(Commands::Convert(a)) => a,
                other => panic!("{other:?}"),
            }
        };
        let req = conversion_request(&parse(&["--to", "e01"])).unwrap();
        assert_eq!(req.target, ConversionTarget::E01);
        assert!(
            req.case.is_none(),
            "case fields come from the source report"
        );
        assert!(req.output_dir.is_absolute());
        // C-5: a report next to the source is not "given": the converter
        // finds it and ignores it with a note when it does not list the
        // image; only --report is strict
        assert!(req.source_report.is_none(), "{:?}", req.source_report);
        assert_eq!(
            report_next_to(&src).as_deref(),
            Some(tmp.path().join("c_ea01_e1_SER.info.json").as_path())
        );
        let given = tmp.path().join("c_ea01_e1_SER.info.json");
        let req = conversion_request(&parse(&[
            "--to",
            "e01",
            "--report",
            given.to_str().unwrap(),
        ]))
        .unwrap();
        assert_eq!(req.source_report.as_deref(), Some(given.as_path()));
        let req = conversion_request(&parse(&[
            "--to", "e01", "-C", "K1", "-E", "E2", "-e", "Exa", "--split", "none",
        ]))
        .unwrap();
        let case = req.case.unwrap();
        assert_eq!(
            (
                case.case_number.as_str(),
                case.evidence_number.as_str(),
                case.examiner.as_str()
            ),
            ("K1", "E2", "Exa")
        );
        assert_eq!(case.authority, "", "nothing is filled in");
        assert_eq!(req.split_size, crate::models::config::SplitSize::None);
        let e = conversion_request(&parse(&["--to", "raw", "--compression", "best"])).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        let e = conversion_request(&parse(&["--to", "e01", "--report", "/nonexistent.json"]))
            .unwrap_err();
        assert_eq!(e.exit_code(), 2);
        // The destination allowances reach the converter
        let req = conversion_request(&parse(&[
            "--to",
            "e01",
            "--allow-tmpfs",
            "--allow-low-space",
        ]))
        .unwrap();
        assert!(req.allow_tmpfs && req.allow_low_space);
        assert!(
            !conversion_request(&parse(&["--to", "e01"]))
                .unwrap()
                .allow_tmpfs
        );
        let e = conversion_request(&parse(&["--to", "raw", "--allow-low-space"])).unwrap_err();
        assert_eq!(e.exit_code(), 2);
    }
}
