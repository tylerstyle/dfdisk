//! `dfdisk list`, `unmount`, `verify` and `convert` (§15). `acquire` and
//! `check` live in [`crate::cli::acquire`].

use crate::cli::acquire::{compression_of, error_json, more_severe, split_of};
use crate::cli::args::{CliImageFormat, ConvertArgs, ListArgs, UnmountArgs, VerifyArgs};
use crate::cli::console::{progress_line, Console, ProgressPrinter};
use crate::cli::drive::{drive, next_signal, report_signal, with_signals, Activity};
use crate::cli::resolve::{resolve_argument, ResolvedSource};
use crate::discovery::{identity, safety, smart, DeviceScanner};
use crate::engines::converter;
use crate::engines::pieces::{self, PiecesReport};
use crate::engines::process::StopControl;
use crate::engines::verify::{self, CheckStatus, ExpectedHashes, VerifyEvent, VerifyOptions};
use crate::engines::{AcquisitionError, ErrorKind};
use crate::models::case::CaseMetadata;
use crate::models::config::SmartPolicy;
use crate::models::conversion::{ConversionRequest, ConversionTarget};
use crate::models::device::BlockDevice;
use crate::models::identity::{SourceIdentity, SourceKind};
use crate::models::info_report::INFO_JSON_SUFFIX;
use crate::models::outcome::{exit_code, Outcome, VerificationResult};
use crate::models::telemetry::{AcquisitionStatus, PhaseProgress, ProgressTelemetry};
use crate::models::text::{format_iec, sanitize_line};
use crate::signals::{AbortController, SignalListener};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// `dfdisk list [--json] [--smart]`.
pub async fn handle_list(args: ListArgs, console: &Console) -> Result<i32, AcquisitionError> {
    let mut devices = tokio::task::spawn_blocking(DeviceScanner::scan_devices)
        .await
        .map_err(|e| AcquisitionError::failed(format!("the device scan stopped: {e}")))?
        .map_err(|e| AcquisitionError::failed(format!("cannot list the block devices: {e}")))?;
    if args.smart {
        add_smart(&mut devices).await;
    }
    if console.json() {
        console.data(
            &serde_json::to_string_pretty(&devices)
                .map_err(|e| AcquisitionError::failed(e.to_string()))?,
        );
    } else {
        console.data(&device_table(&devices, args.smart));
    }
    Ok(exit_code::VERIFIED)
}

/// SMART summary of every whole disk (on request only: §8 keeps SMART out of
/// scans). Inaccessible SMART stays UNKNOWN.
async fn add_smart(devices: &mut [BlockDevice]) {
    let control = StopControl::none();
    let jobs = devices
        .iter()
        .enumerate()
        .filter(|(_, d)| d.kind == SourceKind::Disk)
        .map(|(i, d)| {
            let id = SourceIdentity::from_block_device(d);
            let control = &control;
            async move {
                (
                    i,
                    smart::snapshot(&id, SmartPolicy::Basic, None, control, None).await,
                )
            }
        })
        .collect::<Vec<_>>();
    for (i, snap) in futures::future::join_all(jobs).await {
        if let Some(s) = snap {
            devices[i].smart = Some(s.summary);
        }
    }
}

/// The state badges of a device: SYSTEM or MOUNTED, PROTECTED, RO, IN-USE.
pub fn badges(dev: &BlockDevice) -> String {
    let mut b: Vec<&str> = Vec::new();
    if dev.safety.is_system() {
        b.push("SYSTEM");
    } else if dev.safety.is_mounted() {
        b.push("MOUNTED");
    }
    if dev.protected.is_some() {
        b.push("PROTECTED");
    }
    if dev.is_read_only {
        b.push("RO");
    }
    if !dev.holders.is_empty() {
        b.push("IN-USE");
    }
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
                "unmounted": result.unmounted,
                "holders": result.holders,
                "audit_record": result.audit_hash,
            }))
            .unwrap_or_default(),
        );
        return Ok(exit_code::VERIFIED);
    }
    if result.unmounted.is_empty() {
        console.data(&format!("[+] Nothing of {device} was mounted"));
    }
    for m in &result.unmounted {
        console.data(&format!("[+] Unmounted {}", sanitize_line(m)));
    }
    if !result.holders.is_empty() {
        console.data(&format!(
            "[!] Devices stacked on {device} stay open (dfdisk does not close them): {}",
            result.holders.join(", ")
        ));
    }
    if let Some(h) = &result.audit_hash {
        console.data(&format!("[+] Audit record: {h}"));
    }
    Ok(exit_code::VERIFIED)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// The files of a RAW image in order: the file itself, or for a numbered
/// segment (`.001`, `.000`) it and every following segment that exists.
/// Starting in the middle of a family is a usage error.
pub fn raw_image_files(image: &Path) -> Result<Vec<PathBuf>, AcquisitionError> {
    let ext = image
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    if ext.len() < 2 || !ext.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(vec![image.to_path_buf()]);
    }
    let width = ext.len();
    let first: u64 = ext.parse().unwrap_or(0);
    let segment = |n: u64| image.with_extension(format!("{n:0width$}"));
    if first > 0 && segment(first - 1).exists() {
        return Err(AcquisitionError::usage(format!(
            "{} is not the first segment of its split image ({} exists); give the first one",
            image.display(),
            segment(first - 1).display()
        )));
    }
    let mut files = Vec::new();
    let mut n = first;
    while segment(n).is_file() {
        files.push(segment(n));
        n += 1;
    }
    if files.is_empty() {
        files.push(image.to_path_buf());
    }
    Ok(files)
}

/// The exit code of a verification and an optional piece check: a mismatch
/// anywhere is 5, a failure 4, a successful comparison 0, and nothing
/// compared at all 9 (decision 1), never 0.
pub fn verify_exit_code(
    hashes: &VerificationResult,
    pieces: Option<&Result<PiecesReport, AcquisitionError>>,
) -> i32 {
    let hash_code = match hashes {
        VerificationResult::Matched { .. } => exit_code::VERIFIED,
        VerificationResult::Mismatched { .. } => exit_code::MISMATCH,
        VerificationResult::Failed { .. } => exit_code::FAILED,
        VerificationResult::NotPossible { .. } => exit_code::UNVERIFIED,
    };
    let Some(pieces) = pieces else {
        return hash_code;
    };
    let piece_code = match pieces {
        Err(e) => e.exit_code(),
        Ok(r) if !r.mismatches.is_empty() => exit_code::MISMATCH,
        Ok(r) if r.all_match() => exit_code::VERIFIED,
        Ok(_) => exit_code::FAILED, // no piece was checked
    };
    if hash_code == exit_code::UNVERIFIED {
        // The pieces were the only comparison
        return piece_code;
    }
    more_severe(hash_code, piece_code)
}

/// The piece check, line by line.
pub fn pieces_summary(r: &Result<PiecesReport, AcquisitionError>) -> Vec<String> {
    match r {
        Err(e) => vec![format!(
            "Pieces: the piece check did not complete ({}): {}",
            e.kind.label(),
            e.message
        )],
        Ok(p) if p.pieces_checked == 0 => vec![format!(
            "Pieces: no piece was checked against {}",
            p.pieces_file.display()
        )],
        Ok(p) if p.mismatches.is_empty() => vec![format!(
            "Pieces: all {} pieces ({} bytes) match {}",
            p.pieces_checked,
            p.bytes_checked,
            p.pieces_file.display()
        )],
        Ok(p) => {
            let mut l = vec![format!(
                "Pieces: {} of {} pieces DIFFER from {}",
                p.mismatches.len(),
                p.pieces_checked,
                p.pieces_file.display()
            )];
            for m in &p.mismatches {
                l.push(format!(
                    "  piece {} at offset {} ({} bytes): expected {}, computed {}",
                    m.index, m.offset, m.length, m.expected_sha256, m.computed_sha256
                ));
            }
            l
        }
    }
}

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

/// `dfdisk verify <image> [--md5 ..] [--report <info.json>] [--pieces <tsv>]`.
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
    let piece_files = match &args.pieces {
        Some(_) if ewf => {
            return Err(AcquisitionError::usage(
                "--pieces applies to RAW images (the pieces describe the RAW byte stream); an EWF image is checked through its digests",
            ))
        }
        Some(tsv) if !tsv.is_file() => {
            return Err(AcquisitionError::usage(format!(
                "pieces file not found: {}",
                tsv.display()
            )))
        }
        Some(_) => Some(raw_image_files(&args.image)?),
        None => None,
    };
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

    let stop = controller.stop_flags();
    let interval = progress_interval(console);
    let mut last = None::<Instant>;
    let verification = with_signals(
        verify::verify_image(
            &args.image,
            &expected,
            &VerifyOptions::recorded(),
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

    let pieces_result = match (&args.pieces, piece_files) {
        (Some(tsv), Some(files)) => {
            Some(check_pieces(files, tsv.clone(), controller, listener, console).await)
        }
        _ => None,
    };
    if let Some(Err(e)) = &pieces_result {
        if e.kind == ErrorKind::Aborted {
            return Err(e.clone());
        }
    }

    let code = more_severe(
        v.exit_code,
        verify_exit_code(&v.result, pieces_result.as_ref()),
    );
    let compared = matches!(v.result, VerificationResult::Matched { .. })
        || matches!(&pieces_result, Some(Ok(p)) if p.all_match());
    let verdict = match code {
        exit_code::VERIFIED if compared => {
            "VERIFICATION RESULT: PASSED (every expected value matches)".to_string()
        }
        exit_code::MISMATCH => "VERIFICATION RESULT: FAILED (HASH MISMATCH)".to_string(),
        exit_code::FAILED => format!(
            "VERIFICATION RESULT: FAILED ({})",
            match &v.result {
                VerificationResult::Failed { reason } => reason.clone(),
                _ => "the piece check did not complete".into(),
            }
        ),
        _ => "VERIFICATION RESULT: NOT VERIFIED (digests computed, nothing to compare against)"
            .to_string(),
    };

    if console.json() {
        let (pieces, pieces_error) = match &pieces_result {
            Some(Ok(p)) => (
                serde_json::to_value(p).unwrap_or_default(),
                serde_json::Value::Null,
            ),
            Some(Err(e)) => (serde_json::Value::Null, error_json(e)["error"].clone()),
            None => (serde_json::Value::Null, serde_json::Value::Null),
        };
        console.data(
            &serde_json::to_string_pretty(&json!({
                "verification": v,
                "pieces": pieces,
                "pieces_error": pieces_error,
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
    if let Some(p) = &pieces_result {
        for line in pieces_summary(p) {
            console.data(&line);
        }
        console.data("  (the piece check is not part of the addendum and audit record above)");
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

/// The piece check on a blocking thread, printing progress and signals.
async fn check_pieces(
    files: Vec<PathBuf>,
    tsv: PathBuf,
    controller: &AbortController,
    listener: &mut Option<SignalListener>,
    console: &Console,
) -> Result<PiecesReport, AcquisitionError> {
    let total: u64 = files
        .iter()
        .filter_map(|f| std::fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();
    console.note(&format!(
        "[*] Checking {} file(s) against {}",
        files.len(),
        tsv.display()
    ));
    let done = Arc::new(AtomicU64::new(0));
    let abort = controller.abort_flag();
    let progress = done.clone();
    let task = tokio::task::spawn_blocking(move || {
        pieces::verify_pieces(&files, &tsv, &abort, |n| {
            progress.store(n, Ordering::Relaxed);
        })
    });
    tokio::pin!(task);
    let mut tick = tokio::time::interval(progress_interval(console));
    tick.tick().await;
    let t0 = Instant::now();
    let result = loop {
        tokio::select! {
            r = &mut task => break r,
            _ = tick.tick() => {
                let n = done.load(Ordering::Relaxed);
                let secs = t0.elapsed().as_secs_f64();
                let speed = if secs > 0.0 { n as f64 / secs } else { 0.0 };
                if let Some(line) = progress_line(&verify_progress(n, total, speed)) {
                    console.progress(&line);
                }
            }
            (kind, action) = next_signal(listener) => {
                report_signal(console, kind, action, Activity::Verification);
            }
        }
    };
    console.end_progress();
    result.map_err(|e| AcquisitionError::failed(format!("the piece check stopped: {e}")))?
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

/// The conversion the flags describe.
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
    Ok(ConversionRequest {
        source: args.source.clone(),
        target,
        output_dir,
        case,
        compression: compression_of(args.compression),
        split_size: split_of(args.split),
        notes: Vec::new(),
        source_report: args.report.clone().or_else(|| report_next_to(&args.source)),
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
    if let Some(r) = &req.source_report {
        console.say(&format!("    source report: {}", r.display()));
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
    console.data(&format!(
        "[{}] {} (exit code {})",
        if report.outcome == Outcome::Verified {
            "+"
        } else {
            "!"
        },
        report.outcome.label(),
        report.exit_code()
    ));
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
    use crate::engines::pieces::PieceMismatch;
    use crate::models::device::{DeviceSafety, Partition};

    #[test]
    fn split_raw_families_are_collected_from_the_first_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let single = tmp.path().join("img.raw");
        assert_eq!(raw_image_files(&single).unwrap(), vec![single.clone()]);
        for n in 1..=3 {
            std::fs::write(tmp.path().join(format!("split.{n:03}")), b"x").unwrap();
        }
        let files = raw_image_files(&tmp.path().join("split.001")).unwrap();
        assert_eq!(files.len(), 3);
        assert!(files[2].ends_with("split.003"));
        let e = raw_image_files(&tmp.path().join("split.002")).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        // A missing first segment is passed on (the checker reports it)
        let missing = tmp.path().join("other.001");
        assert_eq!(raw_image_files(&missing).unwrap(), vec![missing]);
    }

    fn report(checked: u64, mismatches: usize) -> Result<PiecesReport, AcquisitionError> {
        Ok(PiecesReport {
            pieces_file: "x.pieces.tsv".into(),
            pieces_checked: checked,
            bytes_checked: checked << 20,
            mismatches: (0..mismatches as u64)
                .map(|i| PieceMismatch {
                    index: i,
                    offset: i << 20,
                    length: 1 << 20,
                    expected_sha256: "a".into(),
                    computed_sha256: "b".into(),
                })
                .collect(),
        })
    }

    #[test]
    fn verify_exit_codes_never_pass_without_a_comparison() {
        let matched = VerificationResult::Matched { method: "m".into() };
        let nothing = VerificationResult::NotPossible { reason: "r".into() };
        let mismatch = VerificationResult::Mismatched {
            method: "m".into(),
            details: "d".into(),
        };
        let failed = VerificationResult::Failed { reason: "r".into() };
        assert_eq!(verify_exit_code(&matched, None), 0);
        assert_eq!(verify_exit_code(&nothing, None), 9, "decision 1");
        assert_eq!(verify_exit_code(&mismatch, None), 5);
        assert_eq!(verify_exit_code(&failed, None), 4);
        // Pieces as the only comparison
        assert_eq!(verify_exit_code(&nothing, Some(&report(4, 0))), 0);
        assert_eq!(verify_exit_code(&nothing, Some(&report(4, 1))), 5);
        assert_eq!(verify_exit_code(&nothing, Some(&report(0, 0))), 4);
        assert_eq!(
            verify_exit_code(&nothing, Some(&Err(AcquisitionError::failed("x")))),
            4
        );
        // Both
        assert_eq!(verify_exit_code(&matched, Some(&report(4, 0))), 0);
        assert_eq!(verify_exit_code(&matched, Some(&report(4, 2))), 5);
        assert_eq!(verify_exit_code(&mismatch, Some(&report(4, 0))), 5);
        assert_eq!(verify_exit_code(&failed, Some(&report(4, 1))), 5);
        assert_eq!(
            verify_exit_code(&matched, Some(&Err(AcquisitionError::aborted("x")))),
            8
        );
        let lines = pieces_summary(&report(4, 2));
        assert!(lines[0].contains("2 of 4 pieces DIFFER"), "{lines:?}");
        assert_eq!(lines.len(), 3);
        assert!(pieces_summary(&report(4, 0))[0].contains("all 4 pieces"));
        assert!(pieces_summary(&report(0, 0))[0].contains("no piece was checked"));
    }

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
            t.contains("MOUNTED PROTECTED RO IN-USE / not queried"),
            "{t}"
        );
        assert!(t.contains("/dev/sdb1"), "{t}");
        assert!(t.contains("mounted at /media/x"), "{t}");
        assert!(t.contains("protected by the dfnix registry"), "{t}");
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
        assert_eq!(
            req.source_report.as_deref(),
            Some(tmp.path().join("c_ea01_e1_SER.info.json").as_path())
        );
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
    }
}
