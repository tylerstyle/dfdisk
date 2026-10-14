//! Rescue engine (§13 Rescue): GNU ddrescue copies what it can read into
//! `<base>.raw` and records every area in `<base>.map`; dfdisk hashes the
//! image afterwards.
//!
//! RESCUE AGENT: this is the 0.1 engine adapted to the session interface;
//! map parsing into exact ranges, the identity sidecar and resume sessions,
//! the process runner with graceful abort, and `--rescue-to-e01` (§13) are
//! still to do.

use crate::engines::error::AcquisitionError;
use crate::engines::hasher::{HashProgress, MultiHasher};
use crate::engines::session::{EngineContext, EngineOutput};
use crate::models::{
    info_report::HashResults,
    outcome::{ReadErrorTable, VerificationResult},
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use regex::Regex;
use std::fs;
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

/// Rescue the source into `<base>.raw` with its map `<base>.map` (step 8).
pub async fn acquire(ctx: &EngineContext) -> Result<EngineOutput, AcquisitionError> {
    let config = ctx.config();
    if config.rescue_to_e01 {
        return Err(AcquisitionError::usage(
            "--rescue-to-e01 is not available in this build",
        ));
    }
    let instant_start = Instant::now();
    let expected = ctx.expected_bytes();
    let sector_size = ctx.sector_size();
    let raw_path = ctx.output_path(".raw");
    let map_path = ctx.output_path(".map");

    let mut cmd = Command::new("ddrescue");
    cmd.arg("-d"); // Direct I/O
    cmd.arg("-r").arg(config.error_retries.to_string());
    cmd.arg("-b").arg(sector_size.to_string());
    if config.resume {
        // The map must describe a source of the same size
        cmd.arg("-I");
    }
    cmd.arg(&ctx.tool_source_path);
    cmd.arg(&raw_path);
    cmd.arg(&map_path);
    cmd.env("LC_ALL", "C");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    cmd.kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| AcquisitionError::failed(format!("cannot start ddrescue: {e}")))?;
    let child_pid = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AcquisitionError::failed("cannot capture the output of ddrescue"))?;
    let mut reader = BufReader::new(stdout).lines();

    let mut telemetry = ProgressTelemetry {
        status: AcquisitionStatus::Acquiring,
        total_bytes: expected,
        current_segment: format!("{}.raw", ctx.base_name),
        status_message: "Starting resilient ddrescue acquisition...".to_string(),
        ..Default::default()
    };

    let mut bad_sectors = 0u64;
    let regex_pct = Regex::new(r"pct rescued:\s*(\d+(?:\.\d+)?)%").unwrap();
    let regex_bad_size =
        Regex::new(r"(?:bad-sector|errsize):\s*(\d+(?:\.\d+)?)\s*([kKMGT]?i?B)").unwrap();
    let regex_speed =
        Regex::new(r"(?:current rate|average rate):\s*(\d+(?:\.\d+)?)\s*([kKMGT]?i?B/s)").unwrap();
    let regex_read_errors = Regex::new(r"read errors:\s*(\d+)").unwrap();
    let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
    let mut last_read_bytes = 0u64;
    let mut last_poll_time = Instant::now();

    loop {
        if ctx.abort.load(Ordering::SeqCst) {
            let _ = child.kill().await;
            telemetry.push_log("Rescue aborted by the examiner.");
            ctx.progress.send(telemetry.take_update());
            return Err(AcquisitionError::aborted(
                "the rescue was aborted by the examiner",
            ));
        }
        tokio::select! {
            _ = poll_interval.tick() => {
                if let Some(rchar) = child_pid.and_then(read_proc_rchar) {
                    let total = expected.max(1);
                    let processed = rchar.min(total);
                    telemetry.bytes_processed = processed;
                    telemetry.percentage = (processed as f64 / total as f64) * 100.0;
                    let dt = last_poll_time.elapsed().as_secs_f64();
                    if dt >= 0.1 {
                        telemetry.speed_bps = processed.saturating_sub(last_read_bytes) as f64 / dt;
                        last_read_bytes = processed;
                        last_poll_time = Instant::now();
                    }
                    let elapsed = instant_start.elapsed().as_secs_f64();
                    telemetry.elapsed_secs = elapsed as u64;
                    if elapsed > 0.0 {
                        telemetry.avg_speed_bps = processed as f64 / elapsed;
                    }
                    if telemetry.avg_speed_bps > 0.0 && total > processed {
                        telemetry.eta_secs = Some(((total - processed) as f64 / telemetry.avg_speed_bps) as u64);
                    }
                    ctx.progress.send(telemetry.take_update());
                }
            }
            line_res = reader.next_line() => {
                match line_res {
                    Ok(Some(line)) => {
                        let text = line.trim();
                        if !text.is_empty() {
                            if let Some(caps) = regex_pct.captures(text) {
                                if let Ok(pct) = caps[1].parse::<f64>() {
                                    telemetry.percentage = pct;
                                }
                            }
                            if let Some(caps) = regex_speed.captures(text) {
                                let val = caps[1].parse::<f64>().unwrap_or(0.0);
                                let mult = match &caps[2] {
                                    "kB/s" | "KB/s" => 1_000.0,
                                    "MB/s" | "mB/s" => 1_000_000.0,
                                    "GB/s" => 1_000_000_000.0,
                                    "KiB/s" => 1024.0,
                                    "MiB/s" => 1024.0 * 1024.0,
                                    "GiB/s" => 1024.0 * 1024.0 * 1024.0,
                                    _ => 1.0,
                                };
                                telemetry.speed_bps = val * mult;
                            }
                            if let Some(caps) = regex_bad_size.captures(text) {
                                if let Ok(val) = caps[1].parse::<f64>() {
                                    let bad_bytes = parse_size_to_bytes(val, &caps[2]);
                                    bad_sectors = bad_bytes.div_ceil(u64::from(sector_size));
                                    telemetry.bad_sectors = bad_sectors;
                                }
                            }
                            if let Some(caps) = regex_read_errors.captures(text) {
                                if let Ok(err_count) = caps[1].parse::<u64>() {
                                    if bad_sectors == 0 && err_count > 0 {
                                        bad_sectors = err_count;
                                        telemetry.bad_sectors = bad_sectors;
                                    }
                                }
                            }
                            telemetry.status_message = text.to_string();
                            ctx.progress.send(telemetry.take_update());
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|e| AcquisitionError::failed(format!("cannot wait for ddrescue: {e}")))?;
    if !status.success() {
        return Err(AcquisitionError::failed(format!(
            "ddrescue failed with exit code {:?}",
            status.code()
        )));
    }

    let image_len = fs::metadata(&raw_path).map(|m| m.len()).unwrap_or(0);
    let (bytes_acquired, stop_reason) = rescue_extent(bad_sectors, image_len, expected);
    Ok(EngineOutput {
        bytes_acquired,
        expected_bytes: expected,
        read_errors: ReadErrorTable::new(
            sector_size,
            "ddrescue screen output (map not parsed by this engine version)",
        ),
        stop_reason,
        image_files: vec![raw_path],
        auxiliary_files: vec![map_path],
        ..Default::default()
    })
}

/// Hash the rescued image (step 11, after the session's flush and cache
/// eviction). ddrescue computes no digest while reading, so there is nothing
/// to compare with; `--verify-source` can verify it.
pub async fn verify(ctx: &EngineContext, out: &EngineOutput) -> (VerificationResult, HashResults) {
    let Some(image) = out.image_files.first().cloned() else {
        return (
            VerificationResult::Failed {
                reason: "ddrescue produced no image".into(),
            },
            HashResults::default(),
        );
    };
    let selection = ctx.selection;
    let abort = ctx.abort.clone();
    let (tx, mut rx) = mpsc::channel::<HashProgress>(50);
    let task = tokio::spawn(async move {
        MultiHasher::hash_stream_with_abort(
            &image,
            selection.md5,
            selection.sha1,
            selection.sha256,
            Some(tx),
            Some(abort),
        )
        .await
    });
    while let Some(hp) = rx.recv().await {
        ctx.progress
            .phase_progress(hp.bytes_hashed, hp.total_bytes, hp.speed_bps);
    }
    match task.await {
        Ok(Ok(hashes)) => (
            VerificationResult::NotPossible {
                reason: "ddrescue computes no digest while reading and the source was not read a second time".into(),
            },
            hashes,
        ),
        Ok(Err(e)) => (VerificationResult::Failed { reason: e }, HashResults::default()),
        Err(e) => (
            VerificationResult::Failed {
                reason: format!("the hashing task failed: {e}"),
            },
            HashResults::default(),
        ),
    }
}

/// Bytes this engine version can claim for a rescue, and why it is not the
/// whole source: it reads unreadable sectors from ddrescue's screen output,
/// not their ranges from the map, so any reported bad sector makes the
/// acquisition count as incomplete rather than as complete.
pub fn rescue_extent(bad_sectors: u64, image_len: u64, expected: u64) -> (u64, Option<String>) {
    let acquired = image_len.min(expected);
    let stop = if bad_sectors > 0 {
        Some(format!(
            "ddrescue reported {bad_sectors} unreadable sectors; this engine version does not read their ranges from the map file"
        ))
    } else if acquired < expected {
        Some(format!("the image holds {acquired} of {expected} bytes"))
    } else {
        None
    };
    (acquired, stop)
}

pub fn parse_size_to_bytes(val: f64, unit: &str) -> u64 {
    let mult: f64 = match unit {
        "B" | "b" => 1.0,
        "kB" | "KB" => 1_000.0,
        "MB" => 1_000_000.0,
        "GB" => 1_000_000_000.0,
        "TB" => 1_000_000_000_000.0,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (val * mult) as u64
}

pub(crate) fn parse_rchar(content: &str) -> Option<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("rchar:") {
            if let Ok(bytes) = rest.trim().parse::<u64>() {
                return Some(bytes);
            }
        }
    }
    None
}

fn read_proc_rchar(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/io", pid);
    let content = fs::read_to_string(path).ok()?;
    parse_rchar(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rchar() {
        let sample_io = "rchar: 104857600\nwchar: 52428800\nsyscr: 100\nsyscw: 50\n";
        assert_eq!(parse_rchar(sample_io), Some(104857600));

        let invalid_io = "wchar: 1000\nsyscr: 20\n";
        assert_eq!(parse_rchar(invalid_io), None);
    }

    #[test]
    fn rescue_never_claims_more_than_it_knows() {
        // Clean and full length: complete, but without a source digest
        assert_eq!(rescue_extent(0, 1000, 1000), (1000, None));
        // Bad sectors without ranges: not complete
        let (n, stop) = rescue_extent(5, 1000, 1000);
        assert_eq!(n, 1000);
        assert!(stop.unwrap().contains("5 unreadable sectors"));
        // Short image
        let (n, stop) = rescue_extent(0, 600, 1000);
        assert_eq!(n, 600);
        assert!(stop.unwrap().contains("600 of 1000 bytes"));
    }

    #[test]
    fn test_rescue_report_hash_truthfulness() {
        use crate::models::{
            case::CaseMetadata,
            config::{AcquisitionConfig, EffectiveConfig, EngineKind},
            device::BlockDevice,
            identity::SourceIdentity,
            info_report::{ForensicInfoReport, HashResults},
            outcome::Outcome,
        };
        let device = BlockDevice {
            name: "sdc".to_string(),
            path: "/dev/dfdisk-test-sdc".to_string(),
            size_bytes: 1000,
            logical_sector_size: 512,
            physical_sector_size: 512,
            ..Default::default()
        };
        let config = AcquisitionConfig {
            rescue_mode: true,
            ..Default::default()
        };
        let source = SourceIdentity::from_block_device(&device);
        let mut report = ForensicInfoReport::new(
            EngineKind::Rescue,
            &CaseMetadata::default(),
            source.clone(),
            EffectiveConfig::build(&config, Some(&source)),
        );
        report.bytes_acquired = 1000;
        report.image_hashes = HashResults {
            md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
            sha1: None,
            sha256: None,
        };
        report.verification.result = VerificationResult::NotPossible {
            reason: "ddrescue computes no digest".into(),
        };
        report.apply_classification();

        // No acquisition digest is invented; the verdict says unverified
        assert!(report.acquisition_hashes.is_empty());
        assert_eq!(report.outcome, Outcome::CompleteUnverified);
        assert_eq!(report.exit_code, 9);
        let text = report.render_text();
        assert!(text.contains("COMPLETE, NOT VERIFIED"), "{text}");
        assert!(text.contains("--verify-source"), "{text}");
        assert!(!text.contains("ALL HASHES MATCH"));

        let (_, stop) = rescue_extent(5, 1000, 1000);
        report.stop_reason = stop;
        report.apply_classification();
        assert_eq!(report.outcome, Outcome::Incomplete);
    }

    #[test]
    fn test_parse_size_to_bytes_units() {
        assert_eq!(parse_size_to_bytes(512.0, "B"), 512);
        assert_eq!(parse_size_to_bytes(10.0, "kB"), 10_000);
        assert_eq!(parse_size_to_bytes(10.0, "KB"), 10_000);
        assert_eq!(parse_size_to_bytes(4.0, "KiB"), 4096);
        assert_eq!(parse_size_to_bytes(2.0, "MB"), 2_000_000);
        assert_eq!(parse_size_to_bytes(1.0, "MiB"), 1_048_576);
        assert_eq!(parse_size_to_bytes(1.0, "GiB"), 1_073_741_824);
    }
}
