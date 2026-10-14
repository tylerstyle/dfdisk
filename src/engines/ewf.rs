use crate::engines::{legacy, preflight};
use crate::models::{
    case::CaseMetadata,
    config::{AcquisitionConfig, EngineKind},
    device::BlockDevice,
    info_report::{
        compare_digests, ForensicInfoReport, HashResults, HashSelection, VerificationInfo,
    },
    outcome::{Outcome, VerificationResult},
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use regex::Regex;
use std::fs;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct EwfAcquireEngine;

impl EwfAcquireEngine {
    pub async fn run_acquisition(
        device: BlockDevice,
        case: CaseMetadata,
        config: AcquisitionConfig,
        progress_tx: mpsc::Sender<ProgressTelemetry>,
        abort_flag: Arc<AtomicBool>,
    ) -> Result<ForensicInfoReport, String> {
        let output_dir = config.output_dir.clone();
        let audit_anchor = crate::engines::audit::started("e01", &device, &config);
        let result = Self::acquire(
            device.clone(),
            case,
            config,
            progress_tx,
            abort_flag,
            audit_anchor,
        )
        .await;
        crate::engines::audit::finished("e01", &device, &output_dir, &result);
        result
    }

    async fn acquire(
        device: BlockDevice,
        case: CaseMetadata,
        config: AcquisitionConfig,
        progress_tx: mpsc::Sender<ProgressTelemetry>,
        abort_flag: Arc<AtomicBool>,
        audit_anchor: Option<String>,
    ) -> Result<ForensicInfoReport, String> {
        let run = legacy::RunClock::start();
        let instant_start = run.instant;

        // Target path without extension (ewfacquire appends .E01 automatically)
        let base_name = case.base_filename_checked(&device.display_serial())?;
        let target_path_without_ext = config.output_dir.join(&base_name);
        let target_str = target_path_without_ext.to_string_lossy().to_string();

        // ewfacquire -u overwrites existing segment files without asking, so
        // collisions are refused here before it is started
        fs::create_dir_all(&config.output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
        preflight::ensure_no_existing_outputs(&config.output_dir, &base_name)?;
        preflight::ensure_not_protected(&device.path)?;
        preflight::ensure_destination_not_on_source(&device.path, &config.output_dir)
            .map_err(|e| e.message)?;

        let selection = ewf_selection(&config);

        let mut cmd = Command::new("ewfacquire");
        cmd.arg("-u"); // Unattended mode (no prompts; overwrite protection is ours)

        // Metadata flags: the same sanitised values the .info records; empty
        // optional fields are omitted, never filled with placeholders
        cmd.arg("-C").arg(case.effective_case().unwrap_or_default());
        cmd.arg("-E")
            .arg(case.effective_evidence().unwrap_or_default());
        cmd.arg("-e")
            .arg(case.effective_examiner().unwrap_or_default());
        if let Some(description) = case.effective_description() {
            cmd.arg("-D").arg(description);
        }
        if let Some(notes) = case.ewf_header_notes() {
            cmd.arg("-N").arg(notes);
        }

        // Format and compression
        cmd.arg("-f").arg("encase6");
        cmd.arg("-c").arg(config.compression.as_ewf_arg());

        // Split size
        cmd.arg("-S").arg(config.split_size.as_ewf_arg());

        // Error handling
        cmd.arg("-r").arg(config.error_retries.to_string());
        if config.wipe_bad_sectors {
            cmd.arg("-w"); // Zero bad sectors
        }

        // All digests are calculated in ewfacquire's single read pass over the
        // source; MD5 is always part of an E01, SHA-1 / SHA-256 on request
        if let Some(extra) = ewf_digest_list(selection, false) {
            cmd.arg("-d").arg(extra);
        }

        // Output and source
        cmd.arg("-t").arg(&target_str);
        cmd.arg(&device.path);

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn ewfacquire (is libewf installed?): {}", e))?;

        let child_pid = child.id();
        let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;
        let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;

        let mut reader_err = BufReader::new(stderr).lines();
        let mut reader_out = BufReader::new(stdout).lines();

        let mut telemetry = ProgressTelemetry {
            status: AcquisitionStatus::Acquiring,
            total_bytes: device.size_bytes,
            current_segment: format!("{}.E01", base_name),
            status_message: "Starting E01 acquisition...".to_string(),
            ..Default::default()
        };

        let mut bad_sectors = 0u64;
        let mut source_hashes = HashResults::default();

        let regex_bad = Regex::new(r"(\d+)\s*bad sector").unwrap();

        // Real-time /proc/pid/io polling interval
        let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
        let mut last_read_bytes = 0u64;
        let mut last_poll_time = Instant::now();

        let target_dir = config.output_dir.clone();
        let base_name_clone = base_name.clone();

        let mut err_closed = false;
        let mut out_closed = false;

        loop {
            if abort_flag.load(Ordering::Relaxed) {
                let _ = child.kill().await;
                telemetry.status = AcquisitionStatus::Aborted;
                telemetry.push_log("Acquisition aborted by examiner.");
                let _ = progress_tx.send(telemetry).await;
                return Err("Acquisition aborted by user.".to_string());
            }

            if err_closed && out_closed {
                break;
            }

            tokio::select! {
                _ = poll_interval.tick() => {
                    if let Some(pid) = child_pid {
                        if let Some(rchar) = read_proc_rchar(pid) {
                            let total = device.size_bytes.max(1);
                            let processed = rchar.min(total);
                            telemetry.bytes_processed = processed;
                            telemetry.percentage = (processed as f64 / total as f64) * 100.0;

                            let dt = last_poll_time.elapsed().as_secs_f64();
                            if dt >= 0.1 {
                                let bytes_diff = processed.saturating_sub(last_read_bytes);
                                telemetry.speed_bps = bytes_diff as f64 / dt;
                                last_read_bytes = processed;
                                last_poll_time = Instant::now();
                            }

                            let elapsed = instant_start.elapsed().as_secs_f64();
                            telemetry.elapsed_secs = elapsed as u64;
                            if elapsed > 0.0 {
                                telemetry.avg_speed_bps = processed as f64 / elapsed;
                            }

                            if telemetry.avg_speed_bps > 0.0 && total > processed {
                                let rem = total - processed;
                                telemetry.eta_secs = Some((rem as f64 / telemetry.avg_speed_bps) as u64);
                            }

                            // Compute compression ratio from output files
                            let written_bytes = calculate_target_bytes(&target_dir, &base_name_clone);
                            if written_bytes > 0 && processed > 0 {
                                telemetry.compression_ratio = Some(processed as f64 / written_bytes as f64);
                            }

                            let _ = progress_tx.send(telemetry.take_update()).await;
                        }
                    }
                }
                line_err = reader_err.next_line(), if !err_closed => {
                    match line_err {
                        Ok(Some(line)) => {
                            let text = line.trim();
                            if !text.is_empty() {
                                if let Some(caps) = regex_bad.captures(text) {
                                    if let Ok(bad) = caps[1].parse::<u64>() {
                                        bad_sectors = bad;
                                        telemetry.bad_sectors = bad;
                                    }
                                }
                                telemetry.push_log(text);
                                let _ = progress_tx.send(telemetry.take_update()).await;
                            }
                        }
                        Ok(None) | Err(_) => {
                            err_closed = true;
                        }
                    }
                }
                line_out = reader_out.next_line(), if !out_closed => {
                    match line_out {
                        Ok(Some(line)) => {
                            let text = line.trim();
                            if !text.is_empty() {
                                telemetry.push_log(text);

                                record_calculated_hash(&mut source_hashes, text);
                            }
                        }
                        Ok(None) | Err(_) => {
                            out_closed = true;
                        }
                    }
                }
            }
        }

        let status = child
            .wait()
            .await
            .map_err(|e| format!("Failed to wait on ewfacquire: {}", e))?;

        if !status.success() {
            telemetry.status = AcquisitionStatus::Failed(format!(
                "ewfacquire exited with code {:?}",
                status.code()
            ));
            let _ = progress_tx.send(telemetry).await;
            return Err(format!(
                "ewfacquire acquisition failed with exit code {:?}",
                status.code()
            ));
        }

        // Identify generated segment files
        let mut generated_files = Vec::new();
        let target_dir = &config.output_dir;
        if let Ok(entries) = std::fs::read_dir(target_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_ewf_segment(&base_name, &name) {
                    generated_files.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
        generated_files.sort();

        if generated_files.is_empty() {
            return Err(
                "No EWF segment files found in output directory after acquisition".to_string(),
            );
        }

        // Post-acquisition independent destination verification pass using ewfverify
        telemetry.status = AcquisitionStatus::Verifying;
        telemetry.percentage = 0.0;
        telemetry.status_message = "Verifying written E01 image via ewfverify...".to_string();
        telemetry
            .push_log("Beginning post-acquisition destination verification pass via ewfverify...");
        let _ = progress_tx.send(telemetry.take_update()).await;

        let first_segment = &generated_files[0];
        let mut v_cmd = Command::new("ewfverify");
        // Recalculate exactly the selected digests over the written image
        if let Some(digests) = ewf_digest_list(selection, true) {
            v_cmd.arg("-d").arg(digests);
        }
        v_cmd.arg(first_segment);
        v_cmd.stdout(Stdio::piped());
        v_cmd.stderr(Stdio::piped());

        let mut v_child = v_cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn ewfverify: {}", e))?;

        let v_stdout = v_child
            .stdout
            .take()
            .ok_or("Failed to capture ewfverify stdout")?;
        let v_stderr = v_child
            .stderr
            .take()
            .ok_or("Failed to capture ewfverify stderr")?;

        let mut v_reader_out = BufReader::new(v_stdout).lines();
        let mut v_reader_err = BufReader::new(v_stderr).lines();

        let mut destination_hashes = HashResults::default();
        let mut ewfverify_success = false;

        let mut v_out_closed = false;
        let mut v_err_closed = false;

        while !v_out_closed || !v_err_closed {
            if abort_flag.load(Ordering::Relaxed) {
                let _ = v_child.kill().await;
                telemetry.status = AcquisitionStatus::Aborted;
                let _ = progress_tx.send(telemetry).await;
                return Err("EWF verification aborted by user.".to_string());
            }

            tokio::select! {
                line = v_reader_out.next_line(), if !v_out_closed => {
                    match line {
                        Ok(Some(l)) => {
                            let text = l.trim();
                            if text.contains("ewfverify: SUCCESS") {
                                ewfverify_success = true;
                            }
                            // Only digests recalculated over the image data count; "stored in
                            // file" and "Additional hash values" merely echo the acquisition
                            record_calculated_hash(&mut destination_hashes, text);
                        }
                        Ok(None) | Err(_) => v_out_closed = true,
                    }
                }
                line = v_reader_err.next_line(), if !v_err_closed => {
                    match line {
                        Ok(Some(l)) => {
                            let text = l.trim();
                            if !text.is_empty() {
                                telemetry.push_log(text);
                                let _ = progress_tx.send(telemetry.take_update()).await;
                            }
                        }
                        Ok(None) | Err(_) => v_err_closed = true,
                    }
                }
            }
        }

        let v_status = v_child
            .wait()
            .await
            .map_err(|e| format!("Failed to wait on ewfverify: {}", e))?;

        if !v_status.success() || !ewfverify_success {
            telemetry.push_log(format!(
                "ewfverify failed with status {:?}",
                v_status.code()
            ));
        }

        let digests = ewf_digest_list(selection, true).unwrap_or_default();
        let method = format!("ewfverify -d {digests} (image re-read)");
        let result = if v_status.success() && ewfverify_success {
            compare_digests(selection, &source_hashes, &destination_hashes, &method)
        } else {
            VerificationResult::Failed {
                reason: format!("ewfverify exited with status {:?}", v_status.code()),
            }
        };

        let mut report = legacy::new_report(
            EngineKind::Ewf,
            &device,
            &case,
            &config,
            &base_name,
            &run,
            &audit_anchor,
        );
        // ewfacquire finished successfully; this engine version does not yet
        // cross-check the media size with ewfinfo
        report.bytes_acquired = device.size_bytes;
        if bad_sectors > 0 {
            report.stop_reason = Some(format!(
                "ewfacquire reported {bad_sectors} unreadable sectors whose positions this engine version does not record"
            ));
        }
        report.acquisition_hashes = source_hashes;
        report.image_hashes = destination_hashes;
        report.verification = VerificationInfo {
            result,
            method,
            source_reread: None,
        };
        report.image_files = generated_files.clone();
        legacy::finish_report(&mut report, &run, device.size_bytes);
        let files = legacy::write_reports(&report, &config.output_dir, &base_name)?;
        telemetry.push_log(format!(
            "Forensic report saved to: {}",
            files.text.display()
        ));
        let hashes_match = report.outcome == Outcome::Verified;

        telemetry.status = AcquisitionStatus::Completed;
        telemetry.percentage = 100.0;
        telemetry.bytes_processed = device.size_bytes;
        telemetry.status_message = if hashes_match {
            "Acquisition and verification successfully completed.".to_string()
        } else {
            "Acquisition completed with verification warning/failure.".to_string()
        };
        let _ = progress_tx.send(telemetry).await;

        Ok(report)
    }
}

/// Digests verified for an E01: MD5 is always calculated by ewfacquire.
pub fn ewf_selection(config: &AcquisitionConfig) -> HashSelection {
    HashSelection {
        md5: true,
        sha1: config.calc_sha1,
        sha256: config.calc_sha256,
    }
}

/// Comma-separated `-d` value. ewfacquire always calculates MD5 and only takes
/// the additional types; ewfverify takes the full list.
pub fn ewf_digest_list(selection: HashSelection, include_md5: bool) -> Option<String> {
    let list: Vec<&str> = [
        (include_md5 && selection.md5, "md5"),
        (selection.sha1, "sha1"),
        (selection.sha256, "sha256"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| *name)
    .collect();
    if list.is_empty() {
        None
    } else {
        Some(list.join(","))
    }
}

/// Parse a libewf "<ALGO> hash calculated over data: <hex>" line.
pub fn parse_calculated_hash(line: &str) -> Option<(&'static str, String)> {
    let (label, value) = line.split_once(':')?;
    let algo = match label.trim() {
        "MD5 hash calculated over data" => "md5",
        "SHA1 hash calculated over data" => "sha1",
        "SHA256 hash calculated over data" => "sha256",
        _ => return None,
    };
    let value = value.trim().to_ascii_lowercase();
    let expected_len = match algo {
        "md5" => 32,
        "sha1" => 40,
        _ => 64,
    };
    if value.len() == expected_len && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some((algo, value))
    } else {
        None
    }
}

fn record_calculated_hash(hashes: &mut HashResults, line: &str) {
    match parse_calculated_hash(line) {
        Some(("md5", v)) => hashes.md5 = Some(v),
        Some(("sha1", v)) => hashes.sha1 = Some(v),
        Some(("sha256", v)) => hashes.sha256 = Some(v),
        _ => {}
    }
}

pub fn is_ewf_segment(base_name: &str, file_name: &str) -> bool {
    let prefix = format!("{}.", base_name);
    if !file_name.starts_with(&prefix) {
        return false;
    }

    let ext = &file_name[prefix.len()..];
    if ext.len() != 3 {
        return false;
    }

    let bytes = ext.as_bytes();
    let first = bytes[0].to_ascii_uppercase();
    let second = bytes[1].to_ascii_uppercase();
    let third = bytes[2].to_ascii_uppercase();

    match first {
        b'E' | b'S' => {
            (second.is_ascii_digit() && third.is_ascii_digit())
                || (second.is_ascii_alphabetic() && third.is_ascii_alphabetic())
        }
        b'0'..=b'9' => second.is_ascii_digit() && third.is_ascii_digit(),
        _ => false,
    }
}

fn read_proc_rchar(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/io", pid);
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("rchar:") {
            if let Ok(bytes) = rest.trim().parse::<u64>() {
                return Some(bytes);
            }
        }
    }
    None
}

fn calculate_target_bytes(output_dir: &std::path::Path, base_name: &str) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(output_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_ewf_segment(base_name, &name) {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    // Output captured from libewf 20231119 (ewfacquire / ewfverify)
    const EWFVERIFY_SHA256_ONLY: &str = "\
MD5 hash stored in file:\t\t3ece4002f6ecc0968e80e6a7e154637c
MD5 hash calculated over data:\t\t3ece4002f6ecc0968e80e6a7e154637c
SHA256 hash stored in file:\t\tN/A
SHA256 hash calculated over data:\tb0a771d9cfebc5f2609d54de66263a89b45139a01e6ab7ab2ff9dd961fcd9245

Additional hash values:
SHA1:\t250d58633db80fb956a63c9342520e013ec06a34

ewfverify: SUCCESS";

    fn parse_all(output: &str) -> HashResults {
        let mut h = HashResults::default();
        for line in output.lines() {
            record_calculated_hash(&mut h, line.trim());
        }
        h
    }

    #[test]
    fn test_parse_only_calculated_hashes() {
        let h = parse_all(EWFVERIFY_SHA256_ONLY);
        assert_eq!(h.md5.as_deref(), Some("3ece4002f6ecc0968e80e6a7e154637c"));
        assert_eq!(
            h.sha256.as_deref(),
            Some("b0a771d9cfebc5f2609d54de66263a89b45139a01e6ab7ab2ff9dd961fcd9245")
        );
        // The stored SHA-1 under "Additional hash values" is not a recalculation
        assert_eq!(h.sha1, None);
        assert_eq!(
            parse_calculated_hash("SHA256 hash stored in file:\t\tN/A"),
            None
        );
        assert_eq!(
            parse_calculated_hash("MD5 hash calculated over data: nothex"),
            None
        );
    }

    #[test]
    fn test_disabling_sha1_does_not_cause_false_mismatch() {
        let config = AcquisitionConfig {
            calc_sha1: false,
            calc_sha256: true,
            ..Default::default()
        };
        let sel = ewf_selection(&config);
        assert_eq!(ewf_digest_list(sel, false).as_deref(), Some("sha256"));
        assert_eq!(ewf_digest_list(sel, true).as_deref(), Some("md5,sha256"));

        let acquire = "MD5 hash calculated over data:\t\t3ece4002f6ecc0968e80e6a7e154637c\n\
SHA256 hash calculated over data:\tb0a771d9cfebc5f2609d54de66263a89b45139a01e6ab7ab2ff9dd961fcd9245\n\
ewfacquire: SUCCESS";
        let src = parse_all(acquire);
        let dst = parse_all(EWFVERIFY_SHA256_ONLY);
        assert!(compare_digests(sel, &src, &dst, "ewfverify").is_matched());
    }

    #[test]
    fn test_disabling_sha256_and_dual_hash_lists() {
        let base = AcquisitionConfig::default();
        assert_eq!(
            ewf_digest_list(ewf_selection(&base), false).as_deref(),
            Some("sha1,sha256")
        );
        assert_eq!(
            ewf_digest_list(ewf_selection(&base), true).as_deref(),
            Some("md5,sha1,sha256")
        );

        let no256 = AcquisitionConfig {
            calc_sha256: false,
            ..Default::default()
        };
        let sel = ewf_selection(&no256);
        assert_eq!(ewf_digest_list(sel, false).as_deref(), Some("sha1"));
        let src = HashResults {
            md5: Some("a".repeat(32)),
            sha1: Some("b".repeat(40)),
            sha256: None,
        };
        let dst = HashResults {
            md5: Some("a".repeat(32)),
            sha1: Some("b".repeat(40)),
            sha256: Some("c".repeat(64)),
        };
        assert!(compare_digests(sel, &src, &dst, "ewfverify").is_matched());

        let md5_only = AcquisitionConfig {
            calc_sha1: false,
            calc_sha256: false,
            ..Default::default()
        };
        assert_eq!(ewf_digest_list(ewf_selection(&md5_only), false), None);
        assert_eq!(
            ewf_digest_list(ewf_selection(&md5_only), true).as_deref(),
            Some("md5")
        );
    }

    #[test]
    fn test_is_ewf_segment_matching() {
        let base = "case_ea01_cf01_SERIAL";
        assert!(is_ewf_segment(base, "case_ea01_cf01_SERIAL.E01"));
        assert!(is_ewf_segment(base, "case_ea01_cf01_SERIAL.e01"));
        assert!(is_ewf_segment(base, "case_ea01_cf01_SERIAL.E99"));
        assert!(is_ewf_segment(base, "case_ea01_cf01_SERIAL.EAA"));
        assert!(is_ewf_segment(base, "case_ea01_cf01_SERIAL.s01"));
        assert!(is_ewf_segment(base, "case_ea01_cf01_SERIAL.001"));

        // Must reject non-segment files
        assert!(!is_ewf_segment(base, "case_ea01_cf01_SERIAL.info"));
        assert!(!is_ewf_segment(base, "case_ea01_cf01_SERIAL.old"));
        assert!(!is_ewf_segment(base, "case_ea01_cf01_SERIAL.E01.bak"));
        assert!(!is_ewf_segment(base, "case_ea01_cf01_SERIAL_copy.E01"));
        assert!(!is_ewf_segment(base, "other_case.E01"));
    }
}
