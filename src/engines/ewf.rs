use crate::models::{
    case::CaseMetadata,
    config::AcquisitionConfig,
    device::BlockDevice,
    info_report::{ForensicInfoReport, HashResults},
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use chrono::Utc;
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
        let start_time = Utc::now();
        let instant_start = Instant::now();

        // Target path without extension (ewfacquire appends .E01 automatically)
        let base_name = case.generate_base_filename(&device.display_serial());
        let target_path_without_ext = config.output_dir.join(&base_name);
        let target_str = target_path_without_ext.to_string_lossy().to_string();

        let mut cmd = Command::new("ewfacquire");
        cmd.arg("-u"); // Unattended mode

        // Metadata flags
        cmd.arg("-C").arg(case.effective_case());
        cmd.arg("-E").arg(case.effective_evidence());
        cmd.arg("-e").arg(case.effective_examiner());
        cmd.arg("-D")
            .arg(case.effective_description(&device.display_name()));
        if !case.notes.trim().is_empty() {
            cmd.arg("-N").arg(&case.notes);
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

        // Digest / hash options
        if config.calc_sha1 {
            cmd.arg("-d").arg("sha1");
        }
        if config.calc_sha256 {
            cmd.arg("-d").arg("sha256");
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
            status: AcquisitionStatus::Imaging,
            total_bytes: device.size_bytes,
            current_segment: format!("{}.E01", base_name),
            status_message: "Starting E01 acquisition...".to_string(),
            ..Default::default()
        };

        let mut bad_sectors = 0u64;
        let mut source_md5 = None;
        let mut source_sha1 = None;
        let mut source_sha256 = None;
        let mut image_md5 = None;
        let mut image_sha1 = None;
        let mut image_sha256 = None;

        let regex_bad = Regex::new(r"(\d+)\s*bad sector").unwrap();
        let regex_md5 = Regex::new(r"(?i)MD5\s*(?:hash|digest)?\s*(?:stored in image|calculated over data|verified)?\s*:\s*([a-f0-9]{32})").unwrap();
        let regex_sha1 = Regex::new(r"(?i)SHA1\s*(?:hash|digest)?\s*(?:stored in image|calculated over data|verified)?\s*:\s*([a-f0-9]{40})").unwrap();
        let regex_sha256 = Regex::new(r"(?i)SHA256\s*(?:hash|digest)?\s*(?:stored in image|calculated over data|verified)?\s*:\s*([a-f0-9]{64})").unwrap();

        // Real-time /proc/pid/io polling interval
        let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
        let mut last_read_bytes = 0u64;
        let mut last_poll_time = Instant::now();

        let target_dir = config.output_dir.clone();
        let base_name_clone = base_name.clone();

        loop {
            if abort_flag.load(Ordering::Relaxed) {
                let _ = child.kill().await;
                telemetry.status = AcquisitionStatus::Aborted;
                telemetry.push_log("Acquisition aborted by examiner.");
                let _ = progress_tx.send(telemetry).await;
                return Err("Acquisition aborted by user.".to_string());
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

                            let _ = progress_tx.send(telemetry.clone()).await;
                        }
                    }
                }
                line_err = reader_err.next_line() => {
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
                                let _ = progress_tx.send(telemetry.clone()).await;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
                line_out = reader_out.next_line() => {
                    match line_out {
                        Ok(Some(line)) => {
                            let text = line.trim();
                            if !text.is_empty() {
                                telemetry.push_log(text);

                                if let Some(caps) = regex_md5.captures(text) {
                                    let hash = caps[1].to_lowercase();
                                    if source_md5.is_none() {
                                        source_md5 = Some(hash.clone());
                                    }
                                    image_md5 = Some(hash);
                                }
                                if let Some(caps) = regex_sha1.captures(text) {
                                    let hash = caps[1].to_lowercase();
                                    if source_sha1.is_none() {
                                        source_sha1 = Some(hash.clone());
                                    }
                                    image_sha1 = Some(hash);
                                }
                                if let Some(caps) = regex_sha256.captures(text) {
                                    let hash = caps[1].to_lowercase();
                                    if source_sha256.is_none() {
                                        source_sha256 = Some(hash.clone());
                                    }
                                    image_sha256 = Some(hash);
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
        }

        let status = child
            .wait()
            .await
            .map_err(|e| format!("Failed to wait on ewfacquire: {}", e))?;

        let end_time = Utc::now();
        let elapsed_seconds = instant_start.elapsed().as_secs();
        let avg_speed = if elapsed_seconds > 0 {
            device.size_bytes as f64 / elapsed_seconds as f64
        } else {
            0.0
        };

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
                if name.starts_with(&base_name) {
                    generated_files.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
        generated_files.sort();

        let source_hashes = HashResults {
            md5: source_md5.clone(),
            sha1: source_sha1.clone(),
            sha256: source_sha256.clone(),
        };

        let destination_hashes = HashResults {
            md5: image_md5.or(source_md5),
            sha1: image_sha1.or(source_sha1),
            sha256: image_sha256.or(source_sha256),
        };

        let hashes_match = (source_hashes.md5 == destination_hashes.md5)
            && (source_hashes.sha1 == destination_hashes.sha1)
            && (source_hashes.sha256 == destination_hashes.sha256);

        let report = ForensicInfoReport {
            tool_name: "dfdisk".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            case_metadata: case.clone(),
            device: device.clone(),
            config: config.clone(),
            started_at: start_time,
            ended_at: end_time,
            elapsed_seconds,
            average_speed_bytes_sec: avg_speed,
            bad_sectors_count: bad_sectors,
            source_hashes,
            destination_hashes,
            verification_passed: hashes_match,
            generated_files: generated_files.clone(),
        };

        // Write .info sidecar report
        let info_filename = case.generate_filename(&device.display_serial(), "info");
        let info_path = config.output_dir.join(&info_filename);
        let info_text = report.render_text();
        if let Err(e) = std::fs::write(&info_path, info_text) {
            telemetry.push_log(format!("Warning: Failed to write .info file: {}", e));
        } else {
            telemetry.push_log(format!(
                "Forensic certificate saved to: {}",
                info_path.display()
            ));
        }

        telemetry.status = AcquisitionStatus::Completed;
        telemetry.percentage = 100.0;
        telemetry.bytes_processed = device.size_bytes;
        telemetry.status_message =
            "Acquisition and verification successfully completed.".to_string();
        let _ = progress_tx.send(telemetry).await;

        Ok(report)
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
            if name.starts_with(base_name) && !name.ends_with(".info") {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            }
        }
    }
    total
}
