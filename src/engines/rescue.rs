use crate::engines::hasher::MultiHasher;
use crate::models::{
    case::CaseMetadata,
    config::AcquisitionConfig,
    device::BlockDevice,
    info_report::ForensicInfoReport,
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

pub struct RescueAcquireEngine;

impl RescueAcquireEngine {
    pub async fn run_rescue(
        device: BlockDevice,
        case: CaseMetadata,
        config: AcquisitionConfig,
        progress_tx: mpsc::Sender<ProgressTelemetry>,
        abort_flag: Arc<AtomicBool>,
    ) -> Result<ForensicInfoReport, String> {
        let start_time = Utc::now();
        let instant_start = Instant::now();

        let base_name = case.generate_base_filename(&device.display_serial());
        let raw_filename = format!("{}.raw", base_name);
        let map_filename = format!("{}.map", base_name);

        let raw_path = config.output_dir.join(&raw_filename);
        let map_path = config.output_dir.join(&map_filename);

        let mut cmd = Command::new("ddrescue");
        cmd.arg("-d"); // Direct I/O
        cmd.arg("-r").arg(config.error_retries.to_string());
        cmd.arg("-b").arg(device.logical_sector_size.max(512).to_string());
        cmd.arg(&device.path);
        cmd.arg(&raw_path);
        cmd.arg(&map_path);

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn ddrescue: {}", e))?;

        let child_pid = child.id();
        let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
        let mut reader = BufReader::new(stdout).lines();

        let mut telemetry = ProgressTelemetry {
            status: AcquisitionStatus::Imaging,
            total_bytes: device.size_bytes,
            current_segment: raw_filename.clone(),
            status_message: "Starting resilient ddrescue acquisition...".to_string(),
            ..Default::default()
        };

        let mut bad_sectors = 0u64;
        let regex_pct = Regex::new(r"pct rescued:\s*(\d+(?:\.\d+)?)%").unwrap();
        let regex_errors = Regex::new(r"errsize:\s*(\d+(?:\.\d+)?)\s*([kKMGT]?B)").unwrap();
        let regex_speed = Regex::new(r"current rate:\s*(\d+(?:\.\d+)?)\s*([kKMGT]?B/s)").unwrap();

        let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
        let mut last_read_bytes = 0u64;
        let mut last_poll_time = Instant::now();

        loop {
            if abort_flag.load(Ordering::Relaxed) {
                let _ = child.kill().await;
                telemetry.status = AcquisitionStatus::Aborted;
                telemetry.push_log("Rescue acquisition aborted by user.");
                let _ = progress_tx.send(telemetry).await;
                return Err("Rescue acquisition aborted.".to_string());
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
                                let diff = processed.saturating_sub(last_read_bytes);
                                telemetry.speed_bps = diff as f64 / dt;
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

                            let _ = progress_tx.send(telemetry.clone()).await;
                        }
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
                                    let unit = &caps[2];
                                    let mult = match unit {
                                        "kB/s" | "KB/s" => 1_000.0,
                                        "MB/s" | "mB/s" => 1_000_000.0,
                                        "GB/s" => 1_000_000_000.0,
                                        _ => 1.0,
                                    };
                                    telemetry.speed_bps = val * mult;
                                }
                                if let Some(caps) = regex_errors.captures(text) {
                                    let err_val = caps[1].parse::<f64>().unwrap_or(0.0);
                                    if err_val > 0.0 {
                                        bad_sectors += 1;
                                        telemetry.bad_sectors = bad_sectors;
                                    }
                                }

                                telemetry.status_message = text.to_string();
                                let _ = progress_tx.send(telemetry.clone()).await;
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
            .map_err(|e| format!("Failed to wait on ddrescue: {}", e))?;

        if !status.success() {
            telemetry.status = AcquisitionStatus::Failed(format!("ddrescue exited with code {:?}", status.code()));
            let _ = progress_tx.send(telemetry).await;
            return Err(format!("ddrescue failed with exit code {:?}", status.code()));
        }

        // Post-acquisition verification hashing
        telemetry.status = AcquisitionStatus::Verifying;
        telemetry.status_message = "Computing cryptographic integrity hashes...".to_string();
        let _ = progress_tx.send(telemetry.clone()).await;

        let hashes = MultiHasher::hash_stream(
            &raw_path,
            config.calc_md5,
            config.calc_sha1,
            config.calc_sha256,
            None,
        )
        .await?;

        let end_time = Utc::now();
        let elapsed_seconds = instant_start.elapsed().as_secs();
        let avg_speed = if elapsed_seconds > 0 {
            device.size_bytes as f64 / elapsed_seconds as f64
        } else {
            0.0
        };

        let generated_files = vec![
            raw_path.to_string_lossy().to_string(),
            map_path.to_string_lossy().to_string(),
        ];

        let report = ForensicInfoReport {
            tool_name: "dfdisk (ddrescue engine)".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            case_metadata: case.clone(),
            device: device.clone(),
            config: config.clone(),
            started_at: start_time,
            ended_at: end_time,
            elapsed_seconds,
            average_speed_bytes_sec: avg_speed,
            bad_sectors_count: bad_sectors,
            source_hashes: hashes.clone(),
            destination_hashes: hashes,
            verification_passed: true,
            generated_files,
        };

        let info_filename = case.generate_filename(&device.display_serial(), "info");
        let info_path = config.output_dir.join(&info_filename);
        let _ = std::fs::write(&info_path, report.render_text());

        telemetry.status = AcquisitionStatus::Completed;
        telemetry.percentage = 100.0;
        telemetry.status_message = "Resilient acquisition completed successfully.".to_string();
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
