use crate::engines::hasher::{HashProgress, MultiHasher};
use crate::models::{
    case::CaseMetadata,
    config::AcquisitionConfig,
    device::BlockDevice,
    info_report::{ForensicInfoReport, HashResults, VerificationStatus},
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use chrono::Utc;
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct RawAcquireEngine;

impl RawAcquireEngine {
    pub async fn run_acquisition(
        device: BlockDevice,
        case: CaseMetadata,
        config: AcquisitionConfig,
        progress_tx: mpsc::Sender<ProgressTelemetry>,
        abort_flag: Arc<AtomicBool>,
    ) -> Result<ForensicInfoReport, String> {
        let start_time = Utc::now();
        let instant_start = Instant::now();

        std::fs::create_dir_all(&config.output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;

        let raw_filename = case.generate_filename(&device.display_serial(), "raw");
        let raw_path = config.output_dir.join(&raw_filename);

        let mut telemetry = ProgressTelemetry {
            status: AcquisitionStatus::Imaging,
            total_bytes: device.size_bytes,
            current_segment: raw_filename.clone(),
            status_message: format!(
                "Starting native RAW streaming acquisition to {}...",
                raw_filename
            ),
            ..Default::default()
        };
        let _ = progress_tx.send(telemetry.clone()).await;

        // Perform streaming block copy on a blocking task
        let src_path = device.path.clone();
        let target_raw_path = raw_path.clone();
        let total_device_bytes = device.size_bytes;
        let calc_md5 = config.calc_md5;
        let calc_sha1 = config.calc_sha1;
        let calc_sha256 = config.calc_sha256;

        let (copy_prog_tx, mut copy_prog_rx) = mpsc::channel::<ProgressTelemetry>(100);
        let copy_abort = abort_flag.clone();

        let copy_task =
            tokio::task::spawn_blocking(move || -> Result<(HashResults, u64), String> {
                let mut src_file = File::open(&src_path)
                    .map_err(|e| format!("Failed to open source device {}: {}", src_path, e))?;

                let mut dest_file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&target_raw_path)
                    .map_err(|e| {
                        format!(
                            "Failed to create RAW destination file {}: {}",
                            target_raw_path.display(),
                            e
                        )
                    })?;

                let mut md5_hasher = if calc_md5 { Some(Md5::new()) } else { None };
                let mut sha1_hasher = if calc_sha1 { Some(Sha1::new()) } else { None };
                let mut sha256_hasher = if calc_sha256 {
                    Some(Sha256::new())
                } else {
                    None
                };

                let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer
                let mut bytes_processed = 0u64;
                let mut last_read_bytes = 0u64;
                let mut last_report = Instant::now();
                let mut last_speed_calc = Instant::now();
                let start_t = Instant::now();

                loop {
                    if copy_abort.load(Ordering::Relaxed) {
                        let _ = std::fs::remove_file(&target_raw_path);
                        return Err("RAW acquisition aborted by user.".to_string());
                    }

                    let n = match src_file.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => {
                            return Err(format!("I/O read error from source {}: {}", src_path, e));
                        }
                    };

                    let chunk = &buffer[..n];

                    // In-flight multi-hashing
                    if let Some(ref mut h) = md5_hasher {
                        h.update(chunk);
                    }
                    if let Some(ref mut h) = sha1_hasher {
                        h.update(chunk);
                    }
                    if let Some(ref mut h) = sha256_hasher {
                        h.update(chunk);
                    }

                    // Write to destination
                    if let Err(e) = dest_file.write_all(chunk) {
                        if e.kind() == std::io::ErrorKind::StorageFull
                            || e.raw_os_error() == Some(28)
                        {
                            return Err(
                                "Destination filesystem out of space while writing RAW image"
                                    .to_string(),
                            );
                        }
                        return Err(format!(
                            "I/O write error to {}: {}",
                            target_raw_path.display(),
                            e
                        ));
                    }

                    bytes_processed += n as u64;

                    if last_report.elapsed() >= Duration::from_millis(100) {
                        let total = total_device_bytes.max(1);
                        let pct = ((bytes_processed as f64 / total as f64) * 100.0).min(100.0);

                        let dt = last_speed_calc.elapsed().as_secs_f64();
                        let speed = if dt >= 0.1 {
                            let diff = bytes_processed.saturating_sub(last_read_bytes);
                            last_read_bytes = bytes_processed;
                            last_speed_calc = Instant::now();
                            diff as f64 / dt
                        } else {
                            0.0
                        };

                        let elapsed = start_t.elapsed().as_secs_f64();
                        let avg_speed = if elapsed > 0.0 {
                            bytes_processed as f64 / elapsed
                        } else {
                            0.0
                        };

                        let eta = if avg_speed > 0.0 && total_device_bytes > bytes_processed {
                            Some(((total_device_bytes - bytes_processed) as f64 / avg_speed) as u64)
                        } else {
                            None
                        };

                        let p = ProgressTelemetry {
                            status: AcquisitionStatus::Imaging,
                            bytes_processed,
                            total_bytes: total_device_bytes,
                            speed_bps: speed,
                            avg_speed_bps: avg_speed,
                            percentage: pct,
                            elapsed_secs: elapsed as u64,
                            eta_secs: eta,
                            current_segment: target_raw_path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string(),
                            status_message: format!("Streaming RAW bytes... {:.1}%", pct),
                            bad_sectors: 0,
                            compression_ratio: None,
                            log_messages: vec![],
                        };

                        let _ = copy_prog_tx.blocking_send(p);
                        last_report = Instant::now();
                    }
                }

                dest_file
                    .flush()
                    .map_err(|e| format!("Failed to flush RAW file: {}", e))?;
                dest_file
                    .sync_all()
                    .map_err(|e| format!("Failed to sync RAW file to disk: {}", e))?;

                let source_hashes = HashResults {
                    md5: md5_hasher.map(|h| hex::encode(h.finalize())),
                    sha1: sha1_hasher.map(|h| hex::encode(h.finalize())),
                    sha256: sha256_hasher.map(|h| hex::encode(h.finalize())),
                };

                Ok((source_hashes, bytes_processed))
            });

        // Forward progress events during copying
        while let Some(prog) = copy_prog_rx.recv().await {
            telemetry = prog;
            let _ = progress_tx.send(telemetry.clone()).await;
        }

        let (source_hashes, bytes_copied) = match copy_task.await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                telemetry.status = AcquisitionStatus::Failed(e.clone());
                let _ = progress_tx.send(telemetry).await;
                return Err(e);
            }
            Err(e) => {
                let msg = format!("RAW copying task panicked: {}", e);
                telemetry.status = AcquisitionStatus::Failed(msg.clone());
                let _ = progress_tx.send(telemetry).await;
                return Err(msg);
            }
        };

        // Post-acquisition readback verification
        telemetry.status = AcquisitionStatus::Verifying;
        telemetry.percentage = 0.0;
        telemetry.status_message =
            "Verifying written RAW image cryptographic hashes...".to_string();
        telemetry.push_log("Beginning post-acquisition destination verification pass...");
        let _ = progress_tx.send(telemetry.clone()).await;

        let (v_tx, mut v_rx) = mpsc::channel::<HashProgress>(50);
        let raw_path_clone = raw_path.clone();

        let verif_handle = tokio::spawn(async move {
            MultiHasher::hash_stream_with_capacity(
                &raw_path_clone,
                config.calc_md5,
                config.calc_sha1,
                config.calc_sha256,
                Some(bytes_copied),
                Some(v_tx),
            )
            .await
        });

        while let Some(hp) = v_rx.recv().await {
            telemetry.percentage = hp.percentage;
            telemetry.speed_bps = hp.speed_bps;
            telemetry.status_message = format!("Verifying RAW image: {:.1}%", hp.percentage);
            let _ = progress_tx.send(telemetry.clone()).await;
        }

        let destination_hashes = verif_handle
            .await
            .map_err(|e| format!("Verification task error: {}", e))?
            .map_err(|e| format!("Failed to compute destination image hashes: {}", e))?;

        let end_time = Utc::now();
        let elapsed_seconds = instant_start.elapsed().as_secs();
        let avg_speed = if elapsed_seconds > 0 {
            bytes_copied as f64 / elapsed_seconds as f64
        } else {
            0.0
        };

        // Compare source vs destination
        let mut compared = 0;
        let mut all_match = true;

        if let (Some(s), Some(d)) = (&source_hashes.md5, &destination_hashes.md5) {
            compared += 1;
            if !s.eq_ignore_ascii_case(d) {
                all_match = false;
            }
        }
        if let (Some(s), Some(d)) = (&source_hashes.sha1, &destination_hashes.sha1) {
            compared += 1;
            if !s.eq_ignore_ascii_case(d) {
                all_match = false;
            }
        }
        if let (Some(s), Some(d)) = (&source_hashes.sha256, &destination_hashes.sha256) {
            compared += 1;
            if !s.eq_ignore_ascii_case(d) {
                all_match = false;
            }
        }

        let verification_passed = compared > 0 && all_match;
        let verification_status = if verification_passed {
            VerificationStatus::Verified
        } else if compared > 0 {
            VerificationStatus::Mismatch
        } else {
            VerificationStatus::Failed
        };

        let generated_files = vec![raw_path.to_string_lossy().to_string()];

        let report = ForensicInfoReport {
            tool_name: "dfdisk (raw engine)".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            case_metadata: case.clone(),
            device: device.clone(),
            config: config.clone(),
            started_at: start_time,
            ended_at: end_time,
            elapsed_seconds,
            average_speed_bytes_sec: avg_speed,
            bad_sectors_count: 0,
            source_hashes,
            destination_hashes,
            verification_passed,
            verification_status,
            generated_files,
        };

        // Write court certificate sidecar
        let info_filename = case.generate_filename(&device.display_serial(), "info");
        let info_path = config.output_dir.join(&info_filename);
        let _ = std::fs::write(&info_path, report.render_text());

        telemetry.status = AcquisitionStatus::Completed;
        telemetry.percentage = 100.0;
        telemetry.bytes_processed = bytes_copied;
        telemetry.status_message = if verification_passed {
            "RAW acquisition and verification successfully completed.".to_string()
        } else {
            "RAW acquisition completed with verification failure.".to_string()
        };
        let _ = progress_tx.send(telemetry).await;

        Ok(report)
    }
}
