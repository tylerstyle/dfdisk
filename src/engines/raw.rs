use crate::engines::hasher::{HashProgress, MultiHasher};
use crate::engines::preflight;
use crate::models::{
    case::CaseMetadata,
    config::AcquisitionConfig,
    device::BlockDevice,
    info_report::{
        compare_selected, ForensicInfoReport, HashResults, HashSelection, IncompleteAcquisition,
        VerificationStatus,
    },
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use chrono::Utc;
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How the native RAW engine deals with read errors, stated in every report.
pub const RAW_ERROR_HANDLING: &str =
    "None: native RAW engine stops at the first unreadable sector (no retries, no zero-fill; use rescue mode for damaged media)";

const CHUNK_SIZE: usize = 1024 * 1024;

/// All selected digests, fed from the single read pass.
struct StreamHasher {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
}

impl StreamHasher {
    fn new(selection: HashSelection) -> Self {
        Self {
            md5: selection.md5.then(Md5::new),
            sha1: selection.sha1.then(Sha1::new),
            sha256: selection.sha256.then(Sha256::new),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        if let Some(h) = self.md5.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = self.sha1.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = self.sha256.as_mut() {
            h.update(chunk);
        }
    }

    fn finish(self) -> HashResults {
        HashResults {
            md5: self.md5.map(|h| hex::encode(h.finalize())),
            sha1: self.sha1.map(|h| hex::encode(h.finalize())),
            sha256: self.sha256.map(|h| hex::encode(h.finalize())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CopyOutcome {
    pub bytes_copied: u64,
    /// Digests over exactly the bytes copied
    pub source_hashes: HashResults,
    /// Set when an unreadable sector ended the copy before the end of input
    pub read_error: Option<String>,
}

fn read_retrying_interrupts<R: Read>(src: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match src.read(buf) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// Copy `src` to `dst`, hashing every byte once. A failed bulk read is retried
/// sector by sector so that everything readable before the first bad sector is
/// still copied, and the exact offset of that sector is reported.
pub fn copy_and_hash<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    sector_size: usize,
    selection: HashSelection,
    abort: &AtomicBool,
    mut on_progress: impl FnMut(u64),
) -> Result<CopyOutcome, String> {
    let mut hasher = StreamHasher::new(selection);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut sector = vec![0u8; sector_size.max(512)];
    let mut copied = 0u64;

    let mut emit =
        |chunk: &[u8], hasher: &mut StreamHasher, copied: &mut u64| -> Result<(), String> {
            hasher.update(chunk);
            dst.write_all(chunk).map_err(|e| {
                if e.kind() == ErrorKind::StorageFull || e.raw_os_error() == Some(28) {
                    "Destination filesystem out of space while writing RAW image".to_string()
                } else {
                    format!("I/O write error to destination: {}", e)
                }
            })?;
            *copied += chunk.len() as u64;
            Ok(())
        };

    'bulk: loop {
        if abort.load(Ordering::Relaxed) {
            return Err("RAW acquisition aborted by user.".to_string());
        }
        match read_retrying_interrupts(src, &mut buffer) {
            Ok(0) => break,
            Ok(n) => emit(&buffer[..n], &mut hasher, &mut copied)?,
            Err(_) => {
                // Narrow the failure down to the first unreadable sector
                let mut salvaged = 0usize;
                while salvaged < CHUNK_SIZE {
                    match read_retrying_interrupts(src, &mut sector) {
                        Ok(0) => break 'bulk,
                        Ok(n) => {
                            emit(&sector[..n], &mut hasher, &mut copied)?;
                            salvaged += n;
                        }
                        Err(e) => {
                            return Ok(CopyOutcome {
                                bytes_copied: copied,
                                source_hashes: hasher.finish(),
                                read_error: Some(format!("{} at byte offset {}", e, copied)),
                            });
                        }
                    }
                }
            }
        }
        on_progress(copied);
    }

    Ok(CopyOutcome {
        bytes_copied: copied,
        source_hashes: hasher.finish(),
        read_error: None,
    })
}

/// Why a finished copy does not cover the whole source, if it does not.
pub fn incompleteness(outcome: &CopyOutcome, expected_bytes: u64) -> Option<IncompleteAcquisition> {
    let reason = if let Some(err) = &outcome.read_error {
        format!("Read error: {}", err)
    } else if expected_bytes > 0 && outcome.bytes_copied != expected_bytes {
        format!(
            "Source returned end of data after {} bytes, but its reported size is {} bytes",
            outcome.bytes_copied, expected_bytes
        )
    } else {
        return None;
    };
    Some(IncompleteAcquisition {
        bytes_acquired: outcome.bytes_copied,
        expected_bytes,
        reason,
    })
}

pub struct RawAcquireEngine;

impl RawAcquireEngine {
    pub async fn run_acquisition(
        device: BlockDevice,
        case: CaseMetadata,
        config: AcquisitionConfig,
        progress_tx: mpsc::Sender<ProgressTelemetry>,
        abort_flag: Arc<AtomicBool>,
    ) -> Result<ForensicInfoReport, String> {
        let output_dir = config.output_dir.clone();
        let audit_anchor = crate::engines::audit::started("raw", &device, &config);
        let result = Self::acquire(
            device.clone(),
            case,
            config,
            progress_tx,
            abort_flag,
            audit_anchor,
        )
        .await;
        crate::engines::audit::finished("raw", &device, &output_dir, &result);
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
        let start_time = Utc::now();
        let instant_start = Instant::now();
        let selection = HashSelection::from_config(&config);

        std::fs::create_dir_all(&config.output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;

        let base_name = case.generate_base_filename(&device.display_serial());
        let raw_filename = case.generate_filename(&device.display_serial(), "raw");
        let raw_path = config.output_dir.join(&raw_filename);

        preflight::ensure_no_existing_outputs(&config.output_dir, &base_name)?;
        preflight::ensure_not_protected(&device.path)?;
        preflight::ensure_destination_not_on_source(&device.path, &config.output_dir)?;

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
        let sector_size = device.logical_sector_size as usize;

        let (copy_prog_tx, mut copy_prog_rx) = mpsc::channel::<ProgressTelemetry>(100);
        let copy_abort = abort_flag.clone();

        let copy_task = tokio::task::spawn_blocking(move || -> Result<CopyOutcome, String> {
            let mut src_file = File::open(&src_path)
                .map_err(|e| format!("Failed to open source device {}: {}", src_path, e))?;

            let mut dest_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target_raw_path)
                .map_err(|e| {
                    format!(
                        "Failed to exclusively create RAW destination file {}: {}",
                        target_raw_path.display(),
                        e
                    )
                })?;

            let segment_name = target_raw_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let start_t = Instant::now();
            let mut last_report = Instant::now();
            let mut last_speed_calc = Instant::now();
            let mut last_read_bytes = 0u64;

            let outcome = copy_and_hash(
                &mut src_file,
                &mut dest_file,
                sector_size,
                selection,
                &copy_abort,
                |bytes_processed| {
                    if last_report.elapsed() < Duration::from_millis(100) {
                        return;
                    }
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

                    let _ = copy_prog_tx.blocking_send(ProgressTelemetry {
                        status: AcquisitionStatus::Imaging,
                        bytes_processed,
                        total_bytes: total_device_bytes,
                        speed_bps: speed,
                        avg_speed_bps: avg_speed,
                        percentage: pct,
                        elapsed_secs: elapsed as u64,
                        eta_secs: eta,
                        current_segment: segment_name.clone(),
                        status_message: format!("Streaming RAW bytes... {:.1}%", pct),
                        bad_sectors: 0,
                        compression_ratio: None,
                        log_messages: vec![],
                    });
                    last_report = Instant::now();
                },
            );

            let outcome = match outcome {
                Ok(o) => o,
                Err(e) => {
                    if copy_abort.load(Ordering::Relaxed) {
                        let _ = std::fs::remove_file(&target_raw_path);
                    }
                    return Err(e);
                }
            };

            // Partial images are kept: they are evidence of what could be read
            dest_file
                .flush()
                .map_err(|e| format!("Failed to flush RAW file: {}", e))?;
            dest_file
                .sync_all()
                .map_err(|e| format!("Failed to sync RAW file to disk: {}", e))?;

            Ok(outcome)
        });

        // Forward progress events during copying
        while let Some(prog) = copy_prog_rx.recv().await {
            telemetry = prog;
            let _ = progress_tx.send(telemetry.clone()).await;
        }

        let outcome = match copy_task.await {
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
        let bytes_copied = outcome.bytes_copied;
        let incomplete = incompleteness(&outcome, total_device_bytes);
        if let Some(inc) = &incomplete {
            telemetry.push_log(format!("Acquisition stopped early: {}", inc.reason));
        }

        // Post-acquisition readback verification (of the partial image as well)
        telemetry.status = AcquisitionStatus::Verifying;
        telemetry.percentage = 0.0;
        telemetry.status_message =
            "Verifying written RAW image cryptographic hashes...".to_string();
        telemetry.push_log("Beginning post-acquisition destination verification pass...");
        let _ = progress_tx.send(telemetry.clone()).await;

        let (v_tx, mut v_rx) = mpsc::channel::<HashProgress>(50);
        let raw_path_clone = raw_path.clone();
        let verif_abort = abort_flag.clone();

        let verif_handle = tokio::spawn(async move {
            MultiHasher::hash_stream_with_capacity(
                &raw_path_clone,
                selection.md5,
                selection.sha1,
                selection.sha256,
                Some(bytes_copied),
                Some(v_tx),
                Some(verif_abort),
            )
            .await
        });

        while let Some(hp) = v_rx.recv().await {
            if abort_flag.load(Ordering::Relaxed) {
                telemetry.status = AcquisitionStatus::Aborted;
                let _ = progress_tx.send(telemetry).await;
                return Err("RAW verification aborted by user.".to_string());
            }
            telemetry.percentage = hp.percentage;
            telemetry.speed_bps = hp.speed_bps;
            telemetry.status_message = format!("Verifying RAW image: {:.1}%", hp.percentage);
            let _ = progress_tx.send(telemetry.clone()).await;
        }

        let destination_hashes = match verif_handle.await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                telemetry.status = AcquisitionStatus::Failed(e.clone());
                let _ = progress_tx.send(telemetry).await;
                return Err(e);
            }
            Err(e) => {
                let msg = format!("Verification task error: {}", e);
                telemetry.status = AcquisitionStatus::Failed(msg.clone());
                let _ = progress_tx.send(telemetry).await;
                return Err(msg);
            }
        };

        let end_time = Utc::now();
        let elapsed_seconds = instant_start.elapsed().as_secs();
        let avg_speed = if elapsed_seconds > 0 {
            bytes_copied as f64 / elapsed_seconds as f64
        } else {
            0.0
        };

        let verification_status = if incomplete.is_some() {
            VerificationStatus::Incomplete
        } else {
            compare_selected(selection, &outcome.source_hashes, &destination_hashes)
        };
        let verification_passed = verification_status == VerificationStatus::Verified;

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
            bad_sectors_count: u64::from(outcome.read_error.is_some()),
            source_hashes: outcome.source_hashes.clone(),
            destination_hashes,
            verification_passed,
            verification_status,
            generated_files,
            audit_anchor: audit_anchor.clone(),
            error_handling_note: Some(RAW_ERROR_HANDLING.to_string()),
            incomplete: incomplete.clone(),
        };

        // Write court certificate sidecar atomically and propagate errors
        let info_filename = case.generate_filename(&device.display_serial(), "info");
        let info_path = config.output_dir.join(&info_filename);
        let tmp_info_path = config.output_dir.join(format!("{}.tmp", info_filename));
        std::fs::write(&tmp_info_path, report.render_text()).map_err(|e| {
            format!(
                "Failed to write forensic report to temporary file {}: {}",
                tmp_info_path.display(),
                e
            )
        })?;
        std::fs::rename(&tmp_info_path, &info_path).map_err(|e| {
            format!(
                "Failed to finalize forensic report {}: {}",
                info_path.display(),
                e
            )
        })?;

        if let Some(inc) = incomplete {
            let msg = format!(
                "Acquisition incomplete: acquired {} of {} bytes ({}). Partial image {} and report {} were kept.",
                inc.bytes_acquired,
                inc.expected_bytes,
                inc.reason,
                raw_path.display(),
                info_path.display()
            );
            telemetry.status = AcquisitionStatus::Failed(msg.clone());
            telemetry.bytes_processed = bytes_copied;
            let _ = progress_tx.send(telemetry).await;
            return Err(msg);
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Device that cannot read any byte at or beyond `bad_from`. Reads stopping
    /// short of it succeed (short reads included), like a block device.
    struct FailingDevice {
        data: Vec<u8>,
        pos: usize,
        bad_from: usize,
    }

    impl Read for FailingDevice {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let end = (self.pos + buf.len()).min(self.data.len());
            if end > self.bad_from {
                return Err(std::io::Error::from_raw_os_error(5));
            }
            let n = end - self.pos;
            buf[..n].copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;
            Ok(n)
        }
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    const ALL: HashSelection = HashSelection {
        md5: true,
        sha1: true,
        sha256: true,
    };

    fn copy(src: &mut impl Read, out: &mut Vec<u8>, sel: HashSelection) -> CopyOutcome {
        copy_and_hash(src, out, 512, sel, &AtomicBool::new(false), |_| {}).unwrap()
    }

    #[test]
    fn complete_copy_hashes_everything_once() {
        let data = sample(3 * CHUNK_SIZE + 777);
        let mut out = Vec::new();
        let o = copy(&mut Cursor::new(data.clone()), &mut out, ALL);
        assert_eq!(out, data);
        assert_eq!(o.bytes_copied, data.len() as u64);
        assert!(o.read_error.is_none());
        assert_eq!(o.source_hashes.md5, Some(hex::encode(Md5::digest(&data))));
        assert_eq!(o.source_hashes.sha1, Some(hex::encode(Sha1::digest(&data))));
        assert_eq!(
            o.source_hashes.sha256,
            Some(hex::encode(Sha256::digest(&data)))
        );
        assert!(incompleteness(&o, data.len() as u64).is_none());
    }

    #[test]
    fn read_error_keeps_every_readable_sector_and_reports_offset() {
        let data = sample(2 * CHUNK_SIZE);
        let bad = CHUNK_SIZE + 7 * 512; // 8th sector of the second chunk
        let mut dev = FailingDevice {
            data: data.clone(),
            pos: 0,
            bad_from: bad,
        };
        let mut out = Vec::new();
        let o = copy(&mut dev, &mut out, ALL);

        assert_eq!(o.bytes_copied, bad as u64);
        assert_eq!(out, &data[..bad]);
        let err = o.read_error.as_deref().unwrap();
        assert!(err.contains(&format!("byte offset {}", bad)), "{err}");
        // Hashes describe exactly the acquired prefix
        assert_eq!(
            o.source_hashes.sha256,
            Some(hex::encode(Sha256::digest(&data[..bad])))
        );

        let inc = incompleteness(&o, data.len() as u64).unwrap();
        assert_eq!(inc.bytes_acquired, bad as u64);
        assert_eq!(inc.expected_bytes, data.len() as u64);
        assert!(inc.reason.starts_with("Read error"));
    }

    #[test]
    fn read_error_in_first_sector_copies_nothing() {
        let mut dev = FailingDevice {
            data: sample(4096),
            pos: 0,
            bad_from: 0,
        };
        let mut out = Vec::new();
        let o = copy(&mut dev, &mut out, ALL);
        assert_eq!(o.bytes_copied, 0);
        assert!(out.is_empty());
        assert!(o.read_error.unwrap().contains("byte offset 0"));
    }

    #[test]
    fn short_source_is_incomplete_without_read_error() {
        let o = copy(&mut Cursor::new(sample(1000)), &mut Vec::new(), ALL);
        let inc = incompleteness(&o, 4096).unwrap();
        assert!(
            inc.reason.contains("end of data after 1000 bytes"),
            "{}",
            inc.reason
        );
    }

    #[test]
    fn only_selected_digests_are_computed() {
        let sel = HashSelection {
            md5: false,
            sha1: false,
            sha256: true,
        };
        let o = copy(&mut Cursor::new(sample(10)), &mut Vec::new(), sel);
        assert!(o.source_hashes.md5.is_none());
        assert!(o.source_hashes.sha1.is_none());
        assert!(o.source_hashes.sha256.is_some());
    }

    #[test]
    fn abort_stops_copy() {
        let r = copy_and_hash(
            &mut Cursor::new(sample(10)),
            &mut Vec::new(),
            512,
            ALL,
            &AtomicBool::new(true),
            |_| {},
        );
        assert!(r.unwrap_err().contains("aborted"));
    }
}
