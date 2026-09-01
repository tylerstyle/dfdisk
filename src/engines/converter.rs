use crate::models::{
    case::CaseMetadata,
    config::{CompressionLevel, SplitSize},
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct FormatConverter;

impl FormatConverter {
    /// Converts a RAW disk image (.dd, .raw, .img) to E01 format
    pub async fn raw_to_e01(
        source_raw_path: &Path,
        output_dir: &Path,
        case: Option<CaseMetadata>,
        compression: CompressionLevel,
        split_size: SplitSize,
        progress_tx: Option<mpsc::Sender<ProgressTelemetry>>,
        abort_flag: Option<Arc<AtomicBool>>,
    ) -> Result<PathBuf, String> {
        let file_stem_raw = source_raw_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("converted_image");

        let clean_stem = strip_known_extensions(file_stem_raw);
        let target_base = output_dir.join(&clean_stem);
        let target_str = target_base.to_string_lossy().to_string();

        let case_meta = case.unwrap_or_default();

        let mut cmd = Command::new("ewfacquire");
        cmd.arg("-u");
        cmd.arg("-C").arg(&case_meta.case_number);
        cmd.arg("-E").arg(&case_meta.evidence_number);
        cmd.arg("-e").arg(&case_meta.examiner);
        cmd.arg("-D").arg(&case_meta.description);
        cmd.arg("-f").arg("encase6");
        cmd.arg("-c").arg(compression.as_ewf_arg());
        cmd.arg("-S").arg(split_size.as_ewf_arg());
        cmd.arg("-d").arg("sha1");
        cmd.arg("-d").arg("sha256");
        cmd.arg("-t").arg(&target_str);
        cmd.arg(source_raw_path);

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn ewfacquire: {}", e))?;

        let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;
        let mut reader = BufReader::new(stderr).lines();

        let regex_pct = Regex::new(r"(\d+(?:\.\d+)?)%").unwrap();
        let regex_speed = Regex::new(r"(\d+(?:\.\d+)?)\s*(?:MiB/s|MB/s)").unwrap();

        while let Ok(Some(line)) = reader.next_line().await {
            if let Some(ref abort) = abort_flag {
                if abort.load(Ordering::Relaxed) {
                    let _ = child.kill().await;
                    return Err("Conversion aborted by user.".to_string());
                }
            }

            let text = line.trim();
            if let Some(ref tx) = progress_tx {
                let mut tel = ProgressTelemetry {
                    status: AcquisitionStatus::Imaging,
                    status_message: text.to_string(),
                    ..Default::default()
                };

                if let Some(caps) = regex_pct.captures(text) {
                    if let Ok(pct) = caps[1].parse::<f64>() {
                        tel.percentage = pct;
                    }
                }
                if let Some(caps) = regex_speed.captures(text) {
                    if let Ok(spd) = caps[1].parse::<f64>() {
                        tel.speed_bps = spd * 1024.0 * 1024.0;
                    }
                }
                let _ = tx.send(tel).await;
            }
        }

        let status = child
            .wait()
            .await
            .map_err(|e| format!("Failed to wait on ewfacquire: {}", e))?;

        if status.success() {
            Ok(output_dir.join(format!("{}.E01", clean_stem)))
        } else {
            Err(format!(
                "Conversion failed with exit code {:?}",
                status.code()
            ))
        }
    }

    /// Converts an E01 image to a RAW (.raw) image using ewfexport
    pub async fn e01_to_raw(
        source_e01_path: &Path,
        output_dir: &Path,
        progress_tx: Option<mpsc::Sender<ProgressTelemetry>>,
        abort_flag: Option<Arc<AtomicBool>>,
    ) -> Result<PathBuf, String> {
        let file_stem_raw = source_e01_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("exported_image");

        let clean_stem = strip_known_extensions(file_stem_raw);

        // ewfexport appends .raw automatically to target_base
        let target_base = output_dir.join(&clean_stem);
        let target_str = target_base.to_string_lossy().to_string();

        let mut cmd = Command::new("ewfexport");
        cmd.arg("-u"); // Unattended
        cmd.arg("-f").arg("raw"); // Output format raw
        cmd.arg("-t").arg(&target_str);
        cmd.arg(source_e01_path);

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn ewfexport: {}", e))?;

        let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;
        let mut reader = BufReader::new(stderr).lines();

        let regex_pct = Regex::new(r"(\d+(?:\.\d+)?)%").unwrap();

        while let Ok(Some(line)) = reader.next_line().await {
            if let Some(ref abort) = abort_flag {
                if abort.load(Ordering::Relaxed) {
                    let _ = child.kill().await;
                    return Err("Export aborted by user.".to_string());
                }
            }

            let text = line.trim();
            if let Some(ref tx) = progress_tx {
                let mut tel = ProgressTelemetry {
                    status: AcquisitionStatus::Imaging,
                    status_message: text.to_string(),
                    ..Default::default()
                };

                if let Some(caps) = regex_pct.captures(text) {
                    if let Ok(pct) = caps[1].parse::<f64>() {
                        tel.percentage = pct;
                    }
                }
                let _ = tx.send(tel).await;
            }
        }

        let status = child
            .wait()
            .await
            .map_err(|e| format!("Failed to wait on ewfexport: {}", e))?;

        if status.success() {
            Ok(output_dir.join(format!("{}.raw", clean_stem)))
        } else {
            Err(format!(
                "E01 to RAW export failed with exit code {:?}",
                status.code()
            ))
        }
    }
}

fn strip_known_extensions(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.ends_with(".raw")
        || lower.ends_with(".dd")
        || lower.ends_with(".img")
        || lower.ends_with(".e01")
    {
        let (stem, _) = name.rsplit_once('.').unwrap_or((name, ""));
        stem.to_string()
    } else {
        name.to_string()
    }
}
