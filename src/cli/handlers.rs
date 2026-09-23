use crate::cli::args::{
    AcquireArgs, CliCompression, CliImageFormat, CliSplitSize, ConvertArgs, ListArgs, VerifyArgs,
};
use crate::discovery::{DeviceScanner, SafetyChecker};
use crate::engines::{
    EwfAcquireEngine, FormatConverter, MultiHasher, RawAcquireEngine, RescueAcquireEngine,
};
use crate::models::{
    case::CaseMetadata,
    config::{AcquisitionConfig, CompressionLevel, ImageFormat, SplitSize},
    device::{BlockDevice, DeviceSafety},
    info_report::VerificationStatus,
    telemetry::AcquisitionStatus,
};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

pub async fn handle_list(args: ListArgs) -> Result<(), Box<dyn std::error::Error>> {
    let devices = DeviceScanner::scan_devices()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&devices)?);
        return Ok(());
    }

    println!("\n╔════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                 DFDISK STORAGE MEDIA EXPLORER                                      ║");
    println!("╠══════════════╦══════════════╦═════════════════════════════╦════════════════════╦══════════╦════════════╣");
    println!("║ DEVICE       ║ TYPE / BUS   ║ VENDOR / MODEL              ║ SERIAL NUMBER      ║ SIZE     ║ STATUS     ║");
    println!("╠══════════════╬══════════════╬═════════════════════════════╬════════════════════╬══════════╬════════════╣");

    for dev in &devices {
        let (status_str, _color) = match &dev.safety {
            DeviceSafety::Safe => ("SAFE", "32"),
            DeviceSafety::Mounted(_) => ("MOUNTED", "33"),
            DeviceSafety::SystemDisk(_) => ("SYSTEM", "31"),
        };

        println!(
            "║ {:<12} ║ {:<12} ║ {:<27} ║ {:<18} ║ {:<8} ║ {:<10} ║",
            dev.path,
            dev.bus_type,
            truncate(&dev.display_name(), 27),
            truncate(&dev.display_serial(), 18),
            dev.human_size(),
            status_str
        );
    }

    println!("╚══════════════╩══════════════╩═════════════════════════════╩════════════════════╩══════════╩════════════╝\n");
    Ok(())
}

pub async fn handle_acquire(args: AcquireArgs) -> Result<(), Box<dyn std::error::Error>> {
    let target_path = Path::new(&args.device);
    let canonical_path =
        std::fs::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf());
    let canonical_str = canonical_path.to_string_lossy().to_string();

    if !target_path.exists() && !canonical_path.exists() {
        return Err(format!("Target device or file not found: {}", args.device).into());
    }

    let meta = std::fs::symlink_metadata(&canonical_path).map_err(|e| {
        format!(
            "Failed to inspect target {}: {}",
            canonical_path.display(),
            e
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let ft = meta.file_type();
        if !ft.is_file() && !ft.is_block_device() {
            return Err(format!(
                "Critical Safety Error: Target {} is neither a regular file nor a recognized block device.",
                args.device
            ).into());
        }
    }

    #[cfg(not(unix))]
    {
        if !meta.is_file() {
            return Err(format!(
                "Critical Safety Error: Target {} is not a regular file.",
                args.device
            )
            .into());
        }
    }

    let devices = DeviceScanner::scan_devices().unwrap_or_default();

    let mut matched_device: Option<BlockDevice> = None;

    // 1. Check for whole disks
    for dev in &devices {
        let is_dev_match = dev.path == args.device
            || dev.name == args.device
            || dev.path == canonical_str
            || dev
                .devlinks
                .iter()
                .any(|link| link == &args.device || link == &canonical_str);

        let is_canonical_match =
            std::fs::canonicalize(&dev.path).ok() == Some(canonical_path.clone());

        if is_dev_match || is_canonical_match {
            matched_device = Some(dev.clone());
            break;
        }
    }

    // 2. Check for partitions on all discovered disks
    if matched_device.is_none() {
        for dev in &devices {
            for part in &dev.partitions {
                let is_part_match = part.path == args.device
                    || part.name == args.device
                    || part.path == canonical_str;
                let is_part_canonical =
                    std::fs::canonicalize(&part.path).ok() == Some(canonical_path.clone());

                if is_part_match || is_part_canonical {
                    let part_mounts = if let Some(ref m) = part.mountpoint {
                        vec![m.clone()]
                    } else {
                        Vec::new()
                    };
                    let direct_part_safety = SafetyChecker::evaluate_safety(&part_mounts, false);

                    // Inherit parent system disk safety if parent is system
                    let safety = match (&dev.safety, direct_part_safety) {
                        (DeviceSafety::SystemDisk(parent_mounts), _) => {
                            DeviceSafety::SystemDisk(parent_mounts.clone())
                        }
                        (_, DeviceSafety::SystemDisk(mounts)) => DeviceSafety::SystemDisk(mounts),
                        (_, DeviceSafety::Mounted(mounts)) => DeviceSafety::Mounted(mounts),
                        (DeviceSafety::Mounted(parent_mounts), DeviceSafety::Safe) => {
                            DeviceSafety::Mounted(parent_mounts.clone())
                        }
                        (DeviceSafety::Safe, DeviceSafety::Safe) => DeviceSafety::Safe,
                    };

                    matched_device = Some(BlockDevice {
                        name: part.name.clone(),
                        path: part.path.clone(),
                        devlinks: Vec::new(),
                        size_bytes: part.size_bytes,
                        model: dev.model.clone(),
                        vendor: dev.vendor.clone(),
                        serial: dev.serial.clone(),
                        wwn: dev.wwn.clone(),
                        revision: dev.revision.clone(),
                        bus_type: dev.bus_type.clone(),
                        is_rotational: dev.is_rotational,
                        is_removable: dev.is_removable,
                        is_read_only: part.is_read_only,
                        logical_sector_size: dev.logical_sector_size,
                        physical_sector_size: dev.physical_sector_size,
                        partition_table_type: None,
                        partitions: Vec::new(),
                        mountpoints: part_mounts,
                        safety,
                        smart: dev.smart.clone(),
                    });
                    break;
                }
            }
            if matched_device.is_some() {
                break;
            }
        }
    }

    let target_dev = if let Some(d) = matched_device {
        d
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let ft = meta.file_type();
            if ft.is_block_device() {
                return Err(format!(
                    "Critical Safety Error: Block device {} could not be verified by system discovery. Refusing to acquire unverified block device in CLI mode.",
                    args.device
                ).into());
            }
        }

        // Regular file fallback for testing/conversion
        let size_bytes = meta.len();
        let name = target_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("target")
            .to_string();

        BlockDevice {
            name: name.clone(),
            path: args.device.clone(),
            devlinks: Vec::new(),
            size_bytes,
            model: Some(format!("Source File/Image {}", name)),
            vendor: Some("Generic".to_string()),
            serial: Some(format!("FILE_{}", name.to_uppercase())),
            wwn: None,
            revision: None,
            bus_type: "FILE/IMAGE".to_string(),
            is_rotational: Some(false),
            is_removable: false,
            is_read_only: false,
            logical_sector_size: 512,
            physical_sector_size: 512,
            partition_table_type: None,
            partitions: Vec::new(),
            mountpoints: Vec::new(),
            safety: DeviceSafety::Safe,
            smart: None,
        }
    };

    println!("\n[+] Target Device Selected: {}", target_dev.path);
    println!("    Vendor/Model : {}", target_dev.display_name());
    println!("    Serial Number: {}", target_dev.display_serial());
    println!("    Total Size   : {}", target_dev.human_size());

    // Safety checks
    match &target_dev.safety {
        DeviceSafety::SystemDisk(mounts) => {
            eprintln!(
                "\n[!] CRITICAL SAFETY WARNING: {} is a SYSTEM DISK!",
                target_dev.path
            );
            eprintln!("    Active system mountpoints: {}", mounts.join(", "));
            eprintln!("    Acquiring live system disks can cause evidence corruption. Refusing in CLI mode.");
            return Err("Safety check failed: System disk detected.".into());
        }
        DeviceSafety::Mounted(mounts) => {
            if args.auto_unmount {
                println!("[*] Auto-unmounting partitions: {}", mounts.join(", "));
                SafetyChecker::unmount_all(&target_dev.mountpoints)
                    .map_err(|e| format!("Unmount failed: {}", e))?;
                println!("[+] Successfully unmounted all partitions.");
            } else {
                eprintln!(
                    "\n[!] WARNING: Device {} has mounted partitions: {}",
                    target_dev.path,
                    mounts.join(", ")
                );
                eprintln!("    Pass --auto-unmount or use the TUI interface to safely unmount.");
                return Err("Safety check failed: Partitions are mounted.".into());
            }
        }
        DeviceSafety::Safe => {
            println!("[+] Device safety check passed: Safe for acquisition.");
        }
    }

    let case = CaseMetadata {
        case_number: args.case,
        location_ea: args.ea,
        evidence_number: args.evidence,
        authority: args.authority,
        examiner: args.examiner,
        description: args.description,
        notes: args.notes,
    };

    let compression = match args.compression {
        CliCompression::None => CompressionLevel::None,
        CliCompression::Fast => CompressionLevel::Fast,
        CliCompression::Best => CompressionLevel::Best,
    };

    let split_size = match args.split {
        CliSplitSize::None => SplitSize::None,
        CliSplitSize::TwoGb => SplitSize::TwoGb,
        CliSplitSize::FourGb => SplitSize::FourGb,
    };

    let format = match args.format {
        CliImageFormat::E01 => ImageFormat::E01,
        CliImageFormat::Raw => ImageFormat::Raw,
    };

    let config = AcquisitionConfig {
        format,
        output_dir: args.output_dir,
        compression,
        split_size,
        calc_md5: true,
        calc_sha1: true,
        calc_sha256: true,
        error_retries: args.retries,
        wipe_bad_sectors: true,
        rescue_mode: args.rescue,
        resume: args.resume,
    };

    std::fs::create_dir_all(&config.output_dir)?;

    let base_name = case.generate_base_filename(&target_dev.display_serial());
    println!("[+] Output Base Name: {}", base_name);
    println!("[+] Starting forensic acquisition engine...\n");

    let (prog_tx, mut prog_rx) = mpsc::channel(100);
    let abort_flag = Arc::new(AtomicBool::new(false));

    let dev_clone = target_dev.clone();
    let case_clone = case.clone();
    let cfg_clone = config.clone();
    let abort_clone = abort_flag.clone();

    let join_handle = tokio::spawn(async move {
        if cfg_clone.rescue_mode {
            RescueAcquireEngine::run_rescue(dev_clone, case_clone, cfg_clone, prog_tx, abort_clone)
                .await
        } else {
            match cfg_clone.format {
                ImageFormat::E01 => {
                    EwfAcquireEngine::run_acquisition(
                        dev_clone,
                        case_clone,
                        cfg_clone,
                        prog_tx,
                        abort_clone,
                    )
                    .await
                }
                ImageFormat::Raw => {
                    RawAcquireEngine::run_acquisition(
                        dev_clone,
                        case_clone,
                        cfg_clone,
                        prog_tx,
                        abort_clone,
                    )
                    .await
                }
            }
        }
    });

    while let Some(prog) = prog_rx.recv().await {
        print!(
            "\r[*] Phase: {:<10} │ Progress: {:>5.1}% │ Speed: {:>10} │ ETA: {:>8} │ Errors: {:<4}",
            prog.status.display_str(),
            prog.percentage,
            prog.human_speed(),
            prog.human_eta(),
            prog.bad_sectors
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());

        if prog.status == AcquisitionStatus::Completed
            || matches!(prog.status, AcquisitionStatus::Failed(_))
        {
            break;
        }
    }
    println!("\n");

    let report_res = join_handle.await?;
    match report_res {
        Ok(report) => {
            println!("{}", report.render_text());
            match report.verification_status {
                VerificationStatus::Verified => {
                    println!("[+] Acquisition and verification completed successfully!");
                    Ok(())
                }
                VerificationStatus::DamagedMedia => {
                    println!(
                        "[!] Resilient acquisition completed with {} bad/unreadable sectors.",
                        report.bad_sectors_count
                    );
                    println!(
                        "    Destination image hashes recorded. Live source verification skipped due to media defects."
                    );
                    Ok(())
                }
                VerificationStatus::Mismatch => {
                    eprintln!("[!] CRITICAL FORENSIC ERROR: Cryptographic verification failed!");
                    eprintln!("    Destination image hashes do NOT match source hashes. Evidence integrity compromised.");
                    Err("Cryptographic verification failed: hash mismatch detected.".into())
                }
                VerificationStatus::Failed => {
                    eprintln!("[!] Acquisition finished, but cryptographic verification failed or could not be completed.");
                    Err("Verification failed.".into())
                }
                VerificationStatus::NotVerified => {
                    if report.verification_passed {
                        println!("[+] Acquisition and verification completed successfully!");
                    } else {
                        println!("[+] Acquisition completed (verification not requested).");
                    }
                    Ok(())
                }
            }
        }
        Err(e) => {
            eprintln!("[!] Acquisition failed: {}", e);
            Err(e.into())
        }
    }
}

pub async fn handle_convert(args: ConvertArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n[*] Forensic Format Converter");
    println!("    Source: {}", args.source.display());
    println!("    Target: {:?}", args.to);

    std::fs::create_dir_all(&args.output_dir)?;

    let (prog_tx, mut prog_rx) = mpsc::channel(50);
    let abort = Arc::new(AtomicBool::new(false));

    let src = args.source.clone();
    let out = args.output_dir.clone();
    let to_fmt = args.to;

    let case = if args.case.is_some() || args.evidence.is_some() {
        Some(CaseMetadata {
            case_number: args.case.unwrap_or_else(|| "CONV001".to_string()),
            evidence_number: args.evidence.unwrap_or_else(|| "e01".to_string()),
            ..Default::default()
        })
    } else {
        None
    };

    let join_handle = tokio::spawn(async move {
        match to_fmt {
            CliImageFormat::E01 => {
                FormatConverter::raw_to_e01(
                    &src,
                    &out,
                    case,
                    CompressionLevel::Fast,
                    SplitSize::TwoGb,
                    Some(prog_tx),
                    Some(abort),
                )
                .await
            }
            CliImageFormat::Raw => {
                FormatConverter::e01_to_raw(&src, &out, Some(prog_tx), Some(abort)).await
            }
        }
    });

    while let Some(prog) = prog_rx.recv().await {
        print!(
            "\r[*] Converting: {:>5.1}% │ Speed: {:>10} │ {}",
            prog.percentage,
            prog.human_speed(),
            prog.status_message
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    println!("\n");

    let out_path = join_handle.await??;
    println!("[+] Converted file saved to: {}", out_path.display());
    Ok(())
}

pub fn is_ewf_image_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ext == "e01" || ext == "s01" {
        return true;
    }

    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut magic = [0u8; 6];
        if f.read_exact(&mut magic).is_ok() && &magic == b"EVF\x09\x0d\x0a" {
            return true;
        }
    }

    false
}

pub async fn handle_verify_ewf(args: VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n[*] Forensic E01 Decoded Stream Verifier (ewfverify)");
    println!("    Target EWF Segment: {}", args.image.display());

    let mut cmd = tokio::process::Command::new("ewfverify");
    cmd.arg("-d").arg("md5,sha1,sha256");
    cmd.arg(&args.image);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        format!(
            "Failed to spawn ewfverify (ensure libewf is installed): {}",
            e
        )
    })?;

    let stdout = child
        .stdout
        .take()
        .ok_or("Failed to capture ewfverify stdout")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Failed to capture ewfverify stderr")?;

    let mut reader_out = tokio::io::BufReader::new(stdout).lines();
    let mut reader_err = tokio::io::BufReader::new(stderr).lines();

    let regex_md5 =
        regex::Regex::new(r"MD5 hash calculated over data:\s*([a-fA-F0-9]{32})").unwrap();
    let regex_sha1 =
        regex::Regex::new(r"SHA1 hash calculated over data:\s*([a-fA-F0-9]{40})").unwrap();
    let regex_sha256 =
        regex::Regex::new(r"SHA256 hash calculated over data:\s*([a-fA-F0-9]{64})").unwrap();

    let mut calc_md5 = None;
    let mut calc_sha1 = None;
    let mut calc_sha256 = None;
    let mut verify_success = false;

    let mut out_closed = false;
    let mut err_closed = false;

    while !out_closed || !err_closed {
        tokio::select! {
            line = reader_out.next_line(), if !out_closed => {
                match line {
                    Ok(Some(l)) => {
                        let text = l.trim();
                        if text.contains("ewfverify: SUCCESS") {
                            verify_success = true;
                        }
                        if let Some(caps) = regex_md5.captures(text) {
                            calc_md5 = Some(caps[1].to_lowercase());
                        }
                        if let Some(caps) = regex_sha1.captures(text) {
                            calc_sha1 = Some(caps[1].to_lowercase());
                        }
                        if let Some(caps) = regex_sha256.captures(text) {
                            calc_sha256 = Some(caps[1].to_lowercase());
                        }
                    }
                    Ok(None) | Err(_) => out_closed = true,
                }
            }
            line = reader_err.next_line(), if !err_closed => {
                match line {
                    Ok(Some(l)) => {
                        let text = l.trim();
                        if !text.is_empty() {
                            eprintln!("[ewfverify] {}", text);
                        }
                    }
                    Ok(None) | Err(_) => err_closed = true,
                }
            }
        }
    }

    let status = child.wait().await?;
    println!("\n================================================================================");
    println!(
        "  MD5 (decoded data)   : {}",
        calc_md5.as_deref().unwrap_or("N/A")
    );
    println!(
        "  SHA-1 (decoded data) : {}",
        calc_sha1.as_deref().unwrap_or("N/A")
    );
    println!(
        "  SHA-256 (decoded data): {}",
        calc_sha256.as_deref().unwrap_or("N/A")
    );
    println!("================================================================================");

    let any_checked = args.md5.is_some() || args.sha1.is_some() || args.sha256.is_some();
    let mut all_match = true;

    if let (Some(exp), Some(calc)) = (&args.md5, &calc_md5) {
        if exp.eq_ignore_ascii_case(calc) {
            println!("  [+] MD5 MATCH");
        } else {
            println!("  [!] MD5 MISMATCH! Expected: {}", exp);
            all_match = false;
        }
    }
    if let (Some(exp), Some(calc)) = (&args.sha1, &calc_sha1) {
        if exp.eq_ignore_ascii_case(calc) {
            println!("  [+] SHA-1 MATCH");
        } else {
            println!("  [!] SHA-1 MISMATCH! Expected: {}", exp);
            all_match = false;
        }
    }
    if let (Some(exp), Some(calc)) = (&args.sha256, &calc_sha256) {
        if exp.eq_ignore_ascii_case(calc) {
            println!("  [+] SHA-256 MATCH");
        } else {
            println!("  [!] SHA-256 MISMATCH! Expected: {}", exp);
            all_match = false;
        }
    }

    if !status.success() || !verify_success {
        println!("\n[!] VERIFICATION RESULT: FAILED (EWF structure or media checksum error)");
        return Err("EWF image verification failed".into());
    }

    if !any_checked {
        println!("\n[*] HASH COMPUTATION COMPLETE (No verification hashes supplied, EWF structure verified)");
        Ok(())
    } else if all_match {
        println!("\n[+] VERIFICATION RESULT: PASSED");
        Ok(())
    } else {
        println!("\n[!] VERIFICATION RESULT: FAILED (INTEGRITY ERROR)");
        Err("Cryptographic hash mismatch".into())
    }
}

pub async fn handle_verify(args: VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    if is_ewf_image_file(&args.image) {
        return handle_verify_ewf(args).await;
    }

    println!("\n[*] Cryptographic Image Integrity Verifier");
    println!("    Image: {}", args.image.display());

    let (prog_tx, mut prog_rx) = mpsc::channel(50);
    let img = args.image.clone();

    let join_handle = tokio::spawn(async move {
        MultiHasher::hash_stream(&img, true, true, true, Some(prog_tx)).await
    });

    while let Some(prog) = prog_rx.recv().await {
        print!(
            "\r[*] Hashing: {:>5.1}% │ Speed: {:>10} MB/s",
            prog.percentage,
            (prog.speed_bps / (1024.0 * 1024.0)) as u64
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    println!("\n");

    let hashes = join_handle.await??;
    println!("================================================================================");
    println!("  MD5    : {}", hashes.md5.as_deref().unwrap_or("N/A"));
    println!("  SHA-1  : {}", hashes.sha1.as_deref().unwrap_or("N/A"));
    println!("  SHA-256: {}", hashes.sha256.as_deref().unwrap_or("N/A"));
    println!("================================================================================");

    let any_checked = args.md5.is_some() || args.sha1.is_some() || args.sha256.is_some();
    let mut all_match = true;
    if let (Some(exp), Some(calc)) = (&args.md5, &hashes.md5) {
        if exp.eq_ignore_ascii_case(calc) {
            println!("  [+] MD5 MATCH");
        } else {
            println!("  [!] MD5 MISMATCH! Expected: {}", exp);
            all_match = false;
        }
    }
    if let (Some(exp), Some(calc)) = (&args.sha1, &hashes.sha1) {
        if exp.eq_ignore_ascii_case(calc) {
            println!("  [+] SHA-1 MATCH");
        } else {
            println!("  [!] SHA-1 MISMATCH! Expected: {}", exp);
            all_match = false;
        }
    }
    if let (Some(exp), Some(calc)) = (&args.sha256, &hashes.sha256) {
        if exp.eq_ignore_ascii_case(calc) {
            println!("  [+] SHA-256 MATCH");
        } else {
            println!("  [!] SHA-256 MISMATCH! Expected: {}", exp);
            all_match = false;
        }
    }

    if !any_checked {
        println!("\n[*] HASH COMPUTATION COMPLETE (No verification hashes supplied)");
        Ok(())
    } else if all_match {
        println!("\n[+] VERIFICATION RESULT: PASSED");
        Ok(())
    } else {
        println!("\n[!] VERIFICATION RESULT: FAILED (INTEGRITY ERROR)");
        Err("Cryptographic hash mismatch".into())
    }
}

pub(crate) fn truncate(s: &str, max_len: usize) -> String {
    let char_count = s.chars().count();
    if char_count > max_len {
        if max_len <= 3 {
            s.chars().take(max_len).collect()
        } else {
            let keep = max_len.saturating_sub(3);
            let prefix: String = s.chars().take(keep).collect();
            format!("{}...", prefix)
        }
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_ascii() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("test", 4), "test");
        assert_eq!(truncate("test", 3), "tes");
        assert_eq!(truncate("test", 1), "t");
        assert_eq!(truncate("test", 0), "");
    }

    #[test]
    fn test_truncate_utf8_multibyte() {
        // German umlauts (2 bytes each)
        let s = "äöüäöüäöü";
        assert_eq!(truncate(s, 6), "äöü...");
        assert_eq!(truncate(s, 9), "äöüäöüäöü");

        // Cyrillic (2 bytes each)
        let cyr = "Привет мир";
        assert_eq!(truncate(cyr, 8), "Приве...");

        // Japanese / Chinese (3 bytes each)
        let cjk = "こんにちは世界";
        assert_eq!(truncate(cjk, 5), "こん...");

        // Emoji (4 bytes each)
        let emoji = "🚀🔒🛡️⚡🎯";
        let truncated = truncate(emoji, 4);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_truncate_stress_adversarial_utf8() {
        let samples = [
            "",
            "a",
            "ab",
            "abc",
            "abcd",
            "ä",
            "äöü",
            "äöüäöü",
            "こんにちは世界",
            "Привет, мир! Как дела?",
            "🚀🔒🛡️⚡🎯🎉",
            "👨‍👩‍👧‍👦",
            "e\u{0301}a\u{0301}o\u{0301}",
            "العربية",
            "עִבְרִית",
            "Mix 🚀 ä 世 test 123",
            "   spaces   ",
            "...",
            "......",
        ];

        for s in &samples {
            for max_len in 0..=30 {
                let res = truncate(s, max_len);
                let res_chars = res.chars().count();
                let orig_chars = s.chars().count();

                if orig_chars <= max_len {
                    assert_eq!(&res, *s, "Expected full string when orig_chars <= max_len");
                } else {
                    assert_eq!(
                        res_chars, max_len,
                        "Truncated string char count must equal max_len"
                    );
                    if max_len > 3 {
                        assert!(
                            res.ends_with("..."),
                            "Must end with ellipsis when max_len > 3"
                        );
                    }
                }
            }
        }
    }
}
