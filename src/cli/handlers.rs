use crate::cli::args::{
    AcquireArgs, CliCompression, CliImageFormat, CliSplitSize, ConvertArgs, ListArgs, VerifyArgs,
};
use crate::discovery::{DeviceScanner, SafetyChecker};
use crate::engines::{EwfAcquireEngine, FormatConverter, MultiHasher, RescueAcquireEngine};
use crate::models::{
    case::CaseMetadata,
    config::{AcquisitionConfig, CompressionLevel, ImageFormat, SplitSize},
    device::{BlockDevice, DeviceSafety},
    telemetry::AcquisitionStatus,
};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
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
    let devices = DeviceScanner::scan_devices().unwrap_or_default();
    let target_dev = if let Some(d) = devices
        .into_iter()
        .find(|d| d.path == args.device || d.name == args.device)
    {
        d
    } else if Path::new(&args.device).exists() {
        let path = Path::new(&args.device);
        let meta = std::fs::metadata(path)?;
        let size_bytes = meta.len();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("target")
            .to_string();

        BlockDevice {
            name: name.clone(),
            path: args.device.clone(),
            devlinks: Vec::new(),
            size_bytes,
            model: Some(format!("Source File/Disk {}", name)),
            vendor: Some("Generic".to_string()),
            serial: Some(format!("TEST_{}", name.to_uppercase())),
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
    } else {
        return Err(format!("Target device or file not found: {}", args.device).into());
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
            EwfAcquireEngine::run_acquisition(
                dev_clone,
                case_clone,
                cfg_clone,
                prog_tx,
                abort_clone,
            )
            .await
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
            println!("[+] Acquisition and verification completed successfully!");
            Ok(())
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

pub async fn handle_verify(args: VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
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
