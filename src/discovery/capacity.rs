//! Capacity of the source as the drive reports it and areas hidden from the
//! operating system (§7, R6): ATA `hdparm -N` (READ NATIVE MAX ADDRESS, no
//! modification) and `hdparm --dco-identify` (DEVICE CONFIGURATION
//! IDENTIFY), NVMe `nvme id-ns -o json` (IDENTIFY NAMESPACE).
//!
//! Every query goes to the physical disk of the source (the disk itself, or
//! the single disk under a partition, dm or md source, R6) through a
//! [`ToolRunner`](crate::discovery::runner::ToolRunner) with a 15 s timeout
//! each; the stop control is honoured and every command is recorded. Nothing
//! for regular files and loop devices. dfdisk never changes HPA or DCO: `-N`
//! is only ever passed without a value.
//!
//! What the tools print decides, never their exit status alone: hdparm exits
//! 0 when it could not identify the drive at all (it then prints no "max
//! sectors" line; verified with hdparm 9.65), so a missing line is "unknown",
//! never "no HPA". Values that do not match the kernel's size of the disk are
//! reported but not trusted (a USB bridge may answer for itself).
//!
//! The session calls [`probe`] at step 6 (after the audit "started" record,
//! R7) and in `check`; the TUI calls it on explicit request only, never in
//! discovery scans.

use crate::discovery::runner::{physical_disk, PhysicalDisk, ProbeEnv, ToolRun};
use crate::engines::process::StopControl;
use crate::models::capacity::{AtaCapacity, CapacityInfo, NvmeCapacity};
use crate::models::identity::SourceIdentity;
use crate::models::provenance::ProvenanceRecorder;
use serde_json::Value;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Timeout of each capacity probe command.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// How hdparm judged the visible versus the native maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeMaxState {
    /// "HPA is enabled"
    HpaEnabled,
    /// "HPA is disabled"
    HpaDisabled,
    /// "ACCESSIBLE MAX ADDRESS enabled" (ACS-3 successor of HPA)
    AmaxEnabled,
    /// "ACCESSIBLE MAX ADDRESS disabled"
    AmaxDisabled,
    /// "HPA setting seems invalid": visible above native
    Invalid,
}

/// The "max sectors" line of `hdparm -N`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeMax {
    /// Sectors the drive currently reports (IDENTIFY), what the OS sees
    pub visible_sectors: u64,
    /// READ NATIVE MAX ADDRESS (+1): sectors including an HPA
    pub native_sectors: u64,
    pub state: NativeMaxState,
}

/// Parse `hdparm -N` standard output (hdparm 9.x):
/// ` max sectors   = 976771055/976773168, HPA is enabled`. `None` when the
/// line is missing (drive not identified, command failed).
pub fn parse_hdparm_native_max(stdout: &str) -> Option<NativeMax> {
    stdout.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("max sectors")?;
        let rest = rest.trim_start().strip_prefix('=')?.trim_start();
        let (visible, rest) = split_number(rest)?;
        let rest = rest.strip_prefix('/')?;
        let (native, rest) = split_number(rest)?;
        let state = if rest.contains("HPA setting seems invalid") {
            NativeMaxState::Invalid
        } else if rest.contains("ACCESSIBLE MAX ADDRESS enabled") {
            NativeMaxState::AmaxEnabled
        } else if rest.contains("ACCESSIBLE MAX ADDRESS disabled") {
            NativeMaxState::AmaxDisabled
        } else if rest.contains("HPA is enabled") {
            NativeMaxState::HpaEnabled
        } else if rest.contains("HPA is disabled") {
            NativeMaxState::HpaDisabled
        } else {
            return None;
        };
        Some(NativeMax {
            visible_sectors: visible,
            native_sectors: native,
            state,
        })
    })
}

fn split_number(s: &str) -> Option<(u64, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let n = s[..end].parse().ok()?;
    Some((n, &s[end..]))
}

/// What `hdparm --dco-identify` reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcoIdentify {
    /// "Real max sectors" (maximum LBA + 1 without the overlay)
    pub real_max_sectors: u64,
    /// "DCO Checksum verified." / "DCO Checksum FAILED!"; `None` if neither
    pub checksum_ok: Option<bool>,
}

/// Parse `hdparm --dco-identify` standard output. `None` when there is no
/// "Real max sectors" line (DCO unsupported, frozen, or the command failed).
pub fn parse_hdparm_dco(stdout: &str) -> Option<DcoIdentify> {
    let real = stdout.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("Real max sectors:")?;
        split_number(rest.trim_start()).map(|(n, _)| n)
    })?;
    let checksum_ok = if stdout.contains("DCO Checksum verified.") {
        Some(true)
    } else if stdout.contains("DCO Checksum FAILED!") {
        Some(false)
    } else {
        None
    };
    Some(DcoIdentify {
        real_max_sectors: real,
        checksum_ok,
    })
}

/// Parse `nvme id-ns -o json` (nvme-cli 1.x and 2.x). The logical block size
/// is that of the format in use (the entry marked `in_use`, else `flbas`).
pub fn parse_nvme_id_ns(json: &str) -> Result<NvmeCapacity, String> {
    let v: Value = serde_json::from_str(json.trim())
        .map_err(|e| format!("nvme id-ns output is not JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!(
            "nvme id-ns reported an error: {}",
            err.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| err.to_string())
        ));
    }
    let num = |key: &str| -> Option<u64> {
        match v.get(key)? {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    };
    let nsze = num("nsze");
    if nsze.is_none() {
        return Err("nvme id-ns output has no namespace size (nsze)".into());
    }
    let lbafs = v.get("lbafs").and_then(Value::as_array);
    let in_use = lbafs.and_then(|l| {
        l.iter().find(|f| {
            f.get("in_use")
                .is_some_and(|u| u.as_u64() == Some(1) || u.as_bool() == Some(true))
        })
    });
    let by_flbas = num("flbas").and_then(|flbas| {
        // Format index: bits 3:0, extended by bits 6:5 when more than 16 formats
        let index = (flbas & 0x0f) | (((flbas >> 5) & 0x03) << 4);
        lbafs.and_then(|l| l.get(index as usize))
    });
    let lba_bytes = in_use
        .or(by_flbas)
        .and_then(|f| f.get("ds"))
        .and_then(Value::as_u64)
        .filter(|ds| (9..=16).contains(ds))
        .map(|ds| 1u32 << ds);
    Ok(NvmeCapacity {
        nsze,
        ncap: num("ncap"),
        nuse: num("nuse"),
        lba_bytes,
    })
}

/// Capacity and hidden areas of the disk the source is stored on. Never
/// fails: what could not be probed is stated in `method` / `errors`.
pub async fn probe(
    identity: &SourceIdentity,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> CapacityInfo {
    probe_with(&ProbeEnv::host(), identity, control, recorder).await
}

/// [`probe`] in a given environment (tests: fake sysfs, scripted tools).
pub async fn probe_with(
    env: &ProbeEnv<'_>,
    identity: &SourceIdentity,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> CapacityInfo {
    let disk = match physical_disk(env, identity) {
        Ok(d) => d,
        Err(reason) => return CapacityInfo::not_probed(identity.size_bytes, reason),
    };
    let disk_bytes = env
        .sys
        .attr(&disk.kname, "size")
        .and_then(|s| s.parse::<u64>().ok())
        .map(|s| s.saturating_mul(512));
    let logical = env
        .sys
        .attr(&disk.kname, "queue/logical_block_size")
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&b| b >= 512)
        .unwrap_or(512);
    let mut info = match protocol(&disk) {
        DiskProtocol::Ata => probe_ata(env, &disk, disk_bytes, logical, control, recorder).await,
        DiskProtocol::Nvme => probe_nvme(env, &disk, disk_bytes, control, recorder).await,
        DiskProtocol::None(reason) => {
            return CapacityInfo {
                probed_device: None,
                ..CapacityInfo::not_probed(identity.size_bytes, reason)
            }
        }
    };
    info.reported_bytes = identity.size_bytes;
    info.probed_device = Some(disk.path.clone());
    if let Some(statement) = disk.r6_statement(identity) {
        info.method.push_str("; ");
        info.method.push_str(&statement);
    }
    info
}

enum DiskProtocol {
    Ata,
    Nvme,
    None(String),
}

fn protocol(disk: &PhysicalDisk) -> DiskProtocol {
    let transport = disk.transport.as_deref().unwrap_or("");
    if disk.kname.starts_with("nvme") || transport == "nvme" {
        DiskProtocol::Nvme
    } else if !(disk.kname.starts_with("sd") || disk.kname.starts_with("hd")) {
        DiskProtocol::None(format!(
            "HPA/DCO probing applies to ATA disks (hdparm) and NVMe namespaces (nvme-cli); {} is neither",
            disk.path
        ))
    } else if matches!(transport, "sas" | "fc" | "iscsi" | "spi" | "srp" | "ibp") {
        DiskProtocol::None(format!(
            "{} is attached over {transport}; HPA and DCO are ATA features that dfdisk does not query there",
            disk.path
        ))
    } else {
        DiskProtocol::Ata
    }
}

async fn run(
    env: &ProbeEnv<'_>,
    program: &str,
    args: &[&str],
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> ToolRun {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    env.runner
        .run(program, &args, PROBE_TIMEOUT, control, recorder)
        .await
}

/// Abort or force requested.
pub(crate) fn is_stopped(control: &StopControl) -> bool {
    let set = |f: &Option<std::sync::Arc<std::sync::atomic::AtomicBool>>| {
        f.as_ref().is_some_and(|f| f.load(Ordering::Relaxed))
    };
    set(&control.abort) || set(&control.force)
}

async fn probe_ata(
    env: &ProbeEnv<'_>,
    disk: &PhysicalDisk,
    disk_bytes: Option<u64>,
    logical: u64,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> CapacityInfo {
    let mut info = CapacityInfo {
        method: format!(
            "hdparm -N {p} (READ NATIVE MAX ADDRESS, read only); hdparm --dco-identify {p} (DEVICE CONFIGURATION IDENTIFY)",
            p = disk.path
        ),
        ..Default::default()
    };
    if disk.transport.as_deref() == Some("usb") {
        info.method
            .push_str("; sent through a USB bridge, which may not pass ATA commands on");
    }
    let mut ata = AtaCapacity::default();

    if is_stopped(control) {
        info.errors.push("aborted before the capacity probe".into());
        info.ata = Some(ata);
        return info;
    }
    let n = run(env, "hdparm", &["-N", &disk.path], control, recorder).await;
    let native = if n.start_error.is_some() || n.stopped {
        info.errors.push(n.describe_failure());
        None
    } else {
        let parsed = parse_hdparm_native_max(&n.stdout);
        if parsed.is_none() {
            info.errors.push(format!(
                "{} reported no max sectors (the drive was not identified or the command failed): {}",
                n.command_line(),
                n.first_message().unwrap_or_else(|| n.status.clone())
            ));
        }
        parsed
    };
    let mut trusted = false;
    if let Some(m) = native {
        ata.current_max_sectors = Some(m.visible_sectors);
        ata.native_max_sectors = Some(m.native_sectors);
        let visible_bytes = m.visible_sectors.saturating_mul(logical);
        if m.state == NativeMaxState::Invalid || m.visible_sectors > m.native_sectors {
            info.errors.push(format!(
                "hdparm reports an invalid HPA setting ({} visible sectors above the native maximum {}); the values are not trusted",
                m.visible_sectors, m.native_sectors
            ));
        } else if disk_bytes.is_some_and(|b| b != visible_bytes) {
            info.errors.push(format!(
                "hdparm reports {} visible sectors ({} bytes at {} bytes per sector) but the kernel reports {} bytes for {}; the values may come from a bridge and are not trusted",
                m.visible_sectors,
                visible_bytes,
                logical,
                disk_bytes.unwrap_or_default(),
                disk.path
            ));
        } else {
            trusted = true;
            ata.hpa_present = Some(m.native_sectors > m.visible_sectors);
        }
    }

    if is_stopped(control) {
        info.errors
            .push("aborted before the DCO query; DCO state unknown".into());
        info.ata = Some(ata);
        return info;
    }
    let d = run(
        env,
        "hdparm",
        &["--dco-identify", &disk.path],
        control,
        recorder,
    )
    .await;
    if d.start_error.is_some() || d.stopped {
        info.errors.push(d.describe_failure());
    } else {
        match parse_hdparm_dco(&d.stdout) {
            None => info.errors.push(format!(
                "{} returned no DCO data (DCO unsupported, frozen or not passed on by the interface); DCO state unknown: {}",
                d.command_line(),
                d.first_message().unwrap_or_else(|| d.status.clone())
            )),
            Some(dco) if dco.checksum_ok == Some(false) => info.errors.push(format!(
                "{}: DCO checksum FAILED; the DCO data ({} real max sectors) is not trusted",
                d.command_line(),
                dco.real_max_sectors
            )),
            Some(dco) => {
                ata.dco_real_max_sectors = Some(dco.real_max_sectors);
                match ata.native_max_sectors {
                    Some(native) if trusted && dco.real_max_sectors >= native => {
                        ata.dco_present = Some(dco.real_max_sectors > native);
                    }
                    Some(native) if trusted => info.errors.push(format!(
                        "DCO real max sectors {} is below the native maximum {native}; DCO state not trusted",
                        dco.real_max_sectors
                    )),
                    _ => info.errors.push(
                        "the native maximum is unknown or not trusted, so the DCO real maximum cannot be compared; DCO state unknown"
                            .into(),
                    ),
                }
            }
        }
    }
    info.ata = Some(ata);
    info
}

async fn probe_nvme(
    env: &ProbeEnv<'_>,
    disk: &PhysicalDisk,
    disk_bytes: Option<u64>,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> CapacityInfo {
    let mut info = CapacityInfo {
        method: format!(
            "nvme id-ns -o json {} (IDENTIFY NAMESPACE; NVMe has no HPA or DCO; other namespaces and unallocated NVM capacity are not examined)",
            disk.path
        ),
        ..Default::default()
    };
    if is_stopped(control) {
        info.errors.push("aborted before the capacity probe".into());
        return info;
    }
    let r = run(
        env,
        "nvme",
        &["id-ns", "-o", "json", &disk.path],
        control,
        recorder,
    )
    .await;
    if r.start_error.is_some() || r.stopped {
        info.errors.push(r.describe_failure());
        return info;
    }
    match parse_nvme_id_ns(&r.stdout) {
        Ok(ns) => {
            if let (Some(nsze), Some(lba), Some(bytes)) = (ns.nsze, ns.lba_bytes, disk_bytes) {
                let ns_bytes = nsze.saturating_mul(u64::from(lba));
                if ns_bytes != bytes {
                    info.errors.push(format!(
                        "the namespace size {nsze} blocks of {lba} bytes ({ns_bytes} bytes) differs from the kernel's size of {} ({bytes} bytes)",
                        disk.path
                    ));
                }
            }
            if ns.lba_bytes.is_none() {
                info.errors.push(
                    "the logical block size of the namespace format in use is unknown".into(),
                );
            }
            info.nvme = Some(ns);
        }
        Err(e) => info
            .errors
            .push(format!("{}: {e} ({})", r.command_line(), r.status)),
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::runner::ScriptedRunner;
    use crate::discovery::sysfs::fake::FakeSysfs;
    use crate::models::identity::SourceKind;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    const SATA: &str = "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0";
    const SATA2: &str = "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0";
    const USB: &str = "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0";
    const NVME: &str = "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0";

    const HPA_ON: &str = "\n/dev/sdb:\n max sectors   = 976771055/976773168, HPA is enabled\n";
    const HPA_OFF: &str = "\n/dev/sdb:\n max sectors   = 976773168/976773168, HPA is disabled\n";

    fn dco(real: u64) -> String {
        format!(
            "\n/dev/sdb:\nDCO Checksum verified.\nDCO Revision: 0x0002\nThe following features can be selectively disabled via DCO:\n\tTransfer modes:\n\t\t mdma0 mdma1 mdma2\n\t\t udma0 udma1 udma2 udma3 udma4 udma5 udma6\n\tReal max sectors: {real}\n\tATA command/feature sets:\n\t\t SMART self_test error_log security PUIS AAM HPA 48_bit\n"
        )
    }

    fn node_dev(p: &Path) -> Option<(u32, u32)> {
        match p.file_name()?.to_str()? {
            "sdb" => Some((8, 16)),
            "nvme0n1" => Some((259, 0)),
            "sdc" => Some((8, 32)),
            _ => None,
        }
    }

    fn disk_identity(kname: &str, size: u64) -> SourceIdentity {
        SourceIdentity {
            path: format!("/dev/{kname}"),
            kernel_name: kname.into(),
            kind: SourceKind::Disk,
            size_bytes: size,
            ..Default::default()
        }
    }

    fn script(argv: &[&str], stdout: &str, stderr: &str) -> (Vec<String>, ToolRun) {
        (
            argv.iter().map(|a| a.to_string()).collect(),
            ToolRun::exited(argv, 0, stdout, stderr),
        )
    }

    fn runner(runs: Vec<(Vec<String>, ToolRun)>) -> ScriptedRunner {
        runs.into_iter()
            .fold(ScriptedRunner::new(), |r, (argv, run)| {
                let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
                r.respond(&argv, run)
            })
    }

    async fn probe_in(f: &FakeSysfs, runner: &ScriptedRunner, id: &SourceIdentity) -> CapacityInfo {
        let env = ProbeEnv {
            sys: f.root(),
            dev_dir: "/dev".into(),
            node_dev: &node_dev,
            runner,
        };
        probe_with(&env, id, &StopControl::none(), None).await
    }

    #[test]
    fn parses_every_native_max_variant() {
        let on = parse_hdparm_native_max(HPA_ON).unwrap();
        assert_eq!(on.visible_sectors, 976_771_055);
        assert_eq!(on.native_sectors, 976_773_168);
        assert_eq!(on.state, NativeMaxState::HpaEnabled);
        assert_eq!(
            parse_hdparm_native_max(HPA_OFF).unwrap().state,
            NativeMaxState::HpaDisabled
        );
        let amax = " max sectors   = 7814037168/7814037168, ACCESSIBLE MAX ADDRESS disabled\n";
        assert_eq!(
            parse_hdparm_native_max(amax).unwrap().state,
            NativeMaxState::AmaxDisabled
        );
        let invalid = " max sectors   = 976773168/1(976773168?), HPA setting seems invalid (buggy kernel device driver?)\n";
        let inv = parse_hdparm_native_max(invalid).unwrap();
        assert_eq!(inv.state, NativeMaxState::Invalid);
        assert_eq!(inv.native_sectors, 1);
        assert_eq!(parse_hdparm_native_max("\n/dev/sdb:\n"), None);
        assert_eq!(parse_hdparm_native_max(""), None);
    }

    #[test]
    fn parses_dco_identify() {
        let d = parse_hdparm_dco(&dco(976_773_168)).unwrap();
        assert_eq!(d.real_max_sectors, 976_773_168);
        assert_eq!(d.checksum_ok, Some(true));
        let failed = dco(5).replace("verified.", "FAILED!");
        assert_eq!(parse_hdparm_dco(&failed).unwrap().checksum_ok, Some(false));
        assert_eq!(parse_hdparm_dco("\n/dev/sdb:\n"), None);
    }

    #[test]
    fn parses_nvme_id_ns_formats() {
        let v2 = r#"{"nsze":1953525168,"ncap":1953525168,"nuse":1953525168,"nsfeat":0,"nlbaf":1,"flbas":0,
            "lbafs":[{"lbaf":0,"ms":0,"ds":9,"rp":2,"in_use":1},{"lbaf":1,"ms":0,"ds":12,"rp":1,"in_use":0}]}"#;
        let ns = parse_nvme_id_ns(v2).unwrap();
        assert_eq!(ns.nsze, Some(1_953_525_168));
        assert_eq!(ns.lba_bytes, Some(512));
        // nvme-cli 1.x: no in_use, flbas selects the format
        let v1 = r#"{"nsze":244190646,"ncap":244190646,"nuse":12,"flbas":1,
            "lbafs":[{"ms":0,"ds":9,"rp":2},{"ms":0,"ds":12,"rp":1}]}"#;
        let ns = parse_nvme_id_ns(v1).unwrap();
        assert_eq!(ns.lba_bytes, Some(4096));
        assert_eq!(ns.nuse, Some(12));
        assert!(parse_nvme_id_ns(r#"{"error":"not a block device"}"#)
            .unwrap_err()
            .contains("not a block device"));
        assert!(parse_nvme_id_ns("Usage: nvme id-ns").is_err());
        assert!(parse_nvme_id_ns("{}").is_err());
    }

    #[tokio::test]
    async fn ata_disk_with_hpa_and_dco_matching_native() {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 976_771_055);
        let r = runner(vec![
            script(&["hdparm", "-N", "/dev/sdb"], HPA_ON, ""),
            script(
                &["hdparm", "--dco-identify", "/dev/sdb"],
                &dco(976_773_168),
                "",
            ),
        ]);
        let info = probe_in(&f, &r, &disk_identity("sdb", 976_771_055 * 512)).await;
        let ata = info.ata.as_ref().unwrap();
        assert_eq!(ata.hpa_present, Some(true));
        assert_eq!(ata.dco_present, Some(false));
        assert_eq!(info.hidden_area(), Some(true));
        assert_eq!(info.probed_device.as_deref(), Some("/dev/sdb"));
        assert!(info.errors.is_empty(), "{:?}", info.errors);
        assert!(
            info.summary().contains("2113 sectors"),
            "{}",
            info.summary()
        );
        // Only the two read-only queries were sent, -N without a value
        assert_eq!(
            r.calls(),
            [
                vec!["hdparm", "-N", "/dev/sdb"],
                vec!["hdparm", "--dco-identify", "/dev/sdb"]
            ]
        );
    }

    #[tokio::test]
    async fn dco_above_native_is_a_hidden_area() {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 976_773_168);
        let r = runner(vec![
            script(&["hdparm", "-N", "/dev/sdb"], HPA_OFF, ""),
            script(
                &["hdparm", "--dco-identify", "/dev/sdb"],
                &dco(1_953_525_168),
                "",
            ),
        ]);
        let info = probe_in(&f, &r, &disk_identity("sdb", 976_773_168 * 512)).await;
        let ata = info.ata.as_ref().unwrap();
        assert_eq!(ata.hpa_present, Some(false));
        assert_eq!(ata.dco_present, Some(true));
        assert!(info.summary().contains("Device Configuration Overlay"));
    }

    #[tokio::test]
    async fn partition_source_probes_its_disk_and_says_so() {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 976_773_168);
        f.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 1000);
        let r = runner(vec![
            script(&["hdparm", "-N", "/dev/sdb"], HPA_OFF, ""),
            script(
                &["hdparm", "--dco-identify", "/dev/sdb"],
                "\n/dev/sdb:\n",
                " HDIO_DRIVE_CMD(dco_identify) failed: Input/output error\n",
            ),
        ]);
        let id = SourceIdentity {
            path: "/dev/sdb1".into(),
            kernel_name: "sdb1".into(),
            kind: SourceKind::Partition,
            parent_disks: vec!["/dev/sdb".into()],
            size_bytes: 512_000,
            ..Default::default()
        };
        let info = probe_in(&f, &r, &id).await;
        assert_eq!(info.reported_bytes, 512_000);
        assert_eq!(info.probed_device.as_deref(), Some("/dev/sdb"));
        assert!(info
            .method
            .contains("physical disk /dev/sdb that holds the source /dev/sdb1"));
        let ata = info.ata.as_ref().unwrap();
        assert_eq!(ata.hpa_present, Some(false));
        assert_eq!(ata.dco_present, None);
        assert_eq!(info.hidden_area(), None);
        assert!(
            info.errors[0].contains("Input/output error"),
            "{:?}",
            info.errors
        );
    }

    #[tokio::test]
    async fn exit_zero_without_identify_is_unknown_not_clean() {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 976_771_055);
        // hdparm 9.65 on a device it cannot identify: exit 0, header only
        let r = runner(vec![
            script(&["hdparm", "-N", "/dev/sdb"], "\n/dev/sdb:\n", ""),
            script(
                &["hdparm", "--dco-identify", "/dev/sdb"],
                "\n/dev/sdb:\n",
                "",
            ),
        ]);
        let info = probe_in(&f, &r, &disk_identity("sdb", 976_771_055 * 512)).await;
        assert_eq!(info.hidden_area(), None);
        assert_eq!(info.errors.len(), 2, "{:?}", info.errors);
        assert!(info.summary().starts_with("hidden areas unknown"));
    }

    #[tokio::test]
    async fn bridge_values_that_disagree_with_the_kernel_are_not_trusted() {
        let f = FakeSysfs::new();
        f.add_disk(USB, "sdb", (8, 16), 1000);
        let r = runner(vec![
            script(
                &["hdparm", "-N", "/dev/sdb"],
                HPA_ON,
                "SG_IO: bad/missing sense data, sb[]:  70 00 05 00\n",
            ),
            script(
                &["hdparm", "--dco-identify", "/dev/sdb"],
                &dco(976_773_168),
                "",
            ),
        ]);
        let mut id = disk_identity("sdb", 512_000);
        id.transport = Some("usb".into());
        let info = probe_in(&f, &r, &id).await;
        let ata = info.ata.as_ref().unwrap();
        assert_eq!(ata.hpa_present, None);
        assert_eq!(ata.dco_present, None);
        assert!(info.method.contains("USB bridge"));
        assert!(info.errors[0].contains("not trusted"), "{:?}", info.errors);
    }

    #[tokio::test]
    async fn nvme_namespace_and_missing_tool() {
        let f = FakeSysfs::new();
        f.add_disk(NVME, "nvme0n1", (259, 0), 1_953_525_168);
        let json = r#"{"nsze":1953525168,"ncap":1953525168,"nuse":100,"flbas":0,"lbafs":[{"lbaf":0,"ms":0,"ds":9,"rp":0,"in_use":1}]}"#;
        let r = runner(vec![script(
            &["nvme", "id-ns", "-o", "json", "/dev/nvme0n1"],
            json,
            "",
        )]);
        let id = disk_identity("nvme0n1", 1_953_525_168 * 512);
        let info = probe_in(&f, &r, &id).await;
        let ns = info.nvme.as_ref().unwrap();
        assert_eq!(ns.nsze, Some(1_953_525_168));
        assert_eq!(ns.lba_bytes, Some(512));
        assert!(info.errors.is_empty(), "{:?}", info.errors);
        assert!(info.ata.is_none());
        assert!(info.method.contains("NVMe has no HPA or DCO"));

        // No tool installed: stated, nothing claimed
        let none = ScriptedRunner::new();
        let info = probe_in(&f, &none, &id).await;
        assert!(info.nvme.is_none());
        assert!(info.errors[0].contains("not started"), "{:?}", info.errors);
    }

    #[tokio::test]
    async fn no_probe_for_files_loops_untrusted_nodes_and_aborts() {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 976_771_055);
        f.add_virtual("loop0", (7, 0), 100);
        f.add_disk(SATA2, "sdc", (8, 99), 100); // the node /dev/sdc is 8:32
        let r = ScriptedRunner::new();
        let file = SourceIdentity {
            kind: SourceKind::RegularFile,
            size_bytes: 5,
            ..Default::default()
        };
        assert!(probe_in(&f, &r, &file)
            .await
            .method
            .contains("regular file"));
        let looped = SourceIdentity {
            kind: SourceKind::Loop { backing_file: None },
            kernel_name: "loop0".into(),
            ..Default::default()
        };
        assert!(probe_in(&f, &r, &looped)
            .await
            .method
            .contains("loop device"));
        let swapped = probe_in(&f, &r, &disk_identity("sdc", 51_200)).await;
        assert!(
            swapped.method.contains("refusing to query"),
            "{}",
            swapped.method
        );
        let multi = SourceIdentity {
            kind: SourceKind::Md,
            kernel_name: "md0".into(),
            path: "/dev/md0".into(),
            parent_disks: vec!["/dev/sdb".into(), "/dev/sdc".into()],
            ..Default::default()
        };
        assert!(probe_in(&f, &r, &multi).await.method.contains("2 disks"));
        let mmc = SourceIdentity {
            kind: SourceKind::Disk,
            kernel_name: "loop0".into(),
            path: "/dev/loop0".into(),
            ..Default::default()
        };
        assert!(probe_in(&f, &r, &mmc)
            .await
            .method
            .contains("no hardware device"));
        assert!(r.calls().is_empty());

        let env = ProbeEnv {
            sys: f.root(),
            dev_dir: "/dev".into(),
            node_dev: &node_dev,
            runner: &r,
        };
        let abort = Arc::new(AtomicBool::new(true));
        let info = probe_with(
            &env,
            &disk_identity("sdb", 976_771_055 * 512),
            &StopControl::abort(abort),
            None,
        )
        .await;
        assert!(info.errors[0].contains("aborted"));
        assert!(r.calls().is_empty());
    }
}
