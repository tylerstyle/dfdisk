//! Capacity and SMART parsing against REAL tool output captured with
//! tests/fixtures/discovery/tools/capture.sh (hdparm 9.65, smartmontools
//! 7.5, nvme-cli 2.16; emulated drive states through LD_PRELOAD shims, the
//! failure cases on plain files). No tool is run and no device is touched.

use dfdisk::discovery::capacity::{
    parse_hdparm_dco, parse_hdparm_native_max, parse_nvme_id_ns, probe_with, NativeMaxState,
};
use dfdisk::discovery::runner::{ProbeEnv, ScriptedRunner, ToolRun};
use dfdisk::discovery::smart::{snapshot_from_run, BASIC_ARGS, FULL_ARGS};
use dfdisk::discovery::sysfs::SysRoot;
use dfdisk::engines::process::StopControl;
use dfdisk::models::config::SmartPolicy;
use dfdisk::models::device::SmartHealth;
use dfdisk::models::identity::{SourceIdentity, SourceKind};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn tools_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discovery/tools")
}

fn read(name: &str, ext: &str) -> String {
    let p = tools_dir().join(format!("{name}.{ext}"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The captured run `name`, as if `argv` had produced it.
fn captured(argv: &[&str], name: &str) -> ToolRun {
    let exit: i32 = read(name, "exit").trim().parse().unwrap();
    ToolRun::exited(argv, exit, &read(name, "stdout"), &read(name, "stderr"))
}

/// A minimal sysfs tree laid out like a host's (class/block and dev/block
/// links into devices/, a `device` link to the hardware directory).
struct MiniSys {
    dir: tempfile::TempDir,
}

impl MiniSys {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["class/block", "dev/block", "devices"] {
            std::fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        MiniSys { dir }
    }

    fn disk(&self, hw: &str, kname: &str, dev: (u32, u32), sectors: u64) {
        let root = self.dir.path();
        let hwdir = root.join("devices").join(hw);
        let node = hwdir.join("block").join(kname);
        std::fs::create_dir_all(node.join("queue")).unwrap();
        std::fs::create_dir_all(node.join("holders")).unwrap();
        for (attr, value) in [
            ("dev", format!("{}:{}", dev.0, dev.1)),
            ("size", sectors.to_string()),
            ("ro", "0".into()),
            ("removable", "0".into()),
            ("queue/logical_block_size", "512".into()),
            ("queue/physical_block_size", "512".into()),
        ] {
            std::fs::write(node.join(attr), format!("{value}\n")).unwrap();
        }
        symlink(&hwdir, node.join("device")).unwrap();
        symlink(&node, root.join("class/block").join(kname)).unwrap();
        symlink(&node, root.join(format!("dev/block/{}:{}", dev.0, dev.1))).unwrap();
    }

    fn root(&self) -> SysRoot {
        SysRoot::new(self.dir.path())
    }
}

const SATA: &str = "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0";
const NVME: &str = "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0/nvme0n1";

fn node_dev(p: &Path) -> Option<(u32, u32)> {
    match p.file_name()?.to_str()? {
        "sdx" => Some((8, 16)),
        "nvme0n1" => Some((259, 0)),
        _ => None,
    }
}

fn disk(kname: &str, size: u64) -> SourceIdentity {
    SourceIdentity {
        path: format!("/dev/{kname}"),
        kernel_name: kname.into(),
        kind: SourceKind::Disk,
        size_bytes: size,
        ..Default::default()
    }
}

#[test]
fn hdparm_native_max_as_hdparm_prints_it() {
    let on = parse_hdparm_native_max(&read("hdparm-N-hpa-enabled", "stdout")).unwrap();
    assert_eq!(on.state, NativeMaxState::HpaEnabled);
    assert_eq!(
        (on.visible_sectors, on.native_sectors),
        (976_771_055, 976_773_168)
    );
    let off = parse_hdparm_native_max(&read("hdparm-N-hpa-disabled", "stdout")).unwrap();
    assert_eq!(off.state, NativeMaxState::HpaDisabled);
    assert_eq!(off.visible_sectors, off.native_sectors);
    let inv = parse_hdparm_native_max(&read("hdparm-N-invalid", "stdout")).unwrap();
    assert_eq!(inv.state, NativeMaxState::Invalid);
    assert_eq!(inv.native_sectors, 976_771_055);
    // Not identified: exit 0 and no max sectors line
    assert_eq!(read("hdparm-N-not-identified", "exit").trim(), "0");
    assert_eq!(
        parse_hdparm_native_max(&read("hdparm-N-not-identified", "stdout")),
        None
    );
    assert_eq!(read("hdparm-N-permission-denied", "exit").trim(), "13");
    assert_eq!(
        parse_hdparm_native_max(&read("hdparm-N-permission-denied", "stdout")),
        None
    );
}

#[test]
fn hdparm_dco_as_hdparm_prints_it() {
    let eq = parse_hdparm_dco(&read("hdparm-dco-equal", "stdout")).unwrap();
    assert_eq!(eq.real_max_sectors, 976_773_168);
    assert_eq!(eq.checksum_ok, Some(true));
    let above = parse_hdparm_dco(&read("hdparm-dco-above-native", "stdout")).unwrap();
    assert_eq!(above.real_max_sectors, 1_953_525_168);
    for name in ["hdparm-dco-unsupported", "hdparm-dco-not-ata"] {
        // hdparm exits 0 although the command failed
        assert_eq!(read(name, "exit").trim(), "0", "{name}");
        assert_eq!(parse_hdparm_dco(&read(name, "stdout")), None, "{name}");
        assert!(read(name, "stderr").contains("HDIO_DRIVE_CMD(dco_identify) failed"));
    }
}

#[test]
fn hdparm_queries_send_only_identify_class_commands() {
    // IDENTIFY DEVICE (ECh) and READ NATIVE MAX ADDRESS EXT (27h); DEVICE
    // CONFIGURATION IDENTIFY (B1h/C2h). No SET MAX, no DCO SET/RESTORE/FREEZE
    let n = read("hdparm-N", "commands");
    let lines: Vec<&str> = n.lines().collect();
    assert_eq!(
        lines,
        [
            "[ata-emul] HDIO_DRIVE_CMD cmd=0xec feat=0x00 nsect=0x00",
            "[ata-emul] HDIO_DRIVE_TASKFILE cmd=0x27 feat=0x00"
        ]
    );
    let d = read("hdparm-dco", "commands");
    assert_eq!(
        d.lines().collect::<Vec<_>>(),
        ["[ata-emul] HDIO_DRIVE_CMD cmd=0xb1 feat=0xc2 nsect=0x00"]
    );
}

async fn ata_probe(n: &str, dco: &str) -> dfdisk::models::capacity::CapacityInfo {
    let sys = MiniSys::new();
    sys.disk(SATA, "sdx", (8, 16), 976_771_055);
    let runner = ScriptedRunner::new()
        .respond(
            &["hdparm", "-N", "/dev/sdx"],
            captured(&["hdparm", "-N", "/dev/sdx"], n),
        )
        .respond(
            &["hdparm", "--dco-identify", "/dev/sdx"],
            captured(&["hdparm", "--dco-identify", "/dev/sdx"], dco),
        );
    let env = ProbeEnv {
        sys: sys.root(),
        dev_dir: "/dev".into(),
        node_dev: &node_dev,
        runner: &runner,
    };
    probe_with(
        &env,
        &disk("sdx", 976_771_055 * 512),
        &StopControl::none(),
        None,
    )
    .await
}

#[tokio::test]
async fn capacity_probe_on_captured_hdparm_runs() {
    let hpa = ata_probe("hdparm-N-hpa-enabled", "hdparm-dco-equal").await;
    assert_eq!(hpa.hidden_area(), Some(true));
    assert!(
        hpa.summary().contains("Host Protected Area: 2113 sectors"),
        "{}",
        hpa.summary()
    );
    assert!(hpa.errors.is_empty(), "{:?}", hpa.errors);

    // The disk size in sysfs is the visible size; a "clean" capture of a
    // larger drive does not match it and is not trusted
    let mismatch = ata_probe("hdparm-N-hpa-disabled", "hdparm-dco-equal").await;
    assert_eq!(mismatch.hidden_area(), None);
    assert!(
        mismatch.errors[0].contains("not trusted"),
        "{:?}",
        mismatch.errors
    );

    let unknown = ata_probe("hdparm-N-not-identified", "hdparm-dco-not-ata").await;
    assert_eq!(unknown.hidden_area(), None);
    assert_eq!(unknown.errors.len(), 2);
    assert!(
        unknown.errors[1].contains("Inappropriate ioctl"),
        "{:?}",
        unknown.errors
    );

    let denied = ata_probe("hdparm-N-permission-denied", "hdparm-dco-unsupported").await;
    assert!(
        denied.errors[0].contains("Permission denied"),
        "{:?}",
        denied.errors
    );
    assert!(
        denied.errors[1].contains("Input/output error"),
        "{:?}",
        denied.errors
    );
}

#[tokio::test]
async fn capacity_probe_on_captured_dco_above_native() {
    let sys = MiniSys::new();
    sys.disk(SATA, "sdx", (8, 16), 976_773_168);
    let runner = ScriptedRunner::new()
        .respond(
            &["hdparm", "-N", "/dev/sdx"],
            captured(&["hdparm", "-N", "/dev/sdx"], "hdparm-N-hpa-disabled"),
        )
        .respond(
            &["hdparm", "--dco-identify", "/dev/sdx"],
            captured(
                &["hdparm", "--dco-identify", "/dev/sdx"],
                "hdparm-dco-above-native",
            ),
        );
    let env = ProbeEnv {
        sys: sys.root(),
        dev_dir: "/dev".into(),
        node_dev: &node_dev,
        runner: &runner,
    };
    let info = probe_with(
        &env,
        &disk("sdx", 976_773_168 * 512),
        &StopControl::none(),
        None,
    )
    .await;
    let ata = info.ata.as_ref().unwrap();
    assert_eq!(ata.hpa_present, Some(false));
    assert_eq!(ata.dco_present, Some(true));
    assert!(
        info.summary()
            .contains("Device Configuration Overlay: 976752000 sectors"),
        "{}",
        info.summary()
    );
}

#[tokio::test]
async fn nvme_id_ns_as_nvme_cli_prints_it() {
    let ns = parse_nvme_id_ns(&read("nvme-id-ns", "stdout")).unwrap();
    assert_eq!(ns.nsze, Some(1_953_525_168));
    assert_eq!(ns.ncap, Some(1_953_525_168));
    assert_eq!(ns.nuse, Some(488_381_292));
    assert_eq!(ns.lba_bytes, Some(512));
    let err = parse_nvme_id_ns(&read("nvme-id-ns-not-block", "stdout")).unwrap_err();
    assert!(err.contains("is not a block or character device"), "{err}");

    let sys = MiniSys::new();
    sys.disk(NVME, "nvme0n1", (259, 0), 1_953_525_168);
    let argv = ["nvme", "id-ns", "-o", "json", "/dev/nvme0n1"];
    let runner = ScriptedRunner::new().respond(&argv, captured(&argv, "nvme-id-ns"));
    let env = ProbeEnv {
        sys: sys.root(),
        dev_dir: "/dev".into(),
        node_dev: &node_dev,
        runner: &runner,
    };
    let info = probe_with(
        &env,
        &disk("nvme0n1", 1_953_525_168 * 512),
        &StopControl::none(),
        None,
    )
    .await;
    assert!(info.errors.is_empty(), "{:?}", info.errors);
    assert_eq!(info.nvme.unwrap().lba_bytes, Some(512));
}

fn snapshot(name: &str) -> dfdisk::models::device::SmartSnapshot {
    let argv = [
        "smartctl", "-j", "-i", "-H", "-A", "-l", "error", "/dev/sdx",
    ];
    snapshot_from_run(
        SmartPolicy::Basic,
        &captured(&argv, name),
        chrono::Utc::now(),
    )
}

#[test]
fn smartctl_ata_and_nvme_as_smartctl_prints_them() {
    let ok = snapshot("smartctl-ata-passed");
    assert_eq!(ok.summary.health, SmartHealth::Passed);
    assert_eq!(ok.device_serial.as_deref(), Some("EMUL-ATA-00000000000"));
    assert_eq!(ok.smartctl_version.as_deref(), Some("smartctl 7.5"));
    assert_eq!(ok.summary.power_on_hours, Some(4321));
    assert_eq!(ok.summary.temperature_celsius, Some(35));
    assert_eq!(ok.summary.reallocated_sectors, Some(0));
    assert_eq!(ok.exit_status, Some(0));

    let bad = snapshot("smartctl-ata-failed");
    assert_eq!(bad.summary.health, SmartHealth::Failed);
    assert_eq!(bad.exit_status, Some(24));
    assert_eq!(bad.summary.reallocated_sectors, Some(1584));
    assert_eq!(bad.summary.pending_sectors, Some(320));
    assert_eq!(bad.summary.uncorrectable_errors, Some(112));
    assert!(bad.note.unwrap().contains("prefail attributes"));

    let nvme = snapshot("smartctl-nvme");
    assert_eq!(nvme.summary.health, SmartHealth::Passed);
    assert_eq!(nvme.device_serial.as_deref(), Some("EMUL0000000000000001"));
    assert_eq!(nvme.summary.wear_percentage, Some(3));
    assert_eq!(nvme.summary.uncorrectable_errors, Some(0));
    assert_eq!(nvme.summary.temperature_celsius, Some(37));
    assert_eq!(nvme.summary.power_on_hours, Some(1234));

    let full = snapshot("smartctl-ata-full");
    assert_eq!(full.summary.health, SmartHealth::Passed);
    assert!(full.note.is_none(), "{:?}", full.note);
}

#[test]
fn smartctl_failures_are_unknown_never_failed() {
    for (name, text) in [
        (
            "smartctl-ata-standby",
            "device in STANDBY mode, not woken up",
        ),
        (
            "smartctl-permission-denied",
            "SMART not readable: Smartctl open device: noperm [SAT] failed: Permission denied",
        ),
        (
            "smartctl-unknown-type",
            "SMART not readable: img.bin: Unable to detect device type",
        ),
        (
            "smartctl-scsi-inquiry-failed",
            "SMART not readable: Smartctl open device: sdx failed: INQUIRY failed",
        ),
        ("smartctl-sat-no-identify", "SMART not readable"),
    ] {
        let s = snapshot(name);
        assert_eq!(s.summary.health, SmartHealth::Unknown, "{name}");
        assert!(!s.summary.passed, "{name}");
        assert_eq!(s.summary.assessment, text, "{name}");
        assert_eq!(s.device_serial, None, "{name}");
    }
}

#[test]
fn smart_policies_never_touch_the_sct_log() {
    // SCT commands go through SMART READ/WRITE LOG of page E0h; smartctl -x
    // reads it on a drive advertising SCT, dfdisk's basic and full do not
    let x = read("smartctl-x", "commands");
    assert!(
        x.contains("feat=0xd5 nsect=0xe0"),
        "the check must be able to see SCT: {x}"
    );
    for name in ["smartctl-basic", "smartctl-full"] {
        let c = read(name, "commands");
        assert!(!c.contains("nsect=0xe0"), "{name}: {c}");
        assert!(!c.contains("feat=0xd6"), "{name}: {c}"); // SMART WRITE LOG
        assert!(!c.contains("feat=0xd4"), "{name}: {c}"); // EXECUTE OFF-LINE (self-tests)
        assert!(!c.contains("HDIO_DRIVE_TASKFILE"), "{name}: {c}");
    }
    // The capture used exactly dfdisk's argument lists
    let script = read("capture", "sh");
    assert!(script.contains(&format!("basic=\"{}\"", BASIC_ARGS.join(" "))));
    assert!(script.contains(&format!("full=\"{}\"", FULL_ARGS.join(" "))));
}
