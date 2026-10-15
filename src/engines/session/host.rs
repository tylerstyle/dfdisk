//! What the session needs from the host, as a trait ([`SessionHost`]) so tests
//! replace probes, the destination, write protection and the engine with
//! fakes; [`HostSystem`] is the real host.

use super::{EngineContext, EngineOutput};
use crate::discovery::sysfs::SysRoot;
use crate::discovery::{capacity, identity, smart, writeprotect};
use crate::engines::error::AcquisitionError;
use crate::engines::preflight::{self, DestinationFacts};
use crate::engines::process::StopControl;
use crate::models::capacity::CapacityInfo;
use crate::models::config::SmartPolicy;
use crate::models::device::SmartSnapshot;
use crate::models::identity::SourceIdentity;
use crate::models::info_report::HashResults;
use crate::models::outcome::VerificationResult;
use crate::models::protection::WriteProtection;
use crate::models::provenance::{
    capture_tool_versions, ClockInfo, ProvenanceRecorder, ToolProvenance,
};
use dfcore::lsblk::FlatDevice;
use dfcore::protected::Registry;
use dfcore::sysfs::{parse_dev_num, DevNum};
use futures::future::BoxFuture;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// One active swap area from /proc/swaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapEntry {
    /// Device or file path as the kernel lists it
    pub path: String,
    /// "partition" or "file"
    pub kind: String,
    /// The block device holding it: the device itself for a partition, the
    /// device of the filesystem holding a swap file (stat st_dev)
    pub dev: Option<DevNum>,
}

/// Parse /proc/swaps (header line, then `Filename Type Size Used Priority`;
/// spaces in names are octal escapes). `dev_of` maps (path, kind) to the
/// holding block device.
pub fn parse_proc_swaps(
    content: &str,
    dev_of: &dyn Fn(&str, &str) -> Option<DevNum>,
) -> Vec<SwapEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let raw = fields.next()?;
            let kind = fields.next()?.to_string();
            let path = raw.replace("\\040", " ").replace("\\011", "\t");
            Some(SwapEntry {
                dev: dev_of(&path, &kind),
                path,
                kind,
            })
        })
        .collect()
}

/// `program` as an executable file: a path as given, or the first match on
/// PATH (what the process runner would start).
pub fn find_on_path(program: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let executable = |p: &Path| {
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.contains('/') {
        let p = PathBuf::from(program);
        return executable(&p).then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(program))
        .find(|p| executable(p))
}

/// The host as the session sees it. Every method is one probe or action;
/// the engine seams default to the real engines.
pub trait SessionHost: Send + Sync {
    /// Where the external `program` an engine runs is (default:
    /// [`find_on_path`]); `None`: it cannot be run on this host.
    fn find_tool(&self, program: &str) -> Option<PathBuf> {
        find_on_path(program)
    }

    /// The version line of the external `program` (`ewfacquire -V`: e.g.
    /// "ewfacquire 20140807"), before anything is written; `None` when it
    /// does not run or prints none within 5 s.
    fn tool_version(&self, program: &str) -> Option<String> {
        crate::engines::process::tool_version_blocking(
            program,
            crate::models::provenance::version_args(program),
            std::time::Duration::from_secs(5),
        )
    }

    /// Identity of the source at `path` (§5); `Err` refuses (P2).
    fn probe_identity(&self, path: &str) -> Result<SourceIdentity, String>;

    /// The sysfs tree (holders, partitions, read-only flags, topology).
    fn sysfs(&self) -> SysRoot;

    /// Content of /proc/self/mountinfo.
    fn mountinfo(&self) -> Result<String, String>;

    /// Active swap areas.
    fn swaps(&self) -> Result<Vec<SwapEntry>, String>;

    /// The dfnix protected-device registry: `Ok(None)` outside dfnix, `Err`
    /// when it exists but cannot be read (refuses).
    fn registry(&self) -> Result<Option<Registry>, String>;

    /// The block device tree (lsblk), for the registry and system-disk checks.
    fn lsblk(&self) -> Result<Vec<FlatDevice>, String>;

    /// Open the source read-only and exclusively (block devices, R1) and
    /// check that the descriptor is the probed device; held for the run.
    fn open_source(&self, identity: &SourceIdentity) -> Result<File, AcquisitionError>;

    /// Facts about the destination directory (writes nothing).
    fn destination(&self, output_dir: &Path) -> io::Result<DestinationFacts>;

    /// Path external tools read the source through (R3).
    fn tool_source_path(&self, identity: &SourceIdentity) -> String;

    /// Apply the write-protection policy recorded in `wp` and record what was
    /// done (§6, R2); `Err` refuses (exit 3).
    fn enforce_write_protection(
        &self,
        identity: &SourceIdentity,
        wp: &mut WriteProtection,
    ) -> Result<(), String>;

    /// Capacity / hidden areas of the source's disk (§7, R6).
    fn capacity<'a>(
        &'a self,
        identity: &'a SourceIdentity,
        control: &'a StopControl,
        recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, CapacityInfo>;

    /// SMART snapshot (§8); raw JSON saved to `json_file` when given.
    fn smart<'a>(
        &'a self,
        identity: &'a SourceIdentity,
        policy: SmartPolicy,
        json_file: Option<&'a Path>,
        control: &'a StopControl,
        recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, Option<SmartSnapshot>>;

    /// Host clock state at the start of the run (§11).
    fn clock(&self) -> BoxFuture<'static, ClockInfo>;

    /// Build and host provenance (§11).
    fn provenance(&self) -> ToolProvenance;

    /// Version lines of the external tools that ran.
    fn tool_versions<'a>(&'a self, tools: Vec<String>) -> BoxFuture<'a, BTreeMap<String, String>>;

    /// The audit log the run's records go to.
    fn audit_log(&self) -> PathBuf;

    /// Copy the audit log into the case directory (`audit-<boot_id>.jsonl`);
    /// the path of the copy.
    fn export_audit(&self, log: &Path, dir: &Path) -> Result<PathBuf, String>;

    /// Step 8 (default: the real engines).
    fn acquire<'a>(
        &'a self,
        ctx: &'a EngineContext,
    ) -> BoxFuture<'a, Result<EngineOutput, AcquisitionError>> {
        Box::pin(super::acquire(ctx))
    }

    /// Step 11 (default: the real engines).
    fn verify<'a>(
        &'a self,
        ctx: &'a EngineContext,
        out: &'a EngineOutput,
    ) -> BoxFuture<'a, (VerificationResult, HashResults)> {
        Box::pin(super::verify(ctx, out))
    }

    /// Step 10 (default: [`flush_files`](super::flush_files): fsync, page-cache
    /// eviction, directory fsync).
    fn flush(&self, files: &[PathBuf], dir: &Path) -> super::FlushReport {
        super::flush_files(files, dir)
    }

    /// Step 11, `--verify-source` (default: positioned reads through the
    /// held descriptor, `raw::hash_source`).
    fn reread_source<'a>(
        &'a self,
        ctx: &'a EngineContext,
        bytes: u64,
    ) -> BoxFuture<'a, Result<HashResults, AcquisitionError>> {
        Box::pin(super::reread_source(ctx, bytes))
    }
}

/// This host: /sys, /proc, udevadm, lsblk, the dfnix registry and audit log,
/// BLKROSET, the real engines.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostSystem;

fn split_dev(dev: u64) -> DevNum {
    (
        libc::major(dev as libc::dev_t) as u32,
        libc::minor(dev as libc::dev_t) as u32,
    )
}

/// The descriptor must be the device (or file) that was probed: a node
/// replaced between probe and open refuses.
pub(crate) fn check_descriptor(
    file: &File,
    identity: &SourceIdentity,
) -> Result<(), AcquisitionError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = file
        .metadata()
        .map_err(|e| AcquisitionError::refused(format!("cannot inspect the opened source: {e}")))?;
    if identity.is_block_device() {
        let pinned = identity.maj_min.as_deref().and_then(parse_dev_num);
        let actual = meta
            .file_type()
            .is_block_device()
            .then(|| split_dev(meta.rdev()));
        if pinned.is_none() || actual != pinned {
            return Err(AcquisitionError::refused(format!(
                "{} no longer refers to the probed device {} (now {}); refusing",
                identity.path,
                identity.maj_min.as_deref().unwrap_or("unknown"),
                actual
                    .map(|(a, b)| format!("{a}:{b}"))
                    .unwrap_or_else(|| "not a block device".into())
            )));
        }
    } else {
        let actual = format!("{}:{}", meta.dev(), meta.ino());
        if !meta.is_file() || identity.file_id.as_deref() != Some(actual.as_str()) {
            return Err(AcquisitionError::refused(format!(
                "{} is no longer the probed file; refusing",
                identity.path
            )));
        }
    }
    Ok(())
}

impl SessionHost for HostSystem {
    fn probe_identity(&self, path: &str) -> Result<SourceIdentity, String> {
        identity::probe(path)
    }

    fn sysfs(&self) -> SysRoot {
        SysRoot::host()
    }

    fn mountinfo(&self) -> Result<String, String> {
        std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())
    }

    fn swaps(&self) -> Result<Vec<SwapEntry>, String> {
        let content = std::fs::read_to_string("/proc/swaps").map_err(|e| e.to_string())?;
        Ok(parse_proc_swaps(&content, &|path, kind| {
            if kind == "partition" {
                dfcore::sysfs::dev_num_of_path(Path::new(path))
            } else {
                dfcore::sysfs::backing_device_of_path(Path::new(path))
            }
        }))
    }

    fn registry(&self) -> Result<Option<Registry>, String> {
        Registry::load(&dfcore::protected::path()).map_err(|e| format!("{e:#}"))
    }

    fn lsblk(&self) -> Result<Vec<FlatDevice>, String> {
        dfcore::lsblk::scan().map_err(|e| format!("{e:#}"))
    }

    fn open_source(&self, identity: &SourceIdentity) -> Result<File, AcquisitionError> {
        let path = Path::new(&identity.path);
        let file = if identity.is_block_device() {
            writeprotect::open_exclusive(path)
        } else {
            File::open(path)
        }
        .map_err(|e| {
            AcquisitionError::refused(format!("cannot open the source {}: {e}", path.display()))
        })?;
        check_descriptor(&file, identity)?;
        Ok(file)
    }

    fn destination(&self, output_dir: &Path) -> io::Result<DestinationFacts> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
        preflight::probe_destination(output_dir, &mountinfo)
    }

    fn tool_source_path(&self, identity: &SourceIdentity) -> String {
        identity::tool_source_path(identity)
    }

    fn enforce_write_protection(
        &self,
        identity: &SourceIdentity,
        wp: &mut WriteProtection,
    ) -> Result<(), String> {
        writeprotect::enforce(identity, wp)
    }

    fn capacity<'a>(
        &'a self,
        identity: &'a SourceIdentity,
        control: &'a StopControl,
        recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, CapacityInfo> {
        Box::pin(capacity::probe(identity, control, Some(recorder)))
    }

    fn smart<'a>(
        &'a self,
        identity: &'a SourceIdentity,
        policy: SmartPolicy,
        json_file: Option<&'a Path>,
        control: &'a StopControl,
        recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, Option<SmartSnapshot>> {
        Box::pin(smart::snapshot(
            identity,
            policy,
            json_file,
            control,
            Some(recorder),
        ))
    }

    fn clock(&self) -> BoxFuture<'static, ClockInfo> {
        Box::pin(async {
            tokio::task::spawn_blocking(ClockInfo::capture_start)
                .await
                .unwrap_or_default()
        })
    }

    fn provenance(&self) -> ToolProvenance {
        ToolProvenance::capture()
    }

    fn tool_versions<'a>(&'a self, tools: Vec<String>) -> BoxFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let names: Vec<&str> = tools.iter().map(String::as_str).collect();
            capture_tool_versions(&names).await
        })
    }

    fn audit_log(&self) -> PathBuf {
        dfcore::audit::path()
    }

    fn export_audit(&self, log: &Path, dir: &Path) -> Result<PathBuf, String> {
        dfcore::audit::export(log, dir)
            .map(|info| info.jsonl)
            .map_err(|e| format!("{e:#}"))
    }
}
