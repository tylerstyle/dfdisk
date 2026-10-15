//! Source safety (§10, §14, R8, review H7): what belongs to the running
//! system, which mounts and active swap areas lie on a source tree, and the
//! explicit, audited unmount of a source ([`unmount_source_tree`]).
//!
//! "System" is the union of dfdisk's critical mount points
//! ([`SafetyChecker::is_critical_mount`]) and dfcore's
//! (`dfcore::lsblk::is_mount_system`: also /iso, /run, /sysroot, `[SWAP]`)
//! plus the dfnix live-medium label, over the whole disk(s) a source sits on.
//! The source tree is the source node, its partitions (for a disk) and
//! everything stacked on them (dm, LUKS, LVM, md), matched in the mount table
//! by device number and by mount source path.

use crate::discovery::sysfs::SysRoot;
use crate::discovery::writeprotect;
use crate::engines::audit;
use crate::engines::process::{run_blocking, ProcessSpec};
use crate::engines::session::{HostSystem, SessionHost, SwapEntry};
use crate::engines::AcquisitionError;
use crate::models::device::DeviceSafety;
use crate::models::identity::{SourceIdentity, SourceKind};
use crate::models::protection::RegistryPresence;
use crate::models::text::sanitize_line;
use dfcore::lsblk::FlatDevice;
use dfcore::protected::Registry;
use dfcore::sysfs::{parse_dev_num, DevNum};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Timeout of one `umount` (it flushes the filesystem's dirty data).
pub const UMOUNT_TIMEOUT: Duration = Duration::from_secs(120);

/// A mount point that belongs to the running system: dfdisk's critical list
/// or dfcore's (`/`, `/boot*`, `/nix*`, `/iso*`, `/sysroot*`, `/run*` except
/// desktop automounts, `[SWAP]`).
pub fn is_system_mount(mountpoint: &str) -> bool {
    let m = mountpoint.trim();
    !m.is_empty() && (SafetyChecker::is_critical_mount(m) || dfcore::lsblk::is_mount_system(m))
}

fn critical_mount_reasons(dev: &dfcore::lsblk::BlockDevice, out: &mut Vec<String>) {
    for m in dev.mounts() {
        if SafetyChecker::is_critical_mount(m) && !dfcore::lsblk::is_mount_system(m) {
            out.push(format!("{} mounted at {}", dev.dev_path(), m));
        }
    }
    for c in dev.children.iter().flatten() {
        critical_mount_reasons(c, out);
    }
}

/// Why the disk(s) the device at `path` / `dev` sits on belong to the running
/// system: dfcore's system detection (system mounts, live-medium label) plus
/// dfdisk's critical mount points, over every whole disk below it. Empty: not
/// a system disk (as far as lsblk shows).
pub fn system_reasons_for(flat: &[FlatDevice], path: &str, dev: Option<DevNum>) -> Vec<String> {
    let hits = dfcore::lsblk::lookup(flat, path, dev);
    let mut reasons = Vec::new();
    for root in dfcore::lsblk::roots_of(flat, &hits) {
        reasons.extend(dfcore::lsblk::system_reasons(&root.device));
        critical_mount_reasons(&root.device, &mut reasons);
    }
    let mut seen = BTreeSet::new();
    reasons.retain(|r| seen.insert(r.clone()));
    reasons
}

/// Why the dfnix registry protects the device, if it does. An unreadable
/// registry protects everything (fail closed, P2).
pub fn registry_protection(
    registry: &Result<Option<Registry>, String>,
    flat: &[FlatDevice],
    path: &str,
    dev: Option<DevNum>,
) -> Option<String> {
    match registry {
        Err(reason) => Some(format!(
            "the dfnix protected-device registry cannot be read ({reason}); every device is treated as protected"
        )),
        Ok(None) => None,
        Ok(Some(reg)) => reg.protecting_dev(flat, path, dev).map(|p| {
            let role = match p.role {
                dfcore::protected::Role::LiveMedium => "dfnix live medium",
                dfcore::protected::Role::SystemDisk => "system disk",
            };
            let who = p
                .identity
                .serial
                .as_deref()
                .or(p.identity.wwn.as_deref())
                .unwrap_or(&p.identity.kernel_name);
            format!("{role} {who}: {}", p.reasons.join("; "))
        }),
    }
}

/// Registry presence from a registry load result.
pub fn registry_presence_of(registry: &Result<Option<Registry>, String>) -> RegistryPresence {
    match registry {
        Ok(Some(_)) => RegistryPresence::Present,
        Ok(None) => RegistryPresence::Absent,
        Err(reason) => RegistryPresence::Unreadable {
            reason: reason.clone(),
        },
    }
}

/// One line of /proc/self/mountinfo with the mount and parent IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRecord {
    pub id: u64,
    pub parent_id: u64,
    pub dev: DevNum,
    /// Root of the mount within its filesystem
    pub root: String,
    pub mount_point: String,
    pub fstype: String,
    /// Mount source, e.g. "/dev/sdb1", "/dev/mapper/cryptdata"
    pub source: String,
}

/// Mountinfo fields escape space, tab, newline and backslash as `\ooo`.
fn unescape_mountinfo(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 4 <= bytes.len() {
            let oct = &bytes[i + 1..i + 4];
            if oct.iter().all(|b| (b'0'..=b'7').contains(b)) {
                out.push(
                    oct.iter()
                        .fold(0u8, |acc, b| acc.wrapping_mul(8).wrapping_add(b - b'0')),
                );
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse /proc/self/mountinfo
/// (`id parent maj:min root mount-point options [optional...] - fstype source super-options`).
pub fn parse_mountinfo_records(content: &str) -> Vec<MountRecord> {
    content
        .lines()
        .filter_map(|line| {
            let (pre, post) = line.split_once(" - ")?;
            let pre: Vec<&str> = pre.split(' ').collect();
            let post: Vec<&str> = post.split(' ').collect();
            Some(MountRecord {
                id: pre.first()?.parse().ok()?,
                parent_id: pre.get(1)?.parse().ok()?,
                dev: parse_dev_num(pre.get(2)?)?,
                root: unescape_mountinfo(pre.get(3)?),
                mount_point: unescape_mountinfo(pre.get(4)?),
                fstype: unescape_mountinfo(post.first()?),
                source: unescape_mountinfo(post.get(1)?),
            })
        })
        .collect()
}

/// Depth of every mount in the mount tree (number of ancestors visible in
/// the same table). A mount stacked over another is one deeper.
pub fn mount_depths(mounts: &[MountRecord]) -> HashMap<u64, usize> {
    let parent: HashMap<u64, u64> = mounts.iter().map(|m| (m.id, m.parent_id)).collect();
    mounts
        .iter()
        .map(|m| {
            let mut depth = 0;
            let mut cur = m.parent_id;
            while let Some(&next) = parent.get(&cur) {
                if next == cur || depth > 4096 {
                    break;
                }
                depth += 1;
                cur = next;
            }
            (m.id, depth)
        })
        .collect()
}

/// The nodes of a source tree as the mount table and swap list name them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceTree {
    /// Kernel names (sysfs)
    pub nodes: BTreeSet<String>,
    pub devs: BTreeSet<DevNum>,
    /// Device paths: /dev/<kname>, /dev/mapper/<dm name>, lsblk paths
    pub paths: BTreeSet<String>,
}

impl SourceTree {
    /// From sysfs: the source, its partitions (for a disk) and everything
    /// stacked on them (`writeprotect::source_tree`).
    pub fn from_sysfs(sys: &SysRoot, identity: &SourceIdentity) -> Self {
        let mut tree = SourceTree::default();
        for node in writeprotect::source_tree(sys, identity) {
            tree.add_kname(sys, &node);
        }
        tree
    }

    /// Add a sysfs node (its device number, /dev path and mapper name).
    pub fn add_kname(&mut self, sys: &SysRoot, kname: &str) {
        if let Some(dev) = sys.dev_of(kname) {
            self.devs.insert(dev);
        }
        self.paths.insert(format!("/dev/{kname}"));
        if let Some(name) = sys.attr(kname, "dm/name") {
            self.paths.insert(format!("/dev/mapper/{name}"));
        }
        self.nodes.insert(kname.to_string());
    }

    pub fn contains_mount(&self, m: &MountRecord) -> bool {
        self.devs.contains(&m.dev) || self.paths.contains(&m.source)
    }

    /// Mounts of the tree, in mount-table order.
    pub fn mounts<'a>(&self, mounts: &'a [MountRecord]) -> Vec<&'a MountRecord> {
        mounts.iter().filter(|m| self.contains_mount(m)).collect()
    }

    /// Active swap areas on the tree: swap partitions of a node and swap
    /// files on a filesystem of a node (R8).
    pub fn swaps<'a>(&self, swaps: &'a [SwapEntry]) -> Vec<&'a SwapEntry> {
        swaps
            .iter()
            .filter(|s| {
                s.dev.is_some_and(|d| self.devs.contains(&d)) || self.paths.contains(&s.path)
            })
            .collect()
    }
}

/// Text of an R8 refusal for one active swap area.
pub fn swap_refusal(s: &SwapEntry) -> String {
    format!(
        "active swap on the source: {} ({}). dfdisk never runs swapoff itself (it may be this host's own swap); disable that swap area and retry",
        sanitize_line(&s.path),
        s.kind
    )
}

/// What [`unmount_source_tree`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UnmountResult {
    /// Mount points unmounted, deepest first
    pub unmounted: Vec<String>,
    /// Holders of the source tree (open LUKS/LVM/md), reported, never closed
    pub holders: Vec<String>,
    /// Hash of the audit `unmount` record, when it was written
    pub audit_hash: Option<String>,
    /// Mounts of the source tree found before unmounting (mount-table order)
    pub mounts_before: Vec<String>,
    /// Why no audit record exists although one was due
    pub audit_error: Option<String>,
    /// Statements for the examiner (holders left open, namespaces)
    pub notes: Vec<String>,
}

/// What [`unmount_source_tree_with`] needs from the host.
pub trait UnmountHost {
    fn sysfs(&self) -> SysRoot;
    /// Device number of a device node path (`stat` st_rdev).
    fn node_dev(&self, path: &Path) -> Option<DevNum>;
    fn mountinfo(&self) -> Result<String, String>;
    fn swaps(&self) -> Result<Vec<SwapEntry>, String>;
    /// `Ok(None)` outside dfnix, `Err` when it exists but cannot be read.
    fn registry(&self) -> Result<Option<Registry>, String>;
    fn lsblk(&self) -> Result<Vec<FlatDevice>, String>;
    fn audit_log(&self) -> PathBuf;
    /// Unmount the topmost mount at `mount_point`; never lazy, never forced.
    fn unmount(&self, mount_point: &str) -> Result<(), String>;
}

/// This host: /sys, /proc, lsblk, the dfnix registry and audit log, and
/// util-linux `umount <mount point>` (no `-l`, no `-f`) through
/// `engines::process`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostUnmount;

impl UnmountHost for HostUnmount {
    fn sysfs(&self) -> SysRoot {
        SysRoot::host()
    }
    fn node_dev(&self, path: &Path) -> Option<DevNum> {
        dfcore::sysfs::dev_num_of_path(path)
    }
    fn mountinfo(&self) -> Result<String, String> {
        HostSystem.mountinfo()
    }
    fn swaps(&self) -> Result<Vec<SwapEntry>, String> {
        HostSystem.swaps()
    }
    fn registry(&self) -> Result<Option<Registry>, String> {
        HostSystem.registry()
    }
    fn lsblk(&self) -> Result<Vec<FlatDevice>, String> {
        HostSystem.lsblk()
    }
    fn audit_log(&self) -> PathBuf {
        audit::log_path()
    }
    fn unmount(&self, mount_point: &str) -> Result<(), String> {
        let spec = ProcessSpec::new("umount")
            .arg(mount_point)
            .timeout(UMOUNT_TIMEOUT);
        let out = run_blocking(&spec, None).map_err(|e| format!("umount could not be run: {e}"))?;
        if out.outcome.success() {
            Ok(())
        } else {
            let msg = crate::engines::process::first_line(&out.stderr)
                .or_else(|| crate::engines::process::first_line(&out.stdout))
                .unwrap_or_default();
            Err(format!(
                "umount {} failed ({}): {msg}",
                mount_point,
                out.outcome.record.status_text()
            ))
        }
    }
}

/// Unmounts every filesystem of the source and its descendants (§10, R8):
/// registry check first, system mounts, system disks and active swap
/// refused, mounts stacked on top by other devices refused, deepest first,
/// verified afterwards, audited, never lazy or forced. Holders (open
/// LUKS/LVM/md) are reported, not closed. The CLI (`unmount`,
/// `--auto-unmount`) and the TUI call this; on success the caller passes
/// `unmounted` as `AcquisitionRequest::unmounted_by_dfdisk`.
///
/// Errors: `Usage` for a regular file; `Refused` (exit 3) for every safety
/// refusal (recorded in the audit log); `Failed` when an unmount failed or a
/// mount remained (recorded).
pub fn unmount_source_tree(identity: &SourceIdentity) -> Result<UnmountResult, AcquisitionError> {
    unmount_source_tree_with(&HostUnmount, identity)
}

/// The audit record of one unmount attempt.
fn record(
    log: &Path,
    identity: &SourceIdentity,
    details: serde_json::Map<String, serde_json::Value>,
    error: Option<&AcquisitionError>,
) -> Result<String, String> {
    let mut event = dfcore::audit::Event::new(audit::TOOL, audit::VERSION, audit::action::UNMOUNT)
        .device(identity.device_identity());
    event.details = details;
    if let Some(e) = error {
        event = event
            .detail(
                "error_kind",
                serde_json::to_value(e.kind).unwrap_or_default(),
            )
            .outcome(e.audit_outcome(), Some(e.message.clone()));
    }
    audit::append(log, event)
}

/// Whether the audit log can take a record (open for append, or create it in
/// the nearest existing ancestor directory, as dfcore would), without
/// writing one.
fn audit_log_writable(log: &Path) -> Result<(), String> {
    if log.exists() {
        return std::fs::OpenOptions::new()
            .append(true)
            .open(log)
            .map(|_| ())
            .map_err(|e| format!("{}: {e}", log.display()));
    }
    let mut dir = log.parent().unwrap_or(Path::new("."));
    while !dir.exists() {
        dir = match dir.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
    }
    let c =
        std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: access() only reads the NUL-terminated path
    if unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "{}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        ))
    }
}

/// [`unmount_source_tree`] against a given host (tests: fake sysfs, mount
/// table and unmount).
pub fn unmount_source_tree_with(
    host: &dyn UnmountHost,
    identity: &SourceIdentity,
) -> Result<UnmountResult, AcquisitionError> {
    if !identity.is_block_device() {
        return Err(AcquisitionError::usage(format!(
            "{} is a regular file; there is nothing to unmount",
            identity.path
        )));
    }
    let log = host.audit_log();
    let sys = host.sysfs();
    let mut refusals: Vec<String> = Vec::new();

    // The device as selected, still behind its node, and its sysfs name
    let pinned = identity.maj_min.as_deref().and_then(parse_dev_num);
    let mut tree_identity = identity.clone();
    match pinned {
        None => refusals.push(format!(
            "{} has no major:minor; its mounts cannot be identified",
            identity.path
        )),
        Some(dev) => {
            if host.node_dev(Path::new(&identity.path)) != Some(dev) {
                refusals.push(format!(
                    "{} no longer refers to the selected device {}:{}; select it again",
                    identity.path, dev.0, dev.1
                ));
            }
            match sys.kname_of(dev) {
                Some(k) => tree_identity.kernel_name = k,
                None => refusals.push(format!(
                    "block device {}:{} has no entry in sysfs",
                    dev.0, dev.1
                )),
            }
        }
    }

    // 1. Registry and system disk, BEFORE anything is unmounted
    let registry = host.registry();
    let presence = registry_presence_of(&registry);
    if let Err(reason) = &registry {
        refusals.push(format!(
            "the dfnix protected-device registry exists but cannot be read ({reason}); refusing (fail closed)"
        ));
    }
    let canonical = if identity.canonical_path.is_empty() {
        identity.path.clone()
    } else {
        identity.canonical_path.clone()
    };
    match host.lsblk() {
        Err(e) => refusals.push(format!(
            "cannot list the block devices to check the source against the system disks and the dfnix registry: {e}"
        )),
        Ok(flat) => {
            let reg = registry.as_ref().ok().and_then(Option::as_ref);
            if let Err(e) = dfcore::protected::check_against(reg, &flat, &canonical, pinned) {
                refusals.push(format!("{e:#}"));
            }
            let reasons = system_reasons_for(&flat, &canonical, pinned);
            if !reasons.is_empty() {
                refusals.push(format!(
                    "{} is on a disk of the running system ({}); dfdisk does not unmount it",
                    identity.path,
                    reasons.join("; ")
                ));
            }
        }
    }

    // 2. The tree, its mounts, system mounts, foreign mounts on top, swap
    let tree = SourceTree::from_sysfs(&sys, &tree_identity);
    let records = match host.mountinfo() {
        Ok(m) => parse_mountinfo_records(&m),
        Err(e) => {
            refusals.push(format!("cannot read the mount table: {e}"));
            Vec::new()
        }
    };
    let ours = tree.mounts(&records);
    let mounts_before: Vec<String> = ours.iter().map(|m| m.mount_point.clone()).collect();
    for m in &ours {
        if is_system_mount(&m.mount_point) {
            refusals.push(format!(
                "{} is mounted at {}, a mount point of the running system",
                m.source, m.mount_point
            ));
        }
    }
    let our_ids: BTreeSet<u64> = ours.iter().map(|m| m.id).collect();
    for m in records
        .iter()
        .filter(|m| our_ids.contains(&m.parent_id) && !our_ids.contains(&m.id))
    {
        refusals.push(format!(
            "{} ({}) is mounted at {} on top of a filesystem of the source; dfdisk does not unmount filesystems of other devices, unmount it first",
            m.source, m.fstype, m.mount_point
        ));
    }
    match host.swaps() {
        Err(e) => refusals.push(format!("cannot read the active swap areas: {e}")),
        Ok(swaps) => refusals.extend(tree.swaps(&swaps).into_iter().map(swap_refusal)),
    }

    // Holders: stacked devices, not partitions of a disk source
    let partitions: BTreeSet<String> =
        if matches!(tree_identity.kind, SourceKind::Disk | SourceKind::Other) {
            sys.partitions(&tree_identity.kernel_name)
                .into_iter()
                .collect()
        } else {
            BTreeSet::new()
        };
    let holders: Vec<String> = tree
        .nodes
        .iter()
        .filter(|n| **n != tree_identity.kernel_name && !partitions.contains(*n))
        .cloned()
        .collect();
    let mut notes = Vec::new();
    if !holders.is_empty() {
        notes.push(format!(
            "devices stacked on the source stay open ({}); dfdisk does not close LUKS, LVM or md devices. Close them, or acquire with --allow-holders",
            holders.join(", ")
        ));
    }

    let mut details = serde_json::Map::new();
    details.insert("mounts_before".into(), json!(mounts_before));
    details.insert("holders".into(), json!(holders));
    details.insert("registry".into(), json!(presence.label()));

    if !refusals.is_empty() {
        details.insert("refusals".into(), json!(refusals));
        let err = AcquisitionError::refused(format!(
            "unmount of {} refused: {}",
            identity.path,
            refusals.join("; ")
        ));
        let _ = record(&log, identity, details, Some(&err));
        return Err(err);
    }
    if ours.is_empty() {
        notes.push(
            "nothing of the source is mounted in this mount namespace (mounts in other namespaces are detected by the exclusive open at acquisition)"
                .into(),
        );
        return Ok(UnmountResult {
            holders,
            notes,
            ..Default::default()
        });
    }
    // On dfnix an unmount that cannot be recorded does not happen
    if presence == RegistryPresence::Present {
        if let Err(e) = audit_log_writable(&log) {
            return Err(AcquisitionError::refused(format!(
                "the audit log cannot be written ({e}); on dfnix dfdisk does not unmount without an audit record"
            )));
        }
    }

    // 3. Deepest first (mount-tree depth, later mounts first among equals)
    let depths = mount_depths(&records);
    let mut order: Vec<(usize, usize, &MountRecord)> = ours
        .iter()
        .enumerate()
        .map(|(i, m)| (depths.get(&m.id).copied().unwrap_or(0), i, *m))
        .collect();
    order.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    let mut unmounted: Vec<String> = Vec::new();
    let mut failure: Option<AcquisitionError> = None;
    for (_, _, m) in order {
        match host.unmount(&m.mount_point) {
            Ok(()) => unmounted.push(m.mount_point.clone()),
            Err(e) => {
                failure = Some(AcquisitionError::failed(format!(
                    "cannot unmount {} ({}): {e}{}",
                    m.mount_point,
                    m.source,
                    if unmounted.is_empty() {
                        String::new()
                    } else {
                        format!("; already unmounted: {}", unmounted.join(", "))
                    }
                )));
                break;
            }
        }
    }

    // 4. Verify: nothing of the tree may remain mounted
    let remaining: Vec<String> = match host.mountinfo() {
        Ok(m) => tree
            .mounts(&parse_mountinfo_records(&m))
            .iter()
            .map(|r| r.mount_point.clone())
            .collect(),
        Err(e) => {
            if failure.is_none() {
                failure = Some(AcquisitionError::failed(format!(
                    "cannot re-read the mount table to verify the unmount: {e}"
                )));
            }
            Vec::new()
        }
    };
    if !remaining.is_empty() && failure.is_none() {
        failure = Some(AcquisitionError::failed(format!(
            "still mounted after unmounting: {}",
            remaining.join(", ")
        )));
    }
    details.insert("unmounted".into(), json!(unmounted));
    details.insert("remaining".into(), json!(remaining));

    // 5. Audit
    let audited = record(&log, identity, details, failure.as_ref());
    if let Some(mut e) = failure {
        if let Err(reason) = &audited {
            e.message
                .push_str(&format!(" (the audit record was not written: {reason})"));
        }
        return Err(e);
    }
    let (audit_hash, audit_error) = match audited {
        Ok(h) => (Some(h), None),
        Err(reason) => {
            notes.push(format!(
                "the unmount was NOT recorded in the audit log: {reason}"
            ));
            (None, Some(reason))
        }
    };
    Ok(UnmountResult {
        unmounted,
        holders,
        audit_hash,
        mounts_before,
        audit_error,
        notes,
    })
}

pub struct SafetyChecker;

impl SafetyChecker {
    /// dfdisk's own list of mount points of the running system. Use
    /// [`is_system_mount`] for the union with dfcore's list.
    pub fn is_critical_mount(mountpoint: &str) -> bool {
        let m = mountpoint.trim();
        if m.is_empty() {
            return false;
        }

        m == "/"
            || m == "/boot"
            || m.starts_with("/boot/")
            || m == "/nix"
            || m.starts_with("/nix/")
            || m == "/home"
            || m.starts_with("/home/")
            || m == "/etc"
            || m.starts_with("/etc/")
            || m == "/var"
            || m.starts_with("/var/")
            || m == "/usr"
            || m.starts_with("/usr/")
    }

    /// Classify mount points: any system mount (dfdisk's or dfcore's list) or
    /// active swap makes a system disk; other mounts make it mounted.
    pub fn evaluate_safety(mountpoints: &[String], swap_active: bool) -> DeviceSafety {
        let mut critical_mounts = Vec::new();
        let mut normal_mounts = Vec::new();

        for mp in mountpoints {
            let m = mp.trim();
            if m.is_empty() {
                continue;
            }
            if is_system_mount(m) {
                critical_mounts.push(m.to_string());
            } else {
                normal_mounts.push(m.to_string());
            }
        }

        if swap_active {
            critical_mounts.push("[SWAP ACTIVE]".to_string());
        }

        if !critical_mounts.is_empty() {
            DeviceSafety::SystemDisk(critical_mounts)
        } else if !normal_mounts.is_empty() {
            DeviceSafety::Mounted(normal_mounts)
        } else {
            DeviceSafety::Safe
        }
    }

    /// Retired (review H7): unmounting a list of mount points by path, before
    /// the registry check and without an audit record, is unsafe. Always
    /// refuses; use [`unmount_source_tree`] (`dfdisk unmount`).
    pub fn unmount_all(mountpoints: &[String]) -> Result<(), String> {
        Err(format!(
            "REFUSING to unmount {} by mount point: use dfdisk unmount (discovery::safety::unmount_source_tree), which checks the dfnix registry and system mounts first, unmounts the whole source tree deepest first, verifies and audits",
            if mountpoints.is_empty() {
                "nothing".to_string()
            } else {
                mountpoints.join(", ")
            }
        ))
    }
}

#[cfg(test)]
mod tests;
