//! Destination checks of an acquisition (§4 step 4, R4, R11, P5): nothing is
//! written before all of them passed.
//!
//! The facts about a destination ([`DestinationFacts`]: nearest existing
//! directory, its mount, filesystem type, free space, backing device) are read
//! once ([`probe_destination`] on a host); every rule is a pure decision over
//! those facts ([`evaluate`] and the `check_*` functions) so tests can drive
//! each refusal. Only [`prepare_output`] writes: it creates the output
//! directory and the report reservation file, and returns an [`OutputGuard`]
//! that removes the reservation (and directories it created, while empty) on
//! every exit path.

use crate::engines::error::{AcquisitionError, ErrorKind};
use crate::models::config::{AcquisitionConfig, EngineKind};
use crate::models::info_report::{
    create_reserve_file, remove_reserve_file, reserve_path, RESERVE_BYTES, RESERVE_SUFFIX,
};
use crate::models::text::format_iec;
use dfcore::sysfs::{parse_dev_num, BlockTopology, DevNum};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Free space every destination must keep: 64 MiB.
pub const MIN_FREE_BYTES: u64 = 64 << 20;

/// Largest file a FAT (vfat/msdos) filesystem can hold: 4 GiB - 1 byte.
pub const FAT_MAX_FILE_BYTES: u64 = (4 << 30) - 1;

/// One mount from /proc/self/mountinfo, with its filesystem type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountFacts {
    pub mount_point: PathBuf,
    /// "ext4", "vfat", "exfat", "ntfs3", "fuseblk", "tmpfs", ...
    pub fs_type: String,
    /// Mount source, e.g. "/dev/sdc1"
    pub source: String,
    pub dev: DevNum,
    /// Mounted read-only (mount option "ro")
    pub read_only: bool,
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape_octal(s: &str) -> String {
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

/// Parse /proc/self/mountinfo content.
pub fn parse_mounts(mountinfo: &str) -> Vec<MountFacts> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let (pre, post) = line.split_once(" - ")?;
            let pre: Vec<&str> = pre.split(' ').collect();
            let post: Vec<&str> = post.split(' ').collect();
            Some(MountFacts {
                dev: parse_dev_num(pre.get(2)?)?,
                mount_point: PathBuf::from(unescape_octal(pre.get(4)?)),
                read_only: pre
                    .get(5)
                    .is_some_and(|opts| opts.split(',').any(|o| o == "ro")),
                fs_type: post.first()?.to_string(),
                source: unescape_octal(post.get(1).copied().unwrap_or("")),
            })
        })
        .collect()
}

/// The mount holding `path` (longest mount point; the last of stacked mounts).
pub fn mount_containing<'a>(mounts: &'a [MountFacts], path: &Path) -> Option<&'a MountFacts> {
    let mut best: Option<&MountFacts> = None;
    for m in mounts.iter().filter(|m| path.starts_with(&m.mount_point)) {
        let depth = m.mount_point.components().count();
        if best.is_none_or(|b| depth >= b.mount_point.components().count()) {
            best = Some(m);
        }
    }
    best
}

/// What the destination of an acquisition is, read before anything is written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationFacts {
    /// The output directory as given
    pub output_dir: PathBuf,
    /// Nearest existing path at or above it (absolute): where the directory
    /// will be created
    pub existing_ancestor: PathBuf,
    /// The existing ancestor is a directory (not a file in the way)
    pub ancestor_is_dir: bool,
    pub mount_point: Option<PathBuf>,
    pub fs_type: Option<String>,
    pub mount_source: Option<String>,
    pub read_only_mount: bool,
    /// Space available to dfdisk (statvfs f_bavail * f_frsize)
    pub free_bytes: Option<u64>,
    /// Block device holding the destination ("major:minor"), if any
    pub backing_device: Option<String>,
}

impl DestinationFacts {
    /// Device number of the block device holding the destination.
    pub fn backing_dev(&self) -> Option<DevNum> {
        self.backing_device.as_deref().and_then(parse_dev_num)
    }

    /// "ext4 on /dev/sdc1 at /media/case, 120.50 GiB free".
    pub fn summary(&self) -> String {
        let mut s = self
            .fs_type
            .clone()
            .unwrap_or_else(|| "unknown filesystem".into());
        if let Some(src) = self.mount_source.as_deref().filter(|s| !s.is_empty()) {
            s.push_str(&format!(" on {src}"));
        }
        if let Some(mp) = &self.mount_point {
            s.push_str(&format!(" at {}", mp.display()));
        }
        match self.free_bytes {
            Some(free) => s.push_str(&format!(", {} free", format_iec(free))),
            None => s.push_str(", free space unknown"),
        }
        if self.read_only_mount {
            s.push_str(", mounted read-only");
        }
        s
    }
}

/// Free bytes available to an unprivileged writer on the filesystem of `path`.
pub fn statvfs_free(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: statvfs fills the zeroed struct we own from a valid C string
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Read the facts about `output_dir` on this host (`mountinfo`: content of
/// /proc/self/mountinfo). Writes nothing.
pub fn probe_destination(output_dir: &Path, mountinfo: &str) -> io::Result<DestinationFacts> {
    let ancestor = dfcore::sysfs::existing_ancestor(output_dir);
    let canonical = fs::canonicalize(&ancestor).unwrap_or_else(|_| ancestor.clone());
    let mounts = parse_mounts(mountinfo);
    let mount = mount_containing(&mounts, &canonical);
    Ok(DestinationFacts {
        output_dir: output_dir.to_path_buf(),
        ancestor_is_dir: canonical.is_dir(),
        free_bytes: statvfs_free(&canonical).ok(),
        backing_device: dfcore::sysfs::backing_device_of_path(&canonical)
            .map(|(a, b)| format!("{a}:{b}")),
        mount_point: mount.map(|m| m.mount_point.clone()),
        fs_type: mount.map(|m| m.fs_type.clone()),
        mount_source: mount.map(|m| m.source.clone()),
        read_only_mount: mount.is_some_and(|m| m.read_only),
        existing_ancestor: ancestor,
    })
}

/// Filesystems that live in memory: an image there is lost at power-off.
pub fn is_memory_fs(fs_type: &str) -> bool {
    matches!(fs_type, "tmpfs" | "ramfs")
}

/// FAT filesystems with their 4 GiB - 1 file size limit (exFAT has none).
pub fn is_fat(fs_type: &str) -> bool {
    matches!(fs_type, "vfat" | "msdos" | "fat" | "umsdos")
}

/// The destination rules of one acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationRules {
    pub engine: EngineKind,
    /// Size of the source
    pub source_bytes: u64,
    /// E01 segment size; `None` for one unlimited segment
    pub segment_bytes: Option<u64>,
    pub allow_tmpfs: bool,
    pub allow_low_space: bool,
    /// Rescue resume: bytes the existing image already occupies
    pub resumed_image_bytes: u64,
}

impl DestinationRules {
    pub fn new(config: &AcquisitionConfig, source_bytes: u64) -> Self {
        Self {
            engine: config.engine(),
            source_bytes,
            segment_bytes: config.split_size.bytes(),
            allow_tmpfs: config.allow_tmpfs,
            allow_low_space: config.allow_low_space,
            resumed_image_bytes: 0,
        }
    }
}

/// tmpfs/ramfs destinations are refused unless allowed; the note says so.
pub fn check_memory_fs(
    fs_type: Option<&str>,
    allow_tmpfs: bool,
) -> Result<Option<String>, AcquisitionError> {
    match fs_type {
        Some(fs) if is_memory_fs(fs) => {
            if allow_tmpfs {
                Ok(Some(format!(
                    "the destination is a {fs} filesystem in memory (allowed by --allow-tmpfs); its content is lost at power-off"
                )))
            } else {
                Err(AcquisitionError::refused(format!(
                    "the destination is a {fs} filesystem in memory: the image would be lost at power-off. Choose a directory on the case drive, or pass --allow-tmpfs"
                )))
            }
        }
        _ => Ok(None),
    }
}

/// FAT (vfat/msdos) cannot hold a file of 4 GiB or more: a single-file RAW or
/// rescue image of a larger source, or an E01 segment of 4 GiB or more, is
/// refused before anything is written.
pub fn check_file_size_limit(
    rules: &DestinationRules,
    fs_type: Option<&str>,
) -> Result<(), AcquisitionError> {
    let Some(fs) = fs_type.filter(|fs| is_fat(fs)) else {
        return Ok(());
    };
    if rules.source_bytes <= FAT_MAX_FILE_BYTES {
        return Ok(());
    }
    match rules.engine {
        EngineKind::Raw | EngineKind::Rescue => Err(AcquisitionError::refused(format!(
            "the destination is a FAT ({fs}) filesystem, which cannot hold a file larger than 4 GiB - 1 byte, and the {} image of this {}-byte source is one file. Acquire as E01 with 2 GiB segments, or use a destination formatted exFAT, NTFS or ext4",
            rules.engine.label(),
            rules.source_bytes
        ))),
        EngineKind::Ewf => match rules.segment_bytes {
            Some(seg) if seg <= FAT_MAX_FILE_BYTES => Ok(()),
            _ => Err(AcquisitionError::refused(format!(
                "the destination is a FAT ({fs}) filesystem, which cannot hold a file larger than 4 GiB - 1 byte, but the E01 segments of this {}-byte source may be larger. Choose 2 GiB segments (--split 2G)",
                rules.source_bytes
            ))),
        },
    }
}

/// Free space rules (§4, R4): RAW and rescue need the bytes still to be
/// written plus 64 MiB; E01 needs at least 64 MiB and, unless
/// `allow_low_space`, the source size (compression may need less, but that
/// is not known in advance). Unknown free space refuses (P2). Returns the
/// decision as a report note.
pub fn check_free_space(
    rules: &DestinationRules,
    free_bytes: Option<u64>,
) -> Result<String, AcquisitionError> {
    let Some(free) = free_bytes else {
        return Err(AcquisitionError::refused(
            "the free space of the destination cannot be determined (statvfs failed)",
        ));
    };
    let source = rules.source_bytes;
    match rules.engine {
        EngineKind::Raw | EngineKind::Rescue => {
            let remaining = source.saturating_sub(rules.resumed_image_bytes);
            let need = remaining.saturating_add(MIN_FREE_BYTES);
            if free < need {
                return Err(AcquisitionError::refused(format!(
                    "the destination has {} free, but the {} image needs {} more plus a {} margin ({} bytes in all)",
                    format_iec(free),
                    rules.engine.label(),
                    format_iec(remaining),
                    format_iec(MIN_FREE_BYTES),
                    need
                )));
            }
            Ok(format!(
                "free space: {} available, {} required (image {} + {} margin)",
                format_iec(free),
                format_iec(need),
                format_iec(remaining),
                format_iec(MIN_FREE_BYTES)
            ))
        }
        EngineKind::Ewf => {
            if free < MIN_FREE_BYTES {
                return Err(AcquisitionError::refused(format!(
                    "the destination has {} free; at least {} are required",
                    format_iec(free),
                    format_iec(MIN_FREE_BYTES)
                )));
            }
            if free < source {
                if !rules.allow_low_space {
                    return Err(AcquisitionError::refused(format!(
                        "the destination has {} free, less than the source size {}; the E01 image fits only if compression saves the difference. Pass --allow-low-space to accept that risk",
                        format_iec(free),
                        format_iec(source)
                    )));
                }
                return Ok(format!(
                    "free space: {} available, less than the source size {}; accepted by --allow-low-space (the E01 image fits only if compression saves the difference)",
                    format_iec(free),
                    format_iec(source)
                ));
            }
            Ok(format!(
                "free space: {} available for a source of {} (E01)",
                format_iec(free),
                format_iec(source)
            ))
        }
    }
}

/// A dfnix evidence mount (dfcore) is another disk's evidence: never a
/// destination.
pub fn check_evidence_mount(mount_point: Option<&Path>) -> Result<(), AcquisitionError> {
    match mount_point {
        Some(mp) if dfcore::lsblk::is_evidence_mount(&mp.to_string_lossy()) => {
            Err(AcquisitionError::refused(format!(
                "the destination is on {}, a dfnix evidence mount: evidence of another source must never be written to",
                mp.display()
            )))
        }
        _ => Ok(()),
    }
}

/// Every destination rule over the facts; the notes record the decisions.
pub fn evaluate(
    rules: &DestinationRules,
    facts: &DestinationFacts,
) -> Result<Vec<String>, AcquisitionError> {
    let mut notes = Vec::new();
    if !facts.ancestor_is_dir {
        return Err(AcquisitionError::usage(format!(
            "the output directory {} cannot be created: {} exists and is not a directory",
            facts.output_dir.display(),
            facts.existing_ancestor.display()
        )));
    }
    check_evidence_mount(facts.mount_point.as_deref())?;
    if facts.read_only_mount {
        return Err(AcquisitionError::refused(format!(
            "the destination {} is on a filesystem mounted read-only",
            facts.output_dir.display()
        )));
    }
    if let Some(note) = check_memory_fs(facts.fs_type.as_deref(), rules.allow_tmpfs)? {
        notes.push(note);
    }
    check_file_size_limit(rules, facts.fs_type.as_deref())?;
    notes.push(check_free_space(rules, facts.free_bytes)?);
    Ok(notes)
}

/// The destination must not be stored on the physical disk of a block-device
/// source (any partition, or any LVM/RAID/crypt/loop stack on it). Every
/// refusal, including an unresolvable device, is `Refused`.
pub fn check_not_on_source(
    topology: &BlockTopology,
    source: DevNum,
    source_label: &str,
    destination: Option<DevNum>,
    destination_label: &str,
) -> Result<(), AcquisitionError> {
    dfcore::sysfs::check_disjoint(
        topology,
        source,
        source_label,
        destination,
        destination_label,
    )
    .map_err(AcquisitionError::from)
}

/// [`check_not_on_source`] on this host, for a source path and an output
/// directory that may not exist yet. Regular-file sources are not checked.
pub fn ensure_destination_not_on_source(
    source_path: &str,
    output_dir: &Path,
) -> Result<(), AcquisitionError> {
    dfcore::sysfs::ensure_destination_not_on_source(source_path, output_dir)
        .map_err(AcquisitionError::from)
}

/// Files in `output_dir` that belong to an acquisition named `base_name`
/// (`<base>.E01`, `<base>.raw`, `<base>.info`, ...), compared without regard
/// to case: exFAT, NTFS and vfat case drives treat `X.E01` and `x.e01` as the
/// same file.
pub fn existing_outputs(output_dir: &Path, base_name: &str) -> Vec<PathBuf> {
    let prefix = format!("{}.", base_name.to_lowercase());
    let mut found: Vec<PathBuf> = fs::read_dir(output_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .to_lowercase()
                .starts_with(&prefix)
        })
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

/// The part of `file_name` from `.` after `<base>`, lower-cased, if the file
/// belongs to `base`.
fn output_suffix(base_name: &str, file_name: &str) -> Option<String> {
    let lower = file_name.to_lowercase();
    let prefix = format!("{}.", base_name.to_lowercase());
    lower.strip_prefix(&prefix).map(|s| format!(".{s}"))
}

fn numbered(rest: &str) -> bool {
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

/// Files an interrupted rescue leaves that a resumed rescue continues or
/// keeps (the rescue engine handles them): image, map, identity sidecar,
/// earlier reports, SMART snapshots, a stale reservation.
pub fn resume_may_exist(base_name: &str, file_name: &str) -> bool {
    let Some(suffix) = output_suffix(base_name, file_name) else {
        return false;
    };
    if matches!(
        suffix.as_str(),
        ".raw"
            | ".map"
            | ".map.bak"
            | ".identity.json"
            | ".identity.json.tmp"
            | ".info"
            | ".info.tmp"
            | ".info.json"
            | ".info.json.tmp"
            | RESERVE_SUFFIX
            | ".smart-before.json"
            | ".smart-after.json"
    ) {
        return true;
    }
    if let Some(n) = suffix.strip_prefix(".info.session-") {
        return numbered(n);
    }
    for kind in [".smart-before-", ".smart-after-"] {
        if let Some(n) = suffix
            .strip_prefix(kind)
            .and_then(|r| r.strip_suffix(".json"))
        {
            return numbered(n);
        }
    }
    false
}

/// Refuse if any output of `base_name` already exists (never overwrite). For
/// a resumed rescue the files of [`resume_may_exist`] are accepted and
/// returned; they must be regular files, not symbolic links and not the
/// source itself (`source_canonical`).
pub fn check_existing_outputs(
    output_dir: &Path,
    base_name: &str,
    resume_rescue: bool,
    source_canonical: Option<&Path>,
) -> Result<Vec<PathBuf>, AcquisitionError> {
    let found = existing_outputs(output_dir, base_name);
    let (kept, blocking): (Vec<PathBuf>, Vec<PathBuf>) = found.into_iter().partition(|p| {
        resume_rescue
            && p.file_name()
                .is_some_and(|n| resume_may_exist(base_name, &n.to_string_lossy()))
    });
    if !blocking.is_empty() {
        let list = blocking
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let hint = if base_name.to_uppercase().ends_with("_NOSERIAL") {
            " The source reports no serial number, so file names cannot tell drives apart; use a distinct evidence number for each drive."
        } else if resume_rescue {
            " A resumed rescue continues only its own image, map and reports; move the other files away or use a different evidence number."
        } else {
            " Use a different evidence number or output directory."
        };
        return Err(AcquisitionError::refused(format!(
            "Refusing to overwrite: acquisition output already exists: {list}.{hint}"
        )));
    }
    for p in &kept {
        let meta = fs::symlink_metadata(p).map_err(|e| {
            AcquisitionError::refused(format!("cannot inspect {}: {e}", p.display()))
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(AcquisitionError::refused(format!(
                "{} is not a regular file; a resumed rescue writes only to its own regular files",
                p.display()
            )));
        }
        if let (Some(src), Ok(canon)) = (source_canonical, fs::canonicalize(p)) {
            if canon == src {
                return Err(AcquisitionError::refused(format!(
                    "{} is the source itself; refusing to write to it",
                    p.display()
                )));
            }
        }
    }
    Ok(kept)
}

/// A resumed rescue needs its map (not empty) and its image. Returns the bytes
/// the existing image occupies on disk (allocated blocks), for the free space
/// rule.
pub fn check_resume_files(output_dir: &Path, base_name: &str) -> Result<u64, AcquisitionError> {
    use std::os::unix::fs::MetadataExt;
    let find = |suffix: &str| {
        existing_outputs(output_dir, base_name)
            .into_iter()
            .find(|p| {
                p.file_name()
                    .and_then(|n| output_suffix(base_name, &n.to_string_lossy()))
                    .as_deref()
                    == Some(suffix)
            })
    };
    let map = find(".map").ok_or_else(|| {
        AcquisitionError::usage(format!(
            "cannot resume the rescue: the ddrescue map {} does not exist",
            output_dir.join(format!("{base_name}.map")).display()
        ))
    })?;
    let map_len = fs::metadata(&map).map(|m| m.len()).unwrap_or(0);
    if map_len == 0 {
        return Err(AcquisitionError::usage(format!(
            "cannot resume the rescue: the ddrescue map {} is empty",
            map.display()
        )));
    }
    let image = find(".raw").ok_or_else(|| {
        AcquisitionError::usage(format!(
            "cannot resume the rescue: the image {} does not exist",
            output_dir.join(format!("{base_name}.raw")).display()
        ))
    })?;
    Ok(fs::metadata(&image)
        .map(|m| m.blocks().saturating_mul(512))
        .unwrap_or(0))
}

/// Directories `create_dir_all(dir)` would create, outermost first.
pub fn missing_dirs(dir: &Path) -> Vec<PathBuf> {
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut missing: Vec<PathBuf> = absolute
        .ancestors()
        .take_while(|p| fs::symlink_metadata(p).is_err())
        .map(Path::to_path_buf)
        .collect();
    missing.reverse();
    missing
}

/// The output directory and report reservation of a run being prepared or
/// running. Dropping it removes the reservation file (if still there) and,
/// unless [`keep`](Self::keep) was called, the directories it created while
/// they are empty. A run that wrote outputs calls `keep`.
#[derive(Debug)]
pub struct OutputGuard {
    dir: PathBuf,
    base: String,
    created_dirs: Vec<PathBuf>,
    reserve: Option<PathBuf>,
    keep_dirs: bool,
}

impl OutputGuard {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// The reservation file, while it exists.
    pub fn reserve(&self) -> Option<&Path> {
        self.reserve.as_deref().filter(|p| p.exists())
    }

    /// Directories this run created, outermost first.
    pub fn created_dirs(&self) -> &[PathBuf] {
        &self.created_dirs
    }

    /// Outputs exist: never remove the directories.
    pub fn keep(&mut self) {
        self.keep_dirs = true;
    }

    /// Remove the reservation now (the reports remove it themselves).
    pub fn release_reserve(&mut self) -> io::Result<bool> {
        match &self.reserve {
            Some(_) => remove_reserve_file(&self.dir, &self.base),
            None => Ok(false),
        }
    }
}

impl Drop for OutputGuard {
    fn drop(&mut self) {
        if self.reserve.is_some() {
            let _ = remove_reserve_file(&self.dir, &self.base);
        }
        if !self.keep_dirs {
            for d in self.created_dirs.iter().rev() {
                // Only empty directories go; anything written stays
                let _ = fs::remove_dir(d);
            }
        }
    }
}

/// The first write of a run (after every check passed): create the output
/// directory and the 1 MiB report reservation `<base>.info.reserve` (R11).
/// Failure refuses (exit 3) and leaves nothing behind. `stale_reserve_ok`
/// (rescue resume) first removes a reservation an interrupted run left.
pub fn prepare_output(
    dir: &Path,
    base: &str,
    stale_reserve_ok: bool,
) -> Result<OutputGuard, AcquisitionError> {
    let created_dirs = missing_dirs(dir);
    let mut guard = OutputGuard {
        dir: dir.to_path_buf(),
        base: base.to_string(),
        created_dirs,
        reserve: None,
        keep_dirs: false,
    };
    fs::create_dir_all(dir).map_err(|e| {
        AcquisitionError::refused(format!(
            "cannot create the output directory {}: {e}",
            dir.display()
        ))
    })?;
    if stale_reserve_ok {
        remove_reserve_file(dir, base).map_err(|e| {
            AcquisitionError::refused(format!("cannot remove a stale reservation: {e}"))
        })?;
    }
    // Only a reservation this call created is ever removed by the guard
    let path = create_reserve_file(dir, base).map_err(|e| {
        AcquisitionError::new(
            ErrorKind::Refused,
            format!(
                "cannot reserve {} for the report ({}): {e}. The destination has no room for the report; nothing was acquired",
                format_iec(RESERVE_BYTES),
                reserve_path(dir, base).display()
            ),
        )
    })?;
    guard.reserve = Some(path);
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn rules(engine: EngineKind, source_bytes: u64) -> DestinationRules {
        let config = AcquisitionConfig::for_engine(engine, "/out");
        DestinationRules::new(&config, source_bytes)
    }

    fn facts(fs: &str, free: u64) -> DestinationFacts {
        DestinationFacts {
            output_dir: "/media/case/out".into(),
            existing_ancestor: "/media/case".into(),
            ancestor_is_dir: true,
            mount_point: Some("/media/case".into()),
            fs_type: Some(fs.into()),
            mount_source: Some("/dev/sdc1".into()),
            read_only_mount: false,
            free_bytes: Some(free),
            backing_device: Some("8:33".into()),
        }
    }

    #[test]
    fn mountinfo_is_parsed_with_fstype_and_escapes() {
        let info = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
30 22 0:25 / /tmp rw,nosuid shared:5 - tmpfs tmpfs rw,size=4g
41 22 8:33 / /media/case\\040drive ro,nosuid - exfat /dev/sdc1 rw
42 41 8:34 / /media/case\\040drive/inner rw - vfat /dev/sdc2 rw
";
        let mounts = parse_mounts(info);
        assert_eq!(mounts.len(), 4);
        assert_eq!(mounts[2].mount_point, PathBuf::from("/media/case drive"));
        assert_eq!(mounts[2].fs_type, "exfat");
        assert!(mounts[2].read_only);
        assert_eq!(mounts[2].dev, (8, 33));
        let m = mount_containing(&mounts, Path::new("/media/case drive/out")).unwrap();
        assert_eq!(m.fs_type, "exfat");
        let m = mount_containing(&mounts, Path::new("/media/case drive/inner/x")).unwrap();
        assert_eq!(m.fs_type, "vfat");
        let m = mount_containing(&mounts, Path::new("/tmp/a")).unwrap();
        assert_eq!(m.fs_type, "tmpfs");
        let m = mount_containing(&mounts, Path::new("/home/x")).unwrap();
        assert_eq!(m.fs_type, "ext4");
        // Stacked mounts: the last one wins
        let stacked = parse_mounts(&format!(
            "{info}43 41 0:40 / /media/case\\040drive rw - tmpfs tmpfs rw\n"
        ));
        let m = mount_containing(&stacked, Path::new("/media/case drive/out")).unwrap();
        assert_eq!(m.fs_type, "tmpfs");
    }

    #[test]
    fn memory_filesystems_are_refused_unless_allowed() {
        for fs in ["tmpfs", "ramfs"] {
            let e = check_memory_fs(Some(fs), false).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Refused);
            assert!(e.message.contains("--allow-tmpfs"), "{e}");
            let note = check_memory_fs(Some(fs), true).unwrap().unwrap();
            assert!(note.contains("lost at power-off"));
        }
        assert_eq!(check_memory_fs(Some("ext4"), false).unwrap(), None);
        assert_eq!(check_memory_fs(None, false).unwrap(), None);
        let e = evaluate(&rules(EngineKind::Raw, MIB), &facts("tmpfs", 10 * GIB)).unwrap_err();
        assert!(e.message.contains("tmpfs"));
    }

    #[test]
    fn fat_file_size_limit() {
        let big = 5 * GIB;
        for engine in [EngineKind::Raw, EngineKind::Rescue] {
            let e = check_file_size_limit(&rules(engine, big), Some("vfat")).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Refused);
            assert!(e.message.contains("4 GiB - 1 byte"), "{e}");
            assert!(e.message.contains("E01 with 2 GiB segments"), "{e}");
            // Fits, other filesystems, exFAT
            assert!(
                check_file_size_limit(&rules(engine, FAT_MAX_FILE_BYTES), Some("vfat")).is_ok()
            );
            assert!(check_file_size_limit(&rules(engine, big), Some("exfat")).is_ok());
            assert!(check_file_size_limit(&rules(engine, big), Some("ext4")).is_ok());
        }
        // E01: 2 GiB segments fit, 4 GiB (= limit + 1) and unsplit do not
        let mut e01 = rules(EngineKind::Ewf, big);
        assert!(check_file_size_limit(&e01, Some("vfat")).is_ok());
        e01.segment_bytes = Some(4 * GIB);
        assert!(check_file_size_limit(&e01, Some("msdos")).is_err());
        e01.segment_bytes = None;
        let e = check_file_size_limit(&e01, Some("vfat")).unwrap_err();
        assert!(e.message.contains("--split 2G"), "{e}");
    }

    #[test]
    fn free_space_rules() {
        // RAW / rescue: source + 64 MiB
        let raw = rules(EngineKind::Raw, GIB);
        assert!(check_free_space(&raw, Some(GIB + MIN_FREE_BYTES)).is_ok());
        let e = check_free_space(&raw, Some(GIB + MIN_FREE_BYTES - 1)).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Refused);
        // A resumed rescue only needs what is still missing
        let mut resume = rules(EngineKind::Rescue, GIB);
        resume.resumed_image_bytes = GIB / 2;
        assert!(check_free_space(&resume, Some(GIB / 2 + MIN_FREE_BYTES)).is_ok());
        // --allow-low-space does not apply to RAW
        let mut raw_low = raw.clone();
        raw_low.allow_low_space = true;
        assert!(check_free_space(&raw_low, Some(GIB)).is_err());

        // E01 (R4): >= 64 MiB always, source size unless allowed
        let e01 = rules(EngineKind::Ewf, GIB);
        let note = check_free_space(&e01, Some(GIB)).unwrap();
        assert!(note.contains("E01"), "{note}");
        let e = check_free_space(&e01, Some(GIB - 1)).unwrap_err();
        assert!(e.message.contains("--allow-low-space"), "{e}");
        let mut low = e01.clone();
        low.allow_low_space = true;
        let note = check_free_space(&low, Some(GIB / 2)).unwrap();
        assert!(note.contains("accepted by --allow-low-space"), "{note}");
        assert!(check_free_space(&low, Some(MIN_FREE_BYTES - 1)).is_err());
        // Unknown free space fails closed
        assert!(check_free_space(&e01, None).is_err());
    }

    #[test]
    fn evaluate_collects_notes_and_refuses_bad_destinations() {
        let r = rules(EngineKind::Ewf, GIB);
        let notes = evaluate(&r, &facts("ext4", 10 * GIB)).unwrap();
        assert_eq!(notes.len(), 1);
        let mut f = facts("ext4", 10 * GIB);
        f.mount_point = Some("/media/evidence-sdb1".into());
        let e = evaluate(&r, &f).unwrap_err();
        assert!(e.message.contains("evidence mount"), "{e}");
        let mut f = facts("ext4", 10 * GIB);
        f.read_only_mount = true;
        assert!(evaluate(&r, &f).unwrap_err().message.contains("read-only"));
        let mut f = facts("ext4", 10 * GIB);
        f.ancestor_is_dir = false;
        assert_eq!(evaluate(&r, &f).unwrap_err().kind, ErrorKind::Usage);
        assert!(facts("ext4", GIB)
            .summary()
            .contains("ext4 on /dev/sdc1 at /media/case"));
        assert_eq!(facts("ext4", GIB).backing_dev(), Some((8, 33)));
    }

    #[test]
    fn existing_outputs_are_detected_case_insensitively_and_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let base = "case_ea01_cf01_NOSERIAL";

        assert!(check_existing_outputs(dir, base, false, None).is_ok());
        // Different acquisition sharing a prefix is not a collision
        fs::write(dir.join(format!("{}2.E01", base)), b"x").unwrap();
        assert!(check_existing_outputs(dir, base, false, None).is_ok());

        for name in ["E01", "e02", "raw", "map", "info", "info.reserve"] {
            let f = dir.join(format!("{}.{}", base, name));
            fs::write(&f, b"x").unwrap();
            let e = check_existing_outputs(dir, base, false, None).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Refused);
            assert!(e.message.contains("already exists"), "{e}");
            assert!(e.message.contains("no serial number"), "{e}");
            fs::remove_file(&f).unwrap();
        }
        // Another spelling of the same name on a case-insensitive drive
        fs::write(dir.join("CASE_EA01_CF01_SER1.E01"), b"x").unwrap();
        let e = check_existing_outputs(dir, "case_ea01_cf01_SER1", false, None).unwrap_err();
        assert!(!e.message.contains("no serial number"), "{e}");
    }

    #[test]
    fn resumed_rescue_keeps_its_own_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let base = "c_ea01_e_SER";
        for suffix in [
            "raw",
            "map",
            "identity.json",
            "info",
            "info.json",
            "info.session-1",
            "smart-before.json",
            "smart-before-2.json",
        ] {
            fs::write(dir.join(format!("{base}.{suffix}")), b"x").unwrap();
        }
        let kept = check_existing_outputs(dir, base, true, None).unwrap();
        assert_eq!(kept.len(), 8);
        // Without --resume every one of them refuses
        assert!(check_existing_outputs(dir, base, false, None).is_err());
        // A foreign output still refuses a resume
        fs::write(dir.join(format!("{base}.E01")), b"x").unwrap();
        let e = check_existing_outputs(dir, base, true, None).unwrap_err();
        assert!(e.message.contains(".E01"), "{e}");
        fs::remove_file(dir.join(format!("{base}.E01"))).unwrap();
        // The image must not be the source or a link
        let src = fs::canonicalize(dir.join(format!("{base}.raw"))).unwrap();
        assert!(check_existing_outputs(dir, base, true, Some(&src)).is_err());
        fs::remove_file(dir.join(format!("{base}.raw"))).unwrap();
        std::os::unix::fs::symlink("/dev/null", dir.join(format!("{base}.raw"))).unwrap();
        let e = check_existing_outputs(dir, base, true, None).unwrap_err();
        assert!(e.message.contains("not a regular file"), "{e}");

        assert!(resume_may_exist(base, &format!("{base}.info.session-12")));
        assert!(!resume_may_exist(base, &format!("{base}.info.session-")));
        assert!(!resume_may_exist(base, &format!("{base}.pieces.tsv")));
        assert!(!resume_may_exist(base, "other.raw"));
    }

    #[test]
    fn resume_requires_map_and_image() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let base = "c_ea01_e_SER";
        let e = check_resume_files(dir, base).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Usage);
        assert!(e.message.contains("map"), "{e}");
        fs::write(dir.join(format!("{base}.map")), b"").unwrap();
        assert!(check_resume_files(dir, base)
            .unwrap_err()
            .message
            .contains("empty"));
        fs::write(dir.join(format!("{base}.map")), b"# map\n0x0 0x200 +\n").unwrap();
        assert!(check_resume_files(dir, base)
            .unwrap_err()
            .message
            .contains("image"));
        fs::write(dir.join(format!("{base}.RAW")), vec![1u8; 8192]).unwrap();
        assert!(check_resume_files(dir, base).unwrap() >= 8192);
    }

    #[test]
    fn prepare_output_creates_reserves_and_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("a/b/out");
        let base = "c_ea01_e_SER";
        assert_eq!(missing_dirs(&out).len(), 3);
        {
            let guard = prepare_output(&out, base, false).unwrap();
            assert_eq!(guard.created_dirs().len(), 3);
            let reserve = guard.reserve().unwrap().to_path_buf();
            assert_eq!(fs::metadata(&reserve).unwrap().len(), RESERVE_BYTES);
        }
        // Refused or failed run: reservation and the empty directories are gone
        assert!(!tmp.path().join("a").exists());

        {
            let mut guard = prepare_output(&out, base, false).unwrap();
            fs::write(out.join(format!("{base}.raw")), b"image").unwrap();
            guard.keep();
        }
        assert!(out.join(format!("{base}.raw")).exists());
        assert!(!reserve_path(&out, base).exists());

        // A reservation that exists is not ours: refused, and left alone
        fs::write(reserve_path(&out, base), b"stale").unwrap();
        let e = prepare_output(&out, base, false).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Refused);
        assert_eq!(fs::read(reserve_path(&out, base)).unwrap(), b"stale");
        // ... unless a resumed rescue may replace it
        let guard = prepare_output(&out, base, true).unwrap();
        assert_eq!(
            fs::metadata(guard.reserve().unwrap()).unwrap().len(),
            RESERVE_BYTES
        );
        drop(guard);
        assert!(!reserve_path(&out, base).exists());

        // An unwritable destination refuses before anything is written
        let file = tmp.path().join("file");
        fs::write(&file, b"x").unwrap();
        let e = prepare_output(&file.join("out"), base, false).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Refused);
    }
}
