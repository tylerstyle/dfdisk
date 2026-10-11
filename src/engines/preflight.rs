//! Checks every acquisition engine runs before it writes a single byte:
//! no existing output may be overwritten, and the destination must not live on
//! the physical disk being acquired.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Files in `output_dir` that belong to an acquisition named `base_name`
/// (`<base>.E01`, `<base>.E02`, `<base>.raw`, `<base>.map`, `<base>.info`, ...).
pub fn existing_outputs(output_dir: &Path, base_name: &str) -> Vec<PathBuf> {
    let prefix = format!("{}.", base_name);
    let mut found: Vec<PathBuf> = fs::read_dir(output_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

/// Refuse to start if any output of this acquisition already exists.
pub fn ensure_no_existing_outputs(output_dir: &Path, base_name: &str) -> Result<(), String> {
    let found = existing_outputs(output_dir, base_name);
    if found.is_empty() {
        return Ok(());
    }
    let list = found
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let hint = if base_name.ends_with("_NOSERIAL") {
        " The source reports no serial number, so file names cannot tell drives apart; use a distinct evidence number for each drive."
    } else {
        " Use a different evidence number or output directory."
    };
    Err(format!(
        "Refusing to overwrite: acquisition output already exists: {}.{}",
        list, hint
    ))
}

/// A block device as the kernel numbers it.
pub type DevNum = (u32, u32);

/// Read-only view of `/sys/class/block`, rooted elsewhere in tests.
pub struct BlockTopology {
    class_block: PathBuf,
}

impl Default for BlockTopology {
    fn default() -> Self {
        Self::new("/sys/class/block")
    }
}

impl BlockTopology {
    pub fn new(class_block: impl Into<PathBuf>) -> Self {
        Self {
            class_block: class_block.into(),
        }
    }

    /// Kernel name (sda, sda1, dm-0, loop3, ...) of a device number.
    pub fn name_of(&self, dev: DevNum) -> Option<String> {
        let want = format!("{}:{}", dev.0, dev.1);
        fs::read_dir(&self.class_block)
            .ok()?
            .flatten()
            .find(|e| {
                fs::read_to_string(e.path().join("dev"))
                    .map(|s| s.trim() == want)
                    .unwrap_or(false)
            })
            .map(|e| e.file_name().to_string_lossy().into_owned())
    }

    /// Whole physical disks a device ultimately stores its data on: a partition
    /// maps to its disk, device-mapper/md devices to the disks behind their
    /// `slaves`, and loop devices to the disks holding their backing file.
    pub fn backing_disks(&self, name: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect_backing(name, 0, &mut out);
        out
    }

    fn collect_backing(&self, name: &str, depth: usize, out: &mut BTreeSet<String>) {
        if depth > 16 {
            // Unexpectedly deep stack: keep the device itself so it still counts
            out.insert(name.to_string());
            return;
        }
        let node = self.class_block.join(name);

        let slaves: Vec<String> = fs::read_dir(node.join("slaves"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        if !slaves.is_empty() {
            for s in slaves {
                self.collect_backing(&s, depth + 1, out);
            }
            return;
        }

        if let Ok(backing) = fs::read_to_string(node.join("loop").join("backing_file")) {
            if let Some(dev) = backing_device_of_path(Path::new(backing.trim())) {
                if let Some(parent) = self.name_of(dev) {
                    self.collect_backing(&parent, depth + 1, out);
                    return;
                }
            }
        }

        if node.join("partition").exists() {
            // /sys/class/block/sdb1 -> .../block/sdb/sdb1
            if let Some(disk) = fs::canonicalize(&node).ok().and_then(|p| {
                p.parent()
                    .and_then(|d| d.file_name())
                    .map(|f| f.to_string_lossy().into_owned())
            }) {
                out.insert(disk);
                return;
            }
        }

        out.insert(name.to_string());
    }
}

/// One line of /proc/self/mountinfo, reduced to what we need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_point: PathBuf,
    pub dev: DevNum,
    pub source: String,
}

fn unescape_mountinfo(s: &str) -> String {
    // Spaces, tabs, newlines and backslashes are written as \ooo octal escapes
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
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

pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    content
        .lines()
        .filter_map(|line| {
            let (pre, post) = line.split_once(" - ")?;
            let pre: Vec<&str> = pre.split(' ').collect();
            let post: Vec<&str> = post.split(' ').collect();
            let (maj, min) = pre.get(2)?.split_once(':')?;
            Some(MountEntry {
                mount_point: PathBuf::from(unescape_mountinfo(pre.get(4)?)),
                dev: (maj.parse().ok()?, min.parse().ok()?),
                source: unescape_mountinfo(post.get(1)?),
            })
        })
        .collect()
}

/// The mount that contains `path` (longest matching mount point, last one wins
/// for stacked mounts).
pub fn mount_containing<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .filter(|m| path.starts_with(&m.mount_point))
        .max_by_key(|m| m.mount_point.components().count())
}

#[cfg(unix)]
fn dev_split(dev: u64) -> DevNum {
    (
        libc::major(dev as libc::dev_t) as u32,
        libc::minor(dev as libc::dev_t) as u32,
    )
}

/// Block device holding the filesystem that stores `path`, if it is on one.
#[cfg(unix)]
pub fn backing_device_of_path(path: &Path) -> Option<DevNum> {
    use std::os::unix::fs::MetadataExt;
    let canonical = fs::canonicalize(path).ok()?;
    let st_dev = dev_split(fs::metadata(&canonical).ok()?.dev());
    if st_dev.0 != 0 {
        return Some(st_dev);
    }
    // Btrfs, overlayfs and network/virtual filesystems report an anonymous
    // device; the mount source names the real one when there is one
    let mounts = parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").ok()?);
    let m = mount_containing(&mounts, &canonical)?;
    if m.source.starts_with("/dev/") {
        source_device(Path::new(&m.source))
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn backing_device_of_path(_path: &Path) -> Option<DevNum> {
    None
}

/// Device number of a block device node, or `None` for anything else.
#[cfg(unix)]
pub fn source_device(path: &Path) -> Option<DevNum> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = fs::metadata(path).ok()?;
    if meta.file_type().is_block_device() {
        Some(dev_split(meta.rdev()))
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn source_device(_path: &Path) -> Option<DevNum> {
    None
}

/// Core of the destination-on-source check, separated from the host for tests.
pub fn check_disjoint(
    topo: &BlockTopology,
    source: DevNum,
    source_label: &str,
    dest: Option<DevNum>,
    dest_label: &str,
) -> Result<(), String> {
    let Some(dest) = dest else {
        // tmpfs, network shares, FUSE: not stored on any local block device
        return Ok(());
    };
    if dest == source {
        return Err(format!(
            "Critical Safety Error: destination {} is stored on the source device {} itself!",
            dest_label, source_label
        ));
    }
    let src_name = topo.name_of(source).ok_or_else(|| {
        format!(
            "Cannot resolve source {} in sysfs; refusing to acquire",
            source_label
        )
    })?;
    let dst_name = topo.name_of(dest).ok_or_else(|| {
        format!(
            "Cannot resolve the device holding {} ({}:{}) in sysfs; refusing to acquire",
            dest_label, dest.0, dest.1
        )
    })?;
    let src_disks = topo.backing_disks(&src_name);
    let dst_disks = topo.backing_disks(&dst_name);
    let shared: Vec<_> = src_disks.intersection(&dst_disks).cloned().collect();
    if shared.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Critical Safety Error: destination {} is on {} which shares physical disk {} with source {} ({}). Choose an output directory on a separate target drive.",
            dest_label,
            dst_name,
            shared.join(", "),
            source_label,
            src_name
        ))
    }
}

/// Refuse when the output directory lives on the same physical disk (any
/// partition, or any LVM/RAID/crypt/loop stack on it) as a block-device source.
/// Regular-file sources are not block devices and are not checked here.
pub fn ensure_destination_not_on_source(
    source_path: &str,
    output_dir: &Path,
) -> Result<(), String> {
    let Some(source) = source_device(Path::new(source_path)) else {
        return Ok(());
    };
    let dest = backing_device_of_path(output_dir);
    check_disjoint(
        &BlockTopology::default(),
        source,
        source_path,
        dest,
        &output_dir.display().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct FakeSys {
        root: PathBuf,
    }

    impl FakeSys {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "dfdisk_fake_sysfs_{}_{}",
                tag,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("class/block")).unwrap();
            fs::create_dir_all(root.join("devices")).unwrap();
            Self { root }
        }

        fn topo(&self) -> BlockTopology {
            BlockTopology::new(self.root.join("class/block"))
        }

        fn add(&self, real: &str, name: &str, dev: &str, partition: bool, slaves: &[&str]) {
            let dir = self.root.join("devices").join(real);
            fs::create_dir_all(dir.join("slaves")).unwrap();
            fs::write(dir.join("dev"), format!("{}\n", dev)).unwrap();
            if partition {
                fs::write(dir.join("partition"), "1\n").unwrap();
            }
            for s in slaves {
                fs::write(dir.join("slaves").join(s), "").unwrap();
            }
            symlink(&dir, self.root.join("class/block").join(name)).unwrap();
        }

        /// sda (system) + sdb (evidence: sdb1, sdb2, LVM dm-0 on sdb2) +
        /// sdc (target: sdc1, dm-1 crypt on sdc1) + md0 over sdb1 and sdc1
        fn lab(tag: &str) -> Self {
            let s = Self::new(tag);
            s.add("block/sda", "sda", "8:0", false, &[]);
            s.add("block/sda/sda1", "sda1", "8:1", true, &[]);
            s.add("block/sdb", "sdb", "8:16", false, &[]);
            s.add("block/sdb/sdb1", "sdb1", "8:17", true, &[]);
            s.add("block/sdb/sdb2", "sdb2", "8:18", true, &[]);
            s.add("virtual/block/dm-0", "dm-0", "254:0", false, &["sdb2"]);
            s.add("block/sdc", "sdc", "8:32", false, &[]);
            s.add("block/sdc/sdc1", "sdc1", "8:33", true, &[]);
            s.add("virtual/block/dm-1", "dm-1", "254:1", false, &["sdc1"]);
            s.add("virtual/block/md0", "md0", "9:0", false, &["sdb1", "sdc1"]);
            s
        }
    }

    impl Drop for FakeSys {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn backing_disks_resolve_partitions_and_stacks() {
        let s = FakeSys::lab("resolve");
        let t = s.topo();
        let set = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(t.backing_disks("sdb"), set(&["sdb"]));
        assert_eq!(t.backing_disks("sdb1"), set(&["sdb"]));
        assert_eq!(t.backing_disks("dm-0"), set(&["sdb"]));
        assert_eq!(t.backing_disks("dm-1"), set(&["sdc"]));
        assert_eq!(t.backing_disks("md0"), set(&["sdb", "sdc"]));
        assert_eq!(t.name_of((8, 33)).as_deref(), Some("sdc1"));
        assert_eq!(t.name_of((8, 99)), None);
    }

    #[test]
    fn destination_on_other_disk_is_allowed() {
        let s = FakeSys::lab("allowed");
        assert!(check_disjoint(
            &s.topo(),
            (8, 16),
            "/dev/sdb",
            Some((8, 33)),
            "/media/target"
        )
        .is_ok());
        assert!(check_disjoint(
            &s.topo(),
            (8, 16),
            "/dev/sdb",
            Some((254, 1)),
            "/media/target"
        )
        .is_ok());
        assert!(check_disjoint(&s.topo(), (8, 17), "/dev/sdb1", None, "/tmp").is_ok());
    }

    #[test]
    fn destination_on_source_tree_is_refused() {
        let s = FakeSys::lab("refused");
        let t = s.topo();
        // Whole disk source, image written to one of its partitions
        let e = check_disjoint(&t, (8, 16), "/dev/sdb", Some((8, 17)), "/mnt/x").unwrap_err();
        assert!(e.contains("shares physical disk sdb"), "{e}");
        // Partition source, image on a sibling partition
        assert!(check_disjoint(&t, (8, 17), "/dev/sdb1", Some((8, 18)), "/mnt/x").is_err());
        // Image on an LVM volume living on the source disk
        assert!(check_disjoint(&t, (8, 16), "/dev/sdb", Some((254, 0)), "/mnt/x").is_err());
        // Image on a RAID array that has a member on the source disk
        assert!(check_disjoint(&t, (8, 16), "/dev/sdb", Some((9, 0)), "/mnt/x").is_err());
        // Source is the array, image on a disk that is one of its members
        assert!(check_disjoint(&t, (9, 0), "/dev/md0", Some((8, 33)), "/mnt/x").is_err());
        // Same device outright
        assert!(check_disjoint(&t, (8, 17), "/dev/sdb1", Some((8, 17)), "/mnt/x").is_err());
    }

    #[test]
    fn unresolvable_destination_device_is_refused() {
        let s = FakeSys::lab("unresolved");
        let e =
            check_disjoint(&s.topo(), (8, 16), "/dev/sdb", Some((8, 200)), "/mnt/x").unwrap_err();
        assert!(e.contains("Cannot resolve"), "{e}");
    }

    #[test]
    fn mountinfo_parsing_and_lookup() {
        let info = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
40 22 0:35 / /media/target rw,relatime shared:20 - btrfs /dev/sdc1 rw,space_cache=v2
41 40 0:36 / /media/target/sub\\040dir rw - tmpfs tmpfs rw
";
        let mounts = parse_mountinfo(info);
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[1].dev, (0, 35));
        assert_eq!(mounts[1].source, "/dev/sdc1");
        assert_eq!(
            mounts[2].mount_point,
            PathBuf::from("/media/target/sub dir")
        );

        let m = mount_containing(&mounts, Path::new("/media/target/case1")).unwrap();
        assert_eq!(m.source, "/dev/sdc1");
        let m = mount_containing(&mounts, Path::new("/media/target/sub dir/x")).unwrap();
        assert_eq!(m.source, "tmpfs");
        // Prefix match is by path component, not by string
        let m = mount_containing(&mounts, Path::new("/media/targetX")).unwrap();
        assert_eq!(m.mount_point, PathBuf::from("/"));
    }

    #[test]
    fn existing_outputs_are_detected_and_refused() {
        let dir = std::env::temp_dir().join(format!("dfdisk_preflight_out_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let base = "case_ea01_cf01_NOSERIAL";

        assert!(ensure_no_existing_outputs(&dir, base).is_ok());
        // Different acquisition sharing a prefix is not a collision
        fs::write(dir.join(format!("{}2.E01", base)), b"x").unwrap();
        assert!(ensure_no_existing_outputs(&dir, base).is_ok());

        for name in ["E01", "E02", "raw", "map", "info"] {
            let f = dir.join(format!("{}.{}", base, name));
            fs::write(&f, b"x").unwrap();
            let e = ensure_no_existing_outputs(&dir, base).unwrap_err();
            assert!(e.contains("already exists"), "{e}");
            assert!(e.contains("no serial number"), "{e}");
            fs::remove_file(&f).unwrap();
        }

        fs::write(dir.join("case_ea01_cf01_SER1.E01"), b"x").unwrap();
        let e = ensure_no_existing_outputs(&dir, "case_ea01_cf01_SER1").unwrap_err();
        assert!(!e.contains("no serial number"), "{e}");

        let _ = fs::remove_dir_all(&dir);
    }
}
