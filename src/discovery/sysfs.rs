//! Read-only access to a sysfs tree: `/sys` on the host, a temporary
//! directory in tests ([`fake::FakeSysfs`]). Kernel names are validated as
//! single path components so a name never reaches outside `class/block`.

use dfcore::sysfs::{parse_dev_num, BlockTopology, DevNum};
use std::path::{Path, PathBuf};

/// Root of a sysfs tree (normally `/sys`).
#[derive(Debug, Clone)]
pub struct SysRoot {
    root: PathBuf,
}

impl SysRoot {
    pub fn host() -> Self {
        Self::new("/sys")
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn class_block(&self) -> PathBuf {
        self.root.join("class/block")
    }

    /// dfcore's view of the same tree.
    pub fn topology(&self) -> BlockTopology {
        BlockTopology::new(self.class_block())
    }

    /// Directory of a kernel name under `class/block` (a symlink on real hosts).
    pub fn node(&self, kname: &str) -> Option<PathBuf> {
        let valid = !kname.is_empty() && kname != "." && kname != ".." && !kname.contains('/');
        valid.then(|| self.class_block().join(kname))
    }

    /// [`node`](Self::node) with symlinks resolved (the device's place in
    /// `devices/`, where parents and the hardware device are found).
    pub fn canonical_node(&self, kname: &str) -> Option<PathBuf> {
        std::fs::canonicalize(self.node(kname)?).ok()
    }

    pub fn exists(&self, kname: &str) -> bool {
        self.node(kname).is_some_and(|n| n.exists())
    }

    /// Kernel name of a device number: the `dev/block/M:m` link, else a scan
    /// of `class/block`.
    pub fn kname_of(&self, dev: DevNum) -> Option<String> {
        let link = self.root.join(format!("dev/block/{}:{}", dev.0, dev.1));
        if let Some(name) = std::fs::canonicalize(&link)
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        {
            if self.exists(&name) {
                return Some(name);
            }
        }
        self.topology().name_of(dev)
    }

    /// Trimmed content of `<node>/<rel>`.
    pub fn attr(&self, kname: &str, rel: &str) -> Option<String> {
        read_attr(&self.node(kname)?.join(rel))
    }

    /// Raw bytes of `<node>/<rel>` (binary attributes such as `vpd_pg80`).
    pub fn attr_bytes(&self, kname: &str, rel: &str) -> Option<Vec<u8>> {
        std::fs::read(self.node(kname)?.join(rel)).ok()
    }

    pub fn dev_of(&self, kname: &str) -> Option<DevNum> {
        parse_dev_num(&self.attr(kname, "dev")?)
    }

    pub fn is_partition(&self, kname: &str) -> bool {
        self.node(kname)
            .is_some_and(|n| n.join("partition").exists())
    }

    /// Disk a partition belongs to (the parent directory in `devices/`).
    pub fn parent_disk(&self, kname: &str) -> Option<String> {
        if !self.is_partition(kname) {
            return None;
        }
        self.canonical_node(kname)?
            .parent()?
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
    }

    /// Partitions of a disk, sorted by kernel name.
    pub fn partitions(&self, disk: &str) -> Vec<String> {
        let Some(dir) = self.canonical_node(disk) else {
            return Vec::new();
        };
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("partition").exists())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    pub fn read_only(&self, kname: &str) -> Option<bool> {
        match self.attr(kname, "ro")?.as_str() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }

    /// Devices stacked directly on this one, sorted.
    pub fn holders(&self, kname: &str) -> Vec<String> {
        self.topology().holders(kname)
    }

    /// Devices this one is stacked on directly (`slaves/`), sorted.
    pub fn slaves(&self, kname: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .node(kname)
            .and_then(|n| std::fs::read_dir(n.join("slaves")).ok())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Holders, their holders, and so on (breadth first, no duplicates).
    pub fn holders_recursive(&self, kname: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut queue = self.holders(kname);
        while let Some(h) = queue.first().cloned() {
            queue.remove(0);
            if out.contains(&h) || out.len() > 256 {
                continue;
            }
            queue.extend(self.holders(&h));
            out.push(h);
        }
        out
    }

    pub fn diskseq(&self, kname: &str) -> Option<u64> {
        self.topology().diskseq(kname)
    }

    /// Every block device of this tree, by kernel name (sorted).
    pub fn block_devices(&self) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.class_block())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    /// Loop devices backed by a block device, with the device number of that
    /// device. `loop/backing_file` holds a path: `/dev/<kname>` is resolved
    /// through this tree, any other path by its `stat` st_rdev (a regular
    /// backing file has none and is left out).
    pub fn loops_over_block_devices(&self) -> Vec<(String, DevNum)> {
        self.block_devices()
            .into_iter()
            .filter_map(|kname| {
                let backing = self.attr(&kname, "loop/backing_file")?;
                let backing = backing.trim_end_matches(" (deleted)");
                let by_name = backing
                    .strip_prefix("/dev/")
                    .filter(|k| self.exists(k))
                    .and_then(|k| self.dev_of(k));
                let dev = by_name.or_else(|| dfcore::sysfs::dev_num_of_path(Path::new(backing)))?;
                Some((kname, dev))
            })
            .collect()
    }
}

/// Trimmed text of a sysfs attribute file.
pub fn read_attr(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// A sysfs tree in a temporary directory, laid out like a real host:
/// `devices/<path>/block/<disk>/<partition>`, `class/block/<name>` and
/// `dev/block/M:m` links, `device` links to the hardware directory.
#[cfg(test)]
pub(crate) mod fake {
    use super::SysRoot;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    pub(crate) struct FakeSysfs {
        dir: tempfile::TempDir,
    }

    impl FakeSysfs {
        pub(crate) fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for d in ["class/block", "dev/block", "devices/virtual/block"] {
                std::fs::create_dir_all(dir.path().join(d)).unwrap();
            }
            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            self.dir.path()
        }

        pub(crate) fn root(&self) -> SysRoot {
            SysRoot::new(self.dir.path())
        }

        fn register(&self, kname: &str, dir: &Path, dev: (u32, u32), sectors: u64) {
            std::fs::create_dir_all(dir.join("queue")).unwrap();
            std::fs::create_dir_all(dir.join("holders")).unwrap();
            self.write(dir, "dev", &format!("{}:{}", dev.0, dev.1));
            self.write(dir, "size", &sectors.to_string());
            self.write(dir, "ro", "0");
            symlink(dir, self.path().join("class/block").join(kname)).unwrap();
            symlink(
                dir,
                self.path().join(format!("dev/block/{}:{}", dev.0, dev.1)),
            )
            .unwrap();
        }

        fn write(&self, dir: &Path, attr: &str, value: &str) {
            let p = dir.join(attr);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, format!("{value}\n")).unwrap();
        }

        /// A disk below the hardware device `devpath` (relative to devices/).
        pub(crate) fn add_disk(
            &self,
            devpath: &str,
            kname: &str,
            dev: (u32, u32),
            sectors: u64,
        ) -> PathBuf {
            let hw = self.path().join("devices").join(devpath);
            let dir = hw.join("block").join(kname);
            std::fs::create_dir_all(&dir).unwrap();
            self.register(kname, &dir, dev, sectors);
            symlink(&hw, dir.join("device")).unwrap();
            self.write(&dir, "removable", "0");
            self.write(&dir, "queue/logical_block_size", "512");
            self.write(&dir, "queue/physical_block_size", "512");
            self.write(&dir, "queue/rotational", "0");
            dir
        }

        pub(crate) fn add_partition(
            &self,
            disk: &str,
            kname: &str,
            dev: (u32, u32),
            number: u32,
            start: u64,
            sectors: u64,
        ) -> PathBuf {
            let disk_dir =
                std::fs::canonicalize(self.path().join("class/block").join(disk)).unwrap();
            let dir = disk_dir.join(kname);
            std::fs::create_dir_all(&dir).unwrap();
            self.register(kname, &dir, dev, sectors);
            self.write(&dir, "partition", &number.to_string());
            self.write(&dir, "start", &start.to_string());
            dir
        }

        /// A virtual block device (dm, md, loop, zram) under devices/virtual/block.
        pub(crate) fn add_virtual(&self, kname: &str, dev: (u32, u32), sectors: u64) -> PathBuf {
            let dir = self.path().join("devices/virtual/block").join(kname);
            std::fs::create_dir_all(dir.join("slaves")).unwrap();
            self.register(kname, &dir, dev, sectors);
            self.write(&dir, "queue/logical_block_size", "512");
            self.write(&dir, "queue/physical_block_size", "512");
            dir
        }

        /// A loop device whose backing file is `backing` (a path as the
        /// kernel shows it).
        pub(crate) fn add_loop(
            &self,
            kname: &str,
            dev: (u32, u32),
            sectors: u64,
            backing: &str,
        ) -> PathBuf {
            let dir = self.add_virtual(kname, dev, sectors);
            self.write(&dir, "loop/backing_file", backing);
            dir
        }

        /// Write `<class/block/kname>/<attr>`.
        pub(crate) fn set(&self, kname: &str, attr: &str, value: &str) {
            let dir = std::fs::canonicalize(self.path().join("class/block").join(kname)).unwrap();
            self.write(&dir, attr, value);
        }

        /// Write binary `<class/block/kname>/<attr>`.
        pub(crate) fn set_bytes(&self, kname: &str, attr: &str, value: &[u8]) {
            let dir = std::fs::canonicalize(self.path().join("class/block").join(kname)).unwrap();
            std::fs::write(dir.join(attr), value).unwrap();
        }

        /// Write an attribute of a hardware directory (relative to devices/).
        pub(crate) fn set_hw(&self, devpath: &str, attr: &str, value: &str) {
            let dir = self.path().join("devices").join(devpath);
            self.write(&dir, attr, value);
        }

        /// `holder` (dm/md) is stacked on `slave`.
        pub(crate) fn stack(&self, holder: &str, slave: &str) {
            let cb = self.path().join("class/block");
            let holder_dir = std::fs::canonicalize(cb.join(holder)).unwrap();
            let slave_dir = std::fs::canonicalize(cb.join(slave)).unwrap();
            std::fs::create_dir_all(holder_dir.join("slaves")).unwrap();
            symlink(&slave_dir, holder_dir.join("slaves").join(slave)).unwrap();
            symlink(&holder_dir, slave_dir.join("holders").join(holder)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeSysfs;

    #[test]
    fn fake_tree_resolves_like_a_host() {
        let f = FakeSysfs::new();
        f.add_disk("pci0/ata1/host0/target0:0:0/0:0:0:0", "sda", (8, 0), 1000);
        f.add_partition("sda", "sda1", (8, 1), 1, 2048, 500);
        f.add_partition("sda", "sda2", (8, 2), 2, 4096, 400);
        f.add_virtual("dm-0", (254, 0), 300);
        f.stack("dm-0", "sda2");
        f.add_virtual("dm-1", (254, 1), 200);
        f.stack("dm-1", "dm-0");
        let sys = f.root();
        assert_eq!(sys.kname_of((8, 1)).as_deref(), Some("sda1"));
        assert_eq!(sys.kname_of((9, 9)), None);
        assert!(sys.is_partition("sda1"));
        assert!(!sys.is_partition("sda"));
        assert_eq!(sys.parent_disk("sda2").as_deref(), Some("sda"));
        assert_eq!(sys.partitions("sda"), ["sda1", "sda2"]);
        assert_eq!(sys.read_only("sda"), Some(false));
        assert_eq!(sys.holders("sda2"), ["dm-0"]);
        assert_eq!(sys.holders_recursive("sda2"), ["dm-0", "dm-1"]);
        assert_eq!(sys.slaves("dm-1"), ["dm-0"]);
        assert_eq!(sys.slaves("dm-0"), ["sda2"]);
        assert!(sys.slaves("sda2").is_empty());
        assert_eq!(sys.dev_of("dm-0"), Some((254, 0)));
        assert_eq!(sys.node("../etc"), None);
        assert_eq!(
            sys.topology()
                .backing_disks("dm-1")
                .into_iter()
                .collect::<Vec<_>>(),
            ["sda"]
        );
    }

    #[test]
    fn loops_over_block_devices_resolve_their_backing_node() {
        let f = FakeSysfs::new();
        f.add_disk("pci0/ata1/host0/target0:0:0/0:0:0:0", "sdb", (8, 16), 1000);
        f.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 500);
        f.add_loop("loop0", (7, 0), 1000, "/dev/sdb");
        f.add_loop("loop1", (7, 1), 500, "/dev/sdb1");
        // A regular backing file is not a block device
        f.add_loop("loop2", (7, 2), 100, "/srv/images/does-not-exist.img");
        f.add_virtual("loop3", (7, 3), 0); // not bound
        let sys = f.root();
        assert_eq!(
            sys.loops_over_block_devices(),
            [
                ("loop0".to_string(), (8, 16)),
                ("loop1".to_string(), (8, 17))
            ]
        );
        assert!(sys.block_devices().contains(&"loop3".to_string()));
    }
}
