//! Which device the examiner named (§15, review H7): a path is taken as
//! given; a bare name means `/dev/<name>` and is refused when `./<name>`
//! exists too (it is ambiguous). A block device is then matched with the
//! device scan by its device number (major:minor), never by name, so
//! `/dev/disk/by-id/...` links, `/dev/mapper/...` names and kernel names all
//! select the same scan entry. The scan entry is the "selection" the session
//! compares its own probe with (identity pinning, §5).

use crate::engines::AcquisitionError;
use crate::models::device::{BlockDevice, Partition};
use crate::models::identity::SourceKind;
use dfcore::sysfs::DevNum;
use std::path::{Path, PathBuf};

/// The source named on the command line, after resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedSource {
    /// A block device node and the device number it refers to
    Block { path: PathBuf, dev: DevNum },
    /// A regular file (an image used as a source)
    File { path: PathBuf, size: u64 },
}

impl ResolvedSource {
    pub fn path(&self) -> &Path {
        match self {
            ResolvedSource::Block { path, .. } | ResolvedSource::File { path, .. } => path,
        }
    }

    pub fn dev_string(&self) -> Option<String> {
        match self {
            ResolvedSource::Block { dev, .. } => Some(format!("{}:{}", dev.0, dev.1)),
            ResolvedSource::File { .. } => None,
        }
    }
}

/// Turn the argument into a path: a path (anything with a `/`) is used as
/// given; a bare name is `<dev_dir>/<name>` and is ambiguous when
/// `<cwd>/<name>` exists as well.
pub fn argument_path(arg: &str, cwd: &Path, dev_dir: &Path) -> Result<PathBuf, AcquisitionError> {
    if arg.trim().is_empty() {
        return Err(AcquisitionError::usage("no source device was given"));
    }
    if arg.contains('/') {
        return Ok(PathBuf::from(arg));
    }
    let in_dev = dev_dir.join(arg);
    let here = cwd.join(arg);
    // symlink_metadata: a dangling link still makes the name ambiguous
    let dev_exists = std::fs::symlink_metadata(&in_dev).is_ok();
    let here_exists = std::fs::symlink_metadata(&here).is_ok();
    match (dev_exists, here_exists) {
        (true, true) => Err(AcquisitionError::usage(format!(
            "'{arg}' is ambiguous: both {} and ./{arg} exist; write {} for the device or ./{arg} for the file",
            in_dev.display(),
            in_dev.display()
        ))),
        (true, false) => Ok(in_dev),
        (false, true) => Err(AcquisitionError::usage(format!(
            "'{arg}' is not a device in {}; a bare name always means a device. Write ./{arg} to use the file in the current directory",
            dev_dir.display()
        ))),
        (false, false) => Err(AcquisitionError::usage(format!(
            "source not found: neither {} nor ./{arg} exists",
            in_dev.display()
        ))),
    }
}

/// What the path is: a block device (with its device number) or a regular
/// file. Anything else, or a missing path, is a usage error.
pub fn classify_path(path: &Path) -> Result<ResolvedSource, AcquisitionError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = std::fs::metadata(path).map_err(|e| {
        AcquisitionError::usage(format!("source not found: {}: {e}", path.display()))
    })?;
    let ft = meta.file_type();
    if ft.is_block_device() {
        let rdev = meta.rdev() as libc::dev_t;
        Ok(ResolvedSource::Block {
            path: path.to_path_buf(),
            dev: (libc::major(rdev) as u32, libc::minor(rdev) as u32),
        })
    } else if ft.is_file() {
        Ok(ResolvedSource::File {
            path: path.to_path_buf(),
            size: meta.len(),
        })
    } else {
        Err(AcquisitionError::usage(format!(
            "{} is neither a block device nor a regular file",
            path.display()
        )))
    }
}

/// [`argument_path`] + [`classify_path`] on this host.
pub fn resolve_argument(arg: &str) -> Result<ResolvedSource, AcquisitionError> {
    let cwd = std::env::current_dir()
        .map_err(|e| AcquisitionError::failed(format!("cannot read the current directory: {e}")))?;
    classify_path(&argument_path(arg, &cwd, Path::new("/dev"))?)
}

fn parse_maj_min(s: Option<&str>) -> Option<DevNum> {
    s.and_then(dfcore::sysfs::parse_dev_num)
}

/// The scan entry for a partition, device-mapper or md device listed below
/// `disk`: its own name, path, size, device number, kind and position, and
/// the hardware identity (model, serial, WWN) of the disk that holds it. The
/// disk sequence number is the disk's for a partition (the kernel numbers
/// disks only) and unknown for stacked devices (they have their own).
pub fn partition_device(disk: &BlockDevice, part: &Partition) -> BlockDevice {
    let kind = part
        .kind
        .as_deref()
        .map(SourceKind::from_lsblk_type)
        .unwrap_or(SourceKind::Partition);
    let is_partition = kind == SourceKind::Partition;
    BlockDevice {
        name: part.name.clone(),
        path: part.path.clone(),
        devlinks: Vec::new(),
        size_bytes: part.size_bytes,
        model: disk.model.clone(),
        vendor: disk.vendor.clone(),
        serial: disk.serial.clone(),
        wwn: disk.wwn.clone(),
        revision: disk.revision.clone(),
        bus_type: disk.bus_type.clone(),
        is_rotational: disk.is_rotational,
        is_removable: disk.is_removable,
        is_read_only: part.is_read_only,
        logical_sector_size: disk.logical_sector_size,
        physical_sector_size: disk.physical_sector_size,
        partition_table_type: None,
        partitions: Vec::new(),
        mountpoints: part.mountpoint.iter().cloned().collect(),
        safety: Default::default(),
        smart: None,
        maj_min: part.maj_min.clone(),
        diskseq: if is_partition { disk.diskseq } else { None },
        hotplug: disk.hotplug,
        transport: disk.transport.clone(),
        kind,
        parent: Some(disk.path.clone()),
        start_sector: part.start_sector,
        serial_candidates: disk.serial_candidates.clone(),
        ..Default::default()
    }
}

/// The scan entry (disk, or anything listed below a disk) with device number
/// `dev`.
pub fn find_in_scan(scan: &[BlockDevice], dev: DevNum) -> Option<BlockDevice> {
    if let Some(d) = scan
        .iter()
        .find(|d| parse_maj_min(d.maj_min.as_deref()) == Some(dev))
    {
        return Some(d.clone());
    }
    scan.iter().find_map(|d| {
        d.partitions
            .iter()
            .find(|p| parse_maj_min(p.maj_min.as_deref()) == Some(dev))
            .map(|p| partition_device(d, p))
    })
}

/// The selection for a regular file: its canonical path and size, and no
/// hardware identity (nothing is made up: no serial, no model).
pub fn file_device(path: &Path, size: u64) -> BlockDevice {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    BlockDevice {
        name: canonical
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path: canonical.to_string_lossy().into_owned(),
        size_bytes: size,
        bus_type: "FILE".into(),
        logical_sector_size: 512,
        physical_sector_size: 512,
        kind: SourceKind::RegularFile,
        ..Default::default()
    }
}

/// The selected device for `source`: the scan entry with its device number
/// (block devices; a device the scan does not list is refused, fail closed),
/// or the regular file.
pub fn select_device(
    source: &ResolvedSource,
    scan: impl FnOnce() -> Result<Vec<BlockDevice>, String>,
) -> Result<BlockDevice, AcquisitionError> {
    match source {
        ResolvedSource::File { path, size } => Ok(file_device(path, *size)),
        ResolvedSource::Block { path, dev } => {
            let devices = scan().map_err(|e| {
                AcquisitionError::refused(format!(
                    "the block devices cannot be listed ({e}); {} cannot be identified, refusing",
                    path.display()
                ))
            })?;
            find_in_scan(&devices, *dev).ok_or_else(|| {
                AcquisitionError::refused(format!(
                    "{} (major:minor {}:{}) is not in the device scan (lsblk); refusing a block device the scan cannot describe",
                    path.display(),
                    dev.0,
                    dev.1
                ))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("cwd");
        let dev = tmp.path().join("dev");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&dev).unwrap();
        (tmp, cwd, dev)
    }

    #[test]
    fn paths_are_taken_as_given() {
        let (_t, cwd, dev) = dirs();
        assert_eq!(
            argument_path("/dev/sdb", &cwd, &dev).unwrap(),
            PathBuf::from("/dev/sdb")
        );
        assert_eq!(
            argument_path("./image.dd", &cwd, &dev).unwrap(),
            PathBuf::from("./image.dd")
        );
        assert_eq!(
            argument_path("mapper/vg-lv", &cwd, &dev).unwrap(),
            PathBuf::from("mapper/vg-lv")
        );
        assert!(argument_path(" ", &cwd, &dev).is_err());
    }

    #[test]
    fn bare_names_are_devices_and_never_ambiguous() {
        let (_t, cwd, dev) = dirs();
        std::fs::write(dev.join("sdz"), b"").unwrap();
        assert_eq!(argument_path("sdz", &cwd, &dev).unwrap(), dev.join("sdz"));

        // ./sdz as well: ambiguous (review H7: `acquire sdz` imaged /dev/sdz)
        std::fs::write(cwd.join("sdz"), b"").unwrap();
        let e = argument_path("sdz", &cwd, &dev).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.message.contains("ambiguous"), "{e}");
        assert!(e.message.contains("./sdz"), "{e}");

        // A dangling link in the current directory is ambiguous too
        std::fs::write(dev.join("sdy"), b"").unwrap();
        std::os::unix::fs::symlink(cwd.join("missing"), cwd.join("sdy")).unwrap();
        assert!(argument_path("sdy", &cwd, &dev)
            .unwrap_err()
            .message
            .contains("ambiguous"));

        // Only ./name: a bare name never means a file
        std::fs::write(cwd.join("evidence.bin"), b"x").unwrap();
        let e = argument_path("evidence.bin", &cwd, &dev).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.message.contains("./evidence.bin"), "{e}");

        let e = argument_path("nothing", &cwd, &dev).unwrap_err();
        assert!(e.message.contains("not found"), "{e}");
    }

    #[test]
    fn classify_files_devices_and_others() {
        let (tmp, ..) = dirs();
        let file = tmp.path().join("img.dd");
        std::fs::write(&file, vec![0u8; 1024]).unwrap();
        assert_eq!(
            classify_path(&file).unwrap(),
            ResolvedSource::File {
                path: file.clone(),
                size: 1024
            }
        );
        let e = classify_path(tmp.path()).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e
            .message
            .contains("neither a block device nor a regular file"));
        let e = classify_path(&tmp.path().join("missing")).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        // A character device is no source
        if Path::new("/dev/null").exists() {
            assert!(classify_path(Path::new("/dev/null")).is_err());
        }
    }

    fn scan() -> Vec<BlockDevice> {
        vec![BlockDevice {
            name: "sdb".into(),
            path: "/dev/sdb".into(),
            size_bytes: 1 << 30,
            model: Some("Disk".into()),
            serial: Some("SER".into()),
            wwn: Some("0x5000".into()),
            maj_min: Some("8:16".into()),
            diskseq: Some(9),
            logical_sector_size: 512,
            physical_sector_size: 4096,
            transport: Some("usb".into()),
            hotplug: true,
            partitions: vec![
                Partition {
                    name: "sdb1".into(),
                    path: "/dev/sdb1".into(),
                    size_bytes: 1 << 20,
                    maj_min: Some("8:17".into()),
                    kind: Some("part".into()),
                    start_sector: Some(2048),
                    mountpoint: Some("/media/x".into()),
                    ..Default::default()
                },
                Partition {
                    name: "luks-1".into(),
                    path: "/dev/mapper/luks-1".into(),
                    size_bytes: 1 << 19,
                    maj_min: Some("254:3".into()),
                    kind: Some("crypt".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }]
    }

    #[test]
    fn block_devices_are_matched_by_device_number() {
        let disk = find_in_scan(&scan(), (8, 16)).unwrap();
        assert_eq!(disk.path, "/dev/sdb");

        let part = find_in_scan(&scan(), (8, 17)).unwrap();
        assert_eq!(part.path, "/dev/sdb1");
        assert_eq!(part.kind, SourceKind::Partition);
        assert_eq!(part.maj_min.as_deref(), Some("8:17"));
        assert_eq!(part.size_bytes, 1 << 20);
        assert_eq!(part.parent.as_deref(), Some("/dev/sdb"));
        assert_eq!(part.start_sector, Some(2048));
        assert_eq!(part.serial.as_deref(), Some("SER"), "hardware of the disk");
        assert_eq!(
            part.diskseq,
            Some(9),
            "a partition carries its disk's diskseq"
        );
        assert_eq!(part.physical_sector_size, 4096);
        assert_eq!(part.mountpoints, vec!["/media/x".to_string()]);

        let crypt = find_in_scan(&scan(), (254, 3)).unwrap();
        assert_eq!(crypt.path, "/dev/mapper/luks-1");
        assert!(matches!(crypt.kind, SourceKind::DeviceMapper { .. }));
        assert_eq!(crypt.diskseq, None, "a dm device has its own diskseq");

        assert!(find_in_scan(&scan(), (8, 32)).is_none());
    }

    #[test]
    fn selection_fails_closed() {
        let block = ResolvedSource::Block {
            path: "/dev/sdq".into(),
            dev: (65, 0),
        };
        let e = select_device(&block, || Ok(scan())).unwrap_err();
        assert_eq!(e.exit_code(), 3);
        assert!(e.message.contains("65:0"), "{e}");
        let e = select_device(&block, || Err("lsblk missing".into())).unwrap_err();
        assert_eq!(e.exit_code(), 3);
        assert!(e.message.contains("lsblk missing"), "{e}");
        let found = select_device(
            &ResolvedSource::Block {
                path: "/dev/disk/by-id/usb-x".into(),
                dev: (8, 16),
            },
            || Ok(scan()),
        )
        .unwrap();
        assert_eq!(found.path, "/dev/sdb");
        assert_eq!(block.dev_string().as_deref(), Some("65:0"));
    }

    #[test]
    fn files_are_selected_without_made_up_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("evidence.dd");
        std::fs::write(&f, vec![1u8; 4096]).unwrap();
        let rel = ResolvedSource::File {
            path: f.clone(),
            size: 4096,
        };
        let dev = select_device(&rel, || panic!("no scan for files")).unwrap();
        assert_eq!(dev.kind, SourceKind::RegularFile);
        assert_eq!(
            dev.path,
            std::fs::canonicalize(&f).unwrap().to_string_lossy()
        );
        assert_eq!(dev.size_bytes, 4096);
        assert_eq!(dev.serial, None);
        assert_eq!(dev.model, None);
        assert_eq!(rel.dev_string(), None);
        assert_eq!(rel.path(), f.as_path());
    }
}
