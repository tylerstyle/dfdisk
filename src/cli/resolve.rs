//! Which device the examiner named (§15, review H7): a path is taken as
//! given; a bare name means `/dev/<name>` and is refused when `./<name>`
//! exists too (it is ambiguous). A block device is then matched with the
//! device scan by its device number (major:minor), never by name, so
//! `/dev/disk/by-id/...` links, `/dev/mapper/...` names and kernel names all
//! select the same scan entry. The scan entry is the "selection" the session
//! compares its own probe with (identity pinning, §5).

use crate::discovery::devices::Scan;
use crate::engines::AcquisitionError;
use crate::models::device::BlockDevice;
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

/// The scan entry with device number `dev`: any node of the discovery scan
/// (disk, partition, device-mapper, md, loop) as the scan saw it, with its
/// own size, kind, mounts, holders and position, and the hardware identity
/// the scan's sysfs probe gave it: its disk for a partition or a device
/// stacked on one disk, none for a device stacked on several disks or a loop
/// device. A disk carries its partitions. The session probes the same node
/// the same way (`discovery::identity`), so the selection and the probe
/// compare like with like (identity pinning, §5).
pub fn find_in_scan(scan: &Scan, dev: DevNum) -> Option<BlockDevice> {
    let matches = |d: &BlockDevice| parse_maj_min(d.maj_min.as_deref()) == Some(dev);
    if let Some(disk) = scan.devices().into_iter().find(|d| matches(d)) {
        return Some(disk);
    }
    scan.nodes
        .iter()
        .map(|n| &n.device)
        .find(|d| matches(d))
        .cloned()
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
    scan: impl FnOnce() -> Result<Scan, String>,
) -> Result<BlockDevice, AcquisitionError> {
    match source {
        ResolvedSource::File { path, size } => Ok(file_device(path, *size)),
        ResolvedSource::Block { path, dev } => {
            let scan = scan().map_err(|e| {
                AcquisitionError::refused(format!(
                    "the block devices cannot be listed ({e}); {} cannot be identified, refusing",
                    path.display()
                ))
            })?;
            find_in_scan(&scan, *dev).ok_or_else(|| {
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

    use crate::discovery::devices::{scan as run_scan, ScanInput};
    use crate::discovery::identity::{tool_source_path_in, Prober, UdevProperties};
    use crate::discovery::sysfs::fake::FakeSysfs;

    const SATA: &str = "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0";
    const VIRTIO: &str = "pci0000:00/0000:00:05.0/virtio2";
    const SATA3: &str = "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0";
    const SATA4: &str = "pci0000:00/0000:00:17.0/ata4/host3/target3:0:0/3:0:0:0";

    /// lsblk -J -b -O of the fake host: a SATA disk with a mounted
    /// partition, LUKS on it and dm-linear over its second partition; a
    /// virtio disk with dm-linear over the whole disk (as the dfnix CFTT
    /// tests stack dm-linear/dm-error/dm-delay); md RAID over two disks.
    const LSBLK: &str = r#"{"blockdevices": [
      {"name":"sdb", "kname":"sdb", "path":"/dev/sdb", "maj:min":"8:16", "size":1073741824, "type":"disk", "tran":"sata", "serial":"SER", "model":"Disk", "wwn":"0x5000c500a1b2c3d4", "log-sec":512, "phy-sec":4096, "disk-seq":9, "mountpoints":[null],
        "children": [
          {"name":"sdb1", "kname":"sdb1", "path":"/dev/sdb1", "maj:min":"8:17", "size":1048576, "type":"part", "start":2048, "mountpoints":["/media/x"],
            "children": [
              {"name":"luks-1", "kname":"dm-3", "path":"/dev/mapper/luks-1", "maj:min":"254:3", "size":524288, "type":"crypt", "mountpoints":[null]}
            ]},
          {"name":"sdb2", "kname":"sdb2", "path":"/dev/sdb2", "maj:min":"8:18", "size":2097152, "type":"part", "start":6144, "mountpoints":[null],
            "children": [
              {"name":"partlin", "kname":"dm-4", "path":"/dev/mapper/partlin", "maj:min":"254:4", "size":2097152, "type":"dm", "mountpoints":[null]}
            ]}
        ]},
      {"name":"vdb", "kname":"vdb", "path":"/dev/vdb", "maj:min":"252:16", "size":67108864, "type":"disk", "serial":"CFTT-DISK-1", "disk-seq":4, "mountpoints":[null],
        "children": [
          {"name":"lin", "kname":"dm-2", "path":"/dev/mapper/lin", "maj:min":"254:2", "size":67108864, "type":"dm", "mountpoints":[null]}
        ]},
      {"name":"sdc", "kname":"sdc", "path":"/dev/sdc", "maj:min":"8:32", "size":1048576, "type":"disk", "serial":"OTHER", "mountpoints":[null],
        "children": [
          {"name":"md0", "kname":"md0", "path":"/dev/md0", "maj:min":"9:0", "size":1048576, "type":"raid1", "mountpoints":[null]}
        ]},
      {"name":"sdd", "kname":"sdd", "path":"/dev/sdd", "maj:min":"8:48", "size":1048576, "type":"disk", "serial":"THIRD", "mountpoints":[null],
        "children": [
          {"name":"md0", "kname":"md0", "path":"/dev/md0", "maj:min":"9:0", "size":1048576, "type":"raid1", "mountpoints":[null]}
        ]}
    ]}"#;

    fn vpd(serial: &str) -> Vec<u8> {
        let mut b = vec![0u8, 0x80, 0, serial.len() as u8];
        b.extend_from_slice(serial.as_bytes());
        b
    }

    fn host() -> FakeSysfs {
        let f = FakeSysfs::new();
        f.add_disk(SATA, "sdb", (8, 16), 2_097_152);
        f.set("sdb", "diskseq", "9");
        f.set("sdb", "queue/physical_block_size", "4096");
        f.set_bytes("sdb", "device/vpd_pg80", &vpd("SER"));
        f.set_hw(SATA, "model", "Disk");
        f.set_hw(SATA, "wwid", "naa.5000c500a1b2c3d4");
        f.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 2048);
        f.add_partition("sdb", "sdb2", (8, 18), 2, 6144, 4096);
        f.add_virtual("dm-3", (254, 3), 1024);
        f.set("dm-3", "dm/name", "luks-1");
        f.set("dm-3", "dm/uuid", "CRYPT-LUKS2-00112233-luks-1");
        f.set("dm-3", "diskseq", "12");
        f.stack("dm-3", "sdb1");
        f.add_virtual("dm-4", (254, 4), 4096);
        f.set("dm-4", "dm/name", "partlin");
        f.set("dm-4", "diskseq", "13");
        f.stack("dm-4", "sdb2");
        f.add_disk(VIRTIO, "vdb", (252, 16), 131_072);
        f.set("vdb", "serial", "CFTT-DISK-1");
        f.set("vdb", "diskseq", "4");
        f.add_virtual("dm-2", (254, 2), 131_072);
        f.set("dm-2", "dm/name", "lin");
        f.set("dm-2", "diskseq", "11");
        f.stack("dm-2", "vdb");
        f.add_disk(SATA3, "sdc", (8, 32), 2048);
        f.set_bytes("sdc", "device/vpd_pg80", &vpd("OTHER"));
        f.add_disk(SATA4, "sdd", (8, 48), 2048);
        f.set_bytes("sdd", "device/vpd_pg80", &vpd("THIRD"));
        f.add_virtual("md0", (9, 0), 2048);
        f.set("md0", "md/level", "raid1");
        f.stack("md0", "sdc");
        f.stack("md0", "sdd");
        f
    }

    fn scan_of(f: &FakeSysfs) -> Scan {
        run_scan(&ScanInput {
            lsblk_json: LSBLK.into(),
            sys: f.root(),
            mountinfo: Ok("40 22 8:17 / /media/x rw - ext4 /dev/sdb1 rw\n".into()),
            swaps: Ok(Vec::new()),
            registry: Ok(None),
            dev_dir: f.path().join("no-dev"),
        })
        .unwrap()
    }

    /// udev as on a real host: the disks' ID_SERIAL_SHORT (virtio: only
    /// ID_SERIAL), DM names for the mappings.
    fn udev(path: &str) -> Result<UdevProperties, String> {
        let props: &[(&str, &str)] = match path {
            "/dev/sdb" | "/dev/sdb1" | "/dev/sdb2" => {
                &[("ID_SERIAL_SHORT", "SER"), ("ID_BUS", "ata")]
            }
            "/dev/vdb" => &[("ID_SERIAL", "CFTT-DISK-1")],
            "/dev/mapper/lin" => &[("DM_NAME", "lin")],
            "/dev/mapper/partlin" => &[("DM_NAME", "partlin")],
            _ => &[],
        };
        Ok(props
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect())
    }

    #[test]
    fn block_devices_are_matched_by_device_number() {
        let f = host();
        let scan = scan_of(&f);
        let disk = find_in_scan(&scan, (8, 16)).unwrap();
        assert_eq!(disk.path, "/dev/sdb");
        assert_eq!(disk.partitions.len(), 4, "{:?}", disk.partitions);

        let part = find_in_scan(&scan, (8, 17)).unwrap();
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
        assert_eq!(part.holders, ["dm-3"]);

        let crypt = find_in_scan(&scan, (254, 3)).unwrap();
        assert_eq!(crypt.path, "/dev/mapper/luks-1");
        assert_eq!(
            crypt.kind,
            SourceKind::DeviceMapper {
                crypt_plaintext: true
            }
        );
        assert_eq!(crypt.diskseq, Some(12), "a dm device has its own diskseq");
        assert_eq!(crypt.serial.as_deref(), Some("SER"));

        assert!(find_in_scan(&scan, (8, 64)).is_none());

        // An md array on two disks belongs to neither disk
        let md = find_in_scan(&scan, (9, 0)).unwrap();
        assert_eq!(md.path, "/dev/md0");
        assert_eq!(md.kind, SourceKind::Md);
        assert_eq!(md.serial, None, "no single disk's serial");
        assert_eq!(md.parent, None);
        assert_eq!(md.model, None);
    }

    /// dm-linear (dm-error, dm-delay) over a whole disk and over a
    /// partition: the CLI selects the mapping from the scan, the session's
    /// probe of the same node is the same attachment, and external tools
    /// read it through the by-diskseq link only when that resolves to the
    /// pinned device number.
    #[test]
    fn device_mapper_sources_on_one_disk_are_selected_and_pinned() {
        let f = host();
        let scan = scan_of(&f);
        let prober = Prober::new(f.root(), &udev);
        for (path, dev, disk, serial, seq) in [
            ("/dev/mapper/lin", (254, 2), "/dev/vdb", "CFTT-DISK-1", 11),
            ("/dev/mapper/partlin", (254, 4), "/dev/sdb", "SER", 13),
        ] {
            let selected = select_device(
                &ResolvedSource::Block {
                    path: path.into(),
                    dev,
                },
                || Ok(scan.clone()),
            )
            .unwrap();
            assert_eq!(selected.path, path);
            assert_eq!(
                selected.kind,
                SourceKind::DeviceMapper {
                    crypt_plaintext: false
                }
            );
            assert_eq!(selected.parent.as_deref(), Some(disk), "{path}");
            assert_eq!(selected.serial.as_deref(), Some(serial), "{path}");
            assert_eq!(selected.diskseq, Some(seq));

            // The session's identity step (step 2) on the snapshot
            let probed = prober.probe_block(&selected.path, dev).unwrap();
            assert_eq!(probed.hardware_of.as_deref(), Some(&disk[5..]));
            assert_eq!(
                probed.same_attachment(&selected.device_identity()),
                Ok(()),
                "{path}"
            );

            // R3: the by-diskseq link only when it is the pinned node
            let links = tempfile::tempdir().unwrap();
            let link = links.path().join(seq.to_string());
            std::fs::write(&link, b"").unwrap();
            let pinned = |p: &Path| (p == link.as_path()).then_some(dev);
            assert_eq!(
                tool_source_path_in(&probed, links.path(), &pinned),
                link.to_string_lossy()
            );
            let other = |p: &Path| (p == link.as_path()).then_some((254, 99));
            assert_eq!(tool_source_path_in(&probed, links.path(), &other), path);
            let empty = tempfile::tempdir().unwrap();
            assert_eq!(tool_source_path_in(&probed, empty.path(), &pinned), path);
        }

        // The whole virtio disk itself: its serial is read from sysfs, so the
        // probe matches the scan (lsblk shows it from udev's ID_SERIAL)
        let vdb = find_in_scan(&scan, (252, 16)).unwrap();
        assert_eq!(vdb.serial.as_deref(), Some("CFTT-DISK-1"));
        let probed = prober.probe_block("/dev/vdb", (252, 16)).unwrap();
        assert_eq!(probed.same_attachment(&vdb.device_identity()), Ok(()));
        // ... and another disk on the same node is not
        let mut swapped = vdb.clone();
        swapped.serial = Some("CFTT-DISK-2".into());
        assert!(probed.same_attachment(&swapped.device_identity()).is_err());
    }

    #[test]
    fn selection_fails_closed() {
        let f = host();
        let block = ResolvedSource::Block {
            path: "/dev/sdq".into(),
            dev: (65, 0),
        };
        let e = select_device(&block, || Ok(scan_of(&f))).unwrap_err();
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
            || Ok(scan_of(&f)),
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
