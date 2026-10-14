//! Write protection of the source (§6, R1, R2): record the block layer's
//! read-only state, holders, mounts and the dfnix registry ([`capture`]),
//! decide what to set ([`decide`], pure), set it with the BLKROSET ioctl on
//! the whole disk AND on every partition node ([`enforce`]), and hold the
//! source open exclusively ([`open_exclusive`]).
//!
//! dfdisk leaves the read-only flag set after the acquisition and says so.

use crate::discovery::sysfs::SysRoot;
use crate::models::config::WriteProtectPolicy;
use crate::models::identity::{SourceIdentity, SourceKind};
use crate::models::protection::{NodeReadOnly, RegistryPresence, WriteProtection};
use dfcore::sysfs::{parse_mountinfo, DevNum};
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::path::Path;

/// `_IO(0x12, 93)`: set the block device read-only flag.
const BLKROSET: libc::c_ulong = 0x125D;

/// Sets the read-only flag on kernel names and returns the device paths set
/// ([`apply_ro_nodes`] on a host, a stand-in in tests).
pub type ApplyRo<'a> = dyn Fn(&[String]) -> Result<Vec<String>, String> + 'a;

/// Hint appended to a refusal when write protection cannot be established.
pub const WRITE_PROTECT_OFF_HINT: &str =
    "acquire with --write-protect off to proceed without it (the state is still recorded)";

/// Read-only state of one disk the source is stored on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskState {
    /// Kernel name, e.g. "sdb"
    pub node: String,
    pub ro: Option<bool>,
    /// (kernel name, ro) of each partition of the disk
    pub partitions: Vec<(String, Option<bool>)>,
    /// Mount points on this disk outside the source tree
    pub foreign_mounts: Vec<String>,
}

/// Everything [`decide`] needs, read from sysfs and mountinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionInputs {
    pub is_block_device: bool,
    /// Kernel name of the source node
    pub source: String,
    pub source_ro: Option<bool>,
    /// The source itself when it is a disk; otherwise the disks below it
    pub disks: Vec<DiskState>,
}

/// What write protection to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteProtectDecision {
    /// Nothing is set; the state is only recorded
    RecordOnly { reason: String },
    /// Every node that would be set is already read-only
    AlreadyReadOnly,
    /// Set BLKROSET on these kernel names, in this order (disks first)
    Set {
        nodes: Vec<String>,
        notes: Vec<String>,
    },
}

/// Pure decision for policy `auto` / `off`. Under `auto`, the source node,
/// each disk it is stored on and every partition of those disks are set
/// read-only (R2) - except a disk that holds mounts outside the source tree
/// (a sibling partition in use), which stays writable with a note, since the
/// disk flag would make that mount read-only too. Nodes already read-only are
/// not set again.
pub fn decide(policy: WriteProtectPolicy, inputs: &DecisionInputs) -> WriteProtectDecision {
    if policy == WriteProtectPolicy::Off {
        return WriteProtectDecision::RecordOnly {
            reason: "write-protect policy off: the read-only state is recorded, not changed".into(),
        };
    }
    if !inputs.is_block_device {
        return WriteProtectDecision::RecordOnly {
            reason: "the source is a regular file; BLKROSET applies to block devices only".into(),
        };
    }
    let mut targets: Vec<(String, Option<bool>)> = Vec::new();
    let mut notes = Vec::new();
    for disk in &inputs.disks {
        if disk.foreign_mounts.is_empty() {
            targets.push((disk.node.clone(), disk.ro));
            targets.extend(disk.partitions.iter().cloned());
        } else {
            notes.push(format!(
                "/dev/{} and its other partitions were left writable because {} is mounted outside the source",
                disk.node,
                disk.foreign_mounts.join(", ")
            ));
        }
    }
    if !targets.iter().any(|(n, _)| n == &inputs.source) {
        targets.push((inputs.source.clone(), inputs.source_ro));
    }
    let pending: Vec<String> = targets
        .into_iter()
        .filter(|(_, ro)| *ro != Some(true))
        .map(|(n, _)| n)
        .collect();
    if pending.is_empty() {
        WriteProtectDecision::AlreadyReadOnly
    } else {
        WriteProtectDecision::Set {
            nodes: pending,
            notes,
        }
    }
}

fn kname_of_path(p: &str) -> String {
    p.trim_start_matches("/dev/").to_string()
}

/// Disks the source is stored on, by kernel name.
fn disks_of(identity: &SourceIdentity) -> Vec<String> {
    match identity.kind {
        SourceKind::Disk | SourceKind::Other => vec![identity.kernel_name.clone()],
        SourceKind::RegularFile => Vec::new(),
        _ => identity
            .parent_disks
            .iter()
            .map(|d| kname_of_path(d))
            .collect(),
    }
}

/// The source node, its partitions (for a disk) and everything stacked on
/// them: the nodes whose mounts are "in the source tree".
fn source_tree(sys: &SysRoot, identity: &SourceIdentity) -> BTreeSet<String> {
    let mut tree = BTreeSet::new();
    let src = identity.kernel_name.clone();
    let mut roots = vec![src.clone()];
    if matches!(identity.kind, SourceKind::Disk | SourceKind::Other) {
        roots.extend(sys.partitions(&src));
    }
    for r in roots {
        tree.extend(sys.holders_recursive(&r));
        tree.insert(r);
    }
    tree
}

/// Every node of a disk: the disk, its partitions and their holders.
fn disk_tree(sys: &SysRoot, disk: &str) -> BTreeSet<String> {
    let mut tree = BTreeSet::new();
    let mut roots = vec![disk.to_string()];
    roots.extend(sys.partitions(disk));
    for r in roots {
        tree.extend(sys.holders_recursive(&r));
        tree.insert(r);
    }
    tree
}

/// Mount points (from mountinfo content) of the given nodes, matched by
/// device number and by mount source path.
fn mounts_of(sys: &SysRoot, nodes: &BTreeSet<String>, mountinfo: &str) -> Vec<String> {
    let devs: BTreeSet<DevNum> = nodes.iter().filter_map(|n| sys.dev_of(n)).collect();
    let mut sources: BTreeSet<String> = nodes.iter().map(|n| format!("/dev/{n}")).collect();
    for n in nodes {
        if let Some(name) = sys.attr(n, "dm/name") {
            sources.insert(format!("/dev/mapper/{name}"));
        }
    }
    let mut out: Vec<String> = parse_mountinfo(mountinfo)
        .into_iter()
        .filter(|m| devs.contains(&m.dev) || sources.contains(&m.source))
        .map(|m| m.mount_point.to_string_lossy().into_owned())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Inputs for [`decide`] from a sysfs tree and mountinfo content.
pub fn decision_inputs(
    sys: &SysRoot,
    identity: &SourceIdentity,
    mountinfo: &str,
) -> DecisionInputs {
    let tree = source_tree(sys, identity);
    let disks = disks_of(identity)
        .into_iter()
        .map(|disk| {
            let foreign: BTreeSet<String> = disk_tree(sys, &disk)
                .into_iter()
                .filter(|n| !tree.contains(n))
                .collect();
            DiskState {
                ro: sys.read_only(&disk),
                partitions: sys
                    .partitions(&disk)
                    .into_iter()
                    .map(|p| {
                        let ro = sys.read_only(&p);
                        (p, ro)
                    })
                    .collect(),
                foreign_mounts: mounts_of(sys, &foreign, mountinfo),
                node: disk,
            }
        })
        .collect();
    DecisionInputs {
        is_block_device: identity.is_block_device(),
        source: identity.kernel_name.clone(),
        source_ro: sys.read_only(&identity.kernel_name),
        disks,
    }
}

/// Registry presence on this host (`dfcore::protected::path()`).
pub fn registry_presence() -> RegistryPresence {
    match dfcore::protected::Registry::load(&dfcore::protected::path()) {
        Ok(Some(_)) => RegistryPresence::Present,
        Ok(None) => RegistryPresence::Absent,
        Err(e) => RegistryPresence::Unreadable {
            reason: format!("{e:#}"),
        },
    }
}

/// [`capture`] against a given sysfs tree, mountinfo and registry state.
pub fn capture_in(
    sys: &SysRoot,
    identity: &SourceIdentity,
    mountinfo: &str,
    registry: RegistryPresence,
    policy: WriteProtectPolicy,
) -> WriteProtection {
    let mut wp = WriteProtection {
        policy,
        dfnix_registry: registry,
        ..Default::default()
    };
    if !identity.is_block_device() {
        wp.notes
            .push("the source is a regular file: no block-layer read-only flag".into());
        return wp;
    }
    let src = &identity.kernel_name;
    wp.sysfs_ro_before = sys.read_only(src);
    let disks = disks_of(identity);
    if !matches!(identity.kind, SourceKind::Disk | SourceKind::Other) {
        wp.parent_disks_ro_before = disks
            .iter()
            .map(|d| NodeReadOnly {
                node: format!("/dev/{d}"),
                ro: sys.read_only(d),
            })
            .collect();
    }
    wp.partitions_ro_before = disks
        .iter()
        .flat_map(|d| sys.partitions(d))
        .map(|p| NodeReadOnly {
            ro: sys.read_only(&p),
            node: format!("/dev/{p}"),
        })
        .collect();
    let tree = source_tree(sys, identity);
    wp.holders = tree.iter().filter(|n| *n != src).cloned().collect();
    // Partitions of a disk source are part of its tree but not holders
    if matches!(identity.kind, SourceKind::Disk | SourceKind::Other) {
        let parts: BTreeSet<String> = sys.partitions(src).into_iter().collect();
        wp.holders.retain(|h| !parts.contains(h));
        wp.holders.sort();
    }
    wp.mounts_before = mounts_of(sys, &tree, mountinfo);
    wp
}

/// Record the write-protection state of the source on this host
/// (/sys, /proc/self/mountinfo, the dfnix registry). Changes nothing.
pub fn capture(identity: &SourceIdentity, policy: WriteProtectPolicy) -> WriteProtection {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    capture_in(
        &SysRoot::host(),
        identity,
        &mountinfo,
        registry_presence(),
        policy,
    )
}

/// Set the read-only flag (BLKROSET) on `/dev/<kname>` for each kernel name,
/// in order. Returns the device paths set; stops at the first failure.
pub fn apply_ro_nodes(knames: &[String]) -> Result<Vec<String>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let mut done = Vec::new();
    for kname in knames {
        if kname.is_empty() || kname.contains('/') {
            return Err(format!("invalid device name {kname:?}"));
        }
        let node = format!("/dev/{kname}");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&node)
            .map_err(|e| failure(&node, &done, e))?;
        let one: libc::c_int = 1;
        // SAFETY: BLKROSET reads one int through the pointer; fd is open
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), BLKROSET as _, &one) };
        if rc != 0 {
            return Err(failure(&node, &done, io::Error::last_os_error()));
        }
        done.push(node);
    }
    Ok(done)
}

fn failure(node: &str, done: &[String], e: io::Error) -> String {
    let mut msg = format!("cannot set {node} read-only (BLKROSET): {e}");
    if !done.is_empty() {
        msg.push_str(&format!(" (already set: {})", done.join(", ")));
    }
    msg
}

/// Set the source read-only per the `auto` decision on this host (whole disk
/// and every partition node, R2). Returns the device paths set.
pub fn apply_ro(identity: &SourceIdentity) -> Result<Vec<String>, String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let inputs = decision_inputs(&SysRoot::host(), identity, &mountinfo);
    match decide(WriteProtectPolicy::Auto, &inputs) {
        WriteProtectDecision::Set { nodes, .. } => apply_ro_nodes(&nodes),
        _ => Ok(Vec::new()),
    }
}

/// Apply `policy` and record what happened in `wp` (from [`capture`]):
/// decide, set BLKROSET through `apply`, re-read sysfs and require ro=1 on
/// every node set. An `Err` must refuse the acquisition (exit 3); its text
/// ends with [`WRITE_PROTECT_OFF_HINT`].
pub fn enforce_in(
    sys: &SysRoot,
    identity: &SourceIdentity,
    mountinfo: &str,
    wp: &mut WriteProtection,
    apply: &ApplyRo<'_>,
) -> Result<(), String> {
    let inputs = decision_inputs(sys, identity, mountinfo);
    match decide(wp.policy, &inputs) {
        WriteProtectDecision::RecordOnly { reason } => {
            wp.notes.push(reason);
            Ok(())
        }
        WriteProtectDecision::AlreadyReadOnly => {
            wp.notes
                .push("every node of the source was already read-only (sysfs ro=1)".into());
            Ok(())
        }
        WriteProtectDecision::Set { nodes, notes } => {
            wp.notes.extend(notes);
            let set = apply(&nodes).map_err(|e| {
                format!("Cannot write-protect the source: {e}; {WRITE_PROTECT_OFF_HINT}")
            })?;
            wp.set_by_dfdisk = !set.is_empty();
            wp.method = Some("BLKROSET ioctl".into());
            wp.nodes_set = set;
            wp.ro_after = nodes
                .iter()
                .map(|n| NodeReadOnly {
                    node: format!("/dev/{n}"),
                    ro: sys.read_only(n),
                })
                .collect();
            let still_writable: Vec<String> = wp
                .ro_after
                .iter()
                .filter(|n| n.ro != Some(true))
                .map(NodeReadOnly::describe)
                .collect();
            if !still_writable.is_empty() {
                return Err(format!(
                    "Cannot write-protect the source: after BLKROSET sysfs still shows {}; {WRITE_PROTECT_OFF_HINT}",
                    still_writable.join(", ")
                ));
            }
            wp.notes.push(
                "dfdisk leaves the read-only flag set after the acquisition (blockdev --setrw clears it)"
                    .into(),
            );
            Ok(())
        }
    }
}

/// [`enforce_in`] on this host with the real ioctl.
pub fn enforce(identity: &SourceIdentity, wp: &mut WriteProtection) -> Result<(), String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    enforce_in(&SysRoot::host(), identity, &mountinfo, wp, &apply_ro_nodes)
}

/// Turn EBUSY from an exclusive open into a statement of what it means.
pub fn map_exclusive_open_error(path: &Path, err: io::Error) -> io::Error {
    if err.raw_os_error() == Some(libc::EBUSY) {
        io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!(
                "{} is in use: mounted or claimed (device-mapper, md, swap or another exclusive open), possibly in another mount namespace",
                path.display()
            ),
        )
    } else {
        io::Error::new(
            err.kind(),
            format!("cannot open {} exclusively: {err}", path.display()),
        )
    }
}

/// Open the source O_RDONLY|O_EXCL|O_CLOEXEC (R1). On a block device the
/// kernel then refuses mounts, md/dm assembly and other exclusive opens until
/// the file is closed; plain reads by ewfacquire/ddrescue still work.
/// EBUSY becomes an "in use" error (`ErrorKind::ResourceBusy`).
pub fn open_exclusive(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_EXCL | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| map_exclusive_open_error(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::sysfs::fake::FakeSysfs;

    const SATA: &str = "pci0000:00/0000:00:17.0/ata2/host1/target1:0:0/1:0:0:0";

    fn disk(node: &str, ro: Option<bool>, parts: &[(&str, Option<bool>)]) -> DiskState {
        DiskState {
            node: node.into(),
            ro,
            partitions: parts.iter().map(|(p, r)| (p.to_string(), *r)).collect(),
            foreign_mounts: Vec::new(),
        }
    }

    #[test]
    fn decide_off_and_regular_files_record_only() {
        let inputs = DecisionInputs {
            is_block_device: true,
            source: "sdb".into(),
            source_ro: Some(false),
            disks: vec![disk("sdb", Some(false), &[])],
        };
        assert!(matches!(
            decide(WriteProtectPolicy::Off, &inputs),
            WriteProtectDecision::RecordOnly { .. }
        ));
        let file = DecisionInputs {
            is_block_device: false,
            disks: vec![],
            ..inputs
        };
        let WriteProtectDecision::RecordOnly { reason } = decide(WriteProtectPolicy::Auto, &file)
        else {
            panic!()
        };
        assert!(reason.contains("regular file"));
    }

    #[test]
    fn decide_sets_the_disk_and_every_partition() {
        let inputs = DecisionInputs {
            is_block_device: true,
            source: "sdb".into(),
            source_ro: Some(false),
            disks: vec![disk(
                "sdb",
                Some(false),
                &[("sdb1", Some(false)), ("sdb2", None), ("sdb3", Some(true))],
            )],
        };
        assert_eq!(
            decide(WriteProtectPolicy::Auto, &inputs),
            WriteProtectDecision::Set {
                nodes: vec!["sdb".into(), "sdb1".into(), "sdb2".into()],
                notes: vec![]
            }
        );
        let all_ro = DecisionInputs {
            source_ro: Some(true),
            disks: vec![disk("sdb", Some(true), &[("sdb1", Some(true))])],
            ..inputs
        };
        assert_eq!(
            decide(WriteProtectPolicy::Auto, &all_ro),
            WriteProtectDecision::AlreadyReadOnly
        );
    }

    #[test]
    fn decide_partition_and_dm_sources() {
        // Partition source on an otherwise unused disk: disk + all partitions
        let part = DecisionInputs {
            is_block_device: true,
            source: "sdb2".into(),
            source_ro: Some(false),
            disks: vec![disk(
                "sdb",
                Some(false),
                &[("sdb1", Some(false)), ("sdb2", Some(false))],
            )],
        };
        let WriteProtectDecision::Set { nodes, .. } = decide(WriteProtectPolicy::Auto, &part)
        else {
            panic!()
        };
        assert_eq!(nodes, ["sdb", "sdb1", "sdb2"]);

        // A sibling is mounted: only the source partition, with a note
        let mut busy = part.clone();
        busy.disks[0].foreign_mounts = vec!["/mnt/other".into()];
        let WriteProtectDecision::Set { nodes, notes } = decide(WriteProtectPolicy::Auto, &busy)
        else {
            panic!()
        };
        assert_eq!(nodes, ["sdb2"]);
        assert!(notes[0].contains("/mnt/other"), "{notes:?}");

        // dm target on a disk: disk, partitions, then the dm node itself
        let dm = DecisionInputs {
            source: "dm-0".into(),
            ..part
        };
        let WriteProtectDecision::Set { nodes, .. } = decide(WriteProtectPolicy::Auto, &dm) else {
            panic!()
        };
        assert_eq!(nodes, ["sdb", "sdb1", "sdb2", "dm-0"]);
    }

    fn sata_with_partitions(f: &FakeSysfs) {
        f.add_disk(SATA, "sdb", (8, 16), 10_000);
        f.add_partition("sdb", "sdb1", (8, 17), 1, 2048, 4000);
        f.add_partition("sdb", "sdb2", (8, 18), 2, 6048, 3000);
    }

    fn identity(kname: &str, kind: SourceKind, parents: &[&str]) -> SourceIdentity {
        SourceIdentity {
            path: format!("/dev/{kname}"),
            kernel_name: kname.into(),
            kind,
            parent_disks: parents.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
    }

    const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
40 22 8:17 / /mnt/evidence-a rw,relatime - ext4 /dev/sdb1 rw
41 22 0:45 / /mnt/btrfs rw,relatime - btrfs /dev/mapper/cryptdata rw
";

    #[test]
    fn capture_records_ro_holders_mounts_and_registry() {
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        f.set("sdb2", "ro", "1");
        f.add_virtual("dm-0", (254, 0), 2000);
        f.set("dm-0", "dm/name", "cryptdata");
        f.stack("dm-0", "sdb2");
        let sys = f.root();

        let wp = capture_in(
            &sys,
            &identity("sdb", SourceKind::Disk, &[]),
            MOUNTINFO,
            RegistryPresence::Present,
            WriteProtectPolicy::Auto,
        );
        assert_eq!(wp.sysfs_ro_before, Some(false));
        assert!(wp.parent_disks_ro_before.is_empty());
        assert_eq!(
            wp.partitions_ro_before,
            [
                NodeReadOnly {
                    node: "/dev/sdb1".into(),
                    ro: Some(false)
                },
                NodeReadOnly {
                    node: "/dev/sdb2".into(),
                    ro: Some(true)
                }
            ]
        );
        assert_eq!(wp.holders, ["dm-0"]);
        assert_eq!(wp.mounts_before, ["/mnt/btrfs", "/mnt/evidence-a"]);
        assert_eq!(wp.dfnix_registry, RegistryPresence::Present);
        assert!(!wp.set_by_dfdisk);
        assert!(wp.summary().contains("NOT read-only"));

        let part = capture_in(
            &sys,
            &identity("sdb2", SourceKind::Partition, &["/dev/sdb"]),
            MOUNTINFO,
            RegistryPresence::Absent,
            WriteProtectPolicy::Off,
        );
        assert_eq!(part.sysfs_ro_before, Some(true));
        assert_eq!(part.parent_disks_ro_before[0].node, "/dev/sdb");
        assert_eq!(part.holders, ["dm-0"]);
        assert_eq!(part.mounts_before, ["/mnt/btrfs"]);

        let file = capture_in(
            &sys,
            &identity("img", SourceKind::RegularFile, &[]),
            MOUNTINFO,
            RegistryPresence::Absent,
            WriteProtectPolicy::Auto,
        );
        assert_eq!(file.sysfs_ro_before, None);
        assert!(file.notes[0].contains("regular file"));
    }

    #[test]
    fn enforce_sets_verifies_and_refuses_with_a_hint() {
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        let sys = f.root();
        let id = identity("sdb", SourceKind::Disk, &[]);
        // A stand-in for the ioctl that flips sysfs ro like the kernel would
        let fake_ioctl = |nodes: &[String]| -> Result<Vec<String>, String> {
            for n in nodes {
                f.set(n, "ro", "1");
            }
            Ok(nodes.iter().map(|n| format!("/dev/{n}")).collect())
        };
        let mut wp = capture_in(
            &sys,
            &id,
            "",
            RegistryPresence::Absent,
            WriteProtectPolicy::Auto,
        );
        enforce_in(&sys, &id, "", &mut wp, &fake_ioctl).unwrap();
        assert!(wp.set_by_dfdisk);
        assert_eq!(wp.method.as_deref(), Some("BLKROSET ioctl"));
        assert_eq!(wp.nodes_set, ["/dev/sdb", "/dev/sdb1", "/dev/sdb2"]);
        assert!(wp.ro_after.iter().all(|n| n.ro == Some(true)));
        assert!(wp
            .notes
            .iter()
            .any(|n| n.contains("leaves the read-only flag set")));
        assert!(wp.summary().starts_with("set read-only by dfdisk"));

        // Second run: nothing left to set
        let mut again = capture_in(
            &sys,
            &id,
            "",
            RegistryPresence::Absent,
            WriteProtectPolicy::Auto,
        );
        enforce_in(&sys, &id, "", &mut again, &|_| panic!("must not set")).unwrap();
        assert!(!again.set_by_dfdisk);
        assert_eq!(again.sysfs_ro_before, Some(true));

        // The ioctl fails: refused with the hint
        let g = FakeSysfs::new();
        sata_with_partitions(&g);
        let mut wp = WriteProtection::default();
        let err = enforce_in(&g.root(), &id, "", &mut wp, &|_| {
            Err("cannot set /dev/sdb read-only (BLKROSET): Permission denied".into())
        })
        .unwrap_err();
        assert!(err.contains("Permission denied"), "{err}");
        assert!(err.ends_with(WRITE_PROTECT_OFF_HINT), "{err}");

        // The ioctl "succeeds" but sysfs still says ro=0: refused
        let mut wp = WriteProtection::default();
        let err = enforce_in(&g.root(), &id, "", &mut wp, &|n| {
            Ok(n.iter().map(|k| format!("/dev/{k}")).collect())
        })
        .unwrap_err();
        assert!(err.contains("still shows /dev/sdb ro=0"), "{err}");

        // Policy off changes nothing
        let mut off = WriteProtection {
            policy: WriteProtectPolicy::Off,
            ..Default::default()
        };
        enforce_in(&g.root(), &id, "", &mut off, &|_| panic!("must not set")).unwrap();
        assert!(off.notes[0].contains("policy off"));
    }

    #[test]
    fn sibling_mounts_keep_the_disk_writable() {
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        let inputs = decision_inputs(
            &f.root(),
            &identity("sdb2", SourceKind::Partition, &["/dev/sdb"]),
            MOUNTINFO,
        );
        assert_eq!(inputs.disks[0].foreign_mounts, ["/mnt/evidence-a"]);
        let WriteProtectDecision::Set { nodes, notes } = decide(WriteProtectPolicy::Auto, &inputs)
        else {
            panic!()
        };
        assert_eq!(nodes, ["sdb2"]);
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn exclusive_open_and_busy_mapping() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("img");
        std::fs::write(&file, b"x").unwrap();
        assert!(open_exclusive(&file).is_ok());
        let missing = open_exclusive(&tmp.path().join("nope")).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        let busy = map_exclusive_open_error(
            Path::new("/dev/sdb"),
            io::Error::from_raw_os_error(libc::EBUSY),
        );
        assert_eq!(busy.kind(), io::ErrorKind::ResourceBusy);
        assert!(busy.to_string().contains("in use"), "{busy}");
        assert!(busy.to_string().contains("another mount namespace"));
        assert!(apply_ro_nodes(&["../etc".to_string()]).is_err());
    }
}
