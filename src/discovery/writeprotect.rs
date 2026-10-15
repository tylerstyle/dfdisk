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

/// Read-only state of a node the source sits on between it and its disks:
/// the partition under a dm/md source, an intermediate dm or md device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainNode {
    /// Kernel name, e.g. "sdb2", "dm-0"
    pub node: String,
    pub ro: Option<bool>,
    /// Mount points of devices that depend on this node outside the source
    /// tree (another LV of the same volume group, for example)
    pub foreign_mounts: Vec<String>,
}

/// Everything [`decide`] needs, read from sysfs and mountinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionInputs {
    pub is_block_device: bool,
    /// Kernel name of the source node
    pub source: String,
    pub source_ro: Option<bool>,
    /// (kernel name, ro) of the source's own partitions (a loop or md
    /// source's; a disk source's are in `disks`)
    pub source_partitions: Vec<(String, Option<bool>)>,
    /// The nodes the source sits on below it, down to (not including) the
    /// disks: partitions and intermediate dm/md devices
    pub chain: Vec<ChainNode>,
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
/// its own partitions, the nodes it sits on down to the disk (the partition
/// and intermediate dm/md devices), each disk it is stored on and every
/// partition of those disks are set read-only (R2). Exceptions, each named in
/// a note: a disk that holds mounts outside the source tree (a sibling
/// partition in use) stays writable together with its partitions outside the
/// source's chain, since the disk flag would make that mount read-only too;
/// likewise a node of the chain that other mounted devices depend on. Nodes
/// already read-only are not set again.
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
    let in_chain = |n: &str| n == inputs.source || inputs.chain.iter().any(|c| c.node == n);
    let mut targets: Vec<(String, Option<bool>)> = Vec::new();
    let mut notes = Vec::new();
    for disk in &inputs.disks {
        if disk.foreign_mounts.is_empty() {
            targets.push((disk.node.clone(), disk.ro));
            targets.extend(disk.partitions.iter().cloned());
        } else {
            let mut writable = vec![format!("/dev/{}", disk.node)];
            writable.extend(
                disk.partitions
                    .iter()
                    .filter(|(p, _)| !in_chain(p))
                    .map(|(p, _)| format!("/dev/{p}")),
            );
            notes.push(format!(
                "{} left writable because {} is mounted outside the source (the flag on the disk would make that mount read-only too); writes through /dev/{} can still reach the source",
                name_list(&writable),
                disk.foreign_mounts.join(", "),
                disk.node
            ));
        }
    }
    // Bottom-up: the node nearest the disk first
    for c in inputs.chain.iter().rev() {
        if c.foreign_mounts.is_empty() {
            targets.push((c.node.clone(), c.ro));
        } else {
            notes.push(format!(
                "/dev/{} (the source sits on it) was left writable because {} is mounted on another device that depends on it; writes through /dev/{} can still reach the source",
                c.node,
                c.foreign_mounts.join(", "),
                c.node
            ));
        }
    }
    targets.push((inputs.source.clone(), inputs.source_ro));
    targets.extend(inputs.source_partitions.iter().cloned());
    let mut pending: Vec<String> = Vec::new();
    for (n, ro) in targets {
        if ro != Some(true) && !pending.contains(&n) {
            pending.push(n);
        }
    }
    if pending.is_empty() {
        WriteProtectDecision::AlreadyReadOnly
    } else {
        WriteProtectDecision::Set {
            nodes: pending,
            notes,
        }
    }
}

/// "/dev/sdb was", "/dev/sdb and /dev/sdb1 were", "/dev/sdb, /dev/sdb1 and
/// /dev/sdb3 were".
fn name_list(nodes: &[String]) -> String {
    match nodes {
        [] => "nothing was".into(),
        [one] => format!("{one} was"),
        [rest @ .., last] => format!("{} and {last} were", rest.join(", ")),
    }
}

fn kname_of_path(p: &str) -> String {
    p.trim_start_matches("/dev/").to_string()
}

/// Disks whose read-only state belongs to the source, by kernel name. A loop
/// device has none: the disk holding its backing file is the host's, never
/// evidence, and is never set read-only. Under a dm or md source the walk
/// stops at a loop device (S-N1, [`SysRoot::storage_disks`] behind
/// `parent_disks`): the loop node is the disk.
fn disks_of(identity: &SourceIdentity) -> Vec<String> {
    match identity.kind {
        SourceKind::Disk | SourceKind::Other => vec![identity.kernel_name.clone()],
        SourceKind::RegularFile | SourceKind::Loop { .. } => Vec::new(),
        _ => identity
            .parent_disks
            .iter()
            .map(|d| kname_of_path(d))
            .collect(),
    }
}

/// Most nodes a tree is followed to (a guard against a looping sysfs).
const MAX_TREE_NODES: usize = 4096;

/// `root` and everything that depends on it, by kernel name: its partitions
/// (of any device: a disk's, a loop device's, an md array's), the devices
/// stacked on them (dm, LUKS, LVM, md), and loop devices whose backing file is
/// one of these nodes (`losetup /dev/sdb`), each again with its partitions and
/// holders.
fn dependent_tree(sys: &SysRoot, root: &str) -> BTreeSet<String> {
    let mut tree = BTreeSet::new();
    let mut pending = vec![root.to_string()];
    let mut loops: Option<Vec<(String, DevNum)>> = None;
    loop {
        while let Some(node) = pending.pop() {
            if tree.len() >= MAX_TREE_NODES || !tree.insert(node.clone()) {
                continue;
            }
            pending.extend(sys.partitions(&node));
            pending.extend(sys.holders(&node));
        }
        // Loop devices over a node of the tree (listed once, when needed)
        let loops = loops.get_or_insert_with(|| sys.loops_over_block_devices());
        let devs: BTreeSet<DevNum> = tree.iter().filter_map(|n| sys.dev_of(n)).collect();
        pending.extend(
            loops
                .iter()
                .filter(|(l, dev)| devs.contains(dev) && !tree.contains(l))
                .map(|(l, _)| l.clone()),
        );
        if pending.is_empty() {
            return tree;
        }
    }
}

/// The source node and everything that depends on it ([`dependent_tree`]:
/// its own partitions whatever its kind, stacked devices, loop devices over
/// it), by kernel name: the nodes whose mounts (and active swap, R8) are "in
/// the source tree".
pub fn source_tree(sys: &SysRoot, identity: &SourceIdentity) -> BTreeSet<String> {
    dependent_tree(sys, &identity.kernel_name)
}

/// Every node of a disk: the disk and everything that depends on it.
fn disk_tree(sys: &SysRoot, disk: &str) -> BTreeSet<String> {
    dependent_tree(sys, disk)
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
    let disk_names = disks_of(identity);
    let chain = if matches!(identity.kind, SourceKind::Loop { .. }) {
        // A loop device's lower node is its backing file's, never evidence
        Vec::new()
    } else {
        lower_nodes(sys, &identity.kernel_name)
            .into_iter()
            .filter(|n| !disk_names.contains(n))
            .map(|node| {
                let foreign: BTreeSet<String> = dependent_tree(sys, &node)
                    .into_iter()
                    .filter(|n| !tree.contains(n))
                    .collect();
                ChainNode {
                    ro: sys.read_only(&node),
                    foreign_mounts: mounts_of(sys, &foreign, mountinfo),
                    node,
                }
            })
            .collect()
    };
    let source_partitions = if disk_names.contains(&identity.kernel_name) {
        Vec::new()
    } else {
        sys.partitions(&identity.kernel_name)
            .into_iter()
            .map(|p| {
                let ro = sys.read_only(&p);
                (p, ro)
            })
            .collect()
    };
    DecisionInputs {
        is_block_device: identity.is_block_device(),
        source: identity.kernel_name.clone(),
        source_ro: sys.read_only(&identity.kernel_name),
        source_partitions,
        chain,
        disks,
    }
}

/// The nodes `kname` is stacked on, recursively (`slaves/`), nearest first:
/// for dm-1 on dm-0 on sdb2, [dm-0, sdb2]. A partition's disk is not among
/// them (a partition has no slaves).
fn lower_nodes(sys: &SysRoot, kname: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut queue = sys.slaves(kname);
    while !queue.is_empty() && out.len() < MAX_TREE_NODES {
        let n = queue.remove(0);
        if n == kname || out.contains(&n) {
            continue;
        }
        queue.extend(sys.slaves(&n));
        out.push(n);
    }
    out
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
    // The source's own partitions are part of its tree but not holders
    let parts: BTreeSet<String> = sys.partitions(src).into_iter().collect();
    wp.holders = tree
        .iter()
        .filter(|n| *n != src && !parts.contains(*n))
        .cloned()
        .collect();
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
            if !wp.nodes_set.is_empty() {
                wp.notes.push(format!(
                    "dfdisk leaves the read-only flag set after the acquisition on {}; each node keeps its own flag: `blockdev --setrw <node>` clears it on that node only",
                    wp.nodes_set.join(", ")
                ));
            }
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
            source_partitions: vec![],
            chain: vec![],
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
            source_partitions: vec![],
            chain: vec![],
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
            source_partitions: vec![],
            chain: vec![],
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
        // The flag is per node: the note names every node and says so
        assert!(
            wp.notes.iter().any(|n| n.contains(
                "leaves the read-only flag set after the acquisition on /dev/sdb, /dev/sdb1, /dev/sdb2"
            ) && n.contains("`blockdev --setrw <node>` clears it on that node only")),
            "{:?}",
            wp.notes
        );
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
    fn loop_sources_never_touch_the_disk_of_their_backing_file() {
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        f.add_virtual("loop0", (7, 0), 100);
        let id = SourceIdentity {
            path: "/dev/loop0".into(),
            kernel_name: "loop0".into(),
            kind: SourceKind::Loop {
                backing_file: Some("/srv/images/a.img".into()),
            },
            // Even if a probe listed the disk holding the backing file
            parent_disks: vec!["/dev/sdb".into()],
            ..Default::default()
        };
        let inputs = decision_inputs(&f.root(), &id, "");
        assert!(inputs.disks.is_empty());
        let WriteProtectDecision::Set { nodes, .. } = decide(WriteProtectPolicy::Auto, &inputs)
        else {
            panic!()
        };
        assert_eq!(nodes, ["loop0"]);
        let wp = capture_in(
            &f.root(),
            &id,
            "",
            RegistryPresence::Absent,
            WriteProtectPolicy::Auto,
        );
        assert!(wp.parent_disks_ro_before.is_empty());
        assert!(wp.partitions_ro_before.is_empty());
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
    fn loop_devices_over_the_source_are_holders_with_source_mounts() {
        // losetup -P /dev/sdb; mount /dev/loop0p1 /mnt/loop: no sysfs holder
        // link, no exclusive claim on sdb, but writes through loop0 reach it
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        f.add_loop("loop0", (7, 0), 10_000, "/dev/sdb");
        f.add_partition("loop0", "loop0p1", (259, 0), 1, 2048, 4000);
        // A loop over the source's partition, and one over an unrelated file
        f.add_loop("loop1", (7, 1), 3000, "/dev/sdb2");
        f.add_loop("loop2", (7, 2), 100, "/srv/images/unrelated.img");
        let mi = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                  50 22 259:0 / /mnt/loop rw - ext4 /dev/loop0p1 rw\n";
        let sys = f.root();

        let disk = identity("sdb", SourceKind::Disk, &[]);
        let tree = source_tree(&sys, &disk);
        for n in ["sdb", "sdb1", "sdb2", "loop0", "loop0p1", "loop1"] {
            assert!(tree.contains(n), "{n} not in {tree:?}");
        }
        assert!(!tree.contains("loop2"), "{tree:?}");
        let wp = capture_in(
            &sys,
            &disk,
            mi,
            RegistryPresence::Absent,
            WriteProtectPolicy::Auto,
        );
        assert_eq!(wp.mounts_before, ["/mnt/loop"]);
        assert_eq!(wp.holders, ["loop0", "loop0p1", "loop1"]);

        // A partition source: the loop over it is a holder; the loop over the
        // whole disk is outside its tree, so its mount is foreign to sdb2
        let part = identity("sdb2", SourceKind::Partition, &["/dev/sdb"]);
        let wp = capture_in(
            &sys,
            &part,
            mi,
            RegistryPresence::Absent,
            WriteProtectPolicy::Auto,
        );
        assert_eq!(wp.holders, ["loop1"]);
        assert!(wp.mounts_before.is_empty());
        let inputs = decision_inputs(&sys, &part, mi);
        assert_eq!(inputs.disks[0].foreign_mounts, ["/mnt/loop"]);
    }

    #[test]
    fn loop_and_md_sources_include_their_own_partitions() {
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        f.add_loop("loop0", (7, 0), 10_000, "/srv/images/a.img");
        f.add_partition("loop0", "loop0p1", (259, 0), 1, 2048, 4000);
        f.add_virtual("md0", (9, 0), 3000);
        std::fs::create_dir_all(f.path().join("devices/virtual/block/md0/md")).unwrap();
        f.stack("md0", "sdb1");
        f.add_partition("md0", "md0p1", (259, 1), 1, 2048, 2000);
        let mi = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                  50 22 259:0 / /mnt/loop rw - ext4 /dev/loop0p1 rw\n\
                  51 22 259:1 / /mnt/md rw - ext4 /dev/md0p1 rw\n";
        let sys = f.root();
        for (src, kind, mount) in [
            (
                "loop0",
                SourceKind::Loop {
                    backing_file: Some("/srv/images/a.img".into()),
                },
                "/mnt/loop",
            ),
            ("md0", SourceKind::Md, "/mnt/md"),
        ] {
            let id = identity(src, kind, &[]);
            let wp = capture_in(
                &sys,
                &id,
                mi,
                RegistryPresence::Absent,
                WriteProtectPolicy::Auto,
            );
            assert_eq!(wp.mounts_before, [mount], "{src}");
            // Its own partition is part of the source, not a holder
            assert!(wp.holders.is_empty(), "{src}: {:?}", wp.holders);
        }
        // The disk under md0 sees md0 and its partition as holders
        let wp = capture_in(
            &sys,
            &identity("sdb", SourceKind::Disk, &[]),
            mi,
            RegistryPresence::Absent,
            WriteProtectPolicy::Auto,
        );
        assert_eq!(wp.holders, ["md0", "md0p1"]);
        assert_eq!(wp.mounts_before, ["/mnt/md"]);
    }

    fn set_nodes(d: WriteProtectDecision) -> (Vec<String>, Vec<String>) {
        match d {
            WriteProtectDecision::Set { nodes, notes } => (nodes, notes),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_stacked_source_protects_its_chain_down_to_the_disk() {
        // dm-0 (LUKS) on sdb2; the sibling sdb1 is mounted: the disk stays
        // writable, the partition the source sits on does not
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        f.add_partition("sdb", "sdb3", (8, 19), 3, 9048, 500);
        f.add_virtual("dm-0", (254, 0), 2900);
        f.set("dm-0", "dm/name", "evluks");
        f.stack("dm-0", "sdb2");
        let sys = f.root();
        let dm0 = identity(
            "dm-0",
            SourceKind::DeviceMapper {
                crypt_plaintext: true,
            },
            &["/dev/sdb"],
        );
        let inputs = decision_inputs(&sys, &dm0, MOUNTINFO);
        assert_eq!(inputs.chain.len(), 1);
        assert_eq!(inputs.chain[0].node, "sdb2");
        let (nodes, notes) = set_nodes(decide(WriteProtectPolicy::Auto, &inputs));
        assert_eq!(nodes, ["sdb2", "dm-0"]);
        assert_eq!(notes.len(), 1, "{notes:?}");
        // Exactly the nodes left writable, and what that means
        assert!(
            notes[0].starts_with("/dev/sdb, /dev/sdb1 and /dev/sdb3 were left writable"),
            "{notes:?}"
        );
        assert!(notes[0].contains("/mnt/evidence-a"), "{notes:?}");
        assert!(!notes[0].contains("its other partitions"), "{notes:?}");

        // Nothing mounted outside: the whole disk too, bottom-up
        let (nodes, notes) = set_nodes(decide(
            WriteProtectPolicy::Auto,
            &decision_inputs(&sys, &dm0, ""),
        ));
        assert_eq!(nodes, ["sdb", "sdb1", "sdb2", "sdb3", "dm-0"]);
        assert!(notes.is_empty());

        // Two levels (LV dm-1 on LUKS dm-0 on sdb2): the chain bottom-up
        f.add_virtual("dm-1", (254, 1), 2000);
        f.stack("dm-1", "dm-0");
        let dm1 = identity(
            "dm-1",
            SourceKind::DeviceMapper {
                crypt_plaintext: false,
            },
            &["/dev/sdb"],
        );
        let (nodes, _) = set_nodes(decide(
            WriteProtectPolicy::Auto,
            &decision_inputs(&sys, &dm1, MOUNTINFO),
        ));
        assert_eq!(nodes, ["sdb2", "dm-0", "dm-1"]);

        // A second LV on the same LUKS device is mounted: dm-0 and sdb2 carry
        // it, so they stay writable as well, and the notes say so
        f.add_virtual("dm-2", (254, 2), 800);
        f.stack("dm-2", "dm-0");
        let mi = format!("{MOUNTINFO}50 22 254:2 / /mnt/lv2 rw - ext4 /dev/dm-2 rw\n");
        let (nodes, notes) = set_nodes(decide(
            WriteProtectPolicy::Auto,
            &decision_inputs(&sys, &dm1, &mi),
        ));
        assert_eq!(nodes, ["dm-1"]);
        for n in [
            "/dev/sdb2 (the source sits on it)",
            "/dev/dm-0 (the source sits on it)",
        ] {
            assert!(notes.iter().any(|x| x.starts_with(n)), "{n}: {notes:?}");
        }
        assert!(notes
            .iter()
            .all(|x| x.contains("/mnt/lv2") || x.contains("/mnt/evidence-a")));
    }

    #[test]
    fn an_md_source_on_two_disks_protects_both_members() {
        let f = FakeSysfs::new();
        sata_with_partitions(&f);
        f.add_disk(
            "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0",
            "sdc",
            (8, 32),
            10_000,
        );
        f.add_partition("sdc", "sdc1", (8, 33), 1, 2048, 4000);
        f.add_virtual("md0", (9, 0), 3900);
        f.stack("md0", "sdb2");
        f.stack("md0", "sdc1");
        let md = identity("md0", SourceKind::Md, &["/dev/sdb", "/dev/sdc"]);
        // sdb1 is mounted: sdb and sdb1 stay writable, every member is set
        let (nodes, notes) = set_nodes(decide(
            WriteProtectPolicy::Auto,
            &decision_inputs(&f.root(), &md, MOUNTINFO),
        ));
        assert_eq!(nodes, ["sdc", "sdc1", "sdb2", "md0"]);
        assert!(
            notes[0].starts_with("/dev/sdb and /dev/sdb1 were left writable"),
            "{notes:?}"
        );
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
