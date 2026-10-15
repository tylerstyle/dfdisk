//! Device discovery scans (§14, M1, M5, M6, R8): `lsblk` plus sysfs, the
//! mount table, the active swap list and the dfnix registry. Nothing is sent
//! to any device: no SMART, no hdparm, no udev query per device (SMART and
//! capacity are separate, explicit queries: `discovery::smart`,
//! `discovery::capacity`).
//!
//! Every node lsblk lists under a whole disk becomes a [`ScannedNode`]: the
//! disk itself, its partitions and the devices stacked on them (LUKS, LVM,
//! md), each with its own identity (the same sysfs probe the session uses,
//! so a selection matches the probe at acquisition), its own tree of mounts,
//! holders and active swap, the system-disk reasons of the disk(s) below it
//! and the registry protection. [`Scan::devices`] gives the whole disks with
//! their partitions (CLI table, TUI list), [`Scan::sources`] every selectable
//! node, [`Scan::listing`] the `dfdisk list --json` document ([`DeviceList`]).
//!
//! When sysfs has no entry for a node (containers, tests), the identity and
//! tree are taken from lsblk alone and say so in `probe_notes`.

use crate::discovery::identity::Prober;
use crate::discovery::safety::{
    parse_mountinfo_records, registry_presence_of, registry_protection, system_reasons_for,
    MountRecord, SourceTree,
};
use crate::discovery::smart;
use crate::discovery::sysfs::SysRoot;
use crate::engines::process::{first_line, run_blocking, ProcessSpec};
use crate::engines::session::{HostSystem, SessionHost, SwapEntry};
use crate::models::capacity::CapacityInfo;
use crate::models::config::SmartPolicy;
use crate::models::device::{BlockDevice, DeviceSafety, Partition, SmartSnapshot};
use crate::models::identity::{SerialCandidate, SerialSource, SourceIdentity, SourceKind};
use crate::models::protection::RegistryPresence;
use crate::models::text::sanitize_opt;
use chrono::{DateTime, Utc};
use dfcore::lsblk::FlatDevice;
use dfcore::protected::Registry;
use dfcore::sysfs::{parse_dev_num, DevNum};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `lsblk` arguments of a scan: JSON, sizes in bytes, all columns.
pub const LSBLK_ARGS: &[&str] = &["-J", "-b", "-O"];
/// Timeout of the lsblk run.
pub const LSBLK_TIMEOUT: Duration = Duration::from_secs(15);
/// `schema_version` of [`DeviceList`] (`dfdisk list --json`).
pub const LIST_SCHEMA_VERSION: u32 = 1;
/// lsblk TYPEs listed as top-level devices.
const SCANNED_TYPES: &[&str] = &["disk", "loop", "mpath"];
/// udev link directories searched for device links.
const LINK_DIRS: &[&str] = &[
    "disk/by-id",
    "disk/by-path",
    "disk/by-uuid",
    "disk/by-partuuid",
    "disk/by-label",
    "disk/by-partlabel",
    "disk/by-diskseq",
    "disk/by-loop-ref",
    "disk/by-loop-inode",
    "mapper",
];

/// Everything a scan reads; injectable so tests never look at the host.
#[derive(Debug, Clone)]
pub struct ScanInput {
    /// `lsblk -J -b -O` output
    pub lsblk_json: String,
    pub sys: SysRoot,
    /// /proc/self/mountinfo
    pub mountinfo: Result<String, String>,
    /// /proc/swaps, mapped to block devices
    pub swaps: Result<Vec<SwapEntry>, String>,
    /// The dfnix registry (`Ok(None)` outside dfnix)
    pub registry: Result<Option<Registry>, String>,
    /// Normally `/dev` (device links)
    pub dev_dir: PathBuf,
}

impl ScanInput {
    /// This host: runs `lsblk -J -b -O` (15 s timeout) and reads /sys,
    /// /proc/self/mountinfo, /proc/swaps and the dfnix registry.
    pub fn host() -> Result<Self, String> {
        let spec = ProcessSpec::new("lsblk")
            .args(LSBLK_ARGS)
            .timeout(LSBLK_TIMEOUT);
        let out = run_blocking(&spec, None).map_err(|e| format!("Failed to execute lsblk: {e}"))?;
        if !out.outcome.success() {
            return Err(format!(
                "lsblk failed ({}): {}",
                out.outcome.record.status_text(),
                first_line(&out.stderr).unwrap_or_default()
            ));
        }
        let host = HostSystem;
        Ok(ScanInput {
            lsblk_json: out.stdout.join("\n"),
            sys: SysRoot::host(),
            mountinfo: host.mountinfo(),
            swaps: host.swaps(),
            registry: host.registry(),
            dev_dir: PathBuf::from("/dev"),
        })
    }
}

/// One block device node found by a scan.
#[derive(Debug, Clone)]
pub struct ScannedNode {
    /// The node as a selectable source (its own safety, holders, mounts)
    pub device: BlockDevice,
    /// sysfs identity, as the session probes it (no udev)
    pub identity: SourceIdentity,
    /// lsblk TYPE ("disk", "part", "crypt", "lvm", "raid1", "loop", ...)
    pub lsblk_type: String,
    /// 0 for a whole disk
    pub depth: usize,
    /// Path of the enclosing node in the lsblk tree (first one for devices
    /// stacked on several)
    pub parent: Option<String>,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
    /// Mount points of this node itself
    pub own_mounts: Vec<String>,
    /// Why the disk(s) below belong to the running system, plus active swap
    /// on this node's tree (R8)
    pub system_reasons: Vec<String>,
    /// Active swap areas on this node's tree
    pub active_swap: Vec<String>,
}

/// Result of one scan.
#[derive(Debug, Clone)]
pub struct Scan {
    /// Every node once, in lsblk order (each disk followed by its subtree)
    pub nodes: Vec<ScannedNode>,
    /// Node indices below each whole disk (devices stacked on several disks
    /// appear under each), keyed by the disk's index
    pub subtrees: BTreeMap<usize, Vec<usize>>,
    pub registry: RegistryPresence,
    pub swaps: Vec<SwapEntry>,
    /// What could not be read (mount table, swap list)
    pub notes: Vec<String>,
    pub scanned_at: DateTime<Utc>,
}

pub struct DeviceScanner;

impl DeviceScanner {
    /// Scan this host (lsblk + sysfs; nothing is sent to any device).
    pub fn scan() -> Result<Scan, String> {
        scan(&ScanInput::host()?)
    }

    /// Whole disks (and loop/multipath devices) with their partitions.
    pub fn scan_devices() -> Result<Vec<BlockDevice>, String> {
        Ok(Self::scan()?.devices())
    }

    /// Every selectable node: disks, partitions, dm/LUKS/LVM/md devices.
    pub fn scan_sources() -> Result<Vec<BlockDevice>, String> {
        Ok(Self::scan()?.sources())
    }
}

fn jstr(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn ju64(v: &Value, key: &str) -> Option<u64> {
    match v.get(key)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn jbool(v: &Value, key: &str) -> Option<bool> {
    match v.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_u64().map(|n| n != 0),
        Value::String(s) => match s.trim() {
            "1" | "true" => Some(true),
            "0" | "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Mount points lsblk shows for an entry (MOUNTPOINTS or MOUNTPOINT).
fn lsblk_mounts(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .get("mountpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    if let Some(m) = v.get("mountpoint").and_then(Value::as_str) {
        out.push(m.to_string());
    }
    out.retain(|m| !m.is_empty());
    out.dedup();
    out
}

fn children(v: &Value) -> impl Iterator<Item = &Value> {
    v.get("children")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn entry_path(v: &Value) -> String {
    jstr(v, "path").unwrap_or_else(|| format!("/dev/{}", jstr(v, "name").unwrap_or_default()))
}

/// The entry and all its descendants.
fn subtree<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    out.push(v);
    for c in children(v) {
        subtree(c, out);
    }
}

/// lsblk JSON in the shape dfcore parses (string sizes, MOUNTPOINTS), so
/// the registry and system detection run on dfcore's own tree.
fn dfcore_entry(v: &Value) -> Value {
    let kids: Vec<Value> = children(v).map(dfcore_entry).collect();
    json!({
        "name": jstr(v, "name").unwrap_or_default(),
        "path": jstr(v, "path"),
        "maj:min": jstr(v, "maj:min"),
        "size": jstr(v, "size"),
        "ro": jbool(v, "ro"),
        "type": jstr(v, "type"),
        "fstype": jstr(v, "fstype"),
        "label": jstr(v, "label"),
        "mountpoints": lsblk_mounts(v),
        "model": jstr(v, "model"),
        "serial": jstr(v, "serial"),
        "wwn": jstr(v, "wwn"),
        "children": if kids.is_empty() { Value::Null } else { Value::Array(kids) },
    })
}

/// Device links by kernel name of their target (`../../sdb1` -> "sdb1").
fn device_links(dev_dir: &Path) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for sub in LINK_DIRS {
        let Ok(entries) = std::fs::read_dir(dev_dir.join(sub)) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(target) = std::fs::read_link(e.path()) else {
                continue;
            };
            if let Some(name) = target.file_name() {
                map.entry(name.to_string_lossy().into_owned())
                    .or_default()
                    .push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    for links in map.values_mut() {
        links.sort();
    }
    map
}

/// Identity from lsblk alone (no sysfs entry).
fn lsblk_identity(v: &Value, path: &str, root: &str, depth: usize) -> SourceIdentity {
    let lsblk_type = jstr(v, "type").unwrap_or_default();
    SourceIdentity {
        path: path.to_string(),
        canonical_path: path.to_string(),
        kernel_name: jstr(v, "kname")
            .or_else(|| jstr(v, "name"))
            .unwrap_or_default(),
        maj_min: jstr(v, "maj:min"),
        kind: SourceKind::from_lsblk_type(&lsblk_type),
        size_bytes: ju64(v, "size").unwrap_or(0),
        logical_sector_size: ju64(v, "log-sec").unwrap_or(512) as u32,
        physical_sector_size: ju64(v, "phy-sec").unwrap_or(512) as u32,
        partition_number: ju64(v, "partn").and_then(|n| u32::try_from(n).ok()),
        partition_start_sector: ju64(v, "start"),
        parent_disks: if depth > 0 {
            vec![root.to_string()]
        } else {
            Vec::new()
        },
        probe_notes: vec!["no sysfs entry was found; identity taken from lsblk".into()],
        ..Default::default()
    }
}

/// Fill what sysfs did not give from lsblk (sanitised); lsblk's serial is a
/// candidate of the lowest rank.
fn merge_lsblk(id: &mut SourceIdentity, v: &Value) {
    let clean = |key: &str| jstr(v, key).and_then(|s| sanitize_opt(&s));
    if let Some(serial) = jstr(v, "serial") {
        id.add_serial_candidate(&serial, SerialSource::Lsblk);
    }
    if id.wwn.is_none() {
        id.wwn = clean("wwn");
    }
    if id.model.is_none() {
        id.model = clean("model");
    }
    if id.vendor.is_none() {
        id.vendor = clean("vendor");
    }
    if id.firmware_rev.is_none() {
        id.firmware_rev = clean("rev");
    }
    if id.transport.is_none() {
        id.transport = clean("tran").map(|t| t.to_ascii_lowercase());
    }
    id.hotplug |= jbool(v, "hotplug").unwrap_or(false);
    id.removable |= jbool(v, "rm").unwrap_or(false);
    if id.read_only.is_none() {
        id.read_only = jbool(v, "ro");
    }
    if id.rotational.is_none() {
        id.rotational = jbool(v, "rota");
    }
    if id.partition_start_sector.is_none() && id.kind == SourceKind::Partition {
        id.partition_start_sector = ju64(v, "start");
    }
}

/// The 0.1 bus label kept for the device table.
fn bus_type(transport: Option<&str>, path: &str, lsblk_type: &str) -> String {
    match transport {
        Some(t) if !t.is_empty() => t.to_uppercase(),
        _ if path.contains("nvme") => "NVME".into(),
        _ if path.contains("mmcblk") => "MMC/SD".into(),
        _ if lsblk_type == "loop" => "VIRTUAL LOOP".into(),
        _ => "UNKNOWN".into(),
    }
}

struct Ctx<'a> {
    input: &'a ScanInput,
    flat: Vec<FlatDevice>,
    mounts: Vec<MountRecord>,
    links: HashMap<String, Vec<String>>,
}

fn build_node(
    ctx: &Ctx<'_>,
    v: &Value,
    depth: usize,
    parent: Option<String>,
    root: &str,
) -> ScannedNode {
    let input = ctx.input;
    let path = entry_path(v);
    let lsblk_type = jstr(v, "type").unwrap_or_default();
    let maj_min = jstr(v, "maj:min");
    let dev: Option<DevNum> = maj_min.as_deref().and_then(parse_dev_num);
    let probed = dev.and_then(|d| {
        Prober::sysfs_only(input.sys.clone())
            .probe_block(&path, d)
            .ok()
    });
    let in_sysfs = probed.is_some();
    let mut identity = probed.unwrap_or_else(|| lsblk_identity(v, &path, root, depth));
    // The sysfs probe asked no udev; that is by design here, not a finding
    identity
        .probe_notes
        .retain(|n| !n.starts_with("udev properties"));
    merge_lsblk(&mut identity, v);

    // The node's tree: sysfs (partitions, holders) and lsblk's subtree
    let mut tree = if in_sysfs {
        SourceTree::from_sysfs(&input.sys, &identity)
    } else {
        SourceTree::default()
    };
    let mut sub = Vec::new();
    subtree(v, &mut sub);
    for s in &sub {
        if let Some(d) = jstr(s, "maj:min").as_deref().and_then(parse_dev_num) {
            tree.devs.insert(d);
        }
        tree.paths.insert(entry_path(s));
        if let Some(k) = jstr(s, "kname") {
            tree.paths.insert(format!("/dev/{k}"));
        }
    }

    let mut mountpoints: Vec<String> = Vec::new();
    let add = |list: &mut Vec<String>, m: &str| {
        if m != "[SWAP]" && !list.iter().any(|x| x == m) {
            list.push(m.to_string());
        }
    };
    for m in tree.mounts(&ctx.mounts) {
        add(&mut mountpoints, &m.mount_point);
    }
    for s in &sub {
        for m in lsblk_mounts(s) {
            add(&mut mountpoints, &m);
        }
    }
    let mut own_mounts = Vec::new();
    for m in ctx
        .mounts
        .iter()
        .filter(|m| Some(m.dev) == dev || m.source == path)
    {
        add(&mut own_mounts, &m.mount_point);
    }
    for m in lsblk_mounts(v) {
        // A partition's own entry keeps lsblk's "[SWAP]" (shown as before);
        // the swap itself is judged from the active swap list below
        if m == "[SWAP]" && !own_mounts.contains(&m) {
            own_mounts.push(m);
        } else {
            add(&mut own_mounts, &m);
        }
    }

    let active_swap: Vec<String> = match &input.swaps {
        Ok(swaps) => tree
            .swaps(swaps)
            .into_iter()
            .map(|s| format!("{} ({})", s.path, s.kind))
            .collect(),
        // Fail closed: a swap signature counts as active swap
        Err(_) => sub
            .iter()
            .filter(|s| {
                jstr(s, "fstype").as_deref() == Some("swap")
                    || lsblk_mounts(s).iter().any(|m| m == "[SWAP]")
            })
            .map(|s| {
                format!(
                    "{} (swap signature; the active swap list is unreadable, treated as active)",
                    entry_path(s)
                )
            })
            .collect(),
    };
    let mut system_reasons = system_reasons_for(&ctx.flat, &path, dev);
    system_reasons.extend(
        active_swap
            .iter()
            .map(|s| format!("active swap on this device: {s}")),
    );
    let protected = registry_protection(&input.registry, &ctx.flat, &path, dev);

    // Holders: devices stacked on the node or its partitions
    let partitions: BTreeSet<String> = if in_sysfs && identity.kind == SourceKind::Disk {
        input
            .sys
            .partitions(&identity.kernel_name)
            .into_iter()
            .collect()
    } else {
        BTreeSet::new()
    };
    let mut holders: BTreeSet<String> = tree
        .nodes
        .iter()
        .filter(|n| **n != identity.kernel_name && !partitions.contains(*n))
        .cloned()
        .collect();
    for s in sub.iter().skip(1) {
        if jstr(s, "type").as_deref() != Some("part") {
            let k = jstr(s, "kname")
                .or_else(|| jstr(s, "name"))
                .unwrap_or_default();
            // lsblk names dm devices by their mapper name; sysfs by dm-N
            let known = jstr(s, "maj:min")
                .as_deref()
                .and_then(parse_dev_num)
                .and_then(|d| input.sys.kname_of(d));
            holders.insert(known.unwrap_or(k));
        }
    }
    holders.remove("");

    let safety = if !system_reasons.is_empty() {
        DeviceSafety::SystemDisk(system_reasons.clone())
    } else if !mountpoints.is_empty() {
        DeviceSafety::Mounted(mountpoints.clone())
    } else {
        DeviceSafety::Safe
    };
    let mut devlinks = ctx
        .links
        .get(&identity.kernel_name)
        .cloned()
        .unwrap_or_default();
    devlinks.retain(|l| *l != path);

    let device = BlockDevice {
        name: jstr(v, "name").unwrap_or_else(|| identity.kernel_name.clone()),
        path: path.clone(),
        devlinks,
        size_bytes: identity.size_bytes,
        model: identity.model.clone(),
        vendor: identity.vendor.clone(),
        serial: identity.serial.clone(),
        wwn: identity.wwn.clone(),
        revision: identity.firmware_rev.clone(),
        bus_type: bus_type(identity.transport.as_deref(), &path, &lsblk_type),
        is_rotational: identity.rotational,
        is_removable: identity.removable,
        is_read_only: identity.read_only.unwrap_or(false),
        logical_sector_size: identity.logical_sector_size.max(512),
        physical_sector_size: identity.physical_sector_size.max(512),
        partition_table_type: jstr(v, "pttype"),
        partitions: Vec::new(),
        mountpoints,
        safety,
        smart: None,
        maj_min,
        diskseq: identity.diskseq,
        hotplug: identity.hotplug,
        transport: identity.transport.clone(),
        kind: identity.kind.clone(),
        holders: holders.into_iter().collect(),
        protected,
        parent: match identity.parent_disks.as_slice() {
            [one] if depth > 0 => Some(one.clone()),
            _ => None,
        },
        start_sector: identity.partition_start_sector,
        dm_uuid: identity.dm_uuid.clone(),
        serial_candidates: identity.serial_candidates.clone(),
    };
    ScannedNode {
        device,
        identity,
        lsblk_type,
        depth,
        parent,
        fstype: jstr(v, "fstype"),
        label: jstr(v, "label").and_then(|s| sanitize_opt(&s)),
        uuid: jstr(v, "uuid"),
        own_mounts,
        system_reasons,
        active_swap,
    }
}

/// Key that identifies a node across the lsblk tree.
fn node_key(v: &Value) -> String {
    jstr(v, "maj:min").unwrap_or_else(|| entry_path(v))
}

/// Collects nodes in lsblk order, each once.
struct Walker<'c, 'a> {
    ctx: &'c Ctx<'a>,
    nodes: Vec<ScannedNode>,
    index: HashMap<String, usize>,
}

impl Walker<'_, '_> {
    /// Visit `v` and its subtree; indices of the nodes below the whole disk
    /// go to `below_root`.
    fn walk(
        &mut self,
        v: &Value,
        depth: usize,
        parent: Option<String>,
        root: &str,
        below_root: &mut Vec<usize>,
    ) {
        let key = node_key(v);
        let i = match self.index.get(&key) {
            Some(&i) => i,
            None => {
                self.nodes
                    .push(build_node(self.ctx, v, depth, parent, root));
                self.index.insert(key, self.nodes.len() - 1);
                self.nodes.len() - 1
            }
        };
        if depth > 0 && !below_root.contains(&i) {
            below_root.push(i);
        }
        let path = entry_path(v);
        for c in children(v) {
            self.walk(c, depth + 1, Some(path.clone()), root, below_root);
        }
    }
}

/// Scan from the given input. Fails only when the lsblk output cannot be
/// parsed; what else cannot be read is a note (and fails closed: unreadable
/// swap list -> swap signatures count as active, unreadable registry ->
/// everything is protected).
pub fn scan(input: &ScanInput) -> Result<Scan, String> {
    let root: Value = serde_json::from_str(&input.lsblk_json)
        .map_err(|e| format!("Failed to parse lsblk JSON: {e}"))?;
    let entries = root
        .get("blockdevices")
        .and_then(Value::as_array)
        .ok_or_else(|| "No blockdevices array in lsblk output".to_string())?;
    let normalized =
        json!({ "blockdevices": entries.iter().map(dfcore_entry).collect::<Vec<_>>() });
    let flat = dfcore::lsblk::parse(normalized.to_string().as_bytes())
        .map_err(|e| format!("Failed to parse lsblk JSON: {e:#}"))?;
    let mut notes = Vec::new();
    let mounts = match &input.mountinfo {
        Ok(m) => parse_mountinfo_records(m),
        Err(e) => {
            notes.push(format!(
                "the mount table could not be read ({e}); mounts are those lsblk shows"
            ));
            Vec::new()
        }
    };
    if let Err(e) = &input.swaps {
        notes.push(format!(
            "the active swap list could not be read ({e}); every swap signature is treated as active swap"
        ));
    }
    if let Err(e) = &input.registry {
        notes.push(format!(
            "the dfnix protected-device registry could not be read ({e}); every device is treated as protected"
        ));
    }
    let ctx = Ctx {
        input,
        flat,
        mounts,
        links: device_links(&input.dev_dir),
    };
    let mut walker = Walker {
        ctx: &ctx,
        nodes: Vec::new(),
        index: HashMap::new(),
    };
    let mut subtrees = BTreeMap::new();
    for e in entries {
        let t = jstr(e, "type").unwrap_or_default();
        if !SCANNED_TYPES.contains(&t.as_str()) || jstr(e, "name").is_none() {
            continue;
        }
        let root_path = entry_path(e);
        let before = walker.nodes.len();
        let mut below = Vec::new();
        walker.walk(e, 0, None, &root_path, &mut below);
        if walker.nodes.len() > before {
            subtrees.insert(before, below);
        }
    }
    let nodes = walker.nodes;
    Ok(Scan {
        nodes,
        subtrees,
        registry: registry_presence_of(&input.registry),
        swaps: input.swaps.clone().unwrap_or_default(),
        notes,
        scanned_at: Utc::now(),
    })
}

impl ScannedNode {
    /// As a partition entry of its disk.
    pub fn as_partition(&self) -> Partition {
        let d = &self.device;
        Partition {
            name: d.name.clone(),
            path: d.path.clone(),
            size_bytes: d.size_bytes,
            fstype: self.fstype.clone(),
            label: self.label.clone(),
            uuid: self.uuid.clone(),
            mountpoint: self.own_mounts.first().cloned(),
            is_read_only: d.is_read_only,
            maj_min: d.maj_min.clone(),
            kind: Some(self.lsblk_type.clone()),
            start_sector: d.start_sector,
        }
    }
}

impl Scan {
    /// Whole disks (loop, multipath) with every node below them as partitions.
    pub fn devices(&self) -> Vec<BlockDevice> {
        self.subtrees
            .iter()
            .map(|(&disk, below)| {
                let mut d = self.nodes[disk].device.clone();
                d.partitions = below
                    .iter()
                    .map(|&i| self.nodes[i].as_partition())
                    .collect();
                d
            })
            .collect()
    }

    /// Every node as a selectable source, disks first in each subtree.
    pub fn sources(&self) -> Vec<BlockDevice> {
        let disks = self.devices();
        let mut out = Vec::new();
        for (n, (_, below)) in self.subtrees.iter().enumerate() {
            out.push(disks[n].clone());
            for &i in below {
                if self.nodes[i].parent.is_some()
                    && !out
                        .iter()
                        .any(|d: &BlockDevice| d.path == self.nodes[i].device.path)
                {
                    out.push(self.nodes[i].device.clone());
                }
            }
        }
        out
    }

    /// The node at `path`: by path, device link, or the device number of
    /// the node `path` names (a /dev/disk/by-* link, /dev/dm-N for a mapper).
    pub fn find(&self, path: &str) -> Option<&ScannedNode> {
        let rdev = dfcore::sysfs::dev_num_of_path(Path::new(path));
        self.nodes
            .iter()
            .find(|n| n.device.path == path || n.device.devlinks.iter().any(|l| l == path))
            .or_else(|| {
                let rdev = rdev?;
                self.nodes
                    .iter()
                    .find(|n| n.device.maj_min.as_deref().and_then(parse_dev_num) == Some(rdev))
            })
    }

    /// The `dfdisk list --json` document.
    pub fn listing(&self) -> DeviceList {
        let tops: Vec<usize> = self.subtrees.keys().copied().collect();
        DeviceList {
            schema_version: LIST_SCHEMA_VERSION,
            generated_at: self.scanned_at,
            registry: self.registry.clone(),
            active_swaps: self
                .swaps
                .iter()
                .map(|s| ListedSwap {
                    path: s.path.clone(),
                    kind: s.kind.clone(),
                    device: s.dev.map(|(a, b)| format!("{a}:{b}")),
                })
                .collect(),
            notes: self.notes.clone(),
            devices: tops.iter().map(|&i| self.listed(i, 0)).collect(),
        }
    }

    fn listed(&self, i: usize, level: usize) -> ListedDevice {
        let n = &self.nodes[i];
        let d = &n.device;
        let children = if level < 32 {
            self.nodes
                .iter()
                .enumerate()
                .filter(|(_, c)| c.parent.as_deref() == Some(d.path.as_str()))
                .map(|(j, _)| self.listed(j, level + 1))
                .collect()
        } else {
            Vec::new()
        };
        ListedDevice {
            path: d.path.clone(),
            name: d.name.clone(),
            kernel_name: n.identity.kernel_name.clone(),
            maj_min: d.maj_min.clone(),
            diskseq: d.diskseq,
            lsblk_type: n.lsblk_type.clone(),
            kind: d.kind.clone(),
            parent_disks: n.identity.parent_disks.clone(),
            size_bytes: d.size_bytes,
            logical_sector_size: d.logical_sector_size,
            physical_sector_size: d.physical_sector_size,
            model: d.model.clone(),
            vendor: d.vendor.clone(),
            firmware_rev: d.revision.clone(),
            serial: d.serial.clone(),
            serial_candidates: d.serial_candidates.clone(),
            serial_note: n.identity.serial_note(),
            wwn: d.wwn.clone(),
            transport: d.transport.clone(),
            hotplug: d.hotplug,
            removable: d.is_removable,
            rotational: d.is_rotational,
            read_only: n.identity.read_only,
            partition_table: d.partition_table_type.clone(),
            partition_number: n.identity.partition_number,
            start_sector: d.start_sector,
            fstype: n.fstype.clone(),
            label: n.label.clone(),
            uuid: n.uuid.clone(),
            dm_uuid: d.dm_uuid.clone(),
            dm_name: n.identity.dm_name.clone(),
            holders: d.holders.clone(),
            mountpoints: d.mountpoints.clone(),
            active_swap: n.active_swap.clone(),
            system: !n.system_reasons.is_empty(),
            system_reasons: n.system_reasons.clone(),
            protected: d.protected.clone(),
            badges: badges(d, None).into_iter().map(str::to_string).collect(),
            devlinks: d.devlinks.clone(),
            smart: None,
            children,
        }
    }
}

/// Status badges of a device (§16): SYSTEM, PROTECTED, MOUNTED, RO, IN-USE
/// (holders), and HPA/DCO when a capacity probe found a hidden area.
pub fn badges(dev: &BlockDevice, capacity: Option<&CapacityInfo>) -> Vec<&'static str> {
    let mut out = Vec::new();
    if dev.safety.is_system() {
        out.push("SYSTEM");
    }
    if dev.protected.is_some() {
        out.push("PROTECTED");
    }
    if !dev.mountpoints.is_empty() {
        out.push("MOUNTED");
    }
    if dev.is_read_only {
        out.push("RO");
    }
    if !dev.holders.is_empty() {
        out.push("IN-USE");
    }
    if let Some(ata) = capacity.and_then(|c| c.ata.as_ref()) {
        if ata.hpa_present == Some(true) {
            out.push("HPA");
        }
        if ata.dco_present == Some(true) {
            out.push("DCO");
        }
    }
    out
}

/// The scan entry for `path` among `sources` (from [`Scan::sources`]): by
/// path, device link, or the device number of the node at `path`.
pub fn find_source<'a>(sources: &'a [BlockDevice], path: &str) -> Option<&'a BlockDevice> {
    sources
        .iter()
        .find(|d| d.path == path || d.devlinks.iter().any(|l| l == path))
        .or_else(|| {
            let rdev = dfcore::sysfs::dev_num_of_path(Path::new(path))?;
            sources
                .iter()
                .find(|d| d.maj_min.as_deref().and_then(parse_dev_num) == Some(rdev))
        })
}

/// `dfdisk list --json` (schema 1).
#[derive(Debug, Clone, Serialize)]
pub struct DeviceList {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    /// dfnix protected-device registry: present / absent / unreadable
    pub registry: RegistryPresence,
    /// Active swap areas of the host (/proc/swaps)
    pub active_swaps: Vec<ListedSwap>,
    /// What the scan could not read
    pub notes: Vec<String>,
    /// Whole disks; partitions and stacked devices nested in `children`
    pub devices: Vec<ListedDevice>,
}

/// One active swap area.
#[derive(Debug, Clone, Serialize)]
pub struct ListedSwap {
    pub path: String,
    /// "partition" or "file"
    pub kind: String,
    /// "major:minor" of the device holding it
    pub device: Option<String>,
}

/// One block device in [`DeviceList`]. A device stacked on several (md
/// RAID, LVM across disks) is listed once, under the first device lsblk
/// shows it on; `parent_disks` names all disks below it.
#[derive(Debug, Clone, Serialize)]
pub struct ListedDevice {
    pub path: String,
    /// lsblk NAME (the mapper name for dm devices)
    pub name: String,
    /// sysfs kernel name (dm-0, sdb1)
    pub kernel_name: String,
    pub maj_min: Option<String>,
    pub diskseq: Option<u64>,
    /// lsblk TYPE
    pub lsblk_type: String,
    pub kind: SourceKind,
    pub parent_disks: Vec<String>,
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub firmware_rev: Option<String>,
    /// Preferred serial (device-reported > udev > lsblk)
    pub serial: Option<String>,
    pub serial_candidates: Vec<SerialCandidate>,
    /// Candidates disagree / USB bridge statement
    pub serial_note: Option<String>,
    pub wwn: Option<String>,
    pub transport: Option<String>,
    /// Hot-pluggable attachment (USB, eSATA)
    pub hotplug: bool,
    /// Removable media (card readers, optical)
    pub removable: bool,
    pub rotational: Option<bool>,
    /// Block layer read-only flag (sysfs ro)
    pub read_only: Option<bool>,
    pub partition_table: Option<String>,
    pub partition_number: Option<u32>,
    /// First sector on the disk (512-byte units)
    pub start_sector: Option<u64>,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub dm_uuid: Option<String>,
    pub dm_name: Option<String>,
    /// Devices stacked on this device or its partitions (dm, LUKS, LVM, md)
    pub holders: Vec<String>,
    /// Mounts of this device and everything below it
    pub mountpoints: Vec<String>,
    /// Active swap on this device's tree
    pub active_swap: Vec<String>,
    /// On a disk of the running system (or carrying active swap)
    pub system: bool,
    pub system_reasons: Vec<String>,
    /// Why the dfnix registry protects it
    pub protected: Option<String>,
    pub badges: Vec<String>,
    pub devlinks: Vec<String>,
    /// Only with `list --smart` (on-demand query, `-n standby`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smart: Option<SmartSnapshot>,
    pub children: Vec<ListedDevice>,
}

impl DeviceList {
    /// `list --smart`: query each whole disk on demand (`-n standby`, so a
    /// sleeping disk is not woken; never part of a scan).
    pub async fn attach_smart(&mut self, scan: &Scan, policy: SmartPolicy) {
        for listed in &mut self.devices {
            if let Some(node) = scan.nodes.iter().find(|n| n.device.path == listed.path) {
                listed.smart = smart::query_on_demand(&node.identity, policy).await;
            }
        }
    }
}

#[cfg(test)]
mod tests;
