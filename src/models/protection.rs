//! Write protection of an acquisition source as recorded in the report (§6,
//! R1, R2). Captured and enforced by `discovery::writeprotect`.

use crate::models::config::WriteProtectPolicy;
use serde::{Deserialize, Serialize};

/// Whether the dfnix protected-device registry exists on this host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RegistryPresence {
    /// /run/dfnix/protected.json was read (running on dfnix)
    Present,
    /// No registry (not dfnix)
    #[default]
    Absent,
    /// A registry exists but could not be read; on dfnix that refuses (P2)
    Unreadable { reason: String },
}

impl RegistryPresence {
    pub fn label(&self) -> String {
        match self {
            RegistryPresence::Present => "present (dfnix)".into(),
            RegistryPresence::Absent => "absent".into(),
            RegistryPresence::Unreadable { reason } => format!("UNREADABLE: {reason}"),
        }
    }
}

/// The block layer's read-only flag of one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeReadOnly {
    /// Device path, e.g. "/dev/sdb1"
    pub node: String,
    /// sysfs `ro`; `None`: unreadable
    pub ro: Option<bool>,
}

impl NodeReadOnly {
    pub fn describe(&self) -> String {
        format!(
            "{} {}",
            self.node,
            match self.ro {
                Some(true) => "ro=1",
                Some(false) => "ro=0",
                None => "ro=unknown",
            }
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteProtection {
    pub policy: WriteProtectPolicy,
    /// sysfs `ro` of the source node before dfdisk did anything. Reflects
    /// `blockdev --setro`, a udev read-only rule or the write-protect bit a
    /// hardware write blocker reports through the sd driver.
    pub sysfs_ro_before: Option<bool>,
    /// Disks the source is stored on (partition, dm and md sources)
    pub parent_disks_ro_before: Vec<NodeReadOnly>,
    /// Partitions of the source disk, or of its parent disks
    pub partitions_ro_before: Vec<NodeReadOnly>,
    /// dfdisk set the read-only flag itself
    pub set_by_dfdisk: bool,
    /// "BLKROSET ioctl" when dfdisk set it
    pub method: Option<String>,
    /// Every node dfdisk set read-only (R2)
    pub nodes_set: Vec<String>,
    /// sysfs `ro` re-read after setting it
    pub ro_after: Vec<NodeReadOnly>,
    /// Devices stacked on the source (dm, md) and loop devices over it or
    /// its partitions, recursively
    pub holders: Vec<String>,
    /// The source is held open O_EXCL for the whole run (R1)
    pub exclusive_open: bool,
    pub dfnix_registry: RegistryPresence,
    /// Mount points in the source tree before the acquisition
    pub mounts_before: Vec<String>,
    /// Mount points dfdisk unmounted (audited, §10)
    pub unmounted_by_dfdisk: Vec<String>,
    pub notes: Vec<String>,
}

impl WriteProtection {
    /// One line for banners and lists.
    pub fn summary(&self) -> String {
        if self.set_by_dfdisk {
            format!(
                "set read-only by dfdisk ({}) on {}",
                self.method.as_deref().unwrap_or("BLKROSET ioctl"),
                self.nodes_set.join(", ")
            )
        } else {
            match self.sysfs_ro_before {
                Some(true) => "already read-only before dfdisk (sysfs ro=1)".into(),
                Some(false) => format!(
                    "NOT read-only (sysfs ro=0; write-protect policy {})",
                    self.policy.label()
                ),
                None => "read-only state unknown".into(),
            }
        }
    }

    /// (label, value) rows for the report.
    pub fn rows(&self) -> Vec<(String, String)> {
        let ro = |v: Option<bool>| match v {
            Some(true) => "yes (ro=1)".to_string(),
            Some(false) => "no (ro=0)".to_string(),
            None => "unknown".to_string(),
        };
        let list = |v: &[NodeReadOnly]| {
            if v.is_empty() {
                "(none)".to_string()
            } else {
                v.iter()
                    .map(NodeReadOnly::describe)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        };
        let or_none = |v: &[String]| {
            if v.is_empty() {
                "(none)".to_string()
            } else {
                v.join(", ")
            }
        };
        let mut rows = vec![
            ("Policy".to_string(), self.policy.label().to_string()),
            ("Read-only Before".to_string(), ro(self.sysfs_ro_before)),
        ];
        if !self.parent_disks_ro_before.is_empty() {
            rows.push((
                "Parent Disks Before".into(),
                list(&self.parent_disks_ro_before),
            ));
        }
        if !self.partitions_ro_before.is_empty() {
            rows.push(("Partitions Before".into(), list(&self.partitions_ro_before)));
        }
        rows.push((
            "Set by dfdisk".into(),
            if self.set_by_dfdisk {
                format!(
                    "yes, {} on {}",
                    self.method.as_deref().unwrap_or("BLKROSET ioctl"),
                    self.nodes_set.join(", ")
                )
            } else {
                "no".into()
            },
        ));
        if !self.ro_after.is_empty() {
            rows.push(("Read-only After".into(), list(&self.ro_after)));
        }
        rows.push(("Holders".into(), or_none(&self.holders)));
        rows.push((
            "Exclusive Open".into(),
            if self.exclusive_open {
                "yes (O_EXCL held for the whole run)"
            } else {
                "no"
            }
            .into(),
        ));
        rows.push(("dfnix Registry".into(), self.dfnix_registry.label()));
        rows.push(("Mounts Before".into(), or_none(&self.mounts_before)));
        if !self.unmounted_by_dfdisk.is_empty() {
            rows.push((
                "Unmounted by dfdisk".into(),
                self.unmounted_by_dfdisk.join(", "),
            ));
        }
        rows
    }
}
