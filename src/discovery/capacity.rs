//! Capacity of the source as the drive reports it and areas hidden from the
//! operating system (§7, R6): ATA `hdparm -N` (READ NATIVE MAX ADDRESS, no
//! modification) and `hdparm --dco-identify`, NVMe `nvme id-ns -o json`.
//!
//! DISCOVERY AGENT: [`probe`] is a placeholder with its final signature. It
//! must run the probes through `engines::process` (15 s timeout each, the
//! stop control honoured, every command recorded in `recorder`) against the
//! physical disk of the source (`identity.kernel_name` for a whole disk, its
//! single parent disk for a partition or dm/md source, R6) and fill
//! [`CapacityInfo::probed_device`] accordingly; nothing for regular files and
//! loop devices. It never changes HPA or DCO. The session calls it at step 6
//! (after the audit "started" record, R7) and in `check`; the TUI calls it on
//! explicit request only, never in discovery scans.

use crate::engines::process::StopControl;
use crate::models::capacity::CapacityInfo;
use crate::models::identity::SourceIdentity;
use crate::models::provenance::ProvenanceRecorder;
use std::time::Duration;

/// Timeout of each capacity probe command.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Capacity and hidden areas of the disk the source is stored on. Never
/// fails: what could not be probed is stated in `method` / `errors`.
pub async fn probe(
    identity: &SourceIdentity,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> CapacityInfo {
    // Placeholder until the discovery agent implements the probes (see module docs)
    let _ = (control, recorder);
    CapacityInfo::not_probed(
        identity.size_bytes,
        "capacity probing (HPA/DCO, NVMe namespace) is not implemented in this build",
    )
}
