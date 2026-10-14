//! Helpers shared by the integration tests that run acquisition engines.
#![allow(dead_code)]

use dfdisk::models::{
    case::CaseMetadata,
    device::{BlockDevice, DeviceSafety},
};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Point the dfnix audit log and protected-device registry of this test binary
/// at a scratch directory, so no test appends to the host's audit log (or
/// mirrors into its journal) and the host's registry never decides a test.
/// Call it first in every test that runs an engine.
pub fn audit_sandbox() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("dfdisk-audit-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap()
            .keep();
        std::env::set_var("DFNIX_AUDIT_LOG", dir.join("audit.jsonl"));
        std::env::set_var("DFNIX_PROTECTED_FILE", dir.join("protected.json"));
        dir
    })
}

/// Scratch directory with an `out` subdirectory, removed when dropped.
pub fn scratch() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("out")).unwrap();
    dir
}

pub fn case() -> CaseMetadata {
    CaseMetadata {
        case_number: "CASE42".to_string(),
        location_ea: "01".to_string(),
        evidence_number: "CF01".to_string(),
        authority: "DFIR".to_string(),
        examiner: "Examiner".to_string(),
        description: "Integration test".to_string(),
        ..Default::default()
    }
}

/// A regular file standing in for a source device.
pub fn file_device(path: &Path, size_bytes: u64, serial: Option<&str>) -> BlockDevice {
    BlockDevice {
        name: "test_dev".to_string(),
        path: path.to_string_lossy().to_string(),
        size_bytes,
        model: Some("Test".to_string()),
        vendor: Some("Test".to_string()),
        serial: serial.map(str::to_string),
        bus_type: "Virtual".to_string(),
        is_rotational: Some(false),
        logical_sector_size: 512,
        physical_sector_size: 512,
        safety: DeviceSafety::Safe,
        ..Default::default()
    }
}

pub fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}
