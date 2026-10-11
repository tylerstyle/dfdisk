//! Checks every acquisition engine runs before it writes a single byte:
//! no existing output may be overwritten, and the destination must not live on
//! the physical disk being acquired.

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

/// Refuse when the output directory lives on the same physical disk (any
/// partition, or any LVM/RAID/crypt/loop stack on it) as a block-device source.
/// Regular-file sources are not block devices and are not checked here.
pub fn ensure_destination_not_on_source(
    source_path: &str,
    output_dir: &Path,
) -> Result<(), String> {
    dfcore::sysfs::ensure_destination_not_on_source(source_path, output_dir)
        .map_err(|e| e.to_string())
}

/// Refuse a source listed in the dfnix boot-time registry of system disks and the
/// live medium. Outside dfnix there is no registry and nothing to check.
pub fn ensure_not_protected(source_path: &str) -> Result<(), String> {
    let registry = dfcore::protected::Registry::load(&dfcore::protected::path())
        .map_err(|e| format!("{e:#}"))?;
    let Some(registry) = registry else {
        return Ok(());
    };
    let flat = dfcore::lsblk::scan().map_err(|e| format!("{e:#}"))?;
    let canonical = std::fs::canonicalize(source_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| source_path.to_string());
    match registry.protecting(&flat, &canonical) {
        Some(p) => Err(format!(
            "ABORT: {} is protected by the dfnix registry ({:?} {}): {}",
            source_path,
            p.role,
            p.identity
                .serial
                .as_deref()
                .unwrap_or(&p.identity.kernel_name),
            p.reasons.join("; ")
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
