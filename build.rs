//! Embeds the source revisions of dfdisk and dfcore (D17): DFDISK_GIT_REV,
//! DFCORE_GIT_REV and DFCORE_VERSION. Values set in the environment (Nix, CI)
//! win; otherwise `git rev-parse HEAD` runs in this crate and in ../dfcore;
//! otherwise "unknown".

use std::path::Path;
use std::process::Command;

/// HEAD of the repository whose top level is `dir` (never of an enclosing one).
fn git_rev(dir: &Path) -> Option<String> {
    if !dir.join(".git").exists() {
        return None;
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let rev = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!rev.is_empty() && rev.bytes().all(|b| b.is_ascii_hexdigit())).then_some(rev)
}

/// Re-run when the checked-out commit of the repository at `dir` changes.
fn watch_git_head(dir: &Path) {
    let git = dir.join(".git");
    let head = git.join("HEAD");
    if !head.is_file() {
        return;
    }
    println!("cargo:rerun-if-changed={}", head.display());
    if let Ok(content) = std::fs::read_to_string(&head) {
        if let Some(reference) = content.trim().strip_prefix("ref: ") {
            let r = git.join(reference);
            if r.exists() {
                println!("cargo:rerun-if-changed={}", r.display());
            }
        }
    }
    let packed = git.join("packed-refs");
    if packed.exists() {
        println!("cargo:rerun-if-changed={}", packed.display());
    }
}

fn from_env(name: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// `version = "..."` of the [package] in a Cargo.toml.
fn package_version(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).ok()?;
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = line.strip_prefix("version") {
                let value = rest.trim_start().strip_prefix('=')?.trim();
                return Some(value.trim_matches('"').to_string());
            }
        }
    }
    None
}

fn main() {
    let crate_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let dfcore_dir = crate_dir.join("../dfcore");

    watch_git_head(&crate_dir);
    watch_git_head(&dfcore_dir);
    let dfcore_manifest = dfcore_dir.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", dfcore_manifest.display());

    let dfdisk_rev = from_env("DFDISK_GIT_REV")
        .or_else(|| git_rev(&crate_dir))
        .unwrap_or_else(|| "unknown".into());
    let dfcore_rev = from_env("DFCORE_GIT_REV")
        .or_else(|| git_rev(&dfcore_dir))
        .unwrap_or_else(|| "unknown".into());
    let dfcore_version = from_env("DFCORE_VERSION")
        .or_else(|| package_version(&dfcore_manifest))
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=DFDISK_GIT_REV={dfdisk_rev}");
    println!("cargo:rustc-env=DFCORE_GIT_REV={dfcore_rev}");
    println!("cargo:rustc-env=DFCORE_VERSION={dfcore_version}");
}
