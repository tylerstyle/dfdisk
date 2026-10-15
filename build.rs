//! Embeds the source revisions of dfdisk and dfcore (D17): DFDISK_GIT_REV,
//! DFCORE_GIT_REV and DFCORE_VERSION. Values set in the environment (Nix, CI)
//! win; otherwise `git rev-parse HEAD` runs in this crate and in ../dfcore,
//! with "-dirty" appended when a tracked file differs from that commit (the
//! build is then not of the commit alone); otherwise "unknown".

use std::path::{Path, PathBuf};
use std::process::Command;

/// Output of `git -C dir <args>`, trimmed; `None` when git fails.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

/// HEAD of the repository whose top level is `dir` (never of an enclosing
/// one), plus "-dirty" when a tracked file differs from HEAD (staged or not)
/// or that state cannot be read. Untracked files do not count.
pub fn git_rev(dir: &Path) -> Option<String> {
    if !dir.join(".git").exists() {
        return None;
    }
    let rev = git(dir, &["rev-parse", "HEAD"])?;
    if rev.is_empty() || !rev.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let clean =
        git(dir, &["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| s.is_empty());
    Some(if clean { rev } else { format!("{rev}-dirty") })
}

/// The git directory of the repository at `dir` (`.git`, or the directory a
/// worktree's `.git` file names) and its common directory (refs).
fn git_dirs(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    if !dir.join(".git").exists() {
        return None;
    }
    let abs = |p: String| {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            p
        } else {
            dir.join(p)
        }
    };
    let git_dir = abs(git(dir, &["rev-parse", "--git-dir"])?);
    let common = abs(git(dir, &["rev-parse", "--git-common-dir"])?);
    Some((git_dir, common))
}

/// Re-run when the checked-out commit of the repository at `dir` changes, or
/// when what makes it dirty may have changed: the index (staging, commits,
/// checkouts) and the sources in `sources` (relative to `dir`; a directory is
/// scanned as a whole).
fn watch_git(dir: &Path, sources: &[&str]) {
    let Some((git_dir, common)) = git_dirs(dir) else {
        return;
    };
    let head = git_dir.join("HEAD");
    if head.is_file() {
        println!("cargo:rerun-if-changed={}", head.display());
        if let Ok(content) = std::fs::read_to_string(&head) {
            if let Some(reference) = content.trim().strip_prefix("ref: ") {
                for base in [&git_dir, &common] {
                    let r = base.join(reference);
                    if r.exists() {
                        println!("cargo:rerun-if-changed={}", r.display());
                    }
                }
            }
        }
    }
    for f in [git_dir.join("index"), common.join("packed-refs")] {
        if f.exists() {
            println!("cargo:rerun-if-changed={}", f.display());
        }
    }
    for s in sources {
        let p = dir.join(s);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
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

/// What the binary is built from: a change there may change the dirty state.
const DFDISK_SOURCES: &[&str] = &["src", "Cargo.toml", "Cargo.lock", "build.rs"];
const DFCORE_SOURCES: &[&str] = &["src", "Cargo.toml"];

fn main() {
    let crate_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let dfcore_dir = crate_dir.join("../dfcore");

    let dfcore_manifest = dfcore_dir.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", dfcore_manifest.display());

    let dfdisk_rev = from_env("DFDISK_GIT_REV")
        .or_else(|| {
            watch_git(&crate_dir, DFDISK_SOURCES);
            git_rev(&crate_dir)
        })
        .unwrap_or_else(|| "unknown".into());
    let dfcore_rev = from_env("DFCORE_GIT_REV")
        .or_else(|| {
            watch_git(&dfcore_dir, DFCORE_SOURCES);
            git_rev(&dfcore_dir)
        })
        .unwrap_or_else(|| "unknown".into());
    let dfcore_version = from_env("DFCORE_VERSION")
        .or_else(|| package_version(&dfcore_manifest))
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=DFDISK_GIT_REV={dfdisk_rev}");
    println!("cargo:rustc-env=DFCORE_GIT_REV={dfcore_rev}");
    println!("cargo:rustc-env=DFCORE_VERSION={dfcore_version}");
}
