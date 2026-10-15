//! Test support for tool-dependent tests (E01 engine, `dfdisk verify`).
//!
//! - [`tool_available`]: a tool-dependent test runs when the tool exists and
//!   FAILS (instead of skipping) when it is missing and
//!   `DFDISK_REQUIRE_TOOLS=1` (package.nix checkPhase).
//! - [`fakedev`]: compiles `tests/support/fakedev.c` (an LD_PRELOAD shim that
//!   makes ewfacquire see an image file as a block device whose reads fail
//!   with EIO where a test says so) and puts an `ewfacquire` wrapper first on
//!   this test binary's PATH. The wrapper applies the shim only to sources
//!   that have a `<source>.fakedev` settings file next to them (shell
//!   `KEY=value` lines, see fakedev.c), so every other ewfacquire run is the
//!   real tool, unchanged.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// `DFDISK_REQUIRE_TOOLS=1`: missing tools fail the test.
pub fn tools_required() -> bool {
    std::env::var("DFDISK_REQUIRE_TOOLS").is_ok_and(|v| v == "1")
}

/// Whether `program` can be run (`args`, e.g. `-V`).
pub fn runs(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
}

/// `true` when every tool runs; otherwise skip (print why), or panic when
/// tools are required.
pub fn tool_available(tools: &[&str]) -> bool {
    let missing: Vec<&str> = tools
        .iter()
        .copied()
        .filter(|t| !runs(t, &["-V"]))
        .collect();
    if missing.is_empty() {
        return true;
    }
    if tools_required() {
        panic!(
            "DFDISK_REQUIRE_TOOLS=1 but these tools are missing: {}",
            missing.join(", ")
        );
    }
    eprintln!("skipping: {} not installed", missing.join(", "));
    false
}

/// Full path of `program` on PATH.
pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(program))
        .find(|p| {
            use std::os::unix::fs::PermissionsExt;
            p.metadata()
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// The compiled shim and the wrapper directory first on PATH.
#[derive(Debug)]
pub struct FakeDev {
    pub library: PathBuf,
    pub bin_dir: PathBuf,
    pub real_ewfacquire: PathBuf,
}

impl FakeDev {
    /// Make `source` a fake device with these shim settings, e.g.
    /// `[("FAKEDEV_BAD", "1048576:512")]`. Extra keys the wrapper knows:
    /// `FAKEDEV_VANISH_AFTER=1` renames the source to `<source>.vanished`
    /// after ewfacquire exited.
    pub fn configure(&self, source: &Path, settings: &[(&str, &str)]) {
        let mut text = String::new();
        for (k, v) in settings {
            text.push_str(&format!("{k}='{v}'\n"));
        }
        std::fs::write(sidecar(source), text).unwrap();
    }
}

/// `<source>.fakedev`
pub fn sidecar(source: &Path) -> PathBuf {
    let mut s = source.as_os_str().to_os_string();
    s.push(".fakedev");
    PathBuf::from(s)
}

/// The shim, built once per test binary; `None` (skip) when libewf or a C
/// compiler is missing, a panic when tools are required.
pub fn fakedev() -> Option<&'static FakeDev> {
    static FAKE: OnceLock<Option<FakeDev>> = OnceLock::new();
    FAKE.get_or_init(build).as_ref()
}

fn build() -> Option<FakeDev> {
    if !tool_available(&["ewfacquire", "ewfinfo", "ewfverify"]) {
        return None;
    }
    let Some(cc) = which("cc")
        .or_else(|| which("gcc"))
        .or_else(|| which("clang"))
    else {
        if tools_required() {
            panic!(
                "DFDISK_REQUIRE_TOOLS=1 but no C compiler (cc) is available for the fakedev shim"
            );
        }
        eprintln!("skipping: no C compiler for the fakedev shim");
        return None;
    };
    let real_ewfacquire = which("ewfacquire")?;
    let dir = tempfile::Builder::new()
        .prefix("dfdisk-fakedev-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
        .keep();
    let library = dir.join("fakedev.so");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fakedev.c");
    let out = Command::new(&cc)
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&library)
        .arg(&source)
        .arg("-ldl")
        .output()
        .expect("run the C compiler");
    assert!(
        out.status.success(),
        "compiling the fakedev shim failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bin_dir = dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let wrapper = bin_dir.join("ewfacquire");
    std::fs::write(
        &wrapper,
        format!(
            r#"#!/bin/sh
# dfdisk test wrapper: the real ewfacquire, with the fakedev shim for sources
# that have a "<source>.fakedev" settings file
for last; do :; done
if [ -n "$last" ] && [ -f "$last.fakedev" ]; then
    set -a
    . "$last.fakedev"
    set +a
    export FAKEDEV_TARGET="$last" FAKEDEV_PROG=ewfacquire LD_PRELOAD='{lib}'
    if [ -z "$FAKEDEV_VANISH_AFTER" ]; then
        exec '{real}' "$@"
    fi
    '{real}' "$@"
    status=$?
    mv "$last" "$last.vanished"
    exit $status
fi
exec '{real}' "$@"
"#,
            lib = library.display(),
            real = real_ewfacquire.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let joined =
        std::env::join_paths(std::iter::once(bin_dir.clone()).chain(std::env::split_paths(&path)))
            .unwrap();
    // Once per test binary, before any test of it runs a tool (every test
    // that needs the shim calls fakedev() first)
    std::env::set_var("PATH", joined);
    Some(FakeDev {
        library,
        bin_dir,
        real_ewfacquire,
    })
}
