//! Steps of the release workflow (`.github/workflows/release.yml`) run with
//! bash against fixture files: the version check and the NUR recipe update.
//! Nothing is fetched or pushed (git and curl are stand-ins where a step
//! would reach a remote). The workflow is not part of every source tree (the
//! Nix build copies only the crate): without it these tests have nothing to
//! check and say so.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workflow() -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml");
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) => {
            eprintln!(
                "skipping: {} is not in this source tree ({e})",
                path.display()
            );
            None
        }
    }
}

/// The `run: |` script of the step named `name`, dedented.
fn step_script(workflow: &str, name: &str) -> String {
    let lines: Vec<&str> = workflow.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim() == format!("- name: {name}"))
        .unwrap_or_else(|| panic!("no step named {name:?}"));
    let run = (start + 1..lines.len())
        .find(|&i| lines[i].trim() == "run: |")
        .unwrap_or_else(|| panic!("step {name:?} has no run block"));
    let key_indent = lines[run].len() - lines[run].trim_start().len();
    let mut body = Vec::new();
    for l in &lines[run + 1..] {
        let indent = l.len() - l.trim_start().len();
        if !l.trim().is_empty() && indent <= key_indent {
            break;
        }
        body.push(*l);
    }
    let strip = body
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    body.iter()
        .map(|l| if l.len() >= strip { &l[strip..] } else { "" })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Replace `${{ expr }}` expressions with test values.
fn substitute(script: &str, values: &[(&str, &str)]) -> String {
    let mut out = script.to_string();
    for (expr, value) in values {
        out = out.replace(&format!("${{{{ {expr} }}}}"), value);
    }
    assert!(
        !out.contains("${{"),
        "unsubstituted expression left in:\n{out}"
    );
    out
}

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
    output_file: String,
}

fn bash(script: &str, dir: &Path, env: &[(&str, &str)], path_prefix: Option<&Path>) -> Run {
    let output = dir.join("github_output");
    std::fs::write(&output, "").unwrap();
    let mut cmd = Command::new("bash");
    cmd.arg("-e")
        .arg("-c")
        .arg(script)
        .current_dir(dir)
        .env("GITHUB_OUTPUT", &output);
    if let Some(prefix) = path_prefix {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let joined = std::env::join_paths(
            std::iter::once(prefix.to_path_buf()).chain(std::env::split_paths(&path)),
        )
        .unwrap();
        cmd.env("PATH", joined);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run bash");
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        output_file: std::fs::read_to_string(&output).unwrap_or_default(),
    }
}

fn version_fixture(dir: &Path, changelog_heading: &str) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"dfdisk\"\nversion = \"0.2.0\"\n\n[dependencies]\nfoo = { version = \"1.0\" }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        "[[package]]\nname = \"dfcore\"\nversion = \"0.2.0\"\n\n[[package]]\nname = \"dfdisk\"\nversion = \"0.2.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("package.nix"),
        "{ lib }:\nrustPlatform.buildRustPackage {\n  pname = \"dfdisk\";\n  version = \"0.2.0\";\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("CHANGELOG.md"),
        format!("# Changelog\n\n{changelog_heading}\n\n### Added\n\n- things\n\n## [0.1.10] - 2026-10-11\n"),
    )
    .unwrap();
}

#[test]
fn the_version_check_requires_a_dated_changelog_section() {
    let Some(wf) = workflow() else {
        return;
    };
    let script = step_script(
        &wf,
        "Tag, Cargo.toml, Cargo.lock, package.nix and CHANGELOG.md agree",
    );
    let env = [("GITHUB_REF_TYPE", "branch"), ("GITHUB_REF_NAME", "main")];
    for (heading, accepted) in [
        ("## [0.2.0] - 2026-10-20", true),
        ("## [0.2.0] - Unreleased", false),
        ("## [0.2.0]", false),
        ("## [0.2.0] - soon", false),
        // The version's dots are not wildcards
        ("## [0x2y0] - 2026-10-20", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        version_fixture(dir.path(), heading);
        let r = bash(&script, dir.path(), &env, None);
        assert_eq!(
            r.ok, accepted,
            "{heading:?}: stdout {}\nstderr {}",
            r.stdout, r.stderr
        );
        if accepted {
            assert!(r.output_file.contains("version=0.2.0"), "{}", r.output_file);
        } else {
            assert!(
                r.stdout.contains("dated section"),
                "{heading:?}: {}",
                r.stdout
            );
        }
    }

    // A tag must name the same version
    let dir = tempfile::tempdir().unwrap();
    version_fixture(dir.path(), "## [0.2.0] - 2026-10-20");
    let r = bash(
        &script,
        dir.path(),
        &[("GITHUB_REF_TYPE", "tag"), ("GITHUB_REF_NAME", "v0.2.1")],
        None,
    );
    assert!(!r.ok && r.stdout.contains("does not match"), "{}", r.stdout);
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn have_git() -> bool {
    let ok = Command::new("git").arg("--version").output().is_ok();
    if !ok {
        eprintln!("skipping: git is not installed");
    }
    ok
}

#[test]
fn the_tag_commit_is_resolved_through_an_annotated_tag() {
    let Some(wf) = workflow() else {
        return;
    };
    if !have_git() {
        return;
    }
    let script = step_script(&wf, "Commit of the tag");
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    std::fs::write(dir.path().join("a"), "a").unwrap();
    git(dir.path(), &["add", "a"]);
    git(dir.path(), &["commit", "-q", "-m", "release"]);
    let commit = git(dir.path(), &["rev-parse", "HEAD"]);
    git(dir.path(), &["tag", "-a", "v0.2.0", "-m", "dfdisk 0.2.0"]);
    let tag_object = git(dir.path(), &["rev-parse", "v0.2.0"]);
    assert_ne!(
        tag_object, commit,
        "an annotated tag is an object of its own"
    );

    let r = bash(&script, dir.path(), &[("GITHUB_REF_NAME", "v0.2.0")], None);
    assert!(r.ok, "{}{}", r.stdout, r.stderr);
    assert_eq!(r.output_file.trim(), format!("dfdisk_rev={commit}"));

    let r = bash(&script, dir.path(), &[("GITHUB_REF_NAME", "v9.9.9")], None);
    assert!(!r.ok, "an unknown tag fails: {}", r.output_file);
    assert!(r.output_file.is_empty());
}

/// The NUR recipe as it is maintained (abridged): DFDISK_GIT_REV still from
/// the fetched source, which is fetched by tag.
const RECIPE: &str = r#"{ lib, rustPlatform, fetchFromGitHub }:
let
  version = "0.1.10";
  dfdiskSrc = fetchFromGitHub {
    owner = "tylerstyle";
    repo = "dfdisk";
    tag = "v${version}";
    hash = "sha256-OLDDFDISKHASH000000000000000000000000000000=";
  };
  dfcoreSrc = fetchFromGitHub {
    owner = "tylerstyle";
    repo = "dfcore";
    rev = "1111111111111111111111111111111111111111";
    hash = "sha256-OLDDFCOREHASH000000000000000000000000000000=";
  };
in
rustPlatform.buildRustPackage {
  pname = "dfdisk";
  inherit version;
  cargoHash = "sha256-OLDCARGOHASH0000000000000000000000000000000=";
  env = {
    DFDISK_GIT_REV = dfdiskSrc.rev;
    DFCORE_GIT_REV = dfcoreSrc.rev;
  };
  # libewf ddrescue smartmontools util-linux systemd hdparm nvme-cli
}
"#;

#[test]
fn the_nur_update_rewrites_the_embedded_dfdisk_revision() {
    let Some(wf) = workflow() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    // The recipe repository the stand-in git "clones"
    let upstream = dir.path().join("upstream");
    std::fs::create_dir_all(upstream.join("pkgs/dfdisk")).unwrap();
    std::fs::write(upstream.join("pkgs/dfdisk/default.nix"), RECIPE).unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let calls = dir.path().join("calls");
    let fake_git = format!(
        r#"#!/bin/sh
echo "git $*" >> '{calls}'
case "$1" in
  clone) cp -r '{upstream}' "$3" ;;
  diff) exit 1 ;;
esac
exit 0
"#,
        calls = calls.display(),
        upstream = upstream.display()
    );
    let fake_curl = format!(
        "#!/bin/sh\necho \"curl $*\" >> '{}'\nexit 0\n",
        calls.display()
    );
    for (name, text) in [("git", fake_git), ("curl", fake_curl)] {
        let p = bin.join(name);
        std::fs::write(&p, text).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();

    let dfdisk_rev = "abcdef0123456789abcdef0123456789abcdef01";
    let dfcore_rev = "2222222222222222222222222222222222222222";
    let script = substitute(
        &step_script(&wf, "Update NUR derivation and push"),
        &[
            ("steps.hashes.outputs.version", "0.2.0"),
            (
                "steps.hashes.outputs.src_hash",
                "sha256-NEWDFDISKHASH000000000000000000000000000000=",
            ),
            (
                "steps.hashes.outputs.cargo_hash",
                "sha256-NEWCARGOHASH0000000000000000000000000000000=",
            ),
            ("steps.hashes.outputs.dfcore_rev", dfcore_rev),
            (
                "steps.hashes.outputs.dfcore_hash",
                "sha256-NEWDFCOREHASH000000000000000000000000000000=",
            ),
            ("steps.tagrev.outputs.dfdisk_rev", dfdisk_rev),
        ],
    );
    let r = bash(
        &script,
        &work,
        &[("NUR_UPDATE_TOKEN", "test-token")],
        Some(&bin),
    );
    assert!(r.ok, "{}{}", r.stdout, r.stderr);
    let recipe: PathBuf = work.join("nur-packages/pkgs/dfdisk/default.nix");
    let updated = std::fs::read_to_string(&recipe).unwrap();
    assert!(
        updated.contains(&format!("DFDISK_GIT_REV = \"{dfdisk_rev}\";")),
        "{updated}"
    );
    assert!(
        updated.contains("DFCORE_GIT_REV = dfcoreSrc.rev;"),
        "{updated}"
    );
    assert!(
        updated.contains(&format!("rev = \"{dfcore_rev}\";")),
        "{updated}"
    );
    assert!(updated.contains("version = \"0.2.0\";"), "{updated}");
    assert!(updated.contains("NEWDFDISKHASH") && updated.contains("NEWDFCOREHASH"));
    assert!(updated.contains("NEWCARGOHASH"), "{updated}");
    let calls = std::fs::read_to_string(&calls).unwrap();
    assert!(calls.contains("git push origin main"), "{calls}");
}
