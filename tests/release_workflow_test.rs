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

fn ci_workflow() -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml");
    std::fs::read_to_string(&path).ok()
}

/// The lines of job `id` (two spaces of indent under `jobs:`), up to the next job.
fn job<'a>(workflow: &'a str, id: &str) -> Vec<&'a str> {
    let lines: Vec<&str> = workflow.lines().collect();
    let start = lines
        .iter()
        .position(|l| *l == format!("  {id}:"))
        .unwrap_or_else(|| panic!("no job {id:?}"));
    let end = (start + 1..lines.len())
        .find(|&i| {
            let l = lines[i];
            l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':')
        })
        .unwrap_or(lines.len());
    lines[start..end].to_vec()
}

/// Nothing runs on the hosted Ubuntu 22.04 image any more; what needs that
/// distribution (its ewf-tools and gddrescue for the tests, its glibc for the
/// native binary and the .deb) runs in an ubuntu:22.04 container, and the
/// cross builds run outside one.
#[test]
fn jobs_that_need_ubuntu_22_04_run_in_its_container() {
    let (Some(release), Some(ci)) = (workflow(), ci_workflow()) else {
        return;
    };
    for (name, wf) in [("release.yml", &release), ("ci.yml", &ci)] {
        for line in wf.lines() {
            let l = line.trim();
            assert!(
                !(l.starts_with("runs-on:") && l.contains("22.04")),
                "{name}: {l}"
            );
        }
    }
    for (name, wf, id) in [
        ("ci.yml", &ci, "test"),
        ("release.yml", &release, "test"),
        ("release.yml", &release, "build-deb"),
    ] {
        let lines = job(wf, id);
        assert!(
            lines.iter().any(|l| l.trim() == "container: ubuntu:22.04"),
            "{name} {id}: {lines:#?}"
        );
    }
    // The tests run as an unprivileged user in both workflows
    for (name, wf) in [("ci.yml", &ci), ("release.yml", &release)] {
        let lines = job(wf, "test");
        assert!(
            lines
                .iter()
                .any(|l| l.trim() == "shell: runuser -u ci -- bash -e {0}"),
            "{name} test: {lines:#?}"
        );
    }
    // The matrix: a container for the native target only
    let lines = job(&release, "build-binaries");
    let entries: Vec<(String, String)> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim().starts_with("- target: "))
        .map(|(i, l)| {
            let target = l.trim().trim_start_matches("- target: ").to_string();
            let container = lines[i + 1..]
                .iter()
                .take_while(|l| !l.trim().starts_with("- "))
                .find_map(|l| l.trim().strip_prefix("container: "))
                .unwrap_or_else(|| panic!("{target} names no container"))
                .to_string();
            (target, container)
        })
        .collect();
    assert_eq!(
        entries,
        [
            (
                "x86_64-unknown-linux-gnu".to_string(),
                "ubuntu:22.04".to_string()
            ),
            ("x86_64-unknown-linux-musl".to_string(), "''".to_string()),
            ("aarch64-unknown-linux-gnu".to_string(), "''".to_string()),
        ]
    );
}

/// git must be installed before the checkout in every container job: without
/// it the checkout has no .git and the binary's revisions are "unknown".
#[test]
fn container_jobs_install_git_before_the_checkout() {
    let (Some(release), Some(ci)) = (workflow(), ci_workflow()) else {
        return;
    };
    for (name, wf, id) in [
        ("ci.yml", &ci, "test"),
        ("release.yml", &release, "test"),
        ("release.yml", &release, "build-binaries"),
        ("release.yml", &release, "build-deb"),
    ] {
        let lines = job(wf, id);
        let checkout = lines
            .iter()
            .position(|l| l.trim().starts_with("uses: actions/checkout@"))
            .unwrap_or_else(|| panic!("{name} {id}: no checkout"));
        let installs_git = lines[..checkout].iter().any(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            words.contains(&"git") && words.contains(&"ca-certificates")
        });
        assert!(
            installs_git,
            "{name} {id}: git is not installed before the checkout"
        );
    }
}

#[test]
fn a_release_binary_must_name_its_commit_and_the_locked_dfcore() {
    let Some(wf) = workflow() else {
        return;
    };
    if Command::new("jq").arg("--version").output().is_err() {
        eprintln!("skipping: jq is not installed");
        return;
    }
    let name = "The binary names the commit it was built from and the locked dfcore";
    assert_eq!(
        wf.matches(&format!("- name: {name}")).count(),
        2,
        "the tarballs' binaries and the .deb's binary are both checked"
    );
    let script = step_script(&wf, name);
    let commit = "abcdef0123456789abcdef0123456789abcdef01";
    let dfcore = "2222222222222222222222222222222222222222";
    let run = |binary: &str, sha: &str| {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("flake.lock"),
            format!(r#"{{"nodes":{{"dfcore":{{"locked":{{"rev":"{dfcore}"}}}}}}}}"#),
        )
        .unwrap();
        std::fs::write(dir.path().join("dfdisk"), binary).unwrap();
        bash(
            &script,
            dir.path(),
            &[("GITHUB_SHA", sha), ("BINARY", "dfdisk")],
            None,
        )
    };
    let good = format!("\0ELF\0dfdisk git revision: {commit}\0dfcore {dfcore}\0");
    let r = run(&good, commit);
    assert!(r.ok, "{}{}", r.stdout, r.stderr);

    for (what, binary, expected) in [
        (
            "no dfdisk revision",
            format!("\0unknown\0{dfcore}\0"),
            "does not contain the revision abcdef",
        ),
        (
            "no dfcore revision",
            format!("\0{commit}\0unknown\0"),
            "does not contain the revision 2222",
        ),
        (
            "another commit",
            format!("\0{}\0{dfcore}\0", commit.replace('a', "b")),
            "does not contain the revision abcdef",
        ),
        (
            "modified dfdisk checkout",
            format!("\0{commit}-dirty\0{dfcore}\0"),
            "modified checkout of abcdef",
        ),
        (
            "modified dfcore checkout",
            format!("\0{commit}\0{dfcore}-dirty\0"),
            "modified checkout of 2222",
        ),
    ] {
        let r = run(&binary, commit);
        assert!(!r.ok, "{what} must fail: {}", r.stdout);
        assert!(r.stdout.contains(expected), "{what}: {}", r.stdout);
    }
    // No commit to compare with: an empty needle would match anything
    let r = run(&good, "");
    assert!(
        !r.ok && r.stdout.contains("is not a commit"),
        "{}",
        r.stdout
    );
}

/// The release builds run as root in a workspace owned by the runner's user.
/// The checkout action marks it safe for its own git calls only, so each
/// build marks it safe before cargo runs build.rs (a dry run of 0.2.2 built
/// binaries with an "unknown" revision without this).
#[test]
fn root_builds_mark_the_checkout_safe_for_git() {
    let Some(wf) = workflow() else {
        return;
    };
    for id in ["build-binaries", "build-deb"] {
        let lines = job(&wf, id);
        let at = |needle: &str| {
            lines
                .iter()
                .position(|l| l.trim().starts_with(needle))
                .unwrap_or_else(|| panic!("{id}: no line starting with {needle:?}"))
        };
        let checkout = at("uses: actions/checkout@");
        let safe = at("run: git config --global --add safe.directory \"$GITHUB_WORKSPACE\"");
        let build = at("- name: Build ");
        assert!(
            checkout < safe && safe < build,
            "{id}: {checkout} {safe} {build}"
        );
    }
}
