//! The revision build.rs embeds (`dfdisk --version`, every report): HEAD, and
//! "-dirty" when a tracked file differs from it. build.rs is compiled into
//! this test as a module and run against temporary repositories. git is not a
//! tool dfdisk runs; without it (the Nix build sandbox) there is nothing to
//! check.

#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use std::path::Path;
use std::process::Command;

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

#[test]
fn a_modified_tracked_file_marks_the_revision_dirty() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git is not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    assert_eq!(build_script::git_rev(repo), None, "not a repository");

    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/main.rs"), "fn main() {}\n").unwrap();
    git(repo, &["add", "src/main.rs"]);
    git(repo, &["commit", "-q", "-m", "one"]);
    let head = git(repo, &["rev-parse", "HEAD"]);

    assert_eq!(build_script::git_rev(repo).as_deref(), Some(head.as_str()));

    // Untracked files are not part of the build's sources
    std::fs::write(repo.join("notes.txt"), "scratch").unwrap();
    assert_eq!(build_script::git_rev(repo).as_deref(), Some(head.as_str()));

    // A modified tracked file: the build is not of HEAD alone
    std::fs::write(repo.join("src/main.rs"), "fn main() { todo!() }\n").unwrap();
    let dirty = format!("{head}-dirty");
    assert_eq!(build_script::git_rev(repo).as_deref(), Some(dirty.as_str()));

    // Staged but not committed: still dirty
    git(repo, &["add", "src/main.rs"]);
    assert_eq!(build_script::git_rev(repo).as_deref(), Some(dirty.as_str()));

    // Committed: clean again, at the new HEAD
    git(repo, &["commit", "-q", "-m", "two"]);
    let head2 = git(repo, &["rev-parse", "HEAD"]);
    assert_ne!(head2, head);
    assert_eq!(build_script::git_rev(repo).as_deref(), Some(head2.as_str()));

    // A deleted tracked file is a difference too
    std::fs::remove_file(repo.join("src/main.rs")).unwrap();
    assert_eq!(build_script::git_rev(repo), Some(format!("{head2}-dirty")));
}
