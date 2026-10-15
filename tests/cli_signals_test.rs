//! Signals against the running binary (§15): SIGINT/SIGTERM stop an
//! acquisition gracefully with an ABORTED report and exit 8, a second SIGINT
//! forces, SIGHUP keeps it running to its report. The long-running tool is a
//! fake `ddrescue` on PATH that copies half of the source, writes a real
//! ddrescue mapfile and then waits (for a release file, or a signal).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_dfdisk");
const SIZE: usize = 256 * 1024;

const FAKE_DDRESCUE: &str = r##"#!/bin/sh
# Fake GNU ddrescue for tests: ddrescue [options] infile outfile mapfile
case "$1" in --version|-V) echo "GNU ddrescue 1.28"; exit 0;; esac
src=; img=; map=
for a in "$@"; do src=$img; img=$map; map=$a; done
size=$(wc -c < "$src")
write_map() {
  {
    echo "# Mapfile. Created by GNU ddrescue version 1.28"
    echo "# current_pos  current_status  current_pass"
    if [ "$1" -ge "$size" ]; then
      printf '0x%08X     +               1\n' "$size"
    else
      printf '0x%08X     ?               1\n' "$1"
    fi
    echo "#      pos        size  status"
    printf '0x%08X  0x%08X  +\n' 0 "$1"
    if [ "$1" -lt "$size" ]; then printf '0x%08X  0x%08X  ?\n' "$1" $((size - $1)); fi
  } > "$map"
}
half=$((size / 2))
head -c "$half" "$src" > "$img"
write_map "$half"
if [ -n "$FAKE_DDRESCUE_IGNORE_INT" ]; then trap '' INT; else trap 'exit 130' INT; fi
trap 'exit 143' TERM
echo "pct rescued:   50.00%"
: > "$FAKE_DDRESCUE_STARTED"
while [ ! -e "$FAKE_DDRESCUE_RELEASE" ]; do sleep 0.1; done
cat "$src" > "$img"
write_map "$size"
echo "pct rescued:  100.00%"
exit 0
"##;

struct Run {
    _tmp: tempfile::TempDir,
    out: PathBuf,
    started: PathBuf,
    release: PathBuf,
    child: Child,
}

fn start(ignore_int: bool) -> Run {
    let tmp = tempfile::Builder::new()
        .prefix("dfdisk-cli-sig-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (tool, script) in [
        ("ddrescue", FAKE_DDRESCUE),
        ("lsblk", "#!/bin/sh\necho '{\"blockdevices\": []}'\n"),
        ("udevadm", "#!/bin/sh\nexit 1\n"),
        ("smartctl", "#!/bin/sh\necho '{}'\nexit 2\n"),
    ] {
        let p = bin.join(tool);
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let src = tmp.path().join("evidence.bin");
    std::fs::write(
        &src,
        (0..SIZE).map(|i| (i * 31 % 251) as u8).collect::<Vec<_>>(),
    )
    .unwrap();
    let out = tmp.path().join("out");
    let started = tmp.path().join("started");
    let release = tmp.path().join("release");
    let mut cmd = Command::new(BIN);
    cmd.env(
        "PATH",
        format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    )
    .env("DFNIX_AUDIT_LOG", tmp.path().join("audit.jsonl"))
    .env("DFNIX_PROTECTED_FILE", tmp.path().join("protected.json"))
    .env("FAKE_DDRESCUE_STARTED", &started)
    .env("FAKE_DDRESCUE_RELEASE", &release)
    .args([
        "acquire",
        &src.to_string_lossy(),
        "--rescue",
        "-o",
        &out.to_string_lossy(),
        "-C",
        "SIG-1",
        "-E",
        "E1",
        "--examiner",
        "Tester",
        "--allow-tmpfs",
        "--smart",
        "off",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    if ignore_int {
        cmd.env("FAKE_DDRESCUE_IGNORE_INT", "1");
    }
    let child = cmd.spawn().unwrap();
    Run {
        _tmp: tmp,
        out,
        started,
        release,
        child,
    }
}

fn wait_for(path: &Path, run: &mut Run) {
    let t0 = Instant::now();
    while !path.exists() {
        if let Some(status) = run.child.try_wait().unwrap() {
            let mut err = String::new();
            if let Some(mut e) = run.child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut e, &mut err);
            }
            panic!("dfdisk ended early ({status}): {err}");
        }
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "the fake ddrescue never started"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn signal(run: &Run, sig: libc::c_int) {
    // SAFETY: sending a signal to our own child process
    let rc = unsafe { libc::kill(run.child.id() as libc::pid_t, sig) };
    assert_eq!(rc, 0);
}

/// What a finished run left: exit code, stdout, stderr, output directory
/// (and the scratch directory, kept alive).
struct Finished {
    code: i32,
    stdout: String,
    stderr: String,
    out: PathBuf,
    _tmp: tempfile::TempDir,
}

/// Wait for the exit (at most 120 s; the pipes are drained meanwhile).
fn finish(run: Run) -> Finished {
    let Run {
        _tmp, out, child, ..
    } = run;
    let pid = child.id();
    let waiter = std::thread::spawn(move || child.wait_with_output().unwrap());
    let t0 = Instant::now();
    while !waiter.is_finished() {
        if t0.elapsed() > Duration::from_secs(120) {
            // SAFETY: killing our own child process
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            panic!("dfdisk did not end after the signal");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = waiter.join().unwrap();
    Finished {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        out,
        _tmp,
    }
}

fn report(out: &Path) -> serde_json::Value {
    let json = std::fs::read_dir(out)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(".info.json"))
        .expect("a report");
    serde_json::from_str(&std::fs::read_to_string(json).unwrap()).unwrap()
}

#[test]
fn sigint_aborts_gracefully_with_a_report_and_exit_8() {
    let mut run = start(false);
    let started = run.started.clone();
    wait_for(&started, &mut run);
    signal(&run, libc::SIGINT);
    let f = finish(run);
    assert_eq!(f.code, 8, "{}\n{}", f.stdout, f.stderr);
    assert!(
        f.stderr.contains("SIGINT: stopping the acquisition"),
        "{}",
        f.stderr
    );
    assert!(f.stdout.contains("ABORTED (exit code 8)"), "{}", f.stdout);
    let r = report(&f.out);
    assert_eq!(r["outcome"], "aborted");
    assert_eq!(r["exit_code"], 8);
    // The partial outputs are kept
    let kept: Vec<_> = std::fs::read_dir(&f.out)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(kept.iter().any(|n| n.ends_with(".raw")), "{kept:?}");
    assert!(kept.iter().any(|n| n.ends_with(".map")), "{kept:?}");
}

#[test]
fn sigterm_aborts_gracefully() {
    let mut run = start(false);
    let started = run.started.clone();
    wait_for(&started, &mut run);
    signal(&run, libc::SIGTERM);
    let f = finish(run);
    assert_eq!(f.code, 8, "{}\n{}", f.stdout, f.stderr);
    assert!(f.stderr.contains("SIGTERM"), "{}", f.stderr);
    assert_eq!(report(&f.out)["outcome"], "aborted");
}

#[test]
fn a_second_sigint_kills_a_tool_that_ignores_the_first() {
    let mut run = start(true);
    let started = run.started.clone();
    wait_for(&started, &mut run);
    signal(&run, libc::SIGINT);
    std::thread::sleep(Duration::from_millis(500));
    // An engine that stops its tool at the first SIGINT may already be done
    let second = run.child.try_wait().unwrap().is_none();
    if second {
        signal(&run, libc::SIGINT);
    }
    let f = finish(run);
    assert_eq!(f.code, 8, "{}\n{}", f.stdout, f.stderr);
    if second && f.stderr.contains("SIGINT: killing") {
        // The second SIGINT reached a running acquisition: forced, still reported
        assert!(f.stdout.contains("ABORTED (exit code 8)"), "{}", f.stdout);
    }
    assert_eq!(report(&f.out)["outcome"], "aborted");
}

#[test]
fn sighup_keeps_the_acquisition_running_to_its_report() {
    let mut run = start(false);
    let started = run.started.clone();
    wait_for(&started, &mut run);
    signal(&run, libc::SIGHUP);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        run.child.try_wait().unwrap().is_none(),
        "SIGHUP must not end the acquisition"
    );
    std::fs::write(&run.release, b"").unwrap();
    let f = finish(run);
    let r = report(&f.out);
    assert_ne!(r["outcome"], "aborted", "{}\n{}", f.stdout, f.stderr);
    assert_ne!(f.code, 8, "{}", f.stderr);
    assert_eq!(r["exit_code"], f.code, "the exit code is the report's");
    // Piped (not a terminal): output still arrives after SIGHUP
    assert!(f.stdout.contains("(exit code"), "{}", f.stdout);
}
