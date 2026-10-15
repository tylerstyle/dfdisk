//! How discovery runs external identify-class tools (`hdparm`, `nvme`,
//! `smartctl`): through [`ToolRunner`], so the host goes through
//! `engines::process` (LC_ALL=C, own process group, timeout, abort, every
//! command recorded) and tests replay captured real tool output
//! ([`ScriptedRunner`]) without touching a device.

use crate::discovery::sysfs::SysRoot;
use crate::engines::process::{run_collect, ProcessSpec, StopControl};
use crate::models::identity::{SourceIdentity, SourceKind};
use crate::models::provenance::ProvenanceRecorder;
use dfcore::sysfs::DevNum;
use futures::future::BoxFuture;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// Device number of a device node path (`stat` st_rdev; nothing is opened).
pub type NodeDev<'a> = dyn Fn(&Path) -> Option<DevNum> + Send + Sync + 'a;

/// What capacity and SMART probes need from the host: sysfs (to find the
/// physical disk), the device directory and node check, and a tool runner.
pub struct ProbeEnv<'a> {
    pub sys: SysRoot,
    /// Normally `/dev`
    pub dev_dir: PathBuf,
    pub node_dev: &'a NodeDev<'a>,
    pub runner: &'a dyn ToolRunner,
}

fn host_node_dev(path: &Path) -> Option<DevNum> {
    dfcore::sysfs::dev_num_of_path(path)
}

impl ProbeEnv<'static> {
    /// /sys, /dev and `engines::process`.
    pub fn host() -> Self {
        ProbeEnv {
            sys: SysRoot::host(),
            dev_dir: PathBuf::from("/dev"),
            node_dev: &host_node_dev,
            runner: &HostRunner,
        }
    }
}

/// The physical disk an identify-class query goes to (R6): the disk itself,
/// or the single disk a partition, dm or md source is stored on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalDisk {
    /// Kernel name, e.g. "sdb", "nvme0n1"
    pub kname: String,
    /// Device node, e.g. "/dev/sdb"
    pub path: String,
    /// Transport of the disk as probed (usb, sata, nvme, ...)
    pub transport: Option<String>,
    /// The source is this disk itself (not a partition or mapping on it)
    pub is_source: bool,
}

impl PhysicalDisk {
    /// Statement for reports when the source is not the disk itself (R6).
    pub fn r6_statement(&self, identity: &SourceIdentity) -> Option<String> {
        (!self.is_source).then(|| {
            format!(
                "the values describe the physical disk {} that holds the source {}",
                self.path, identity.path
            )
        })
    }
}

/// Resolve the physical disk of `identity` in `env` and check that its device
/// node is the device sysfs names (so a query never reaches a different disk
/// that took over the node). `Err` says why no disk applies or why the node
/// is not trusted; nothing was sent to any device.
pub fn physical_disk(
    env: &ProbeEnv<'_>,
    identity: &SourceIdentity,
) -> Result<PhysicalDisk, String> {
    let kname = match &identity.kind {
        SourceKind::RegularFile => {
            return Err("the source is a regular file, not a disk".into());
        }
        SourceKind::Loop { .. } => {
            return Err(
                "the source is a loop device; the disk holding its backing file is not the evidence"
                    .into(),
            );
        }
        SourceKind::Other => {
            return Err(format!(
                "{} is a virtual block device without disk hardware",
                identity.path
            ));
        }
        SourceKind::Disk => identity.kernel_name.clone(),
        SourceKind::Partition | SourceKind::DeviceMapper { .. } | SourceKind::Md => {
            match identity.parent_disks.as_slice() {
                [one] => one.trim_start_matches("/dev/").to_string(),
                [] => return Err(format!("no disk was found below {}", identity.path)),
                many => {
                    return Err(format!(
                        "{} is stored on {} disks ({}); no single physical disk applies",
                        identity.path,
                        many.len(),
                        many.join(", ")
                    ))
                }
            }
        }
    };
    let Some(node) = env.sys.node(&kname) else {
        return Err(format!("invalid kernel name {kname:?}"));
    };
    if !node.join("device").exists() {
        return Err(format!(
            "{kname} has no hardware device in sysfs (virtual, loop or memory device)"
        ));
    }
    let expected = env
        .sys
        .dev_of(&kname)
        .ok_or_else(|| format!("sysfs has no device number for {kname}"))?;
    let path = env.dev_dir.join(&kname);
    match (env.node_dev)(&path) {
        Some(actual) if actual == expected => {}
        Some(actual) => {
            return Err(format!(
                "{} is block device {}:{}, but sysfs lists {kname} as {}:{}; refusing to query it",
                path.display(),
                actual.0,
                actual.1,
                expected.0,
                expected.1
            ))
        }
        None => {
            return Err(format!(
                "{} is not a block device node; refusing to query it",
                path.display()
            ))
        }
    }
    Ok(PhysicalDisk {
        is_source: identity.kind == SourceKind::Disk,
        transport: identity.transport.clone(),
        path: path.to_string_lossy().into_owned(),
        kname,
    })
}

/// What one tool run produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolRun {
    /// The command as run (program first)
    pub argv: Vec<String>,
    /// Exit status; `None` when it was killed or never started
    pub exit_code: Option<i32>,
    /// Standard output, lines joined with `\n` (with a final `\n` when there
    /// was output)
    pub stdout: String,
    pub stderr: String,
    /// The run was stopped by dfdisk (abort, force, timeout)
    pub stopped: bool,
    /// Why it could not be started (missing program, permissions)
    pub start_error: Option<String>,
    /// One-line description of how it ended, e.g. "exit 0", "timed out"
    pub status: String,
}

impl ToolRun {
    /// A run that exited by itself with this code and output.
    pub fn exited(argv: &[&str], exit_code: i32, stdout: &str, stderr: &str) -> Self {
        Self {
            argv: argv.iter().map(|a| a.to_string()).collect(),
            exit_code: Some(exit_code),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            stopped: false,
            start_error: None,
            status: format!("exit {exit_code}"),
        }
    }

    /// A run that could not be started.
    pub fn not_started(argv: &[&str], error: &str) -> Self {
        Self {
            argv: argv.iter().map(|a| a.to_string()).collect(),
            start_error: Some(error.to_string()),
            status: format!("not started: {error}"),
            ..Default::default()
        }
    }

    /// The command line as one string (for methods and notes).
    pub fn command_line(&self) -> String {
        self.argv.join(" ")
    }

    /// First non-empty line of stderr, else of stdout (for error statements).
    pub fn first_message(&self) -> Option<String> {
        self.stderr
            .lines()
            .chain(self.stdout.lines())
            .map(crate::models::text::sanitize_line)
            .find(|l| !l.is_empty())
    }

    /// "<command>: <how it ended>[: <first message>]".
    pub fn describe_failure(&self) -> String {
        let mut s = format!("{}: {}", self.command_line(), self.status);
        if let Some(m) = self.first_message() {
            s.push_str(": ");
            s.push_str(&m);
        }
        s
    }
}

/// Runs one external tool to completion.
pub trait ToolRunner: Send + Sync {
    /// Run `program args` with `timeout`, honouring `control` and recording
    /// the command in `recorder`. Never fails: a tool that cannot be started
    /// is a [`ToolRun`] with `start_error`.
    fn run<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        timeout: Duration,
        control: &'a StopControl,
        recorder: Option<&'a ProvenanceRecorder>,
    ) -> BoxFuture<'a, ToolRun>;
}

/// The host: `engines::process::run_collect`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostRunner;

impl ToolRunner for HostRunner {
    fn run<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        timeout: Duration,
        control: &'a StopControl,
        recorder: Option<&'a ProvenanceRecorder>,
    ) -> BoxFuture<'a, ToolRun> {
        Box::pin(async move {
            let spec = ProcessSpec::new(program).args(args).timeout(timeout);
            let mut argv = vec![program.to_string()];
            argv.extend(args.iter().cloned());
            match run_collect(&spec, control, recorder).await {
                Ok(out) => {
                    let o = &out.outcome;
                    let join = |lines: &[String]| {
                        if lines.is_empty() {
                            String::new()
                        } else {
                            let mut s = lines.join("\n");
                            s.push('\n');
                            s
                        }
                    };
                    ToolRun {
                        argv,
                        exit_code: o.exit_code,
                        stdout: join(&out.stdout),
                        stderr: join(&out.stderr),
                        stopped: o.aborted || o.timed_out || o.force_killed,
                        start_error: None,
                        status: if o.timed_out {
                            format!("timed out after {} s", timeout.as_secs())
                        } else {
                            o.record.status_text()
                        },
                    }
                }
                Err(e) => ToolRun {
                    argv,
                    start_error: Some(e.to_string()),
                    status: format!("not started: {e}"),
                    ..Default::default()
                },
            }
        })
    }
}

/// Replays canned [`ToolRun`]s by command line and remembers every command
/// it was asked to run (tests: prove which commands reach a device).
#[derive(Debug, Default)]
pub struct ScriptedRunner {
    responses: Vec<(Vec<String>, ToolRun)>,
    calls: Mutex<Vec<Vec<String>>>,
}

impl ScriptedRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer `argv` (program first, compared exactly) with `run`.
    pub fn respond(mut self, argv: &[&str], run: ToolRun) -> Self {
        self.responses
            .push((argv.iter().map(|a| a.to_string()).collect(), run));
        self
    }

    /// Answer `argv` with an exit code and output read from fixture files
    /// (`None`: empty stream).
    pub fn respond_files(
        self,
        argv: &[&str],
        exit_code: i32,
        stdout: Option<&Path>,
        stderr: Option<&Path>,
    ) -> Self {
        let read = |p: Option<&Path>| {
            p.map(|p| {
                std::fs::read_to_string(p)
                    .unwrap_or_else(|e| panic!("fixture {}: {e}", p.display()))
            })
            .unwrap_or_default()
        };
        let run = ToolRun::exited(argv, exit_code, &read(stdout), &read(stderr));
        self.respond(argv, run)
    }

    /// Every command run so far, in order.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl ToolRunner for ScriptedRunner {
    fn run<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        _timeout: Duration,
        _control: &'a StopControl,
        _recorder: Option<&'a ProvenanceRecorder>,
    ) -> BoxFuture<'a, ToolRun> {
        let mut argv = vec![program.to_string()];
        argv.extend(args.iter().cloned());
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(argv.clone());
        }
        let found = self
            .responses
            .iter()
            .find(|(a, _)| *a == argv)
            .map(|(_, r)| r.clone());
        Box::pin(async move {
            found.unwrap_or_else(|| ToolRun {
                start_error: Some("no scripted response".into()),
                status: "not started: no scripted response".into(),
                argv,
                ..Default::default()
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_runner_collects_both_streams_and_records() {
        let rec = ProvenanceRecorder::new();
        let args: Vec<String> = ["-c", "echo out; echo err >&2; exit 3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let run = HostRunner
            .run(
                "sh",
                &args,
                Duration::from_secs(5),
                &StopControl::none(),
                Some(&rec),
            )
            .await;
        assert_eq!(run.exit_code, Some(3));
        assert_eq!(run.stdout, "out\n");
        assert_eq!(run.stderr, "err\n");
        assert!(!run.stopped);
        assert_eq!(run.argv[0], "sh");
        assert_eq!(rec.commands().len(), 1);
        assert_eq!(run.first_message().as_deref(), Some("err"));

        let missing = HostRunner
            .run(
                "/nonexistent/dfdisk-no-such-tool",
                &[],
                Duration::from_secs(5),
                &StopControl::none(),
                None,
            )
            .await;
        assert!(missing.start_error.is_some());
        assert_eq!(missing.exit_code, None);
    }

    #[tokio::test]
    async fn host_runner_times_out() {
        let args: Vec<String> = ["-c", "sleep 5"].iter().map(|s| s.to_string()).collect();
        let run = HostRunner
            .run(
                "sh",
                &args,
                Duration::from_millis(200),
                &StopControl::none(),
                None,
            )
            .await;
        assert!(run.stopped);
        assert!(run.status.contains("timed out"), "{}", run.status);
    }

    #[tokio::test]
    async fn scripted_runner_replays_and_records() {
        let r = ScriptedRunner::new().respond(
            &["hdparm", "-N", "/dev/sdb"],
            ToolRun::exited(&["hdparm", "-N", "/dev/sdb"], 0, "x\n", ""),
        );
        let args = vec!["-N".to_string(), "/dev/sdb".to_string()];
        let run = r
            .run("hdparm", &args, Duration::ZERO, &StopControl::none(), None)
            .await;
        assert_eq!(run.stdout, "x\n");
        let other = r
            .run("smartctl", &[], Duration::ZERO, &StopControl::none(), None)
            .await;
        assert!(other.start_error.is_some());
        assert_eq!(r.calls().len(), 2);
    }
}
