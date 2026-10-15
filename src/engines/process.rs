//! The one way dfdisk runs external tools (D5).
//!
//! Every child runs with `LC_ALL=C` and `LANG=C` (parsable, untranslated
//! output), in its own process group, with stdin from /dev/null, and gets
//! SIGTERM when dfdisk dies however it dies (SIGKILL, OOM, a crash:
//! `PR_SET_PDEATHSIG`), so no tool keeps reading the source after the process
//! that holds its exclusive claim and writes its report is gone. Standard
//! output and standard error are both read, split into bounded lines (on `\n`,
//! `\r` and `\r\n`) and delivered to a callback with their stream. A timer
//! (not the arrival of output) polls the abort flags and the timeout and
//! drives the graceful stop: SIGINT to the process group, after `grace`
//! SIGTERM, after `term_grace` SIGKILL. A force flag kills at once. The child
//! is killed when the future is dropped. Every run, started or not, is
//! recorded as a [`CommandRecord`] (argv, times, exit status, stop, output
//! tails) into an optional [`ProvenanceRecorder`].
//!
//! [`run`] is async (engines); [`run_blocking`] is the same contract for
//! synchronous code such as discovery probes, with a timeout but no abort.

use crate::models::provenance::{CommandRecord, ProvenanceRecorder};
use crate::models::text::sanitize_line;
use chrono::Utc;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Longest line delivered; the rest of a longer line is dropped and the line
/// is flagged `truncated`.
pub const DEFAULT_MAX_LINE: usize = 64 * 1024;
/// Lines of each stream kept in the [`CommandRecord`].
pub const DEFAULT_TAIL_LINES: usize = 40;
/// Characters of one tail line kept in the record.
const TAIL_LINE_CHARS: usize = 1000;
/// Lines of each stream [`run_collect`] / [`run_blocking`] keep in full.
pub const MAX_COLLECTED_LINES: usize = 100_000;

/// Which output stream a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamTag {
    Stdout,
    Stderr,
}

/// A signal dfdisk sends to stop a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopSignal {
    Interrupt,
    Terminate,
    Kill,
}

impl StopSignal {
    pub fn name(&self) -> &'static str {
        match self {
            StopSignal::Interrupt => "SIGINT",
            StopSignal::Terminate => "SIGTERM",
            StopSignal::Kill => "SIGKILL",
        }
    }

    fn number(&self) -> libc::c_int {
        match self {
            StopSignal::Interrupt => libc::SIGINT,
            StopSignal::Terminate => libc::SIGTERM,
            StopSignal::Kill => libc::SIGKILL,
        }
    }
}

/// What to run and how to stop it.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    /// Extra environment; `LC_ALL` and `LANG` are always `C` unless set here
    pub env: Vec<(OsString, OsString)>,
    pub current_dir: Option<PathBuf>,
    /// Stop with SIGTERM (then SIGKILL) after this long
    pub timeout: Option<Duration>,
    /// SIGINT → SIGTERM delay on abort (default 10 s; ewfacquire 15 s,
    /// ddrescue 30 s so it can save its map)
    pub grace: Duration,
    /// SIGTERM → SIGKILL delay (default 5 s)
    pub term_grace: Duration,
    /// How often abort/force/timeout are checked and `Tick` is delivered
    /// (default 100 ms)
    pub poll_interval: Duration,
    /// After the child exited, how long to wait for its output pipes to close
    /// (descendants may hold them) before killing the group (default 2 s)
    pub drain_timeout: Duration,
    pub max_line_len: usize,
    pub tail_lines: usize,
}

impl ProcessSpec {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            env: Vec::new(),
            current_dir: None,
            timeout: None,
            grace: Duration::from_secs(10),
            term_grace: Duration::from_secs(5),
            poll_interval: Duration::from_millis(100),
            drain_timeout: Duration::from_secs(2),
            max_line_len: DEFAULT_MAX_LINE,
            tail_lines: DEFAULT_TAIL_LINES,
        }
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    pub fn term_grace(mut self, term_grace: Duration) -> Self {
        self.term_grace = term_grace;
        self
    }

    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval.max(Duration::from_millis(1));
        self
    }

    pub fn max_line_len(mut self, max: usize) -> Self {
        self.max_line_len = max.max(1);
        self
    }

    pub fn tail_lines(mut self, lines: usize) -> Self {
        self.tail_lines = lines;
        self
    }

    /// Program and arguments as recorded (lossy UTF-8).
    pub fn argv(&self) -> Vec<String> {
        std::iter::once(&self.program)
            .chain(self.args.iter())
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    fn program_name(&self) -> String {
        self.program.to_string_lossy().into_owned()
    }
}

/// Flags the runner polls on its timer.
#[derive(Debug, Clone, Default)]
pub struct StopControl {
    /// Graceful stop: SIGINT, then SIGTERM, then SIGKILL
    pub abort: Option<Arc<AtomicBool>>,
    /// Immediate SIGKILL of the process group (e.g. a second Ctrl+C)
    pub force: Option<Arc<AtomicBool>>,
}

impl StopControl {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn abort(flag: Arc<AtomicBool>) -> Self {
        Self {
            abort: Some(flag),
            force: None,
        }
    }

    pub fn with_force(mut self, flag: Arc<AtomicBool>) -> Self {
        self.force = Some(flag);
        self
    }

    fn is_set(flag: &Option<Arc<AtomicBool>>) -> bool {
        flag.as_ref().is_some_and(|f| f.load(Ordering::Relaxed))
    }
}

/// Delivered to the callback of [`run`].
#[derive(Debug, Clone, Copy)]
pub enum ProcessEvent<'a> {
    /// One line of output, without its terminator
    Line {
        stream: StreamTag,
        text: &'a str,
        /// The line was longer than `max_line_len` and was cut
        truncated: bool,
    },
    /// Timer tick (every `poll_interval`), e.g. to poll /proc/<pid>/io
    Tick { pid: Option<u32>, elapsed: Duration },
}

/// How a run ended.
#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    pub exit_code: Option<i32>,
    /// Signal that ended the process
    pub signal: Option<i32>,
    /// The abort flag was seen and the graceful stop started
    pub aborted: bool,
    pub timed_out: bool,
    /// The force flag was seen and the group was killed at once
    pub force_killed: bool,
    /// Signals dfdisk sent to the process group, in order
    pub signals_sent: Vec<StopSignal>,
    pub elapsed: Duration,
    pub record: CommandRecord,
}

impl ProcessOutcome {
    /// Exited with status 0 on its own (not stopped by dfdisk).
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.aborted && !self.timed_out && !self.force_killed
    }
}

/// [`run_collect`] / [`run_blocking`] result: the outcome and every line.
#[derive(Debug, Clone)]
pub struct CollectedOutput {
    pub outcome: ProcessOutcome,
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
}

/// One line from [`LineSplitter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitLine {
    pub text: String,
    pub truncated: bool,
}

/// Splits a byte stream into lines on `\n`, `\r` and `\r\n`, keeping at most
/// `max` bytes of each line. Invalid UTF-8 is replaced.
#[derive(Debug)]
pub struct LineSplitter {
    buf: Vec<u8>,
    max: usize,
    truncated: bool,
    after_cr: bool,
}

impl LineSplitter {
    pub fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max: max.max(1),
            truncated: false,
            after_cr: false,
        }
    }

    fn take(&mut self) -> SplitLine {
        let line = SplitLine {
            text: String::from_utf8_lossy(&self.buf).into_owned(),
            truncated: self.truncated,
        };
        self.buf.clear();
        self.truncated = false;
        line
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<SplitLine> {
        let mut out = Vec::new();
        for &b in bytes {
            match b {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' => out.push(self.take()),
                b'\r' => {
                    out.push(self.take());
                    self.after_cr = true;
                }
                _ => {
                    self.after_cr = false;
                    if self.buf.len() < self.max {
                        self.buf.push(b);
                    } else {
                        self.truncated = true;
                    }
                }
            }
        }
        out
    }

    /// The unterminated last line, if any.
    pub fn finish(&mut self) -> Option<SplitLine> {
        (!self.buf.is_empty() || self.truncated).then(|| self.take())
    }
}

struct Tails {
    stdout: VecDeque<String>,
    stderr: VecDeque<String>,
    max: usize,
}

impl Tails {
    fn new(max: usize) -> Self {
        Self {
            stdout: VecDeque::new(),
            stderr: VecDeque::new(),
            max,
        }
    }

    fn push(&mut self, stream: StreamTag, text: &str) {
        if self.max == 0 {
            return;
        }
        let q = match stream {
            StreamTag::Stdout => &mut self.stdout,
            StreamTag::Stderr => &mut self.stderr,
        };
        let line: String = sanitize_line(text).chars().take(TAIL_LINE_CHARS).collect();
        if line.is_empty() {
            return;
        }
        if q.len() == self.max {
            q.pop_front();
        }
        q.push_back(line);
    }
}

fn signal_group(pgid: u32, signal: StopSignal) {
    if pgid == 0 || pgid > i32::MAX as u32 {
        return;
    }
    // SAFETY: plain kill(2) on the process group we created for the child
    unsafe {
        libc::kill(-(pgid as libc::pid_t), signal.number());
    }
}

/// Kills the child's process group when dropped unless disarmed.
struct GroupGuard {
    pgid: Option<u32>,
}

impl GroupGuard {
    fn disarm(&mut self) {
        self.pgid = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid {
            signal_group(pgid, StopSignal::Kill);
        }
    }
}

enum StopState {
    Running,
    Interrupted(Instant),
    Terminated(Instant),
    Killed,
}

/// The stop state machine shared by the async and the blocking runner.
struct Stopper {
    state: StopState,
    aborted: bool,
    timed_out: bool,
    force_killed: bool,
    sent: Vec<StopSignal>,
}

impl Stopper {
    fn new() -> Self {
        Self {
            state: StopState::Running,
            aborted: false,
            timed_out: false,
            force_killed: false,
            sent: Vec::new(),
        }
    }

    fn send(&mut self, pgid: Option<u32>, signal: StopSignal) {
        if let Some(pgid) = pgid {
            signal_group(pgid, signal);
        }
        self.sent.push(signal);
    }

    /// Called on every tick while the child is running.
    fn tick(
        &mut self,
        spec: &ProcessSpec,
        control: &StopControl,
        pgid: Option<u32>,
        started: Instant,
    ) {
        if StopControl::is_set(&control.force) && !matches!(self.state, StopState::Killed) {
            self.force_killed = true;
            self.aborted |= StopControl::is_set(&control.abort);
            self.send(pgid, StopSignal::Kill);
            self.state = StopState::Killed;
            return;
        }
        match self.state {
            StopState::Running => {
                if StopControl::is_set(&control.abort) {
                    self.aborted = true;
                    self.send(pgid, StopSignal::Interrupt);
                    self.state = StopState::Interrupted(Instant::now());
                } else if spec.timeout.is_some_and(|t| started.elapsed() >= t) {
                    self.timed_out = true;
                    self.send(pgid, StopSignal::Terminate);
                    self.state = StopState::Terminated(Instant::now());
                }
            }
            StopState::Interrupted(at) if at.elapsed() >= spec.grace => {
                self.send(pgid, StopSignal::Terminate);
                self.state = StopState::Terminated(Instant::now());
            }
            StopState::Terminated(at) if at.elapsed() >= spec.term_grace => {
                self.send(pgid, StopSignal::Kill);
                self.state = StopState::Killed;
            }
            _ => {}
        }
    }

    fn description(&self) -> Option<String> {
        if self.sent.is_empty() {
            return None;
        }
        let why = if self.force_killed {
            "killed"
        } else if self.aborted {
            "aborted"
        } else {
            "timed out"
        };
        let signals: Vec<&str> = self.sent.iter().map(StopSignal::name).collect();
        Some(format!("{why}: {}", signals.join(", ")))
    }
}

fn exit_parts(status: Option<std::process::ExitStatus>) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Some(s) => (s.code(), s.signal()),
        None => (None, None),
    }
}

fn spawn_failure(
    spec: &ProcessSpec,
    err: io::Error,
    started: chrono::DateTime<Utc>,
    recorder: Option<&ProvenanceRecorder>,
) -> io::Error {
    let message = format!("cannot run {}: {}", spec.program_name(), err);
    if let Some(r) = recorder {
        r.record_command(CommandRecord {
            argv: spec.argv(),
            started,
            ended: Utc::now(),
            exit_code: None,
            signal: None,
            stop: None,
            error: Some(err.to_string()),
            stdout_tail: Vec::new(),
            stderr_tail: Vec::new(),
        });
    }
    io::Error::new(err.kind(), message)
}

#[allow(clippy::too_many_arguments)]
fn finish_record(
    spec: &ProcessSpec,
    started: chrono::DateTime<Utc>,
    t0: Instant,
    status: Option<std::process::ExitStatus>,
    stopper: Stopper,
    tails: Tails,
    recorder: Option<&ProvenanceRecorder>,
) -> ProcessOutcome {
    let (exit_code, signal) = exit_parts(status);
    let record = CommandRecord {
        argv: spec.argv(),
        started,
        ended: Utc::now(),
        exit_code,
        signal,
        stop: stopper.description(),
        error: None,
        stdout_tail: tails.stdout.into_iter().collect(),
        stderr_tail: tails.stderr.into_iter().collect(),
    };
    if let Some(r) = recorder {
        r.record_command(record.clone());
    }
    ProcessOutcome {
        exit_code,
        signal,
        aborted: stopper.aborted,
        timed_out: stopper.timed_out,
        force_killed: stopper.force_killed,
        signals_sent: stopper.sent,
        elapsed: t0.elapsed(),
        record,
    }
}

async fn pump<R>(
    mut reader: R,
    stream: StreamTag,
    max: usize,
    tx: tokio::sync::mpsc::Sender<(StreamTag, SplitLine)>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut splitter = LineSplitter::new(max);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                for line in splitter.feed(&buf[..n]) {
                    if tx.send((stream, line)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
    if let Some(line) = splitter.finish() {
        let _ = tx.send((stream, line)).await;
    }
}

/// Between fork and exec in the child: SIGTERM when the parent `parent`
/// dies (`PR_SET_PDEATHSIG`), and no start at all when it died before that
/// was set (the child was re-parented). Only async-signal-safe calls, no
/// allocation.
fn die_with_parent(parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: prctl(PR_SET_PDEATHSIG) and getppid are async-signal-safe
    // system calls without pointers
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::getppid() != parent {
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }
    }
    Ok(())
}

/// This process' id as the child sees its parent.
fn own_pid() -> libc::pid_t {
    // SAFETY: getpid has no preconditions
    unsafe { libc::getpid() }
}

/// Run `spec`, delivering every output line and timer tick to `on_event`.
/// `Err` only when the program could not be started (the attempt is still
/// recorded); a non-zero exit, a signal, an abort or a timeout are reported
/// in the [`ProcessOutcome`].
pub async fn run<F>(
    spec: &ProcessSpec,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
    mut on_event: F,
) -> io::Result<ProcessOutcome>
where
    F: FnMut(ProcessEvent<'_>),
{
    let started = Utc::now();
    let t0 = Instant::now();
    let mut cmd = tokio::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let parent = own_pid();
    // SAFETY: the closure only makes async-signal-safe system calls
    unsafe {
        cmd.pre_exec(move || die_with_parent(parent));
    }
    if let Some(dir) = &spec.current_dir {
        cmd.current_dir(dir);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Err(spawn_failure(spec, e, started, recorder)),
    };
    let pid = child.id();
    let mut guard = GroupGuard { pgid: pid };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<(StreamTag, SplitLine)>(256);
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        readers.push(tokio::spawn(pump(
            out,
            StreamTag::Stdout,
            spec.max_line_len,
            tx.clone(),
        )));
    }
    if let Some(err) = child.stderr.take() {
        readers.push(tokio::spawn(pump(
            err,
            StreamTag::Stderr,
            spec.max_line_len,
            tx,
        )));
    }

    let mut ticker = tokio::time::interval(spec.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tails = Tails::new(spec.tail_lines);
    let mut stopper = Stopper::new();
    let mut status: Option<std::process::ExitStatus> = None;
    let mut exited_at: Option<Instant> = None;
    let mut streams_open = true;

    loop {
        if status.is_some() && !streams_open {
            break;
        }
        tokio::select! {
            line = rx.recv(), if streams_open => match line {
                Some((stream, line)) => {
                    tails.push(stream, &line.text);
                    on_event(ProcessEvent::Line { stream, text: &line.text, truncated: line.truncated });
                }
                None => streams_open = false,
            },
            res = child.wait(), if status.is_none() => {
                match res {
                    Ok(s) => status = Some(s),
                    Err(_) => {
                        // Cannot wait: make sure it is gone and stop waiting
                        stopper.send(pid, StopSignal::Kill);
                        status = child.try_wait().ok().flatten();
                        streams_open = false;
                    }
                }
                exited_at = Some(Instant::now());
            },
            _ = ticker.tick() => {
                on_event(ProcessEvent::Tick { pid, elapsed: t0.elapsed() });
                if status.is_none() {
                    stopper.tick(spec, control, pid, t0);
                } else if exited_at.is_some_and(|at| at.elapsed() >= spec.drain_timeout) {
                    // Descendants keep the pipes open: end them with the group
                    if let Some(pgid) = pid {
                        signal_group(pgid, StopSignal::Kill);
                    }
                    break;
                }
            }
        }
    }
    // Deliver what the readers still hold, then stop them
    while let Ok((stream, line)) = rx.try_recv() {
        tails.push(stream, &line.text);
        on_event(ProcessEvent::Line {
            stream,
            text: &line.text,
            truncated: line.truncated,
        });
    }
    for r in readers {
        r.abort();
    }
    guard.disarm();
    Ok(finish_record(
        spec, started, t0, status, stopper, tails, recorder,
    ))
}

/// [`run`], keeping every line (up to [`MAX_COLLECTED_LINES`] per stream).
pub async fn run_collect(
    spec: &ProcessSpec,
    control: &StopControl,
    recorder: Option<&ProvenanceRecorder>,
) -> io::Result<CollectedOutput> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let outcome = run(spec, control, recorder, |ev| {
        if let ProcessEvent::Line { stream, text, .. } = ev {
            let v = match stream {
                StreamTag::Stdout => &mut stdout,
                StreamTag::Stderr => &mut stderr,
            };
            if v.len() < MAX_COLLECTED_LINES {
                v.push(text.to_string());
            }
        }
    })
    .await?;
    Ok(CollectedOutput {
        outcome,
        stdout,
        stderr,
    })
}

/// Synchronous [`run_collect`] for code outside the async runtime (or inside
/// `spawn_blocking`): same environment, process group and recording; stops
/// only on `spec.timeout` (SIGTERM, then SIGKILL after `term_grace`).
pub fn run_blocking(
    spec: &ProcessSpec,
    recorder: Option<&ProvenanceRecorder>,
) -> io::Result<CollectedOutput> {
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;

    let started = Utc::now();
    let t0 = Instant::now();
    let mut cmd = std::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let parent = own_pid();
    // SAFETY: the closure only makes async-signal-safe system calls
    unsafe {
        cmd.pre_exec(move || die_with_parent(parent));
    }
    if let Some(dir) = &spec.current_dir {
        cmd.current_dir(dir);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Err(spawn_failure(spec, e, started, recorder)),
    };
    let pid = Some(child.id());
    let mut guard = GroupGuard { pgid: pid };

    let (tx, rx) = mpsc::channel::<(StreamTag, SplitLine)>();
    let mut readers = Vec::new();
    let streams: [(Option<Box<dyn Read + Send>>, StreamTag); 2] = [
        (
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
            StreamTag::Stdout,
        ),
        (
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
            StreamTag::Stderr,
        ),
    ];
    for (reader, tag) in streams {
        if let Some(mut reader) = reader {
            let tx = tx.clone();
            let max = spec.max_line_len;
            readers.push(std::thread::spawn(move || {
                let mut splitter = LineSplitter::new(max);
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            for line in splitter.feed(&buf[..n]) {
                                if tx.send((tag, line)).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                if let Some(line) = splitter.finish() {
                    let _ = tx.send((tag, line));
                }
            }));
        }
    }
    drop(tx);

    let mut tails = Tails::new(spec.tail_lines);
    let mut stopper = Stopper::new();
    let control = StopControl::none();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let mut status = None;
    let mut exited_at: Option<Instant> = None;
    let mut streams_open = true;
    let mut collect = |stream: StreamTag, line: SplitLine, tails: &mut Tails| {
        tails.push(stream, &line.text);
        let v = match stream {
            StreamTag::Stdout => &mut stdout,
            StreamTag::Stderr => &mut stderr,
        };
        if v.len() < MAX_COLLECTED_LINES {
            v.push(line.text);
        }
    };
    loop {
        if status.is_some() && !streams_open {
            break;
        }
        if streams_open {
            match rx.recv_timeout(spec.poll_interval) {
                Ok((stream, line)) => collect(stream, line, &mut tails),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => streams_open = false,
            }
        } else {
            std::thread::sleep(spec.poll_interval.min(Duration::from_millis(20)));
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(s)) => {
                    status = Some(s);
                    exited_at = Some(Instant::now());
                }
                Ok(None) => stopper.tick(spec, &control, pid, t0),
                Err(_) => {
                    stopper.send(pid, StopSignal::Kill);
                    status = child.wait().ok();
                    exited_at = Some(Instant::now());
                }
            }
        } else if exited_at.is_some_and(|at| at.elapsed() >= spec.drain_timeout) {
            if let Some(pgid) = pid {
                signal_group(pgid, StopSignal::Kill);
            }
            break;
        }
    }
    while let Ok((stream, line)) = rx.try_recv() {
        collect(stream, line, &mut tails);
    }
    guard.disarm();
    // Readers end with the pipes; detached if a descendant still holds one
    drop(readers);
    let outcome = finish_record(spec, started, t0, status, stopper, tails, recorder);
    Ok(CollectedOutput {
        outcome,
        stdout,
        stderr,
    })
}

/// First non-empty line of `lines`, sanitised.
pub fn first_line<'a>(lines: impl IntoIterator<Item = &'a String>) -> Option<String> {
    lines
        .into_iter()
        .map(|l| sanitize_line(l))
        .find(|l| !l.is_empty())
}

/// The version line of a version query: only from a run that exited 0 (a
/// failing tool's first line is an error message, never its version), stdout
/// first, else stderr (ewfexport prints its version there).
fn version_from(output: &CollectedOutput) -> Option<String> {
    if !output.outcome.success() {
        return None;
    }
    first_line(&output.stdout).or_else(|| first_line(&output.stderr))
}

/// First line `program args` prints (stdout, else stderr) when it exits 0,
/// e.g. "ewfacquire 20231119"; `None` when it cannot be run, fails or times
/// out.
pub async fn tool_version(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let spec = ProcessSpec::new(program).args(args).timeout(timeout);
    let out = run_collect(&spec, &StopControl::none(), None).await.ok()?;
    version_from(&out)
}

/// Blocking [`tool_version`].
pub fn tool_version_blocking(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let spec = ProcessSpec::new(program).args(args).timeout(timeout);
    let out = run_blocking(&spec, None).ok()?;
    version_from(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> ProcessSpec {
        ProcessSpec::new("sh").arg("-c").arg(script)
    }

    #[test]
    fn splitter_handles_cr_lf_and_long_lines() {
        let mut s = LineSplitter::new(4);
        let lines = s.feed(b"ab\ncd\r\nef\rgh");
        let texts: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["ab", "cd", "ef"]);
        // CR at the end of one chunk, LF at the start of the next: one break
        let mut s2 = LineSplitter::new(64);
        assert_eq!(s2.feed(b"x\r").len(), 1);
        assert!(s2.feed(b"\ny\n").iter().map(|l| &l.text).eq(["y"].iter()));
        assert_eq!(s.finish().unwrap().text, "gh");
        assert_eq!(s.finish(), None);
        let long = s.feed(b"123456789\nz\n");
        assert_eq!(long[0].text, "1234");
        assert!(long[0].truncated);
        assert_eq!(long[1].text, "z");
        assert!(!long[1].truncated);
        // Empty lines are delivered (block separators matter to parsers)
        assert_eq!(LineSplitter::new(8).feed(b"\n\n").len(), 2);
        // Invalid UTF-8 is replaced, not dropped
        assert_eq!(LineSplitter::new(8).feed(b"\xff\n")[0].text, "\u{fffd}");
    }

    #[tokio::test]
    async fn both_streams_are_captured_and_recorded() {
        let rec = ProvenanceRecorder::new();
        let mut seen = Vec::new();
        let out = run(
            &sh("echo out1; echo err1 >&2; echo out2; printf 'no newline'"),
            &StopControl::none(),
            Some(&rec),
            |ev| {
                if let ProcessEvent::Line { stream, text, .. } = ev {
                    seen.push((stream, text.to_string()));
                }
            },
        )
        .await
        .unwrap();
        assert!(out.success());
        assert_eq!(out.exit_code, Some(0));
        let stdout: Vec<_> = seen
            .iter()
            .filter(|(s, _)| *s == StreamTag::Stdout)
            .map(|(_, t)| t.as_str())
            .collect();
        assert_eq!(stdout, ["out1", "out2", "no newline"]);
        assert!(seen.contains(&(StreamTag::Stderr, "err1".to_string())));
        let cmds = rec.commands();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].argv[0], "sh");
        assert_eq!(cmds[0].exit_code, Some(0));
        assert_eq!(cmds[0].stdout_tail, ["out1", "out2", "no newline"]);
        assert_eq!(cmds[0].stderr_tail, ["err1"]);
        assert!(cmds[0].ended >= cmds[0].started);
    }

    #[tokio::test]
    async fn long_lines_are_bounded_and_tails_limited() {
        let spec = sh("i=0; while [ $i -lt 5 ]; do echo line$i; i=$((i+1)); done; head -c 5000 /dev/zero | tr '\\0' x; echo; echo after")
            .max_line_len(100)
            .tail_lines(2);
        let mut truncated = Vec::new();
        let out = run(&spec, &StopControl::none(), None, |ev| {
            if let ProcessEvent::Line {
                text, truncated: t, ..
            } = ev
            {
                truncated.push((text.len(), t));
            }
        })
        .await
        .unwrap();
        assert!(truncated.contains(&(100, true)), "{truncated:?}");
        assert_eq!(out.record.stdout_tail.len(), 2);
        assert_eq!(out.record.stdout_tail[1], "after");
    }

    #[tokio::test]
    async fn environment_is_c_locale_and_stdin_is_null() {
        let spec = sh("echo \"$LC_ALL|$LANG|$DFDISK_PROCESS_TEST\"; cat; echo done")
            .env("DFDISK_PROCESS_TEST", "value")
            .timeout(Duration::from_secs(10));
        let out = run_collect(&spec, &StopControl::none(), None)
            .await
            .unwrap();
        assert_eq!(out.stdout, ["C|C|value", "done"]);
        assert!(out.outcome.success());
    }

    #[tokio::test]
    async fn abort_interrupts_and_a_trapping_tool_exits_cleanly() {
        let abort = Arc::new(AtomicBool::new(false));
        let flag = abort.clone();
        let spec = sh("trap 'echo got-int; exit 0' INT; echo ready; while :; do sleep 0.05; done")
            .grace(Duration::from_secs(20))
            .poll_interval(Duration::from_millis(20));
        let mut lines = Vec::new();
        let out = run(&spec, &StopControl::abort(abort.clone()), None, |ev| {
            if let ProcessEvent::Line { text, .. } = ev {
                if text == "ready" {
                    flag.store(true, Ordering::Relaxed);
                }
                lines.push(text.to_string());
            }
        })
        .await
        .unwrap();
        assert!(out.aborted);
        assert!(!out.success());
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.signals_sent, [StopSignal::Interrupt]);
        assert!(lines.contains(&"got-int".to_string()), "{lines:?}");
        assert!(out.elapsed < Duration::from_secs(10));
        assert_eq!(out.record.stop.as_deref(), Some("aborted: SIGINT"));
    }

    #[tokio::test]
    async fn a_tool_ignoring_int_and_term_is_killed() {
        let abort = Arc::new(AtomicBool::new(false));
        let flag = abort.clone();
        let spec = sh("trap '' INT TERM; echo ready; while :; do sleep 0.05; done")
            .grace(Duration::from_millis(200))
            .term_grace(Duration::from_millis(200))
            .poll_interval(Duration::from_millis(20));
        let out = run(&spec, &StopControl::abort(abort), None, |ev| {
            if let ProcessEvent::Line { text: "ready", .. } = ev {
                flag.store(true, Ordering::Relaxed);
            }
        })
        .await
        .unwrap();
        assert!(out.aborted);
        assert_eq!(
            out.signals_sent,
            [
                StopSignal::Interrupt,
                StopSignal::Terminate,
                StopSignal::Kill
            ]
        );
        assert_eq!(out.signal, Some(libc::SIGKILL));
        assert_eq!(out.exit_code, None);
        assert_eq!(
            out.record.stop.as_deref(),
            Some("aborted: SIGINT, SIGTERM, SIGKILL")
        );
    }

    #[tokio::test]
    async fn force_kills_at_once() {
        let abort = Arc::new(AtomicBool::new(true));
        let force = Arc::new(AtomicBool::new(true));
        let spec = sh("trap '' INT TERM; while :; do sleep 0.05; done")
            .grace(Duration::from_secs(60))
            .poll_interval(Duration::from_millis(20));
        let control = StopControl::abort(abort).with_force(force);
        let out = run(&spec, &control, None, |_| {}).await.unwrap();
        assert!(out.force_killed);
        assert_eq!(out.signals_sent, [StopSignal::Kill]);
        assert!(out.elapsed < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn timeout_terminates() {
        let spec = sh("sleep 30")
            .timeout(Duration::from_millis(300))
            .poll_interval(Duration::from_millis(20));
        let out = run_collect(&spec, &StopControl::none(), None)
            .await
            .unwrap();
        assert!(out.outcome.timed_out);
        assert!(!out.outcome.aborted);
        assert_eq!(out.outcome.signals_sent[0], StopSignal::Terminate);
        assert_eq!(out.outcome.signal, Some(libc::SIGTERM));
        assert!(out.outcome.elapsed < Duration::from_secs(10));
        assert_eq!(
            out.outcome.record.stop.as_deref(),
            Some("timed out: SIGTERM")
        );
    }

    #[tokio::test]
    async fn ticks_are_delivered_with_the_pid() {
        let mut ticks = 0;
        let mut pid_seen = None;
        let spec = sh("sleep 0.3").poll_interval(Duration::from_millis(20));
        run(&spec, &StopControl::none(), None, |ev| {
            if let ProcessEvent::Tick { pid, .. } = ev {
                ticks += 1;
                pid_seen = pid;
            }
        })
        .await
        .unwrap();
        assert!(ticks >= 3, "{ticks}");
        assert!(pid_seen.is_some());
    }

    #[tokio::test]
    async fn missing_program_is_an_error_and_recorded() {
        let rec = ProvenanceRecorder::new();
        let spec = ProcessSpec::new("dfdisk-no-such-tool-x").arg("-V");
        let err = run(&spec, &StopControl::none(), Some(&rec), |_| {})
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("dfdisk-no-such-tool-x"));
        let cmds = rec.commands();
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].error.is_some());
        assert!(cmds[0].status_text().starts_with("not started"));
    }

    #[tokio::test]
    async fn non_zero_exit_is_reported() {
        let out = run_collect(&sh("echo bad >&2; exit 3"), &StopControl::none(), None)
            .await
            .unwrap();
        assert_eq!(out.outcome.exit_code, Some(3));
        assert!(!out.outcome.success());
        assert_eq!(out.stderr, ["bad"]);
    }

    #[test]
    fn blocking_runner_collects_and_times_out() {
        let rec = ProvenanceRecorder::new();
        let out = run_blocking(&sh("echo \"$LC_ALL\"; echo e >&2"), Some(&rec)).unwrap();
        assert!(out.outcome.success());
        assert_eq!(out.stdout, ["C"]);
        assert_eq!(out.stderr, ["e"]);
        assert_eq!(rec.commands().len(), 1);

        let slow = sh("sleep 30")
            .timeout(Duration::from_millis(200))
            .poll_interval(Duration::from_millis(20));
        let out = run_blocking(&slow, None).unwrap();
        assert!(out.outcome.timed_out);
        assert!(out.outcome.elapsed < Duration::from_secs(10));

        let stubborn = sh("trap '' TERM; echo x; while :; do sleep 0.05; done")
            .timeout(Duration::from_millis(100))
            .term_grace(Duration::from_millis(200))
            .poll_interval(Duration::from_millis(20));
        let out = run_blocking(&stubborn, None).unwrap();
        assert_eq!(
            out.outcome.signals_sent,
            [StopSignal::Terminate, StopSignal::Kill]
        );
        assert_eq!(out.outcome.signal, Some(libc::SIGKILL));
        assert!(run_blocking(&ProcessSpec::new("dfdisk-no-such-tool-x"), None).is_err());
    }

    #[tokio::test]
    async fn tool_versions_take_the_first_line() {
        assert_eq!(
            tool_version(
                "sh",
                &["-c", "echo; echo 'mytool 1.2.3'; echo more"],
                Duration::from_secs(5)
            )
            .await
            .as_deref(),
            Some("mytool 1.2.3")
        );
        // Version on stderr only
        assert_eq!(
            tool_version_blocking("sh", &["-c", "echo 'v 2' >&2"], Duration::from_secs(5))
                .as_deref(),
            Some("v 2")
        );
        assert_eq!(
            tool_version("dfdisk-no-such-tool-x", &["-V"], Duration::from_secs(1)).await,
            None
        );
        assert_eq!(
            tool_version("sh", &["-c", "sleep 5"], Duration::from_millis(100)).await,
            None
        );
        // A failing tool's message is not a version
        assert_eq!(
            tool_version(
                "sh",
                &[
                    "-c",
                    "echo 'error while loading shared libraries' >&2; exit 127"
                ],
                Duration::from_secs(5)
            )
            .await,
            None
        );
        assert_eq!(
            tool_version_blocking(
                "sh",
                &["-c", "echo 'tool 1.0'; exit 1"],
                Duration::from_secs(5)
            ),
            None
        );
    }

    // ---- the tool dies with dfdisk (PR_SET_PDEATHSIG) ----

    const PDEATH_PIDFILE: &str = "DFDISK_TEST_PDEATH_PIDFILE";
    const PDEATH_ASYNC: &str = "DFDISK_TEST_PDEATH_ASYNC";

    /// Run in a child process by `tools_die_with_dfdisk` (a stand-in for a
    /// dfdisk process): starts a tool that would run for a minute and waits
    /// for it. Does nothing in a normal test run.
    #[test]
    fn pdeath_helper() {
        let Some(pidfile) = std::env::var_os(PDEATH_PIDFILE) else {
            return;
        };
        let script = format!(
            "echo $$ > '{}'; exec sleep 60",
            std::path::Path::new(&pidfile).display()
        );
        let spec = sh(&script).timeout(Duration::from_secs(90));
        if std::env::var_os(PDEATH_ASYNC).is_some() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = rt.block_on(run_collect(&spec, &StopControl::none(), None));
        } else {
            let _ = run_blocking(&spec, None);
        }
    }

    /// The process is alive (a zombie is not: it has ended).
    fn alive(pid: i32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => false,
            Ok(stat) => !matches!(
                stat.rsplit_once(") ")
                    .and_then(|(_, rest)| rest.chars().next()),
                Some('Z') | Some('X') | None
            ),
        }
    }

    /// A "dfdisk" killed with SIGKILL (no handler runs) while its tool runs:
    /// the tool gets SIGTERM and ends instead of running on unsupervised.
    fn tool_dies_with_parent(async_runner: bool) {
        let tmp = tempfile::tempdir().unwrap();
        let pidfile = tmp.path().join("tool.pid");
        let mut helper = std::process::Command::new(std::env::current_exe().unwrap());
        helper
            .args([
                "engines::process::tests::pdeath_helper",
                "--exact",
                "--test-threads=1",
            ])
            .env(PDEATH_PIDFILE, &pidfile)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if async_runner {
            helper.env(PDEATH_ASYNC, "1");
        }
        let mut helper = helper.spawn().unwrap();
        let mut pid = None;
        for _ in 0..400 {
            if let Some(p) = std::fs::read_to_string(&pidfile)
                .ok()
                .and_then(|t| t.trim().parse::<i32>().ok())
            {
                pid = Some(p);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let Some(pid) = pid else {
            let _ = helper.kill();
            panic!("the helper never started its tool");
        };
        assert!(alive(pid));
        helper.kill().unwrap();
        helper.wait().unwrap();
        let gone = (0..200).any(|_| {
            let a = alive(pid);
            if a {
                std::thread::sleep(Duration::from_millis(25));
            }
            !a
        });
        if !gone {
            // SAFETY: ending the stray test process
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        assert!(
            gone,
            "the tool (pid {pid}) kept running after its parent was killed"
        );
    }

    #[test]
    fn tools_die_with_dfdisk() {
        tool_dies_with_parent(false);
        tool_dies_with_parent(true);
    }
}
