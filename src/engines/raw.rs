//! Native RAW engine (§13 RAW).
//!
//! [`acquire`] copies the source into `<base>.raw` through the descriptor the
//! session holds (O_RDONLY|O_EXCL for block devices, R1), with O_DIRECT and
//! page-aligned buffers (fallback: buffered reads + POSIX_FADV_DONTNEED, see
//! [`UncachedReader`]). Every byte written is hashed once (the selected
//! digests) and, with a piece size, per piece (SHA-256, `<base>.pieces.tsv`,
//! R5). A failed 1 MiB read is narrowed down by reading every logical
//! sector of it on its own, so one bad 512-byte sector is located exactly:
//!
//! - `--on-read-error stop` (default): the acquisition ends at the first
//!   unreadable sector; everything before it is in the image, the rest is
//!   listed as not read (outcome Incomplete, exact offset).
//! - `--on-read-error zero-fill`: each unreadable sector is replaced by zeros
//!   and listed (outcome CompletedWithReadErrors); after
//!   [`SOURCE_LOSS_SECTORS`] consecutive unreadable sectors the source counts
//!   as lost and the acquisition ends (Incomplete).
//!
//! ENODEV/ENXIO/ENOMEDIUM end the acquisition at once ("source lost"). A full
//! destination (ENOSPC/EDQUOT) ends it with the image truncated to the last
//! byte that was written; the digests and pieces describe exactly that
//! image. The examiner's abort keeps the partial image (and its pieces).
//!
//! [`verify`] re-reads the image (after the session's fsync and cache
//! eviction) with O_DIRECT, recomputes the digests and every piece, and
//! names differing pieces. [`hash_source`] is the second source read
//! (`--verify-source`) of every engine.

use crate::engines::error::{AcquisitionError, ErrorKind};
use crate::engines::hasher::{
    round_up, AlignedBuf, ReadAt, StreamHasher, UncachedReader, CHUNK_SIZE,
};
use crate::engines::pieces::{self, ImageCheck, PiecesOutput, PIECES_SUFFIX};
use crate::engines::progress::ProgressSink;
use crate::engines::session::{EngineContext, EngineOutput};
use crate::models::config::{EngineSettings, OnReadError, RawSettings};
use crate::models::info_report::{compare_digests, HashResults, HashSelection};
use crate::models::outcome::{RangeKind, ReadErrorTable, VerificationResult};
use crate::models::telemetry::{AcquisitionStatus, ProgressTelemetry};
use crate::models::text::{format_iec, plural};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How the RAW engine deals with read errors under `--on-read-error stop`
/// (the default), stated in the report.
pub const RAW_ERROR_HANDLING: &str =
    "Read errors: the native RAW engine stops at the first unreadable sector and records its exact offset (no retries, no zero-fill); use --on-read-error zero-fill or the rescue engine for damaged media";

/// How the RAW engine deals with read errors under `--on-read-error
/// zero-fill`, stated in the report.
pub const RAW_ZERO_FILL_HANDLING: &str =
    "Read errors: after a failed read the native RAW engine reads every sector of it on its own (one attempt each, no retries), replaces each unreadable sector by zeros and lists it; 4096 consecutive unreadable sectors count as a lost source and end the acquisition";

/// Consecutive unreadable sectors after which a zero-filling acquisition
/// treats the source as lost (§13).
pub use crate::models::config::SOURCE_LOSS_SECTORS;

/// `ReadErrorTable::source` of RAW acquisitions.
pub const RAW_TABLE_SOURCE: &str = "raw engine (sector reads)";

// ---------------------------------------------------------------------------
// The copy loop
// ---------------------------------------------------------------------------

/// What [`copy_source`] does.
#[derive(Debug, Clone, Copy)]
pub struct CopyPlan {
    /// Logical sector size: salvage granularity and alignment unit
    pub sector_size: u32,
    /// Bytes to copy; `None`: until the source ends
    pub length: Option<u64>,
    pub on_read_error: OnReadError,
    /// Consecutive unreadable sectors that end a zero-filling copy as
    /// "source lost"
    pub loss_threshold_sectors: u64,
    pub selection: HashSelection,
    /// Bulk read size (rounded up to whole sectors)
    pub chunk_size: usize,
}

impl CopyPlan {
    pub fn new(
        sector_size: u32,
        length: Option<u64>,
        on_read_error: OnReadError,
        selection: HashSelection,
    ) -> Self {
        Self {
            sector_size,
            length,
            on_read_error,
            loss_threshold_sectors: SOURCE_LOSS_SECTORS,
            selection,
            chunk_size: CHUNK_SIZE,
        }
    }

    fn sector(&self) -> usize {
        self.sector_size.max(512) as usize
    }
}

/// Why a copy ended before the end of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// `--on-read-error stop` and an unreadable sector
    ReadError,
    /// A read failed for a reason that is not a media error (EINVAL, ...)
    ReadFailed,
    /// ENODEV/ENXIO/ENOMEDIUM, or too many consecutive unreadable sectors
    SourceLost,
    /// The source ended before its size
    SourceEnded,
    /// ENOSPC/EDQUOT on the destination
    DestinationFull,
    /// Any other write error on the destination
    WriteFailed,
}

impl StopKind {
    /// The rest of the source was not read because of the source.
    pub fn is_source_side(&self) -> bool {
        matches!(
            self,
            StopKind::ReadError
                | StopKind::ReadFailed
                | StopKind::SourceLost
                | StopKind::SourceEnded
        )
    }
}

/// Where and why a copy ended early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyStop {
    pub kind: StopKind,
    /// Byte offset of the source at which the copy ended (= bytes in the image)
    pub offset: u64,
    /// The report's stop reason
    pub reason: String,
}

/// Progress of a copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyProgress {
    pub bytes_done: u64,
    pub unreadable_sectors: u64,
    /// The copy has ended (the last report)
    pub finished: bool,
}

/// What [`copy_source`] did.
#[derive(Debug, Clone)]
pub struct CopyResult {
    /// Bytes in the image (read or substituted), from offset 0
    pub bytes_copied: u64,
    /// Digests of exactly those bytes
    pub hashes: HashResults,
    /// Substituted sectors and, when the source stopped the copy, the part
    /// of the source that was not read
    pub read_errors: ReadErrorTable,
    /// Sectors that could not be read (substituted, or the one that stopped)
    pub unreadable_sectors: u64,
    pub stop: Option<CopyStop>,
    /// Stopped by [`CopyObserver::should_stop`]
    pub aborted: bool,
}

/// Hooks of [`copy_source`]; every method has a no-op default.
pub trait CopyObserver {
    /// Bytes written to the image at `offset`, in order (pieces, ...).
    fn data(&mut self, _offset: u64, _bytes: &[u8]) {}
    /// After every read; the observer decides how often to report.
    fn progress(&mut self, _progress: &CopyProgress) {}
    /// A sector at `offset` could not be read; `substituted`: zeros were
    /// written in its place.
    fn unreadable(&mut self, _offset: u64, _length: u64, _error: &io::Error, _substituted: bool) {}
    /// Checked before every read: true stops the copy (abort).
    fn should_stop(&mut self) -> bool {
        false
    }
}

/// An observer that does nothing.
pub struct NoObserver;
impl CopyObserver for NoObserver {}

enum ReadClass {
    /// The device is gone
    Lost,
    /// Not a media error: retrying sector by sector cannot help
    Fatal,
    /// A media error: narrow it down to sectors
    Media,
}

fn classify_read_error(e: &io::Error) -> ReadClass {
    match e.raw_os_error() {
        Some(libc::ENODEV | libc::ENXIO | libc::ENOMEDIUM) => ReadClass::Lost,
        Some(libc::EINVAL | libc::EBADF | libc::EFAULT | libc::EISDIR) => ReadClass::Fatal,
        _ => ReadClass::Media,
    }
}

fn is_destination_full(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT))
        || e.kind() == io::ErrorKind::StorageFull
}

/// Write all of `data`; returns the bytes written and the error that stopped
/// it (EINTR is retried).
fn write_fully<W: Write + ?Sized>(dst: &mut W, data: &[u8]) -> (usize, Option<io::Error>) {
    let mut done = 0;
    while done < data.len() {
        match dst.write(&data[done..]) {
            Ok(0) => {
                return (
                    done,
                    Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the destination accepted no more data",
                    )),
                )
            }
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return (done, Some(e)),
        }
    }
    (done, None)
}

struct Copier<'a, W: Write + ?Sized> {
    dst: &'a mut W,
    observer: &'a mut dyn CopyObserver,
    plan: &'a CopyPlan,
    hasher: StreamHasher,
    table: ReadErrorTable,
    offset: u64,
    unreadable: u64,
    consecutive: u64,
    run_start: u64,
    stop: Option<CopyStop>,
    aborted: bool,
}

impl<W: Write + ?Sized> Copier<'_, W> {
    fn stop_at(&mut self, kind: StopKind, reason: String) {
        self.stop = Some(CopyStop {
            kind,
            offset: self.offset,
            reason,
        });
    }

    fn progress(&mut self, finished: bool) {
        let p = CopyProgress {
            bytes_done: self.offset,
            unreadable_sectors: self.unreadable,
            finished,
        };
        self.observer.progress(&p);
    }

    fn should_stop(&mut self) -> bool {
        if self.observer.should_stop() {
            self.aborted = true;
        }
        self.aborted
    }

    /// Write, hash and observe `data` at the current offset. False: a write
    /// error ended the copy (what was written is accounted for).
    fn write(&mut self, data: &[u8], substituted: bool) -> bool {
        let (done, err) = write_fully(self.dst, data);
        if done > 0 {
            let written = &data[..done];
            self.hasher.update(written);
            self.observer.data(self.offset, written);
            if substituted {
                self.table
                    .push(self.offset, done as u64, RangeKind::Substituted);
            }
            self.offset += done as u64;
        }
        match err {
            None => true,
            Some(e) if is_destination_full(&e) => {
                let reason = format!(
                    "destination full at byte offset {} ({e}); the image ends with the last byte that was written",
                    self.offset
                );
                self.stop_at(StopKind::DestinationFull, reason);
                false
            }
            Some(e) => {
                let reason = format!(
                    "write error on the destination at byte offset {}: {e}",
                    self.offset
                );
                self.stop_at(StopKind::WriteFailed, reason);
                false
            }
        }
    }

    /// The source ended (`Ok(0)`) at the current offset.
    fn source_ended(&mut self) {
        if let Some(len) = self.plan.length {
            let reason = format!(
                "the source returned end of data after {} bytes, but its size was {len} bytes",
                self.offset
            );
            self.stop_at(StopKind::SourceEnded, reason);
        }
    }

    /// A read error that is not a media error ends the copy. True: handled.
    fn fatal_or_lost(&mut self, e: &io::Error) -> bool {
        match classify_read_error(e) {
            ReadClass::Lost => {
                let reason = format!("source lost at byte offset {}: {e}", self.offset);
                self.stop_at(StopKind::SourceLost, reason);
                true
            }
            ReadClass::Fatal => {
                let reason = format!(
                    "the source could not be read at byte offset {}: {e} (not a media error; nothing was substituted)",
                    self.offset
                );
                self.stop_at(StopKind::ReadFailed, reason);
                true
            }
            ReadClass::Media => false,
        }
    }

    /// Read the `want` bytes at the current offset sector by sector (a bulk
    /// read of them failed). False: the copy ends.
    fn salvage<R: ReadAt + ?Sized>(&mut self, src: &mut R, buf: &mut [u8], want: usize) -> bool {
        let ss = self.plan.sector();
        let end = self.offset + want as u64;
        while self.offset < end {
            if self.should_stop() {
                return false;
            }
            let len = (end - self.offset).min(ss as u64) as usize;
            let sector = &mut buf[..ss];
            match src.read_at(sector, self.offset) {
                Ok(0) => {
                    self.source_ended();
                    return false;
                }
                Ok(n) => {
                    self.consecutive = 0;
                    let n = n.min(len);
                    if !self.write(&sector[..n], false) {
                        return false;
                    }
                    if n < len {
                        // The data ends inside this sector
                        self.source_ended();
                        return false;
                    }
                }
                Err(e) => {
                    if self.fatal_or_lost(&e) {
                        return false;
                    }
                    self.unreadable += 1;
                    let zero_fill = self.plan.on_read_error == OnReadError::ZeroFill;
                    self.observer
                        .unreadable(self.offset, len as u64, &e, zero_fill);
                    if !zero_fill {
                        let reason = format!(
                            "read error at byte offset {} (sector {}): {e}; the acquisition stopped there (--on-read-error stop)",
                            self.offset,
                            self.offset / ss as u64
                        );
                        self.stop_at(StopKind::ReadError, reason);
                        return false;
                    }
                    if self.consecutive == 0 {
                        self.run_start = self.offset;
                    }
                    self.consecutive += 1;
                    sector[..len].fill(0);
                    if !self.write(&sector[..len], true) {
                        return false;
                    }
                    if self.consecutive >= self.plan.loss_threshold_sectors.max(1) {
                        let reason = format!(
                            "source lost at byte offset {}: {} consecutive sectors from byte offset {} could not be read (last error: {e}); they are zero-filled in the image, the rest of the source was not read",
                            self.offset, self.consecutive, self.run_start
                        );
                        self.stop_at(StopKind::SourceLost, reason);
                        return false;
                    }
                }
            }
            self.progress(false);
        }
        true
    }

    fn finish(mut self) -> CopyResult {
        if let (Some(stop), Some(len)) = (&self.stop, self.plan.length) {
            if stop.kind.is_source_side() && len > self.offset {
                self.table
                    .push(self.offset, len - self.offset, RangeKind::Unread);
            }
        }
        self.progress(true);
        CopyResult {
            bytes_copied: self.offset,
            hashes: self.hasher.finish(),
            read_errors: self.table,
            unreadable_sectors: self.unreadable,
            stop: self.stop,
            aborted: self.aborted,
        }
    }
}

/// Copy the source to `dst` from offset 0 with positioned reads: bulk reads
/// of `plan.chunk_size`, a failed one narrowed down sector by sector and
/// handled per `plan.on_read_error`. Every byte written is hashed once and
/// passed to `observer.data`. Never fails: how it ended is in the result.
pub fn copy_source<R: ReadAt + ?Sized, W: Write + ?Sized>(
    src: &mut R,
    dst: &mut W,
    plan: &CopyPlan,
    observer: &mut dyn CopyObserver,
) -> CopyResult {
    let ss = plan.sector();
    let chunk = round_up(plan.chunk_size.max(ss), ss);
    let mut buf = AlignedBuf::new(chunk);
    let mut c = Copier {
        dst,
        observer,
        plan,
        hasher: StreamHasher::new(plan.selection),
        table: ReadErrorTable::new(ss as u32, RAW_TABLE_SOURCE),
        offset: 0,
        unreadable: 0,
        consecutive: 0,
        run_start: 0,
        stop: None,
        aborted: false,
    };
    loop {
        if c.should_stop() {
            break;
        }
        let want = match plan.length {
            Some(len) if c.offset >= len => break,
            Some(len) => (len - c.offset).min(chunk as u64) as usize,
            None => chunk,
        };
        // Whole sectors (O_DIRECT); a source longer than its size is cut
        let req = round_up(want, ss).min(chunk);
        match src.read_at(&mut buf[..req], c.offset) {
            Ok(0) => {
                c.source_ended();
                break;
            }
            Ok(n) => {
                c.consecutive = 0;
                let n = n.min(want);
                if !c.write(&buf[..n], false) {
                    break;
                }
                if n < want && n % ss != 0 {
                    // The data ends inside a sector: a file, at its end
                    c.source_ended();
                    break;
                }
            }
            Err(e) => {
                if c.fatal_or_lost(&e) || !c.salvage(src, &mut buf, want) {
                    break;
                }
            }
        }
        c.progress(false);
    }
    c.finish()
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// The image file as the engine needs it (a real file; tests wrap it).
pub(crate) trait ImageSink: Write {
    /// Cut the image to `len` bytes.
    fn truncate(&mut self, len: u64) -> io::Result<()>;
    /// fsync.
    fn sync(&mut self) -> io::Result<()>;
}

impl ImageSink for File {
    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.set_len(len)
    }
    fn sync(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

/// Everything the blocking copy needs from the context.
pub(crate) struct CopyJob {
    pub(crate) image: PathBuf,
    pub(crate) pieces: Option<(PathBuf, u64)>,
    pub(crate) plan: CopyPlan,
    pub(crate) sink: ProgressSink,
    pub(crate) abort: Arc<AtomicBool>,
    pub(crate) force: Arc<AtomicBool>,
    pub(crate) expected: u64,
    pub(crate) source: String,
}

impl CopyJob {
    pub(crate) fn from_ctx(ctx: &EngineContext) -> Self {
        let expected = ctx.expected_bytes();
        let config = ctx.config();
        Self {
            image: ctx.output_path(".raw"),
            pieces: config
                .piece_size
                .map(|size| (ctx.output_path(PIECES_SUFFIX), size)),
            plan: CopyPlan::new(
                ctx.sector_size(),
                (expected > 0).then_some(expected),
                config.on_read_error,
                ctx.selection,
            ),
            sink: ctx.progress.clone(),
            abort: ctx.abort.clone(),
            force: ctx.force.clone(),
            expected,
            source: ctx.identity.path.clone(),
        }
    }
}

/// Progress, warnings, pieces and abort for the engine's copy.
struct EngineObserver<'a> {
    sink: &'a ProgressSink,
    abort: &'a AtomicBool,
    force: &'a AtomicBool,
    pieces: Option<&'a mut PiecesOutput>,
    expected: u64,
    segment: String,
    zero_fill: bool,
    start: Instant,
    last_sent: Option<Instant>,
    speed_at: Instant,
    speed_bytes: u64,
    speed: f64,
    ranges_logged: u64,
    last_unreadable_end: Option<u64>,
}

/// Unreadable ranges announced individually in the progress log.
const LOGGED_RANGES: u64 = 20;

impl CopyObserver for EngineObserver<'_> {
    fn data(&mut self, _offset: u64, bytes: &[u8]) {
        if let Some(p) = self.pieces.as_deref_mut() {
            p.update(bytes);
        }
    }

    fn progress(&mut self, p: &CopyProgress) {
        let now = Instant::now();
        if !p.finished
            && self
                .last_sent
                .is_some_and(|t| now.duration_since(t) < Duration::from_millis(100))
        {
            return;
        }
        let dt = now.duration_since(self.speed_at).as_secs_f64();
        if dt >= 0.5 || self.last_sent.is_none() {
            if dt > 0.0 {
                self.speed = p.bytes_done.saturating_sub(self.speed_bytes) as f64 / dt;
            }
            self.speed_at = now;
            self.speed_bytes = p.bytes_done;
        }
        self.last_sent = Some(now);
        let elapsed = self.start.elapsed().as_secs_f64();
        let avg = if elapsed > 0.0 {
            p.bytes_done as f64 / elapsed
        } else {
            0.0
        };
        let pct = if self.expected > 0 {
            (p.bytes_done as f64 * 100.0 / self.expected as f64).min(100.0)
        } else {
            0.0
        };
        let mut message = format!("Reading the source... {pct:.1}%");
        if p.unreadable_sectors > 0 {
            message.push_str(&format!(
                " ({} unreadable{})",
                plural(p.unreadable_sectors, "sector", "sectors"),
                if self.zero_fill { ", zero-filled" } else { "" }
            ));
        }
        self.sink.send(ProgressTelemetry {
            status: AcquisitionStatus::Acquiring,
            bytes_processed: p.bytes_done,
            total_bytes: self.expected,
            percentage: pct,
            speed_bps: self.speed,
            avg_speed_bps: avg,
            elapsed_secs: elapsed as u64,
            eta_secs: (avg > 0.0 && self.expected > p.bytes_done)
                .then(|| ((self.expected - p.bytes_done) as f64 / avg) as u64),
            bad_sectors: p.unreadable_sectors,
            current_segment: self.segment.clone(),
            status_message: message,
            ..Default::default()
        });
    }

    fn unreadable(&mut self, offset: u64, length: u64, error: &io::Error, substituted: bool) {
        let adjacent = self.last_unreadable_end == Some(offset);
        self.last_unreadable_end = Some(offset + length);
        if adjacent {
            return;
        }
        self.ranges_logged += 1;
        let what = if substituted {
            "zero-filled in the image"
        } else {
            "the acquisition stops here"
        };
        let line = format!("unreadable sector at byte offset {offset}: {error}; {what}");
        match self.ranges_logged {
            1 => self.sink.warn(line),
            n if n <= LOGGED_RANGES => self.sink.log(line),
            n if n == LOGGED_RANGES + 1 => self
                .sink
                .log("further unreadable ranges are not logged here; the report lists every range"),
            _ => {}
        }
    }

    fn should_stop(&mut self) -> bool {
        self.abort.load(Ordering::SeqCst) || self.force.load(Ordering::SeqCst)
    }
}

/// The blocking part of [`acquire`]: copy `reader` into `image` (created by
/// the caller), write the pieces file, truncate after a write error, fsync,
/// and describe the result.
pub(crate) fn run_copy(
    job: CopyJob,
    reader: &mut dyn ReadAt,
    image: &mut dyn ImageSink,
) -> EngineOutput {
    let mut notes = Vec::new();
    let mut pieces = match &job.pieces {
        Some((path, size)) => match PiecesOutput::create(path, *size) {
            Ok(p) => Some(p),
            Err(e) => {
                notes.push(format!(
                    "piecewise SHA-256 ({}) was requested, but {} could not be created: {e}; no pieces were recorded",
                    format_iec(*size),
                    path.display()
                ));
                None
            }
        },
        None => None,
    };
    let segment = job
        .image
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let policy = job.plan.on_read_error;
    let mut start = ProgressTelemetry {
        status: AcquisitionStatus::Acquiring,
        total_bytes: job.expected,
        current_segment: segment.clone(),
        ..Default::default()
    };
    start.push_log(format!(
        "Native RAW acquisition of {} to {segment}: {}; on read error: {}",
        job.source,
        reader.describe(),
        policy.label()
    ));
    job.sink.send(start.take_update());

    let mut observer = EngineObserver {
        sink: &job.sink,
        abort: &job.abort,
        force: &job.force,
        pieces: pieces.as_mut(),
        expected: job.expected,
        segment,
        zero_fill: policy == OnReadError::ZeroFill,
        start: Instant::now(),
        last_sent: None,
        speed_at: Instant::now(),
        speed_bytes: 0,
        speed: 0.0,
        ranges_logged: 0,
        last_unreadable_end: None,
    };
    let copy = copy_source(reader, image, &job.plan, &mut observer);
    let io = reader.describe();

    let mut stop_reason = copy.stop.as_ref().map(|s| s.reason.clone());
    if copy.stop.as_ref().is_some_and(|s| !s.kind.is_source_side()) {
        // Partial writes beyond the accounted bytes must not stay in the image
        if let Err(e) = image.truncate(copy.bytes_copied) {
            notes.push(format!(
                "the image could not be truncated to {} bytes after the write error: {e}",
                copy.bytes_copied
            ));
        }
    }
    if let Err(e) = image.sync() {
        let problem = format!("the image could not be flushed to the destination (fsync: {e})");
        if stop_reason.is_none() {
            stop_reason = Some(problem);
        } else {
            notes.push(problem);
        }
    }

    let mut out = EngineOutput {
        bytes_acquired: copy.bytes_copied,
        expected_bytes: job.expected,
        read_errors: copy.read_errors.clone(),
        stop_reason,
        aborted: copy.aborted,
        acquisition_hashes: copy.hashes.clone(),
        image_files: vec![job.image.clone()],
        ..Default::default()
    };
    let mut applied_piece_size = None;
    if let Some(p) = pieces {
        match p.finish() {
            Ok(done) if done.covered_bytes == copy.bytes_copied => {
                applied_piece_size = Some(done.piece_size);
                out.auxiliary_files.push(done.path.clone());
                out.piecewise = Some(done.info());
            }
            Ok(done) => {
                // Cannot happen: every written byte is fed; never claim pieces
                // that do not describe the image
                let _ = std::fs::remove_file(&done.path);
                notes.push(format!(
                    "the piecewise SHA-256 digests covered {} bytes instead of the {} bytes of the image and were discarded",
                    done.covered_bytes, copy.bytes_copied
                ));
            }
            Err(e) => notes.push(format!(
                "piecewise SHA-256 digests could not be recorded: {e}"
            )),
        }
    }

    out.notes.push(match policy {
        OnReadError::Stop => RAW_ERROR_HANDLING.to_string(),
        OnReadError::ZeroFill => RAW_ZERO_FILL_HANDLING.to_string(),
    });
    if copy.aborted {
        out.notes.push(format!(
            "aborted by the examiner after {} bytes; the partial image is kept and its digests describe exactly those bytes",
            copy.bytes_copied
        ));
    }
    if !io.starts_with("O_DIRECT (page cache bypassed)") || io.contains("then buffered") {
        out.notes.push(format!("source reads: {io}"));
    }
    out.notes.extend(notes);
    out.settings = Some(EngineSettings::Raw(RawSettings {
        on_read_error: policy,
        piece_size: applied_piece_size,
        source_io: Some(format!(
            "{io}; positioned reads of {} through the source descriptor held by the session; after a failed read each {}-byte sector of it is read on its own",
            format_iec(job.plan.chunk_size as u64),
            job.plan.sector()
        )),
        source_loss_sectors: (policy == OnReadError::ZeroFill)
            .then_some(job.plan.loss_threshold_sectors.max(1)),
    }));
    out
}

/// Acquire the source into `<base>.raw` (step 8).
pub async fn acquire(ctx: &EngineContext) -> Result<EngineOutput, AcquisitionError> {
    let src = ctx.dup_source().map_err(|e| {
        AcquisitionError::failed(format!("cannot read the source {}: {e}", ctx.identity.path))
    })?;
    let job = CopyJob::from_ctx(ctx);
    tokio::task::spawn_blocking(move || -> Result<EngineOutput, AcquisitionError> {
        let mut image = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&job.image)
            .map_err(|e| {
                AcquisitionError::failed(format!(
                    "cannot create the RAW image {}: {e}",
                    job.image.display()
                ))
            })?;
        let mut reader = UncachedReader::new(src, true);
        Ok(run_copy(job, &mut reader, &mut image))
    })
    .await
    .map_err(|e| AcquisitionError::failed(format!("the RAW copy task failed: {e}")))?
}

/// The verdict of an image re-read: the digests compared with the
/// acquisition stream, and the pieces compared with the pieces file.
fn judge_image(
    selection: HashSelection,
    out: &EngineOutput,
    check: &ImageCheck,
) -> VerificationResult {
    let pieces_part = match &check.pieces {
        Some(Ok(r)) => format!(
            ", {} compared (SHA-256)",
            plural(r.pieces_checked, "piece", "pieces")
        ),
        _ => String::new(),
    };
    let method = format!("image re-read by dfdisk, {}{pieces_part}", check.io);
    let digests = compare_digests(selection, &out.acquisition_hashes, &check.hashes, &method);
    let pieces_problem = match &check.pieces {
        None => return digests,
        Some(Ok(r)) if r.mismatch_count == 0 && r.uncovered_bytes() == 0 => return digests,
        Some(Ok(r)) => Ok(format!("piecewise SHA-256: {}", r.details(20))),
        Some(Err(e)) => Err(format!(
            "the piecewise SHA-256 digests could not be checked: {}",
            e.message
        )),
    };
    match (digests, pieces_problem) {
        (VerificationResult::Mismatched { method, details }, Ok(p) | Err(p)) => {
            VerificationResult::Mismatched {
                method,
                details: format!("{details}; {p}"),
            }
        }
        (VerificationResult::Failed { reason }, Ok(p) | Err(p)) => VerificationResult::Failed {
            reason: format!("{reason}; {p}"),
        },
        (_, Ok(p)) => VerificationResult::Mismatched { method, details: p },
        (_, Err(p)) => VerificationResult::Failed { reason: p },
    }
}

/// Re-hash the written image (step 11, after the session's flush and cache
/// eviction) with O_DIRECT, compare with the acquisition stream and check
/// every piece.
pub async fn verify(ctx: &EngineContext, out: &EngineOutput) -> (VerificationResult, HashResults) {
    if out.image_files.is_empty() {
        return (
            VerificationResult::Failed {
                reason: "the RAW engine produced no image file".into(),
            },
            HashResults::default(),
        );
    }
    let files = out.image_files.clone();
    let tsv = out.piecewise.as_ref().map(|p| PathBuf::from(&p.file));
    let selection = ctx.selection;
    let abort = ctx.abort.clone();
    let sink = ctx.progress.clone();
    let total: u64 = files
        .iter()
        .filter_map(|f| std::fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();
    let task = tokio::task::spawn_blocking(move || {
        let t0 = Instant::now();
        pieces::hash_image(&files, selection, tsv.as_deref(), &abort, |done| {
            let secs = t0.elapsed().as_secs_f64();
            let speed = if secs > 0.0 { done as f64 / secs } else { 0.0 };
            sink.phase_progress(done, total, speed);
        })
    });
    match task.await {
        Ok(Ok(check)) => (judge_image(selection, out, &check), check.hashes),
        Ok(Err(e)) if e.kind == ErrorKind::Aborted => (
            VerificationResult::NotPossible {
                reason: "the image re-read was aborted".into(),
            },
            HashResults::default(),
        ),
        Ok(Err(e)) => (
            VerificationResult::Failed {
                reason: format!("the image could not be re-read: {}", e.message),
            },
            HashResults::default(),
        ),
        Err(e) => (
            VerificationResult::Failed {
                reason: format!("the verification task failed: {e}"),
            },
            HashResults::default(),
        ),
    }
}

/// Read the first `size` bytes of the source through `fd` with positioned
/// reads (the descriptor offset is not used) and hash them with `selection`.
/// The page cache is bypassed (O_DIRECT, switched back afterwards; fallback:
/// buffered reads + POSIX_FADV_DONTNEED), so the read comes from the medium.
/// `progress` gets the bytes read so far. A read error, a short source or
/// the abort flag end it with an error (Failed / Aborted).
pub fn hash_source(
    fd: &File,
    size: u64,
    selection: HashSelection,
    abort: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<HashResults, AcquisitionError> {
    let mut reader = UncachedReader::new(fd, true);
    let mut hasher = StreamHasher::new(selection);
    let mut buf = AlignedBuf::new(CHUNK_SIZE);
    let mut offset = 0u64;
    let mut last = Instant::now();
    while offset < size {
        if abort.load(Ordering::SeqCst) {
            return Err(AcquisitionError::aborted(format!(
                "the second source read was aborted at byte offset {offset}"
            )));
        }
        let want = (size - offset).min(CHUNK_SIZE as u64) as usize;
        let req = round_up(want, 512).min(CHUNK_SIZE);
        let n = reader.read_at(&mut buf[..req], offset).map_err(|e| {
            AcquisitionError::failed(format!(
                "read error during the second source read at byte offset {offset}: {e}"
            ))
        })?;
        if n == 0 {
            return Err(AcquisitionError::failed(format!(
                "the source ended at byte offset {offset} during the second read; {size} bytes were expected"
            )));
        }
        let n = n.min(want);
        hasher.update(&buf[..n]);
        offset += n as u64;
        if last.elapsed() >= Duration::from_millis(100) || offset == size {
            progress(offset);
            last = Instant::now();
        }
    }
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::pieces::{read_pieces_file, PieceHasher};
    use crate::engines::session::AcquisitionRequest;
    use crate::models::case::CaseMetadata;
    use crate::models::config::AcquisitionConfig;
    use crate::models::device::BlockDevice;
    use crate::models::identity::{SourceIdentity, SourceKind};
    use digest::Digest;
    use md5::Md5;
    use sha1::Sha1;
    use sha2::Sha256;
    use std::collections::BTreeSet;

    const ALL: HashSelection = HashSelection {
        md5: true,
        sha1: true,
        sha256: true,
    };

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251 + 1) as u8).collect()
    }

    fn digests(data: &[u8]) -> HashResults {
        HashResults {
            md5: Some(hex::encode(Md5::digest(data))),
            sha1: Some(hex::encode(Sha1::digest(data))),
            sha256: Some(hex::encode(Sha256::digest(data))),
        }
    }

    /// A block device: reads must be sector aligned; a read touching a bad
    /// sector fails as a whole (EIO), like the kernel's; reads touching
    /// `lost_from` or later fail with ENODEV (device gone).
    struct FakeDevice {
        data: Vec<u8>,
        sector: usize,
        bad: BTreeSet<u64>,
        lost_from: Option<u64>,
        fail_with: Option<i32>,
        reads: usize,
        abort_after: Option<(usize, Arc<AtomicBool>)>,
    }

    impl FakeDevice {
        fn new(data: Vec<u8>, sector: usize) -> Self {
            Self {
                data,
                sector,
                bad: BTreeSet::new(),
                lost_from: None,
                fail_with: None,
                reads: 0,
                abort_after: None,
            }
        }

        fn bad(mut self, sectors: impl IntoIterator<Item = u64>) -> Self {
            self.bad.extend(sectors);
            self
        }
    }

    impl ReadAt for FakeDevice {
        fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            self.reads += 1;
            if let Some((n, flag)) = &self.abort_after {
                if self.reads >= *n {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            assert_eq!(offset % self.sector as u64, 0, "unaligned offset {offset}");
            assert_eq!(buf.len() % self.sector, 0, "unaligned length {}", buf.len());
            if let Some(errno) = self.fail_with {
                return Err(io::Error::from_raw_os_error(errno));
            }
            let len = self.data.len() as u64;
            if offset >= len {
                return Ok(0);
            }
            let end = (offset + buf.len() as u64).min(len);
            if self.lost_from.is_some_and(|l| end > l) {
                return Err(io::Error::from_raw_os_error(libc::ENODEV));
            }
            let ss = self.sector as u64;
            if (offset / ss..end.div_ceil(ss)).any(|s| self.bad.contains(&s)) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let n = (end - offset) as usize;
            buf[..n].copy_from_slice(&self.data[offset as usize..end as usize]);
            Ok(n)
        }

        fn describe(&self) -> String {
            "fake device reads".into()
        }
    }

    /// Records what the copy reported.
    #[derive(Default)]
    struct Recorder {
        data: Vec<u8>,
        unreadable: Vec<(u64, u64, bool)>,
        last: Option<CopyProgress>,
        stop_after_progress: Option<usize>,
        progress_calls: usize,
    }

    impl CopyObserver for Recorder {
        fn data(&mut self, offset: u64, bytes: &[u8]) {
            assert_eq!(offset, self.data.len() as u64, "data arrives in order");
            self.data.extend_from_slice(bytes);
        }
        fn progress(&mut self, p: &CopyProgress) {
            self.progress_calls += 1;
            self.last = Some(*p);
        }
        fn unreadable(&mut self, offset: u64, length: u64, _e: &io::Error, substituted: bool) {
            self.unreadable.push((offset, length, substituted));
        }
        fn should_stop(&mut self) -> bool {
            self.stop_after_progress
                .is_some_and(|n| self.progress_calls >= n)
        }
    }

    fn plan(ss: u32, len: Option<u64>, policy: OnReadError) -> CopyPlan {
        CopyPlan::new(ss, len, policy, ALL)
    }

    fn run(dev: &mut FakeDevice, plan: &CopyPlan) -> (CopyResult, Vec<u8>, Recorder) {
        let mut image = Vec::new();
        let mut rec = Recorder::default();
        let r = copy_source(dev, &mut image, plan, &mut rec);
        assert_eq!(rec.data, image, "the observer sees exactly the image");
        assert_eq!(r.bytes_copied, image.len() as u64);
        assert_eq!(r.hashes, digests(&image), "digests describe the image");
        assert!(rec.last.unwrap().finished);
        (r, image, rec)
    }

    fn ranges(t: &ReadErrorTable) -> Vec<(u64, u64, RangeKind)> {
        t.ranges
            .iter()
            .map(|r| (r.offset, r.length, r.kind))
            .collect()
    }

    #[test]
    fn complete_copies_hash_everything_once() {
        for ss in [512usize, 4096] {
            let data = sample(3 * CHUNK_SIZE + 5 * ss);
            let mut dev = FakeDevice::new(data.clone(), ss);
            let (r, image, _) = run(
                &mut dev,
                &plan(ss as u32, Some(data.len() as u64), OnReadError::Stop),
            );
            assert_eq!(image, data);
            assert!(r.stop.is_none() && !r.aborted);
            assert!(r.read_errors.is_empty());
            assert_eq!(r.unreadable_sectors, 0);
            assert_eq!(dev.reads, 4, "bulk reads only");
        }
        // A regular file whose size is not a multiple of the sector size
        let data = sample(10_000);
        let mut dev = FakeDevice::new(data.clone(), 512);
        let (r, image, _) = run(&mut dev, &plan(512, Some(10_000), OnReadError::Stop));
        assert_eq!(image, data);
        assert!(r.stop.is_none());
        // Unknown size: until the end of the data
        let mut dev = FakeDevice::new(data.clone(), 512);
        let (r, image, _) = run(&mut dev, &plan(512, None, OnReadError::Stop));
        assert_eq!(image, data);
        assert!(r.stop.is_none());
    }

    #[test]
    fn stop_policy_ends_exactly_at_the_first_bad_sector() {
        for ss in [512u64, 4096] {
            let data = sample(4 * CHUNK_SIZE);
            let bad = CHUNK_SIZE as u64 / ss + 7; // 8th sector of the second chunk
            let mut dev = FakeDevice::new(data.clone(), ss as usize).bad([bad, bad + 1]);
            let (r, image, rec) = run(
                &mut dev,
                &plan(ss as u32, Some(data.len() as u64), OnReadError::Stop),
            );
            let at = bad * ss;
            assert_eq!(image, &data[..at as usize]);
            let stop = r.stop.unwrap();
            assert_eq!(stop.kind, StopKind::ReadError);
            assert_eq!(stop.offset, at);
            assert!(
                stop.reason
                    .contains(&format!("byte offset {at} (sector {bad})")),
                "{}",
                stop.reason
            );
            assert_eq!(r.unreadable_sectors, 1);
            assert_eq!(
                ranges(&r.read_errors),
                [(at, data.len() as u64 - at, RangeKind::Unread)]
            );
            assert_eq!(r.read_errors.sector_size, ss as u32);
            assert_eq!(rec.unreadable, [(at, ss, false)]);
        }
    }

    #[test]
    fn zero_fill_substitutes_exactly_the_bad_sectors() {
        for ss in [512u64, 4096] {
            // Chunks 0, 1 and 3 are damaged, chunk 2 is not
            let data = sample(4 * CHUNK_SIZE);
            let last = data.len() as u64 / ss - 1;
            let in_chunk2 = CHUNK_SIZE as u64 / ss + 2;
            let bad = [3, 4, in_chunk2, last];
            let mut dev = FakeDevice::new(data.clone(), ss as usize).bad(bad);
            let (r, image, rec) = run(
                &mut dev,
                &plan(ss as u32, Some(data.len() as u64), OnReadError::ZeroFill),
            );
            let mut expected = data.clone();
            for s in bad {
                expected[(s * ss) as usize..((s + 1) * ss) as usize].fill(0);
            }
            assert_eq!(image, expected, "full length, zeros where unreadable");
            assert!(r.stop.is_none() && !r.aborted);
            assert_eq!(r.unreadable_sectors, 4);
            assert_eq!(
                ranges(&r.read_errors),
                [
                    (3 * ss, 2 * ss, RangeKind::Substituted),
                    (in_chunk2 * ss, ss, RangeKind::Substituted),
                    (last * ss, ss, RangeKind::Substituted),
                ]
            );
            assert_eq!(r.read_errors.substituted_sectors(), 4);
            assert_eq!(rec.unreadable.len(), 4);
            assert!(rec.unreadable.iter().all(|u| u.2));
            // Only the failing chunks were read sector by sector
            let per_chunk = CHUNK_SIZE as u64 / ss;
            assert_eq!(dev.reads as u64, 4 + 3 * per_chunk);
        }
    }

    #[test]
    fn many_consecutive_unreadable_sectors_mean_the_source_is_lost() {
        let data = sample(2 * CHUNK_SIZE);
        let mut dev = FakeDevice::new(data.clone(), 512).bad(100..400);
        let mut p = plan(512, Some(data.len() as u64), OnReadError::ZeroFill);
        p.loss_threshold_sectors = 8;
        let (r, image, _) = run(&mut dev, &p);
        let stop = r.stop.unwrap();
        assert_eq!(stop.kind, StopKind::SourceLost);
        assert_eq!(stop.offset, 108 * 512);
        assert!(
            stop.reason.starts_with(
                "source lost at byte offset 55296: 8 consecutive sectors from byte offset 51200"
            ),
            "{}",
            stop.reason
        );
        assert_eq!(image.len(), 108 * 512);
        assert_eq!(
            ranges(&r.read_errors),
            [
                (51200, 8 * 512, RangeKind::Substituted),
                (55296, data.len() as u64 - 55296, RangeKind::Unread),
            ]
        );
        // The default threshold is the documented one
        assert_eq!(
            CopyPlan::new(512, None, OnReadError::ZeroFill, ALL).loss_threshold_sectors,
            4096
        );
    }

    #[test]
    fn a_vanished_device_ends_the_copy_at_once() {
        let data = sample(4 * CHUNK_SIZE);
        let mut dev = FakeDevice::new(data.clone(), 512);
        dev.lost_from = Some(3 * CHUNK_SIZE as u64 + 512);
        let (r, image, _) = run(
            &mut dev,
            &plan(512, Some(data.len() as u64), OnReadError::ZeroFill),
        );
        let stop = r.stop.unwrap();
        assert_eq!(stop.kind, StopKind::SourceLost);
        assert_eq!(stop.offset, 3 * CHUNK_SIZE as u64);
        assert!(
            stop.reason
                .starts_with("source lost at byte offset 3145728"),
            "{}",
            stop.reason
        );
        assert_eq!(image, &data[..3 * CHUNK_SIZE]);
        assert_eq!(
            dev.reads, 4,
            "no sector-by-sector retries on a vanished device"
        );
        assert_eq!(r.read_errors.unread_bytes(), CHUNK_SIZE as u64);
        assert_eq!(r.read_errors.substituted_bytes(), 0);
    }

    #[test]
    fn errors_that_are_not_media_errors_stop_without_substitution() {
        let mut dev = FakeDevice::new(sample(CHUNK_SIZE), 512);
        dev.fail_with = Some(libc::EINVAL);
        let (r, image, _) = run(
            &mut dev,
            &plan(512, Some(CHUNK_SIZE as u64), OnReadError::ZeroFill),
        );
        assert!(image.is_empty());
        assert_eq!(r.stop.unwrap().kind, StopKind::ReadFailed);
        assert_eq!(dev.reads, 1);
        assert_eq!(r.read_errors.substituted_bytes(), 0);
    }

    #[test]
    fn a_short_source_is_reported_with_the_missing_part() {
        let data = sample(5000);
        let mut dev = FakeDevice::new(data.clone(), 512);
        let (r, image, _) = run(&mut dev, &plan(512, Some(8192), OnReadError::Stop));
        assert_eq!(image, data);
        let stop = r.stop.unwrap();
        assert_eq!(stop.kind, StopKind::SourceEnded);
        assert!(stop
            .reason
            .contains("end of data after 5000 bytes, but its size was 8192 bytes"));
        assert_eq!(ranges(&r.read_errors), [(5000, 3192, RangeKind::Unread)]);
    }

    /// Accepts `room` bytes, then fails like a full file system.
    struct FullDisk {
        out: Vec<u8>,
        room: usize,
        errno: i32,
    }

    impl Write for FullDisk {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let free = self.room - self.out.len();
            if free == 0 {
                return Err(io::Error::from_raw_os_error(self.errno));
            }
            let n = free.min(buf.len());
            self.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_full_destination_ends_the_copy_at_the_last_written_byte() {
        let data = sample(3 * CHUNK_SIZE);
        let room = CHUNK_SIZE + 1000; // in the middle of the second chunk
        let mut dev = FakeDevice::new(data.clone(), 512);
        let mut disk = FullDisk {
            out: Vec::new(),
            room,
            errno: libc::ENOSPC,
        };
        let mut rec = Recorder::default();
        let r = copy_source(
            &mut dev,
            &mut disk,
            &plan(512, Some(data.len() as u64), OnReadError::Stop),
            &mut rec,
        );
        assert_eq!(r.bytes_copied, room as u64);
        assert_eq!(disk.out, &data[..room]);
        assert_eq!(rec.data, disk.out);
        assert_eq!(r.hashes, digests(&data[..room]));
        let stop = r.stop.unwrap();
        assert_eq!(stop.kind, StopKind::DestinationFull);
        assert!(
            stop.reason
                .starts_with(&format!("destination full at byte offset {room}")),
            "{}",
            stop.reason
        );
        // Not a read error: nothing is listed as unreadable
        assert!(r.read_errors.is_empty());

        // Any other write error is reported as such
        let mut disk = FullDisk {
            out: Vec::new(),
            room: 512,
            errno: libc::EIO,
        };
        let r = copy_source(
            &mut FakeDevice::new(data.clone(), 512),
            &mut disk,
            &plan(512, Some(data.len() as u64), OnReadError::Stop),
            &mut NoObserver,
        );
        let stop = r.stop.unwrap();
        assert_eq!(stop.kind, StopKind::WriteFailed);
        assert!(stop
            .reason
            .starts_with("write error on the destination at byte offset 512"));
    }

    #[test]
    fn abort_keeps_what_was_copied() {
        let data = sample(8 * CHUNK_SIZE);
        let mut dev = FakeDevice::new(data.clone(), 512);
        let mut image = Vec::new();
        let mut rec = Recorder {
            stop_after_progress: Some(2),
            ..Default::default()
        };
        let r = copy_source(
            &mut dev,
            &mut image,
            &plan(512, Some(data.len() as u64), OnReadError::Stop),
            &mut rec,
        );
        assert!(r.aborted);
        assert!(r.stop.is_none());
        assert_eq!(r.bytes_copied, 2 * CHUNK_SIZE as u64);
        assert_eq!(image, &data[..2 * CHUNK_SIZE]);
        assert_eq!(r.hashes, digests(&image));
        assert!(r.read_errors.is_empty());

        // Abort while salvaging a damaged chunk
        let mut dev = FakeDevice::new(data.clone(), 512).bad(0..2048);
        let mut rec = Recorder {
            stop_after_progress: Some(10),
            ..Default::default()
        };
        let r = copy_source(
            &mut dev,
            &mut Vec::new(),
            &plan(512, Some(data.len() as u64), OnReadError::ZeroFill),
            &mut rec,
        );
        assert!(r.aborted);
        assert_eq!(r.bytes_copied, 10 * 512);
        assert_eq!(r.read_errors.substituted_bytes(), 10 * 512);
    }

    // -----------------------------------------------------------------------
    // The engine around the copy
    // -----------------------------------------------------------------------

    fn context(
        dir: &std::path::Path,
        size: u64,
        ss: u32,
        config: AcquisitionConfig,
    ) -> EngineContext {
        let device = BlockDevice {
            name: "sdx".into(),
            path: "/dev/sdx".into(),
            size_bytes: size,
            ..Default::default()
        };
        let identity = SourceIdentity {
            path: "/dev/sdx".into(),
            kernel_name: "sdx".into(),
            kind: SourceKind::Disk,
            size_bytes: size,
            logical_sector_size: ss,
            physical_sector_size: ss,
            ..Default::default()
        };
        let case = CaseMetadata {
            case_number: "C".into(),
            evidence_number: "E".into(),
            examiner: "X".into(),
            ..Default::default()
        };
        let config = AcquisitionConfig {
            output_dir: dir.to_path_buf(),
            ..config
        };
        EngineContext::new(
            AcquisitionRequest::new(device, case, config),
            identity,
            "img",
        )
    }

    fn piece_records(data: &[u8], size: u64) -> Vec<crate::engines::pieces::PieceRecord> {
        let mut out = Vec::new();
        let mut h = PieceHasher::new(size);
        h.update(data, &mut |p| out.push(p));
        h.finish(&mut |p| out.push(p));
        out
    }

    fn create_image(ctx: &EngineContext) -> File {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(ctx.output_path(".raw"))
            .unwrap()
    }

    #[test]
    fn engine_writes_image_pieces_and_states_what_it_applied() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(3 * CHUNK_SIZE + 4096);
        let config = AcquisitionConfig {
            on_read_error: OnReadError::ZeroFill,
            piece_size: Some(1 << 20),
            ..AcquisitionConfig::raw(tmp.path())
        };
        let ctx = context(tmp.path(), data.len() as u64, 4096, config);
        let mut dev = FakeDevice::new(data.clone(), 4096).bad([300]);
        let mut image = create_image(&ctx);
        let out = run_copy(CopyJob::from_ctx(&ctx), &mut dev, &mut image);

        let mut expected = data.clone();
        expected[300 * 4096..301 * 4096].fill(0);
        let written = std::fs::read(ctx.output_path(".raw")).unwrap();
        assert_eq!(written, expected);
        assert_eq!(out.bytes_acquired, data.len() as u64);
        assert_eq!(out.expected_bytes, data.len() as u64);
        assert!(out.stop_reason.is_none() && !out.aborted);
        assert_eq!(out.acquisition_hashes, digests(&expected));
        assert_eq!(
            ranges(&out.read_errors),
            [(300 * 4096, 4096, RangeKind::Substituted)]
        );
        assert_eq!(out.read_errors.source, RAW_TABLE_SOURCE);

        // Pieces: 4 records over the image as written, listed as aux file
        let tsv = ctx.output_path(".pieces.tsv");
        assert_eq!(
            read_pieces_file(&tsv).unwrap(),
            piece_records(&expected, 1 << 20)
        );
        assert_eq!(out.auxiliary_files, vec![tsv.clone()]);
        let pw = out.piecewise.as_ref().unwrap();
        assert_eq!((pw.piece_size, pw.count), (1 << 20, 4));
        assert_eq!(pw.file, tsv.to_string_lossy());
        assert_eq!(
            pw.file_sha256,
            crate::models::info_report::sha256_file(&tsv).unwrap()
        );
        assert!(!ctx.output_path(".pieces.tsv.tmp").exists());

        let Some(EngineSettings::Raw(s)) = &out.settings else {
            panic!()
        };
        assert_eq!(s.on_read_error, OnReadError::ZeroFill);
        assert_eq!(s.piece_size, Some(1 << 20));
        assert_eq!(s.source_loss_sectors, Some(SOURCE_LOSS_SECTORS));
        assert!(RAW_ZERO_FILL_HANDLING.contains(&format!("{SOURCE_LOSS_SECTORS} consecutive")));
        let io = s.source_io.as_deref().unwrap();
        assert!(io.starts_with("fake device reads; positioned reads of 1 MiB through the source descriptor held by the session; after a failed read each 4096-byte sector"), "{io}");
        assert!(out.notes.iter().any(|n| n == RAW_ZERO_FILL_HANDLING));
        assert!(!out.notes.iter().any(|n| n == RAW_ERROR_HANDLING));
    }

    #[test]
    fn engine_abort_keeps_the_partial_image_and_its_pieces() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(6 * CHUNK_SIZE);
        let config = AcquisitionConfig {
            piece_size: Some(1 << 20),
            ..AcquisitionConfig::raw(tmp.path())
        };
        let ctx = context(tmp.path(), data.len() as u64, 512, config);
        let mut dev = FakeDevice::new(data.clone(), 512);
        dev.abort_after = Some((2, ctx.abort.clone()));
        let mut image = create_image(&ctx);
        let out = run_copy(CopyJob::from_ctx(&ctx), &mut dev, &mut image);
        assert!(out.aborted);
        assert_eq!(out.bytes_acquired, 2 * CHUNK_SIZE as u64);
        assert!(out.stop_reason.is_none());
        let written = std::fs::read(ctx.output_path(".raw")).unwrap();
        assert_eq!(written, &data[..2 * CHUNK_SIZE]);
        assert_eq!(out.acquisition_hashes, digests(&written));
        assert_eq!(out.piecewise.as_ref().unwrap().count, 2);
        assert!(out
            .notes
            .iter()
            .any(|n| n.starts_with("aborted by the examiner after 2097152 bytes")));
        assert!(out.notes.iter().any(|n| n == RAW_ERROR_HANDLING));
    }

    /// Writes everything to the real file but reports ENOSPC once `room`
    /// bytes were accepted: the engine must cut the image back.
    struct LyingFullDisk {
        file: File,
        accepted: usize,
        room: usize,
    }

    impl Write for LyingFullDisk {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.accepted >= self.room {
                self.file.write_all(buf)?;
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            let n = (self.room - self.accepted).min(buf.len());
            self.file.write_all(&buf[..n])?;
            self.accepted += n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ImageSink for LyingFullDisk {
        fn truncate(&mut self, len: u64) -> io::Result<()> {
            self.file.set_len(len)
        }
        fn sync(&mut self) -> io::Result<()> {
            self.file.sync_all()
        }
    }

    #[test]
    fn engine_truncates_the_image_after_a_full_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(3 * CHUNK_SIZE);
        let ctx = context(
            tmp.path(),
            data.len() as u64,
            512,
            AcquisitionConfig::raw(tmp.path()),
        );
        let room = CHUNK_SIZE + 4096;
        let mut sink = LyingFullDisk {
            file: create_image(&ctx),
            accepted: 0,
            room,
        };
        let out = run_copy(
            CopyJob::from_ctx(&ctx),
            &mut FakeDevice::new(data.clone(), 512),
            &mut sink,
        );
        let written = std::fs::read(ctx.output_path(".raw")).unwrap();
        assert_eq!(written, &data[..room], "cut back to the accounted bytes");
        assert_eq!(out.bytes_acquired, room as u64);
        assert_eq!(out.acquisition_hashes, digests(&written));
        assert!(out
            .stop_reason
            .as_deref()
            .unwrap()
            .starts_with("destination full at byte offset 1052672"));
        assert!(out.read_errors.is_empty());
        // The pieces describe the truncated image
        let pw = out.piecewise.as_ref().unwrap();
        assert_eq!(pw.count, 1);
        assert_eq!(
            read_pieces_file(std::path::Path::new(&pw.file)).unwrap(),
            piece_records(&written, 1 << 30)
        );
    }

    #[test]
    fn pieces_can_be_switched_off_and_failures_are_noted() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(4096);
        let config = AcquisitionConfig {
            piece_size: None,
            ..AcquisitionConfig::raw(tmp.path())
        };
        let ctx = context(tmp.path(), 4096, 512, config);
        let mut image = create_image(&ctx);
        let out = run_copy(
            CopyJob::from_ctx(&ctx),
            &mut FakeDevice::new(data.clone(), 512),
            &mut image,
        );
        assert!(out.piecewise.is_none() && out.auxiliary_files.is_empty());
        let Some(EngineSettings::Raw(s)) = &out.settings else {
            panic!()
        };
        assert_eq!(s.piece_size, None);
        assert_eq!(s.source_loss_sectors, None, "stop policy: no loss limit");
        assert!(!ctx.output_path(".pieces.tsv").exists());

        // A pieces file that cannot be created: the image is still acquired
        let tmp = tempfile::tempdir().unwrap();
        let ctx = context(tmp.path(), 4096, 512, AcquisitionConfig::raw(tmp.path()));
        std::fs::write(ctx.output_path(".pieces.tsv.tmp"), b"in the way").unwrap();
        let mut image = create_image(&ctx);
        let out = run_copy(
            CopyJob::from_ctx(&ctx),
            &mut FakeDevice::new(data.clone(), 512),
            &mut image,
        );
        assert_eq!(out.bytes_acquired, 4096);
        assert!(out.piecewise.is_none());
        let Some(EngineSettings::Raw(s)) = &out.settings else {
            panic!()
        };
        assert_eq!(s.piece_size, None, "no pieces were applied");
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("no pieces were recorded")),
            "{:?}",
            out.notes
        );
    }

    #[test]
    fn buffered_fallback_is_stated_in_the_report() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(64 * 1024);
        let src = tmp.path().join("src.bin");
        std::fs::write(&src, &data).unwrap();
        let ctx = context(
            tmp.path(),
            data.len() as u64,
            512,
            AcquisitionConfig::raw(tmp.path()),
        );
        let mut reader = UncachedReader::new(File::open(&src).unwrap(), false);
        let mut image = create_image(&ctx);
        let out = run_copy(CopyJob::from_ctx(&ctx), &mut reader, &mut image);
        assert_eq!(std::fs::read(ctx.output_path(".raw")).unwrap(), data);
        let Some(EngineSettings::Raw(s)) = &out.settings else {
            panic!()
        };
        let io = s.source_io.as_deref().unwrap();
        assert!(io.starts_with("buffered reads, each range dropped from the page cache afterwards (POSIX_FADV_DONTNEED)"), "{io}");
        assert!(
            out.notes
                .iter()
                .any(|n| n.starts_with("source reads: buffered reads")),
            "{:?}",
            out.notes
        );
    }

    // -----------------------------------------------------------------------
    // acquire + verify through the held descriptor
    // -----------------------------------------------------------------------

    async fn acquire_file(
        dir: &std::path::Path,
        src: &std::path::Path,
        config: AcquisitionConfig,
    ) -> (EngineContext, EngineOutput) {
        let size = std::fs::metadata(src).unwrap().len();
        let mut ctx = context(dir, size, 512, config);
        ctx.source_fd = Some(File::open(src).unwrap());
        let out = acquire(&ctx).await.unwrap();
        (ctx, out)
    }

    #[tokio::test]
    async fn acquire_and_verify_a_file_and_name_damaged_pieces() {
        // tmpfs where available: O_DIRECT may or may not be accepted there,
        // and the report must say what happened either way
        let base = std::path::Path::new("/dev/shm");
        let tmp = if base.is_dir() {
            tempfile::tempdir_in(base).unwrap_or_else(|_| tempfile::tempdir().unwrap())
        } else {
            tempfile::tempdir().unwrap()
        };
        let data = sample(3 * CHUNK_SIZE + 512);
        let src = tmp.path().join("src.bin");
        std::fs::write(&src, &data).unwrap();
        let out_dir = tmp.path().join("out");
        std::fs::create_dir(&out_dir).unwrap();
        let config = AcquisitionConfig {
            piece_size: Some(1 << 20),
            ..AcquisitionConfig::raw(&out_dir)
        };
        let (ctx, out) = acquire_file(&out_dir, &src, config).await;
        assert_eq!(out.bytes_acquired, data.len() as u64);
        assert_eq!(out.acquisition_hashes, digests(&data));
        assert_eq!(std::fs::read(&out.image_files[0]).unwrap(), data);
        let Some(EngineSettings::Raw(s)) = &out.settings else {
            panic!()
        };
        let io = s.source_io.as_deref().unwrap();
        assert!(
            io.starts_with("O_DIRECT") || io.starts_with("buffered reads"),
            "{io}"
        );

        let (result, image) = verify(&ctx, &out).await;
        assert!(result.is_matched(), "{result:?}");
        assert_eq!(image, digests(&data));
        let VerificationResult::Matched { method } = &result else {
            panic!()
        };
        assert!(method.starts_with("image re-read by dfdisk, "), "{method}");
        assert!(method.ends_with("4 pieces compared (SHA-256)"), "{method}");

        // One flipped bit in the third piece: a mismatch that names it
        let img = out.image_files[0].clone();
        let mut bad = data.clone();
        bad[2 * CHUNK_SIZE + 5] ^= 0x80;
        std::fs::write(&img, &bad).unwrap();
        let (result, _) = verify(&ctx, &out).await;
        let VerificationResult::Mismatched { details, .. } = &result else {
            panic!("{result:?}")
        };
        assert!(details.contains("SHA-256"), "{details}");
        assert!(
            details.contains(
                "piecewise SHA-256: 1 of 4 pieces differs; piece 2 (bytes 2097152-3145727)"
            ),
            "{details}"
        );

        // Image intact, pieces file damaged: still not verified
        std::fs::write(&img, &data).unwrap();
        let tsv = std::path::PathBuf::from(&out.piecewise.as_ref().unwrap().file);
        let text = std::fs::read_to_string(&tsv).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let flipped = if lines[1].ends_with('0') { '1' } else { '0' };
        lines[1].pop();
        lines[1].push(flipped);
        std::fs::write(&tsv, lines.join("\n") + "\n").unwrap();
        let (result, _) = verify(&ctx, &out).await;
        let VerificationResult::Mismatched { details, .. } = &result else {
            panic!("{result:?}")
        };
        assert!(
            details.starts_with("piecewise SHA-256: 1 of 4 pieces differs; piece 0"),
            "{details}"
        );

        // A pieces file that is not one: verification failed
        std::fs::write(&tsv, "garbage\n").unwrap();
        let (result, _) = verify(&ctx, &out).await;
        let VerificationResult::Failed { reason } = &result else {
            panic!("{result:?}")
        };
        assert!(reason.contains("could not be checked"), "{reason}");
    }

    #[tokio::test]
    async fn acquire_without_a_held_descriptor_fails_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = context(tmp.path(), 4096, 512, AcquisitionConfig::raw(tmp.path()));
        let e = acquire(&ctx).await.unwrap_err();
        assert_eq!(e.kind, ErrorKind::Failed);
        assert!(!ctx.output_path(".raw").exists());
    }

    #[test]
    fn second_source_read_hashes_exactly_size_bytes_with_positioned_reads() {
        use std::io::Seek;
        use std::os::unix::io::AsRawFd;
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("src");
        let data = sample(3 * CHUNK_SIZE + 100);
        std::fs::write(&p, &data).unwrap();
        let mut f = File::open(&p).unwrap();
        // The descriptor offset does not matter
        f.seek(std::io::SeekFrom::Start(12345)).unwrap();
        // SAFETY: F_GETFL on our descriptor
        let flags = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) };
        let mut seen = 0;
        let h = hash_source(&f, data.len() as u64, ALL, &AtomicBool::new(false), |n| {
            seen = n
        })
        .unwrap();
        assert_eq!(seen, data.len() as u64);
        assert_eq!(h, digests(&data));
        // SAFETY: as above
        assert_eq!(
            unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) },
            flags,
            "flags restored"
        );
        // A prefix that is not a multiple of the sector size
        let h = hash_source(&f, 1000, ALL, &AtomicBool::new(false), |_| {}).unwrap();
        assert_eq!(h, digests(&data[..1000]));
        // A source shorter than expected fails; abort is an abort
        let e = hash_source(
            &f,
            data.len() as u64 + 1,
            ALL,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Failed);
        assert!(e.message.contains("ended at byte offset"), "{e}");
        let e = hash_source(&f, 10, ALL, &AtomicBool::new(true), |_| {}).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Aborted);
    }
}
