//! Native RAW engine (§13 RAW): copies the source through a dup of the
//! session's held descriptor into `<base>.raw`, hashing every byte once, and
//! re-hashes the image for verification. [`hash_source`] is the second
//! source read (`--verify-source`) of every engine.
//!
//! RAW AGENT: this is the 0.1 copy loop adapted to the session interface;
//! O_DIRECT/aligned reads, `--on-read-error zero-fill`, piecewise hashes,
//! source-lost and ENOSPC handling (§13) are still to do.

use crate::engines::error::AcquisitionError;
use crate::engines::hasher::{HashProgress, MultiHasher};
use crate::engines::session::{EngineContext, EngineOutput};
use crate::models::{
    config::{EngineSettings, OnReadError, RawSettings},
    info_report::{compare_digests, HashResults, HashSelection},
    outcome::{RangeKind, ReadErrorTable, VerificationResult},
    telemetry::{AcquisitionStatus, ProgressTelemetry},
};
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How the native RAW engine deals with read errors, stated in every report.
pub const RAW_ERROR_HANDLING: &str =
    "None: native RAW engine stops at the first unreadable sector (no retries, no zero-fill; use rescue mode for damaged media)";

const CHUNK_SIZE: usize = 1024 * 1024;

/// All selected digests, fed from the single read pass.
struct StreamHasher {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
}

impl StreamHasher {
    fn new(selection: HashSelection) -> Self {
        Self {
            md5: selection.md5.then(Md5::new),
            sha1: selection.sha1.then(Sha1::new),
            sha256: selection.sha256.then(Sha256::new),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        if let Some(h) = self.md5.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = self.sha1.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = self.sha256.as_mut() {
            h.update(chunk);
        }
    }

    fn finish(self) -> HashResults {
        HashResults {
            md5: self.md5.map(|h| hex::encode(h.finalize())),
            sha1: self.sha1.map(|h| hex::encode(h.finalize())),
            sha256: self.sha256.map(|h| hex::encode(h.finalize())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CopyOutcome {
    pub bytes_copied: u64,
    /// Digests over exactly the bytes copied
    pub source_hashes: HashResults,
    /// Set when an unreadable sector ended the copy before the end of input
    pub read_error: Option<String>,
}

fn read_retrying_interrupts<R: Read>(src: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match src.read(buf) {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// Copy `src` to `dst`, hashing every byte once. A failed bulk read is retried
/// sector by sector so that everything readable before the first bad sector is
/// still copied, and the exact offset of that sector is reported.
pub fn copy_and_hash<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    sector_size: usize,
    selection: HashSelection,
    abort: &AtomicBool,
    mut on_progress: impl FnMut(u64),
) -> Result<CopyOutcome, String> {
    let mut hasher = StreamHasher::new(selection);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut sector = vec![0u8; sector_size.max(512)];
    let mut copied = 0u64;

    let mut emit =
        |chunk: &[u8], hasher: &mut StreamHasher, copied: &mut u64| -> Result<(), String> {
            hasher.update(chunk);
            dst.write_all(chunk).map_err(|e| {
                if e.kind() == ErrorKind::StorageFull || e.raw_os_error() == Some(28) {
                    "Destination filesystem out of space while writing RAW image".to_string()
                } else {
                    format!("I/O write error to destination: {}", e)
                }
            })?;
            *copied += chunk.len() as u64;
            Ok(())
        };

    'bulk: loop {
        if abort.load(Ordering::Relaxed) {
            return Err("RAW acquisition aborted by user.".to_string());
        }
        match read_retrying_interrupts(src, &mut buffer) {
            Ok(0) => break,
            Ok(n) => emit(&buffer[..n], &mut hasher, &mut copied)?,
            Err(_) => {
                // Narrow the failure down to the first unreadable sector
                let mut salvaged = 0usize;
                while salvaged < CHUNK_SIZE {
                    match read_retrying_interrupts(src, &mut sector) {
                        Ok(0) => break 'bulk,
                        Ok(n) => {
                            emit(&sector[..n], &mut hasher, &mut copied)?;
                            salvaged += n;
                        }
                        Err(e) => {
                            return Ok(CopyOutcome {
                                bytes_copied: copied,
                                source_hashes: hasher.finish(),
                                read_error: Some(format!("{} at byte offset {}", e, copied)),
                            });
                        }
                    }
                }
            }
        }
        on_progress(copied);
    }

    Ok(CopyOutcome {
        bytes_copied: copied,
        source_hashes: hasher.finish(),
        read_error: None,
    })
}

/// Why and where an acquisition stopped before the end of the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompleteAcquisition {
    pub bytes_acquired: u64,
    pub expected_bytes: u64,
    pub reason: String,
}

/// Why a finished copy does not cover the whole source, if it does not.
pub fn incompleteness(outcome: &CopyOutcome, expected_bytes: u64) -> Option<IncompleteAcquisition> {
    let reason = if let Some(err) = &outcome.read_error {
        format!("Read error: {}", err)
    } else if expected_bytes > 0 && outcome.bytes_copied != expected_bytes {
        format!(
            "Source returned end of data after {} bytes, but its reported size is {} bytes",
            outcome.bytes_copied, expected_bytes
        )
    } else {
        return None;
    };
    Some(IncompleteAcquisition {
        bytes_acquired: outcome.bytes_copied,
        expected_bytes,
        reason,
    })
}

/// How the 0.1 copy loop ended.
enum Copy {
    Done(CopyOutcome),
    /// Stopped by the abort flag after this many bytes were written
    Aborted(u64),
}

/// Acquire the source into `<base>.raw` (step 8).
pub async fn acquire(ctx: &EngineContext) -> Result<EngineOutput, AcquisitionError> {
    if ctx.config().on_read_error == OnReadError::ZeroFill {
        return Err(AcquisitionError::usage(
            "--on-read-error zero-fill is not available in this build of the RAW engine",
        ));
    }
    let raw_path = ctx.output_path(".raw");
    let mut src = ctx.dup_source().map_err(|e| {
        AcquisitionError::failed(format!("cannot read the source {}: {e}", ctx.identity.path))
    })?;
    let selection = ctx.selection;
    let expected = ctx.expected_bytes();
    let sector_size = ctx.sector_size() as usize;
    let abort = ctx.abort.clone();
    let sink = ctx.progress.clone();
    let segment_name = format!("{}.raw", ctx.base_name);
    let mut telemetry = ProgressTelemetry {
        status: AcquisitionStatus::Acquiring,
        total_bytes: expected,
        current_segment: segment_name.clone(),
        ..Default::default()
    };
    telemetry.push_log(format!("Native RAW acquisition to {segment_name}"));
    sink.send(telemetry.take_update());

    let target = raw_path.clone();
    let copy = tokio::task::spawn_blocking(move || -> Result<Copy, AcquisitionError> {
        src.seek(SeekFrom::Start(0))?;
        let mut dest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|e| {
                AcquisitionError::failed(format!(
                    "cannot create the RAW image {}: {e}",
                    target.display()
                ))
            })?;
        let start_t = Instant::now();
        let mut last_report = Instant::now();
        let mut last_speed_calc = Instant::now();
        let mut last_read_bytes = 0u64;
        let outcome = copy_and_hash(
            &mut src,
            &mut dest,
            sector_size,
            selection,
            &abort,
            |bytes_processed| {
                if last_report.elapsed() < Duration::from_millis(100) {
                    return;
                }
                let total = expected.max(1);
                let pct = ((bytes_processed as f64 / total as f64) * 100.0).min(100.0);
                let dt = last_speed_calc.elapsed().as_secs_f64();
                let speed = if dt >= 0.1 {
                    let diff = bytes_processed.saturating_sub(last_read_bytes);
                    last_read_bytes = bytes_processed;
                    last_speed_calc = Instant::now();
                    diff as f64 / dt
                } else {
                    0.0
                };
                let elapsed = start_t.elapsed().as_secs_f64();
                let avg_speed = if elapsed > 0.0 {
                    bytes_processed as f64 / elapsed
                } else {
                    0.0
                };
                sink.send(ProgressTelemetry {
                    status: AcquisitionStatus::Acquiring,
                    bytes_processed,
                    total_bytes: expected,
                    speed_bps: speed,
                    avg_speed_bps: avg_speed,
                    percentage: pct,
                    elapsed_secs: elapsed as u64,
                    eta_secs: (avg_speed > 0.0 && expected > bytes_processed)
                        .then(|| ((expected - bytes_processed) as f64 / avg_speed) as u64),
                    current_segment: segment_name.clone(),
                    status_message: format!("Streaming RAW bytes... {:.1}%", pct),
                    ..Default::default()
                });
                last_report = Instant::now();
            },
        );
        // Partial images are kept: they are evidence of what could be read
        let flushed = dest.flush().and_then(|_| dest.sync_all());
        match outcome {
            Ok(o) => {
                flushed.map_err(|e| {
                    AcquisitionError::failed(format!("cannot sync the RAW image: {e}"))
                })?;
                Ok(Copy::Done(o))
            }
            Err(_) if abort.load(Ordering::SeqCst) => {
                Ok(Copy::Aborted(dest.metadata().map(|m| m.len()).unwrap_or(0)))
            }
            Err(e) => Err(AcquisitionError::failed(e)),
        }
    })
    .await
    .map_err(|e| AcquisitionError::failed(format!("the RAW copy task failed: {e}")))??;

    let mut out = EngineOutput {
        expected_bytes: expected,
        read_errors: ReadErrorTable::new(ctx.sector_size(), "raw engine"),
        image_files: vec![raw_path],
        notes: vec![RAW_ERROR_HANDLING.to_string()],
        // What this engine applies: it stops at the first error, no pieces yet
        settings: Some(EngineSettings::Raw(RawSettings {
            on_read_error: OnReadError::Stop,
            piece_size: None,
            source_io: Some("buffered reads through the held source descriptor".into()),
        })),
        ..Default::default()
    };
    match copy {
        Copy::Aborted(bytes) => {
            out.aborted = true;
            out.bytes_acquired = bytes;
            out.notes.push(format!(
                "aborted by the examiner after {bytes} bytes; the partial image is kept"
            ));
        }
        Copy::Done(o) => {
            if let Some(inc) = incompleteness(&o, expected) {
                if o.read_error.is_some() && expected > o.bytes_copied {
                    // Everything from the unreadable sector to the end was not read
                    out.read_errors.push(
                        o.bytes_copied,
                        expected - o.bytes_copied,
                        RangeKind::Unread,
                    );
                }
                out.stop_reason = Some(inc.reason);
            }
            out.bytes_acquired = o.bytes_copied;
            out.acquisition_hashes = o.source_hashes;
        }
    }
    Ok(out)
}

/// Re-hash the written image (step 11, after the session's flush and cache
/// eviction) and compare with the acquisition stream.
pub async fn verify(ctx: &EngineContext, out: &EngineOutput) -> (VerificationResult, HashResults) {
    let Some(image) = out.image_files.first().cloned() else {
        return (
            VerificationResult::Failed {
                reason: "the RAW engine produced no image file".into(),
            },
            HashResults::default(),
        );
    };
    let selection = ctx.selection;
    let abort = ctx.abort.clone();
    let bytes = out.bytes_acquired;
    let (tx, mut rx) = mpsc::channel::<HashProgress>(50);
    let task = tokio::spawn(async move {
        MultiHasher::hash_stream_with_capacity(
            &image,
            selection.md5,
            selection.sha1,
            selection.sha256,
            Some(bytes),
            Some(tx),
            Some(abort),
        )
        .await
    });
    while let Some(hp) = rx.recv().await {
        ctx.progress
            .phase_progress(hp.bytes_hashed, hp.total_bytes, hp.speed_bps);
    }
    match task.await {
        Ok(Ok(image_hashes)) => (
            compare_digests(
                selection,
                &out.acquisition_hashes,
                &image_hashes,
                "image re-read by dfdisk",
            ),
            image_hashes,
        ),
        Ok(Err(e)) => (
            VerificationResult::Failed { reason: e },
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
/// The page cache of the source is dropped first and behind every chunk
/// (POSIX_FADV_DONTNEED), so the read comes from the medium. `progress`
/// gets the bytes read so far. A read error, a short source or the abort
/// flag end it with an error (Failed / Aborted).
pub fn hash_source(
    fd: &File,
    size: u64,
    selection: HashSelection,
    abort: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<HashResults, AcquisitionError> {
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::AsRawFd;
    let evict = |offset: u64, len: u64| {
        // SAFETY: advisory call on a descriptor the caller owns
        unsafe {
            libc::posix_fadvise(
                fd.as_raw_fd(),
                offset as libc::off_t,
                len as libc::off_t,
                libc::POSIX_FADV_DONTNEED,
            )
        };
    };
    evict(0, 0);
    let mut hasher = StreamHasher::new(selection);
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut offset = 0u64;
    let mut last = Instant::now();
    while offset < size {
        if abort.load(Ordering::SeqCst) {
            return Err(AcquisitionError::aborted(format!(
                "the second source read was aborted at byte offset {offset}"
            )));
        }
        let want = (size - offset).min(CHUNK_SIZE as u64) as usize;
        let n = loop {
            match fd.read_at(&mut buf[..want], offset) {
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(AcquisitionError::failed(format!(
                        "read error during the second source read at byte offset {offset}: {e}"
                    )))
                }
                Ok(n) => break n,
            }
        };
        if n == 0 {
            return Err(AcquisitionError::failed(format!(
                "the source ended at byte offset {offset} during the second read; {size} bytes were expected"
            )));
        }
        hasher.update(&buf[..n]);
        evict(offset, n as u64);
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
    use std::io::Cursor;

    /// Device that cannot read any byte at or beyond `bad_from`. Reads stopping
    /// short of it succeed (short reads included), like a block device.
    struct FailingDevice {
        data: Vec<u8>,
        pos: usize,
        bad_from: usize,
    }

    impl Read for FailingDevice {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let end = (self.pos + buf.len()).min(self.data.len());
            if end > self.bad_from {
                return Err(std::io::Error::from_raw_os_error(5));
            }
            let n = end - self.pos;
            buf[..n].copy_from_slice(&self.data[self.pos..end]);
            self.pos = end;
            Ok(n)
        }
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    const ALL: HashSelection = HashSelection {
        md5: true,
        sha1: true,
        sha256: true,
    };

    fn copy(src: &mut impl Read, out: &mut Vec<u8>, sel: HashSelection) -> CopyOutcome {
        copy_and_hash(src, out, 512, sel, &AtomicBool::new(false), |_| {}).unwrap()
    }

    #[test]
    fn complete_copy_hashes_everything_once() {
        let data = sample(3 * CHUNK_SIZE + 777);
        let mut out = Vec::new();
        let o = copy(&mut Cursor::new(data.clone()), &mut out, ALL);
        assert_eq!(out, data);
        assert_eq!(o.bytes_copied, data.len() as u64);
        assert!(o.read_error.is_none());
        assert_eq!(o.source_hashes.md5, Some(hex::encode(Md5::digest(&data))));
        assert_eq!(o.source_hashes.sha1, Some(hex::encode(Sha1::digest(&data))));
        assert_eq!(
            o.source_hashes.sha256,
            Some(hex::encode(Sha256::digest(&data)))
        );
        assert!(incompleteness(&o, data.len() as u64).is_none());
    }

    #[test]
    fn read_error_keeps_every_readable_sector_and_reports_offset() {
        let data = sample(2 * CHUNK_SIZE);
        let bad = CHUNK_SIZE + 7 * 512; // 8th sector of the second chunk
        let mut dev = FailingDevice {
            data: data.clone(),
            pos: 0,
            bad_from: bad,
        };
        let mut out = Vec::new();
        let o = copy(&mut dev, &mut out, ALL);

        assert_eq!(o.bytes_copied, bad as u64);
        assert_eq!(out, &data[..bad]);
        let err = o.read_error.as_deref().unwrap();
        assert!(err.contains(&format!("byte offset {}", bad)), "{err}");
        // Hashes describe exactly the acquired prefix
        assert_eq!(
            o.source_hashes.sha256,
            Some(hex::encode(Sha256::digest(&data[..bad])))
        );

        let inc = incompleteness(&o, data.len() as u64).unwrap();
        assert_eq!(inc.bytes_acquired, bad as u64);
        assert_eq!(inc.expected_bytes, data.len() as u64);
        assert!(inc.reason.starts_with("Read error"));
    }

    #[test]
    fn read_error_in_first_sector_copies_nothing() {
        let mut dev = FailingDevice {
            data: sample(4096),
            pos: 0,
            bad_from: 0,
        };
        let mut out = Vec::new();
        let o = copy(&mut dev, &mut out, ALL);
        assert_eq!(o.bytes_copied, 0);
        assert!(out.is_empty());
        assert!(o.read_error.unwrap().contains("byte offset 0"));
    }

    #[test]
    fn short_source_is_incomplete_without_read_error() {
        let o = copy(&mut Cursor::new(sample(1000)), &mut Vec::new(), ALL);
        let inc = incompleteness(&o, 4096).unwrap();
        assert!(
            inc.reason.contains("end of data after 1000 bytes"),
            "{}",
            inc.reason
        );
    }

    #[test]
    fn only_selected_digests_are_computed() {
        let sel = HashSelection {
            md5: false,
            sha1: false,
            sha256: true,
        };
        let o = copy(&mut Cursor::new(sample(10)), &mut Vec::new(), sel);
        assert!(o.source_hashes.md5.is_none());
        assert!(o.source_hashes.sha1.is_none());
        assert!(o.source_hashes.sha256.is_some());
    }

    #[test]
    fn second_source_read_hashes_exactly_size_bytes_with_positioned_reads() {
        use std::io::Seek;
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("src");
        let data = sample(3 * CHUNK_SIZE + 100);
        std::fs::write(&p, &data).unwrap();
        let mut f = File::open(&p).unwrap();
        // The descriptor offset does not matter
        f.seek(std::io::SeekFrom::Start(12345)).unwrap();
        let mut seen = 0;
        let h = hash_source(&f, data.len() as u64, ALL, &AtomicBool::new(false), |n| {
            seen = n
        })
        .unwrap();
        assert_eq!(seen, data.len() as u64);
        assert_eq!(h.sha256, Some(hex::encode(Sha256::digest(&data))));
        assert_eq!(h.md5, Some(hex::encode(Md5::digest(&data))));
        // A prefix
        let h = hash_source(&f, 1000, ALL, &AtomicBool::new(false), |_| {}).unwrap();
        assert_eq!(h.sha1, Some(hex::encode(Sha1::digest(&data[..1000]))));
        // A source shorter than expected fails; abort is an abort
        let e = hash_source(
            &f,
            data.len() as u64 + 1,
            ALL,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(e.kind, crate::engines::ErrorKind::Failed);
        assert!(e.message.contains("ended at byte offset"), "{e}");
        let e = hash_source(&f, 10, ALL, &AtomicBool::new(true), |_| {}).unwrap_err();
        assert_eq!(e.kind, crate::engines::ErrorKind::Aborted);
    }

    #[test]
    fn abort_stops_copy() {
        let r = copy_and_hash(
            &mut Cursor::new(sample(10)),
            &mut Vec::new(),
            512,
            ALL,
            &AtomicBool::new(true),
            |_| {},
        );
        assert!(r.unwrap_err().contains("aborted"));
    }
}
