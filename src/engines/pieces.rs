//! Piecewise SHA-256 hashes of an image (R5): `<base>.pieces.tsv` with the
//! header `index\toffset\tlength\tsha256`, written during a RAW acquisition
//! and re-checked by `dfdisk verify --pieces <file>`.
//!
//! File format (UTF-8 text, `\n` line ends, fields separated by one tab,
//! shown here as `\t`):
//!
//! ```text
//! index\toffset\tlength\tsha256
//! 0\t0\t1073741824\t<64 lower-case hex digits>
//! 1\t1073741824\t1073741824\t<...>
//! 2\t2147483648\t4096\t<...>
//! ```
//!
//! Pieces are numbered from 0, contiguous from offset 0 (byte offsets and
//! lengths), every piece has the configured size except the last one, which
//! ends with the image. A piece's digest is the SHA-256 of exactly those
//! bytes of the image. The pieces describe the image, so zero-filled
//! (substituted) sectors are hashed as zeros. When the acquisition stopped
//! early, the pieces cover the bytes that were acquired.
//!
//! A damaged image can be narrowed down to the pieces that differ, and the
//! intact pieces still prove the rest of the image.

use crate::engines::hasher::{AlignedBuf, ImageReader, StreamHasher, CHUNK_SIZE};
use crate::engines::AcquisitionError;
use crate::models::info_report::{sha256_file, HashResults, HashSelection, PiecewiseInfo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// First line of every pieces file.
pub const PIECES_HEADER: &str = "index\toffset\tlength\tsha256";

/// Suffix of the pieces file next to the image (`<base>.pieces.tsv`).
pub const PIECES_SUFFIX: &str = ".pieces.tsv";

/// Mismatching pieces listed individually in a [`PiecesReport`]; all of them
/// are counted.
pub const MAX_LISTED_MISMATCHES: usize = 1000;

/// One line of a pieces file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PieceRecord {
    pub index: u64,
    /// Byte offset in the image
    pub offset: u64,
    /// Bytes in this piece
    pub length: u64,
    /// SHA-256 of the piece, lower-case hex
    pub sha256: String,
}

impl PieceRecord {
    /// First byte after the piece.
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }

    /// The line as written to the file (without the line end).
    pub fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.index, self.offset, self.length, self.sha256
        )
    }
}

// ---------------------------------------------------------------------------
// Hashing pieces of a stream
// ---------------------------------------------------------------------------

/// SHA-256 of consecutive pieces of a byte stream.
#[derive(Clone)]
pub struct PieceHasher {
    piece_size: u64,
    next_index: u64,
    start: u64,
    filled: u64,
    sha: Sha256,
}

impl PieceHasher {
    /// Pieces of `piece_size` bytes (at least 1).
    pub fn new(piece_size: u64) -> Self {
        Self {
            piece_size: piece_size.max(1),
            next_index: 0,
            start: 0,
            filled: 0,
            sha: Sha256::new(),
        }
    }

    pub fn piece_size(&self) -> u64 {
        self.piece_size
    }

    /// Bytes fed so far.
    pub fn bytes(&self) -> u64 {
        self.start + self.filled
    }

    /// Feed the next bytes of the stream; every completed piece goes to `emit`.
    pub fn update(&mut self, mut data: &[u8], emit: &mut dyn FnMut(PieceRecord)) {
        while !data.is_empty() {
            let take = (self.piece_size - self.filled).min(data.len() as u64) as usize;
            self.sha.update(&data[..take]);
            self.filled += take as u64;
            data = &data[take..];
            if self.filled == self.piece_size {
                emit(self.take_piece());
            }
        }
    }

    fn take_piece(&mut self) -> PieceRecord {
        let sha = std::mem::replace(&mut self.sha, Sha256::new());
        let rec = PieceRecord {
            index: self.next_index,
            offset: self.start,
            length: self.filled,
            sha256: hex::encode(sha.finalize()),
        };
        self.next_index += 1;
        self.start += self.filled;
        self.filled = 0;
        rec
    }

    /// The last, shorter piece (if any bytes are pending) goes to `emit`.
    pub fn finish(mut self, emit: &mut dyn FnMut(PieceRecord)) {
        if self.filled > 0 {
            emit(self.take_piece());
        }
    }
}

// ---------------------------------------------------------------------------
// Writing and reading pieces files
// ---------------------------------------------------------------------------

/// Writes the header, then one line per piece.
#[derive(Debug)]
pub struct PiecesWriter<W: Write> {
    out: W,
    count: u64,
    next_offset: u64,
}

impl<W: Write> PiecesWriter<W> {
    /// Writes the header line.
    pub fn new(mut out: W) -> io::Result<Self> {
        writeln!(out, "{PIECES_HEADER}")?;
        Ok(Self {
            out,
            count: 0,
            next_offset: 0,
        })
    }

    /// Append `piece` (must be the next one: index = count, contiguous).
    pub fn write_piece(&mut self, piece: &PieceRecord) -> io::Result<()> {
        if piece.index != self.count || piece.offset != self.next_offset || piece.length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "piece {} at offset {} does not follow piece {} ending at {}",
                    piece.index,
                    piece.offset,
                    self.count.wrapping_sub(1),
                    self.next_offset
                ),
            ));
        }
        writeln!(self.out, "{}", piece.to_line())?;
        self.count += 1;
        self.next_offset = piece.end();
        Ok(())
    }

    /// Pieces written.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Bytes covered by the pieces written.
    pub fn covered_bytes(&self) -> u64 {
        self.next_offset
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

/// Reads and validates a pieces file line by line (it can be large: 1 MiB
/// pieces of a big disk are millions of lines).
#[derive(Debug)]
pub struct PiecesReader<R: BufRead> {
    reader: R,
    line_no: u64,
    next_index: u64,
    next_offset: u64,
    line: String,
}

impl<R: BufRead> PiecesReader<R> {
    /// Reads and checks the header line.
    pub fn new(reader: R) -> Result<Self, String> {
        let mut r = Self {
            reader,
            line_no: 0,
            next_index: 0,
            next_offset: 0,
            line: String::new(),
        };
        match r.next_line()? {
            Some(header) if header == PIECES_HEADER => Ok(r),
            Some(other) => Err(format!(
                "line 1 is not the pieces header \"{}\" (found \"{}\")",
                PIECES_HEADER.replace('\t', "\\t"),
                crate::models::text::sanitize_line(&other)
                    .chars()
                    .take(80)
                    .collect::<String>()
            )),
            None => Err("the file is empty (no pieces header)".into()),
        }
    }

    fn next_line(&mut self) -> Result<Option<String>, String> {
        self.line.clear();
        self.line_no += 1;
        match self.reader.read_line(&mut self.line) {
            Ok(0) => Ok(None),
            Ok(_) => {
                let l = self.line.strip_suffix('\n').unwrap_or(&self.line);
                let l = l.strip_suffix('\r').unwrap_or(l);
                Ok(Some(l.to_string()))
            }
            Err(e) => Err(format!("line {} cannot be read: {e}", self.line_no)),
        }
    }

    /// The next piece; `Ok(None)` at the end of the file.
    pub fn next_piece(&mut self) -> Result<Option<PieceRecord>, String> {
        let Some(line) = self.next_line()? else {
            return Ok(None);
        };
        let n = self.line_no;
        let bad = |what: String| Err(format!("line {n}: {what}"));
        if line.is_empty() {
            return bad("empty line".into());
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 4 {
            return bad(format!(
                "{} tab-separated fields instead of 4 (index, offset, length, sha256)",
                fields.len()
            ));
        }
        let number = |s: &str, name: &str| -> Result<u64, String> {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("line {n}: {name} is not a decimal number"));
            }
            s.parse::<u64>()
                .map_err(|_| format!("line {n}: {name} is out of range"))
        };
        let index = number(fields[0], "index")?;
        let offset = number(fields[1], "offset")?;
        let length = number(fields[2], "length")?;
        let sha = fields[3];
        if index != self.next_index {
            return bad(format!("piece index {index}, expected {}", self.next_index));
        }
        if offset != self.next_offset {
            return bad(format!(
                "piece {index} starts at byte offset {offset}, expected {} (pieces must be contiguous)",
                self.next_offset
            ));
        }
        if length == 0 {
            return bad(format!("piece {index} has length 0"));
        }
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return bad(format!("piece {index}: the SHA-256 is not 64 hex digits"));
        }
        let Some(end) = offset.checked_add(length) else {
            return bad(format!("piece {index} ends beyond 2^64 bytes"));
        };
        self.next_index += 1;
        self.next_offset = end;
        Ok(Some(PieceRecord {
            index,
            offset,
            length,
            sha256: sha.to_ascii_lowercase(),
        }))
    }
}

/// Every piece of a pieces file's text (validated like [`PiecesReader`]).
pub fn parse_pieces(text: &str) -> Result<Vec<PieceRecord>, String> {
    let mut r = PiecesReader::new(text.as_bytes())?;
    let mut out = Vec::new();
    while let Some(p) = r.next_piece()? {
        out.push(p);
    }
    Ok(out)
}

/// Every piece of the pieces file at `path` (small files; checks stream).
pub fn read_pieces_file(path: &Path) -> Result<Vec<PieceRecord>, AcquisitionError> {
    let file = open_pieces(path)?;
    let mut r = PiecesReader::new(BufReader::new(file)).map_err(|e| malformed(path, e))?;
    let mut out = Vec::new();
    while let Some(p) = r.next_piece().map_err(|e| malformed(path, e))? {
        out.push(p);
    }
    Ok(out)
}

fn open_pieces(path: &Path) -> Result<File, AcquisitionError> {
    File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            AcquisitionError::usage(format!("the pieces file {} does not exist", path.display()))
        } else {
            AcquisitionError::failed(format!(
                "the pieces file {} cannot be opened: {e}",
                path.display()
            ))
        }
    })
}

fn malformed(path: &Path, what: String) -> AcquisitionError {
    AcquisitionError::failed(format!(
        "the pieces file {} is not usable: {what}",
        path.display()
    ))
}

// ---------------------------------------------------------------------------
// The pieces file of an acquisition
// ---------------------------------------------------------------------------

/// A finished, renamed pieces file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishedPieces {
    pub path: PathBuf,
    pub piece_size: u64,
    pub count: u64,
    /// Bytes covered (= bytes fed)
    pub covered_bytes: u64,
    /// SHA-256 of the pieces file
    pub sha256: String,
}

impl FinishedPieces {
    /// The report's view of the file.
    pub fn info(&self) -> PiecewiseInfo {
        PiecewiseInfo {
            piece_size: self.piece_size,
            file: self.path.to_string_lossy().into_owned(),
            file_sha256: self.sha256.clone(),
            count: self.count,
        }
    }
}

/// The pieces file written while an image is written: lines go to
/// `<path>.tmp` (created, never overwritten), which becomes `<path>` when
/// [`finish`](Self::finish) succeeds. A failed write stops the pieces (the
/// image goes on) and `finish` reports it.
#[derive(Debug)]
pub struct PiecesOutput {
    path: PathBuf,
    tmp: PathBuf,
    writer: Option<PiecesWriter<BufWriter<File>>>,
    hasher: PieceHasher,
    error: Option<io::Error>,
}

impl std::fmt::Debug for PieceHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PieceHasher")
            .field("piece_size", &self.piece_size)
            .field("bytes", &self.bytes())
            .finish()
    }
}

impl PiecesOutput {
    /// Start `<path>.tmp` with the header (`create_new`: an existing file
    /// is an error).
    pub fn create(path: &Path, piece_size: u64) -> io::Result<Self> {
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        let file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let writer = match PiecesWriter::new(BufWriter::with_capacity(64 * 1024, file)) {
            Ok(w) => w,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            tmp,
            writer: Some(writer),
            hasher: PieceHasher::new(piece_size),
            error: None,
        })
    }

    /// Feed the next bytes of the image.
    pub fn update(&mut self, data: &[u8]) {
        let Self {
            hasher,
            writer,
            error,
            ..
        } = self;
        hasher.update(data, &mut |piece| record(writer, error, &piece));
    }

    /// Bytes fed so far.
    pub fn bytes(&self) -> u64 {
        self.hasher.bytes()
    }

    /// Write the last piece, fsync, rename to the final name and hash the
    /// file. On any error the temporary file is removed.
    pub fn finish(self) -> Result<FinishedPieces, String> {
        let Self {
            path,
            tmp,
            mut writer,
            hasher,
            mut error,
        } = self;
        let piece_size = hasher.piece_size();
        let covered = hasher.bytes();
        hasher.finish(&mut |piece| record(&mut writer, &mut error, &piece));
        let result = (|| -> Result<FinishedPieces, String> {
            if let Some(e) = error {
                return Err(format!("writing {} failed: {e}", tmp.display()));
            }
            let w = writer.take().expect("present until finish");
            let count = w.count();
            let file = w
                .into_inner()
                .into_inner()
                .map_err(|e| format!("writing {} failed: {}", tmp.display(), e.error()))?;
            file.sync_all()
                .map_err(|e| format!("fsync of {} failed: {e}", tmp.display()))?;
            drop(file);
            if path.symlink_metadata().is_ok() {
                return Err(format!("{} already exists; not replaced", path.display()));
            }
            std::fs::rename(&tmp, &path).map_err(|e| {
                format!(
                    "renaming {} to {} failed: {e}",
                    tmp.display(),
                    path.display()
                )
            })?;
            let sha256 = sha256_file(&path)
                .map_err(|e| format!("{} cannot be hashed: {e}", path.display()))?;
            Ok(FinishedPieces {
                path: path.clone(),
                piece_size,
                count,
                covered_bytes: covered,
                sha256,
            })
        })();
        if result.is_err() {
            drop(writer);
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Give up: remove the temporary file.
    pub fn abandon(self) {
        let Self { tmp, writer, .. } = self;
        drop(writer);
        let _ = std::fs::remove_file(&tmp);
    }
}

fn record(
    writer: &mut Option<PiecesWriter<BufWriter<File>>>,
    error: &mut Option<io::Error>,
    piece: &PieceRecord,
) {
    if error.is_some() {
        return;
    }
    if let Some(w) = writer.as_mut() {
        if let Err(e) = w.write_piece(piece) {
            *error = Some(e);
        }
    }
}

// ---------------------------------------------------------------------------
// Checking an image against a pieces file
// ---------------------------------------------------------------------------

/// One piece whose image digest differs from the recorded one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PieceMismatch {
    pub index: u64,
    pub offset: u64,
    pub length: u64,
    pub expected_sha256: String,
    /// SHA-256 of the bytes of this piece present in the image (empty when
    /// none are)
    pub computed_sha256: String,
    /// Bytes of this piece present in the image (less than `length` when the
    /// image ends inside or before the piece)
    pub bytes_present: u64,
}

impl PieceMismatch {
    /// "piece 3 (bytes 3072-4095): recorded ab.., image cd.."
    pub fn describe(&self) -> String {
        let range = format!(
            "piece {} (bytes {}-{})",
            self.index,
            self.offset,
            (self.offset + self.length).saturating_sub(1)
        );
        if self.bytes_present == 0 {
            format!("{range}: not in the image (the image ends before it)")
        } else if self.bytes_present < self.length {
            format!(
                "{range}: the image ends inside it ({} of {} bytes present)",
                self.bytes_present, self.length
            )
        } else {
            format!(
                "{range}: recorded SHA-256 {}, image SHA-256 {}",
                self.expected_sha256, self.computed_sha256
            )
        }
    }
}

/// Result of checking an image against a pieces file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PiecesReport {
    pub pieces_file: PathBuf,
    /// Pieces compared (every piece of the file)
    pub pieces_checked: u64,
    /// Image bytes hashed inside pieces
    pub bytes_checked: u64,
    /// The first [`MAX_LISTED_MISMATCHES`] differing pieces
    pub mismatches: Vec<PieceMismatch>,
    /// All differing pieces
    pub mismatch_count: u64,
    /// Bytes the pieces file covers (sum of the piece lengths)
    pub covered_bytes: u64,
    /// Bytes in the image
    pub image_bytes: u64,
}

impl PiecesReport {
    /// Every piece matched and the pieces cover exactly the image.
    pub fn all_match(&self) -> bool {
        self.pieces_checked > 0
            && self.mismatches.is_empty()
            && self.mismatch_count == 0
            && self.image_bytes == self.covered_bytes
    }

    /// Image bytes after the last piece (not vouched for by the file).
    pub fn uncovered_bytes(&self) -> u64 {
        self.image_bytes.saturating_sub(self.covered_bytes)
    }

    /// One sentence, e.g. "all 3 pieces match (3 GiB)" or "2 of 3 pieces
    /// differ".
    pub fn summary(&self) -> String {
        use crate::models::text::{format_iec, plural};
        let mut s = if self.pieces_checked == 0 {
            format!("{} lists no pieces", self.pieces_file.display())
        } else if self.mismatch_count == 0 && self.pieces_checked == 1 {
            format!(
                "the only piece matches ({})",
                format_iec(self.covered_bytes)
            )
        } else if self.mismatch_count == 0 {
            format!(
                "all {} match ({})",
                plural(self.pieces_checked, "piece", "pieces"),
                format_iec(self.covered_bytes)
            )
        } else {
            format!(
                "{} of {} {}",
                self.mismatch_count,
                plural(self.pieces_checked, "piece", "pieces"),
                if self.mismatch_count == 1 {
                    "differs"
                } else {
                    "differ"
                }
            )
        };
        if self.uncovered_bytes() > 0 {
            s.push_str(&format!(
                "; the image has {} bytes after the last piece that the pieces file does not cover",
                self.uncovered_bytes()
            ));
        }
        s
    }

    /// The summary and the first `limit` differing pieces.
    pub fn details(&self, limit: usize) -> String {
        let mut parts = vec![self.summary()];
        parts.extend(self.mismatches.iter().take(limit).map(|m| m.describe()));
        let listed = self.mismatches.len().min(limit) as u64;
        if self.mismatch_count > listed {
            parts.push(format!(
                "{} more differing pieces not listed here",
                self.mismatch_count - listed
            ));
        }
        parts.join("; ")
    }
}

/// Compares the image stream with a pieces file while it is read.
struct PieceChecker {
    reader: PiecesReader<BufReader<File>>,
    path: PathBuf,
    current: Option<PieceRecord>,
    filled: u64,
    sha: Sha256,
    report: PiecesReport,
    failed: Option<AcquisitionError>,
}

impl PieceChecker {
    fn start(path: &Path) -> Result<Self, AcquisitionError> {
        let file = open_pieces(path)?;
        let reader = PiecesReader::new(BufReader::new(file)).map_err(|e| malformed(path, e))?;
        let mut c = Self {
            reader,
            path: path.to_path_buf(),
            current: None,
            filled: 0,
            sha: Sha256::new(),
            report: PiecesReport {
                pieces_file: path.to_path_buf(),
                ..Default::default()
            },
            failed: None,
        };
        c.advance();
        Ok(c)
    }

    fn advance(&mut self) {
        match self.reader.next_piece() {
            Ok(Some(p)) => {
                self.report.covered_bytes += p.length;
                self.current = Some(p);
            }
            Ok(None) => self.current = None,
            Err(e) => {
                self.failed = Some(malformed(&self.path, e));
                self.current = None;
            }
        }
    }

    fn mismatch(&mut self, m: PieceMismatch) {
        self.report.mismatch_count += 1;
        if self.report.mismatches.len() < MAX_LISTED_MISMATCHES {
            self.report.mismatches.push(m);
        }
    }

    /// The current piece is complete (or the image ended inside it).
    fn close_piece(&mut self) {
        let Some(piece) = self.current.take() else {
            return;
        };
        let sha = std::mem::replace(&mut self.sha, Sha256::new());
        let computed = if self.filled > 0 {
            hex::encode(sha.finalize())
        } else {
            String::new()
        };
        self.report.pieces_checked += 1;
        if self.filled != piece.length || computed != piece.sha256 {
            self.mismatch(PieceMismatch {
                index: piece.index,
                offset: piece.offset,
                length: piece.length,
                expected_sha256: piece.sha256,
                computed_sha256: computed,
                bytes_present: self.filled,
            });
        }
        self.filled = 0;
    }

    fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() && self.failed.is_none() {
            let Some(piece) = &self.current else {
                // Beyond the last piece: counted as uncovered at the end
                return;
            };
            let take = (piece.length - self.filled).min(data.len() as u64) as usize;
            self.sha.update(&data[..take]);
            self.filled += take as u64;
            self.report.bytes_checked += take as u64;
            data = &data[take..];
            if self.filled == piece.length {
                self.close_piece();
                self.advance();
            }
        }
    }

    fn finish(mut self, image_bytes: u64) -> Result<PiecesReport, AcquisitionError> {
        // The image ended: the piece being filled and every later piece differ
        while self.failed.is_none() && self.current.is_some() {
            self.close_piece();
            self.advance();
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        self.report.image_bytes = image_bytes;
        Ok(self.report)
    }
}

/// The image re-read once: selected digests, and the pieces check when a
/// pieces file was given.
#[derive(Debug)]
pub struct ImageCheck {
    pub hashes: HashResults,
    /// `None` without a pieces file; `Err` when the pieces file could not be
    /// read or is malformed (the digests are still valid)
    pub pieces: Option<Result<PiecesReport, AcquisitionError>>,
    /// Bytes read from the image files
    pub image_bytes: u64,
    /// How the image was read (O_DIRECT or buffered + POSIX_FADV_DONTNEED)
    pub io: String,
}

/// Read `image_files` (in order, as one stream) once, computing the
/// `selection` digests and, with `pieces_tsv`, comparing every piece.
/// `progress` gets the bytes read (at most every 100 ms, and at the end).
/// Err: no image or a missing image file = Usage, a read error = Failed, the
/// abort flag = Aborted.
pub fn hash_image(
    image_files: &[PathBuf],
    selection: HashSelection,
    pieces_tsv: Option<&Path>,
    abort: &AtomicBool,
    progress: impl FnMut(u64),
) -> Result<ImageCheck, AcquisitionError> {
    let checker = pieces_tsv.map(PieceChecker::start);
    stream_image(image_files, selection, checker, abort, progress)
}

fn stream_image(
    image_files: &[PathBuf],
    selection: HashSelection,
    checker: Option<Result<PieceChecker, AcquisitionError>>,
    abort: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<ImageCheck, AcquisitionError> {
    if image_files.is_empty() {
        return Err(AcquisitionError::usage("no image file was given"));
    }
    let mut reader = ImageReader::open(image_files).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            AcquisitionError::usage(format!("image file missing: {e}"))
        } else {
            AcquisitionError::failed(format!("the image cannot be read: {e}"))
        }
    })?;
    let (mut checker, mut pieces_error) = match checker {
        None => (None, None),
        Some(Ok(c)) => (Some(c), None),
        Some(Err(e)) => (None, Some(e)),
    };
    let mut hasher = StreamHasher::new(selection);
    let mut buf = AlignedBuf::new(CHUNK_SIZE);
    let mut done = 0u64;
    let mut last = Instant::now();
    loop {
        if abort.load(Ordering::SeqCst) {
            return Err(AcquisitionError::aborted(format!(
                "reading the image was aborted at byte offset {done}"
            )));
        }
        let n = reader
            .read(&mut buf)
            .map_err(|e| AcquisitionError::failed(format!("read error in the image: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if let Some(c) = checker.as_mut() {
            c.feed(&buf[..n]);
        }
        done += n as u64;
        if last.elapsed() >= Duration::from_millis(100) {
            progress(done);
            last = Instant::now();
        }
    }
    progress(done);
    let pieces = match (checker, pieces_error.take()) {
        (Some(c), _) => Some(c.finish(done)),
        (None, Some(e)) => Some(Err(e)),
        (None, None) => None,
    };
    Ok(ImageCheck {
        hashes: hasher.finish(),
        pieces,
        image_bytes: done,
        io: reader.describe(),
    })
}

/// Re-hashes `image_files` (one RAW image or the segments of a split RAW
/// image, in order) piece by piece and compares every piece with `tsv`.
/// Err: missing pieces file or image = Usage; unreadable or malformed
/// pieces file, read error = Failed; abort = Aborted. The image is only read
/// when the pieces file starts with a valid header.
pub fn verify_pieces(
    image_files: &[PathBuf],
    tsv: &Path,
    abort: &AtomicBool,
    progress: impl FnMut(u64),
) -> Result<PiecesReport, AcquisitionError> {
    let checker = PieceChecker::start(tsv)?;
    let none = HashSelection {
        md5: false,
        sha1: false,
        sha256: false,
    };
    let check = stream_image(image_files, none, Some(Ok(checker)), abort, progress)?;
    check.pieces.expect("a pieces file was given")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 13 % 251) as u8).collect()
    }

    fn pieces_of(data: &[u8], size: u64) -> Vec<PieceRecord> {
        let mut out = Vec::new();
        let mut h = PieceHasher::new(size);
        // Feed in odd slices: piece boundaries must not depend on them
        for part in data.chunks(777) {
            h.update(part, &mut |p| out.push(p));
        }
        h.finish(&mut |p| out.push(p));
        out
    }

    #[test]
    fn pieces_cover_the_stream_exactly() {
        let data = sample(10_000);
        let pieces = pieces_of(&data, 4096);
        assert_eq!(pieces.len(), 3);
        assert_eq!(
            pieces
                .iter()
                .map(|p| (p.index, p.offset, p.length))
                .collect::<Vec<_>>(),
            [(0, 0, 4096), (1, 4096, 4096), (2, 8192, 1808)]
        );
        for p in &pieces {
            let bytes = &data[p.offset as usize..p.end() as usize];
            assert_eq!(p.sha256, hex::encode(Sha256::digest(bytes)));
        }
        // Exactly a multiple: no empty last piece; nothing fed: no piece
        assert_eq!(pieces_of(&data[..8192], 4096).len(), 2);
        assert!(pieces_of(&[], 4096).is_empty());
    }

    #[test]
    fn written_files_parse_back() {
        let data = sample(10_000);
        let pieces = pieces_of(&data, 4096);
        let mut w = PiecesWriter::new(Vec::new()).unwrap();
        for p in &pieces {
            w.write_piece(p).unwrap();
        }
        assert_eq!(w.count(), 3);
        assert_eq!(w.covered_bytes(), 10_000);
        let text = String::from_utf8(w.into_inner()).unwrap();
        assert!(text.starts_with("index\toffset\tlength\tsha256\n0\t0\t4096\t"));
        assert!(text.ends_with('\n'));
        assert_eq!(parse_pieces(&text).unwrap(), pieces);
        // CRLF copies parse too; upper-case digests are normalised
        let crlf = text
            .replace('\n', "\r\n")
            .to_uppercase()
            .replace("INDEX\tOFFSET\tLENGTH\tSHA256", PIECES_HEADER);
        assert_eq!(parse_pieces(&crlf).unwrap(), pieces);
        // Writing out of order is refused
        let mut w = PiecesWriter::new(Vec::new()).unwrap();
        assert!(w.write_piece(&pieces[1]).is_err());
    }

    #[test]
    fn malformed_files_are_rejected_with_the_line() {
        let ok = format!("{PIECES_HEADER}\n0\t0\t512\t{}\n", "a".repeat(64));
        assert_eq!(parse_pieces(&ok).unwrap().len(), 1);
        let cases = [
            ("", "empty"),
            ("index offset length sha256\n", "line 1"),
            (
                &*format!("{PIECES_HEADER}\n1\t0\t512\t{}\n", "a".repeat(64)),
                "line 2: piece index 1, expected 0",
            ),
            (
                &*format!("{PIECES_HEADER}\n0\t512\t512\t{}\n", "a".repeat(64)),
                "contiguous",
            ),
            (
                &*format!("{PIECES_HEADER}\n0\t0\t0\t{}\n", "a".repeat(64)),
                "length 0",
            ),
            (
                &*format!("{PIECES_HEADER}\n0\t0\t512\t{}\n", "g".repeat(64)),
                "64 hex",
            ),
            (
                &*format!("{PIECES_HEADER}\n0\t0\t512\n"),
                "3 tab-separated fields",
            ),
            (
                &*format!("{PIECES_HEADER}\n0\t0\t+512\t{}\n", "a".repeat(64)),
                "length is not a decimal",
            ),
            (&*format!("{PIECES_HEADER}\n\n"), "line 2: empty line"),
            (
                &*format!(
                    "{PIECES_HEADER}\n0\t0\t512\t{a}\n1\t512\t18446744073709551615\t{a}\n",
                    a = "a".repeat(64)
                ),
                "beyond 2^64",
            ),
        ];
        for (text, want) in cases {
            let e = parse_pieces(text).unwrap_err();
            assert!(e.contains(want), "{text:?}: {e}");
        }
    }

    #[test]
    fn output_is_renamed_only_when_finished_and_never_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.pieces.tsv");
        let data = sample(5000);
        let mut out = PiecesOutput::create(&path, 2048).unwrap();
        out.update(&data[..3000]);
        assert!(!path.exists());
        assert!(tmp.path().join("x.pieces.tsv.tmp").exists());
        out.update(&data[3000..]);
        assert_eq!(out.bytes(), 5000);
        let done = out.finish().unwrap();
        assert_eq!(done.count, 3);
        assert_eq!(done.covered_bytes, 5000);
        assert_eq!(done.sha256, sha256_file(&path).unwrap());
        assert!(!tmp.path().join("x.pieces.tsv.tmp").exists());
        assert_eq!(read_pieces_file(&path).unwrap(), pieces_of(&data, 2048));
        let info = done.info();
        assert_eq!((info.piece_size, info.count), (2048, 3));

        // A second output for the same name: create refuses an existing tmp,
        // finish refuses an existing final file
        let mut again = PiecesOutput::create(&path, 2048).unwrap();
        assert!(PiecesOutput::create(&path, 2048).is_err());
        again.update(b"x");
        let e = again.finish().unwrap_err();
        assert!(e.contains("already exists"), "{e}");
        assert!(!tmp.path().join("x.pieces.tsv.tmp").exists());
        assert_eq!(read_pieces_file(&path).unwrap(), pieces_of(&data, 2048));

        // Abandon removes the temporary file
        let other = tmp.path().join("y.pieces.tsv");
        PiecesOutput::create(&other, 2048).unwrap().abandon();
        assert!(!tmp.path().join("y.pieces.tsv.tmp").exists());
    }

    fn write_tsv(dir: &Path, pieces: &[PieceRecord]) -> PathBuf {
        let p = dir.join("img.pieces.tsv");
        let mut w = PiecesWriter::new(Vec::new()).unwrap();
        for piece in pieces {
            w.write_piece(piece).unwrap();
        }
        std::fs::write(&p, w.into_inner()).unwrap();
        p
    }

    #[test]
    fn verify_pieces_names_the_damaged_piece() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(3 * 4096 + 100);
        let img = tmp.path().join("img.raw");
        std::fs::write(&img, &data).unwrap();
        let tsv = write_tsv(tmp.path(), &pieces_of(&data, 4096));
        let never = AtomicBool::new(false);

        let r = verify_pieces(std::slice::from_ref(&img), &tsv, &never, |_| {}).unwrap();
        assert!(r.all_match(), "{}", r.summary());
        assert_eq!(r.pieces_checked, 4);
        assert_eq!(r.bytes_checked, data.len() as u64);
        assert!(
            r.summary().starts_with("all 4 pieces match"),
            "{}",
            r.summary()
        );

        let mut bad = data.clone();
        bad[4096 + 17] ^= 1;
        std::fs::write(&img, &bad).unwrap();
        let r = verify_pieces(std::slice::from_ref(&img), &tsv, &never, |_| {}).unwrap();
        assert!(!r.all_match());
        assert_eq!(r.mismatch_count, 1);
        let m = &r.mismatches[0];
        assert_eq!(
            (m.index, m.offset, m.length, m.bytes_present),
            (1, 4096, 4096, 4096)
        );
        assert_eq!(
            m.computed_sha256,
            hex::encode(Sha256::digest(&bad[4096..8192]))
        );
        assert!(
            r.details(10).contains("piece 1 (bytes 4096-8191)"),
            "{}",
            r.details(10)
        );
    }

    #[test]
    fn short_and_long_images_do_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(3 * 4096);
        let tsv = write_tsv(tmp.path(), &pieces_of(&data, 4096));
        let img = tmp.path().join("img.raw");
        let never = AtomicBool::new(false);

        // Ends inside piece 1: piece 1 partly present, piece 2 missing
        std::fs::write(&img, &data[..5000]).unwrap();
        let r = verify_pieces(std::slice::from_ref(&img), &tsv, &never, |_| {}).unwrap();
        assert!(!r.all_match());
        assert_eq!(r.pieces_checked, 3);
        assert_eq!(
            r.mismatches
                .iter()
                .map(|m| (m.index, m.bytes_present))
                .collect::<Vec<_>>(),
            [(1, 904), (2, 0)]
        );
        assert!(r.mismatches[1].describe().contains("not in the image"));
        assert!(r.mismatches[0].describe().contains("904 of 4096 bytes"));

        // Longer than the pieces: every piece matches, the rest is uncovered
        let mut long = data.clone();
        long.extend_from_slice(b"extra");
        std::fs::write(&img, &long).unwrap();
        let r = verify_pieces(std::slice::from_ref(&img), &tsv, &never, |_| {}).unwrap();
        assert_eq!(r.mismatch_count, 0);
        assert_eq!(r.uncovered_bytes(), 5);
        assert!(!r.all_match());
        assert!(
            r.summary().contains("5 bytes after the last piece"),
            "{}",
            r.summary()
        );
    }

    #[test]
    fn split_images_are_one_stream() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(10_000);
        let tsv = write_tsv(tmp.path(), &pieces_of(&data, 4096));
        let segs: Vec<PathBuf> = [&data[..3000], &data[3000..6000], &data[6000..]]
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let p = tmp.path().join(format!("img.{:03}", i + 1));
                std::fs::write(&p, part).unwrap();
                p
            })
            .collect();
        let r = verify_pieces(&segs, &tsv, &AtomicBool::new(false), |_| {}).unwrap();
        assert!(r.all_match(), "{}", r.summary());
    }

    #[test]
    fn errors_have_kinds() {
        use crate::engines::ErrorKind;
        let tmp = tempfile::tempdir().unwrap();
        let img = tmp.path().join("img.raw");
        std::fs::write(&img, sample(100)).unwrap();
        let never = AtomicBool::new(false);
        let tsv = tmp.path().join("missing.tsv");
        let e = verify_pieces(std::slice::from_ref(&img), &tsv, &never, |_| {}).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Usage);
        let tsv = write_tsv(tmp.path(), &pieces_of(&sample(100), 4096));
        let e = verify_pieces(&[tmp.path().join("nope.raw")], &tsv, &never, |_| {}).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Usage);
        let e = verify_pieces(&[], &tsv, &never, |_| {}).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Usage);
        let e = verify_pieces(
            std::slice::from_ref(&img),
            &tsv,
            &AtomicBool::new(true),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Aborted);
        std::fs::write(&tsv, "not a pieces file\n").unwrap();
        let e = verify_pieces(std::slice::from_ref(&img), &tsv, &never, |_| {}).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Failed);
        assert!(e.message.contains("line 1"), "{e}");
    }

    #[test]
    fn hash_image_keeps_digests_when_the_pieces_file_is_broken() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(9000);
        let img = tmp.path().join("img.raw");
        std::fs::write(&img, &data).unwrap();
        let tsv = tmp.path().join("bad.tsv");
        std::fs::write(&tsv, format!("{PIECES_HEADER}\n0\t0\t4096\tzz\n")).unwrap();
        let all = HashSelection {
            md5: true,
            sha1: true,
            sha256: true,
        };
        let mut seen = 0;
        let c = hash_image(
            std::slice::from_ref(&img),
            all,
            Some(&tsv),
            &AtomicBool::new(false),
            |n| seen = n,
        )
        .unwrap();
        assert_eq!(seen, 9000);
        assert_eq!(c.image_bytes, 9000);
        assert_eq!(c.hashes.sha256, Some(hex::encode(Sha256::digest(&data))));
        let e = c.pieces.unwrap().unwrap_err();
        assert!(e.message.contains("line 2"), "{e}");
        assert!(!c.io.is_empty());
    }
}
