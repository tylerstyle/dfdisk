//! Digests and uncached reads shared by the engines.
//!
//! - [`StreamHasher`] feeds MD5/SHA-1/SHA-256 (the selected ones) from one
//!   read pass.
//! - [`UncachedReader`] reads a file or block device with positioned reads
//!   that bypass the page cache: O_DIRECT with page-aligned buffers where the
//!   kernel accepts it, otherwise buffered reads followed by
//!   `POSIX_FADV_DONTNEED` for every range read (the report states which, see
//!   [`UncachedReader::describe`]). Verification after the session's flush
//!   and eviction therefore reads the medium, not RAM (M3).
//! - [`ImageReader`] reads the files of an image (one RAW file or the
//!   segments of a split RAW image) as one stream through uncached readers.
//! - [`MultiHasher`] hashes one file with progress reports (rescue engine,
//!   `dfdisk verify`).

use crate::models::info_report::{HashResults, HashSelection};
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::alloc::{self, Layout};
use std::borrow::Borrow;
use std::fs::File;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Alignment of every read buffer: a page satisfies the memory alignment
/// O_DIRECT needs on every Linux block device.
pub const IO_ALIGN: usize = 4096;

/// Size of one bulk read.
pub const CHUNK_SIZE: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// The selected digests, fed in stream order.
#[derive(Clone)]
pub struct StreamHasher {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
}

impl StreamHasher {
    pub fn new(selection: HashSelection) -> Self {
        Self {
            md5: selection.md5.then(Md5::new),
            sha1: selection.sha1.then(Sha1::new),
            sha256: selection.sha256.then(Sha256::new),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if let Some(h) = self.md5.as_mut() {
            h.update(data);
        }
        if let Some(h) = self.sha1.as_mut() {
            h.update(data);
        }
        if let Some(h) = self.sha256.as_mut() {
            h.update(data);
        }
    }

    /// Lower-case hex digests of everything fed so far.
    pub fn finish(self) -> HashResults {
        HashResults {
            md5: self.md5.map(|h| hex::encode(h.finalize())),
            sha1: self.sha1.map(|h| hex::encode(h.finalize())),
            sha256: self.sha256.map(|h| hex::encode(h.finalize())),
        }
    }
}

// ---------------------------------------------------------------------------
// Aligned buffers
// ---------------------------------------------------------------------------

/// A zero-initialised heap buffer aligned to [`IO_ALIGN`] (O_DIRECT reads
/// need aligned memory).
pub struct AlignedBuf {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the buffer is plain owned memory, like a Vec<u8>
unsafe impl Send for AlignedBuf {}
// SAFETY: shared access only hands out &[u8]
unsafe impl Sync for AlignedBuf {}

impl AlignedBuf {
    /// A buffer of `len` bytes (at least one byte is allocated).
    pub fn new(len: usize) -> Self {
        let layout = Self::layout(len);
        // SAFETY: the layout has a non-zero size
        let raw = unsafe { alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        Self { ptr, len }
    }

    fn layout(len: usize) -> Layout {
        Layout::from_size_align(len.max(1), IO_ALIGN).expect("buffer size overflows a Layout")
    }
}

impl Deref for AlignedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: ptr is valid for len initialised bytes for the buffer's lifetime
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, and &mut self guarantees exclusive access
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with exactly this layout
        unsafe { alloc::dealloc(self.ptr.as_ptr(), Self::layout(self.len)) }
    }
}

impl std::fmt::Debug for AlignedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AlignedBuf({} bytes)", self.len)
    }
}

// ---------------------------------------------------------------------------
// Uncached positioned reads
// ---------------------------------------------------------------------------

/// Positioned reads (the descriptor offset is not used). Implemented by
/// [`UncachedReader`]; tests implement it with simulated failing devices.
pub trait ReadAt {
    /// Read up to `buf.len()` bytes at `offset`. Short counts are allowed;
    /// `Ok(0)` is the end of the data. Implementations retry EINTR.
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<usize>;

    /// How the data is read, for the report ("O_DIRECT (page cache
    /// bypassed)", ...).
    fn describe(&self) -> String {
        "positioned reads".to_string()
    }
}

/// How an [`UncachedReader`] currently reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMode {
    /// O_DIRECT: the page cache is bypassed
    Direct,
    /// Buffered reads; every range read is dropped from the page cache
    /// afterwards (POSIX_FADV_DONTNEED) for regular files and block devices
    Buffered,
}

/// Positioned reads from a file or block device that bypass the page cache.
///
/// For a regular file or block device O_DIRECT is switched on for the open
/// file description (`fcntl(F_SETFL)`, so a descriptor the session holds
/// keeps its exclusive claim and nothing is opened again) and switched back
/// when the reader is dropped. When the kernel refuses O_DIRECT for the file,
/// or rejects an O_DIRECT read as misaligned (EINVAL, e.g. a file system with
/// larger alignment needs), the reader continues with buffered reads plus
/// `POSIX_FADV_DONTNEED` and [`describe`](Self::describe) says so. Callers
/// must pass buffers from [`AlignedBuf`] and offsets/lengths that are
/// multiples of the logical sector size to stay on O_DIRECT.
#[derive(Debug)]
pub struct UncachedReader<F: Borrow<File>> {
    file: F,
    mode: ReadMode,
    /// File status flags to restore on drop (O_DIRECT was switched on here)
    restore_flags: Option<libc::c_int>,
    /// Regular file or block device (fadvise applies)
    cacheable: bool,
    /// O_DIRECT was in use for some reads
    direct_used: bool,
    /// Why reads are (or became) buffered
    fallback: Option<String>,
    /// Byte offset at which an O_DIRECT reader switched to buffered reads
    switched_at: Option<u64>,
}

impl<F: Borrow<File>> UncachedReader<F> {
    /// A reader for `file`; `direct` asks for O_DIRECT (falls back as
    /// described on the type). Buffered readers drop the file's cached pages
    /// first.
    pub fn new(file: F, direct: bool) -> Self {
        let kind = file.borrow().metadata().map(|m| m.file_type());
        let cacheable = kind
            .as_ref()
            .is_ok_and(|t| t.is_file() || t.is_block_device());
        let mut reader = Self {
            file,
            mode: ReadMode::Buffered,
            restore_flags: None,
            cacheable,
            direct_used: false,
            fallback: None,
            switched_at: None,
        };
        if !cacheable {
            reader.fallback = Some("not a regular file or block device".into());
        } else if direct {
            match reader.enable_direct() {
                Ok(()) => {
                    reader.mode = ReadMode::Direct;
                    reader.direct_used = true;
                }
                Err(e) => {
                    reader.fallback = Some(format!("O_DIRECT is not supported here ({e})"));
                }
            }
        }
        if reader.mode == ReadMode::Buffered {
            reader.evict(0, 0);
        }
        reader
    }

    fn fd(&self) -> libc::c_int {
        self.file.borrow().as_raw_fd()
    }

    fn enable_direct(&mut self) -> io::Result<()> {
        // SAFETY: fcntl on a descriptor owned by `file`
        let flags = unsafe { libc::fcntl(self.fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_DIRECT != 0 {
            return Ok(());
        }
        // SAFETY: as above
        if unsafe { libc::fcntl(self.fd(), libc::F_SETFL, flags | libc::O_DIRECT) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.restore_flags = Some(flags);
        Ok(())
    }

    fn restore(&mut self) {
        if let Some(flags) = self.restore_flags.take() {
            // SAFETY: fcntl on a descriptor owned by `file`; restores the
            // flags read before O_DIRECT was switched on
            unsafe { libc::fcntl(self.fd(), libc::F_SETFL, flags) };
        }
    }

    /// Drop `len` bytes at `offset` (0, 0: the whole file) from the page cache.
    fn evict(&self, offset: u64, len: u64) {
        if !self.cacheable {
            return;
        }
        // SAFETY: advisory call on a descriptor owned by `file`
        unsafe {
            libc::posix_fadvise(
                self.fd(),
                offset as libc::off_t,
                len as libc::off_t,
                libc::POSIX_FADV_DONTNEED,
            )
        };
    }

    /// Continue with buffered reads (O_DIRECT rejected at `offset`).
    fn fall_back(&mut self, offset: u64, err: &io::Error) {
        self.restore();
        self.mode = ReadMode::Buffered;
        self.switched_at = Some(offset);
        self.fallback = Some(format!(
            "an O_DIRECT read at byte offset {offset} was rejected ({err})"
        ));
        self.evict(0, 0);
    }

    pub fn mode(&self) -> ReadMode {
        self.mode
    }

    /// Why the reader does not (or no longer) use O_DIRECT.
    pub fn fallback_reason(&self) -> Option<&str> {
        self.fallback.as_deref()
    }

    /// Statement for the report, e.g. "O_DIRECT (page cache bypassed)" or
    /// "buffered reads, each range dropped from the page cache afterwards
    /// (POSIX_FADV_DONTNEED); O_DIRECT is not supported here (...)".
    pub fn describe(&self) -> String {
        const BUFFERED: &str =
            "buffered reads, each range dropped from the page cache afterwards (POSIX_FADV_DONTNEED)";
        match (self.mode, self.switched_at, self.fallback.as_deref()) {
            (ReadMode::Direct, _, _) => "O_DIRECT (page cache bypassed)".to_string(),
            (ReadMode::Buffered, Some(at), Some(why)) if self.direct_used => {
                format!(
                    "O_DIRECT (page cache bypassed) up to byte offset {at}, then {BUFFERED}: {why}"
                )
            }
            (ReadMode::Buffered, _, _) if !self.cacheable => {
                "buffered reads (not a regular file or block device)".to_string()
            }
            (ReadMode::Buffered, _, Some(why)) => format!("{BUFFERED}; {why}"),
            (ReadMode::Buffered, _, None) => BUFFERED.to_string(),
        }
    }
}

impl<F: Borrow<File>> ReadAt for UncachedReader<F> {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        loop {
            match self.file.borrow().read_at(buf, offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if self.mode == ReadMode::Direct && e.raw_os_error() == Some(libc::EINVAL) =>
                {
                    self.fall_back(offset, &e);
                }
                Err(e) => return Err(e),
                Ok(n) => {
                    if self.mode == ReadMode::Buffered && n > 0 {
                        self.evict(offset, n as u64);
                    }
                    return Ok(n);
                }
            }
        }
    }

    fn describe(&self) -> String {
        UncachedReader::describe(self)
    }
}

impl<F: Borrow<File>> Drop for UncachedReader<F> {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Round `len` up to a multiple of `unit` (> 0).
pub fn round_up(len: usize, unit: usize) -> usize {
    len.div_ceil(unit) * unit
}

// ---------------------------------------------------------------------------
// Image files as one stream
// ---------------------------------------------------------------------------

/// The files of an image (one RAW file, or split RAW segments in order) read
/// as one stream through [`UncachedReader`]s.
#[derive(Debug)]
pub struct ImageReader {
    files: Vec<PathBuf>,
    sizes: Vec<u64>,
    index: usize,
    current: Option<UncachedReader<File>>,
    pos: u64,
    descriptions: Vec<String>,
}

impl ImageReader {
    /// Every file must exist (their sizes are read now); they are opened one
    /// after the other while reading.
    pub fn open(files: &[PathBuf]) -> io::Result<Self> {
        let sizes = files
            .iter()
            .map(|f| {
                std::fs::metadata(f)
                    .map(|m| m.len())
                    .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", f.display())))
            })
            .collect::<io::Result<Vec<u64>>>()?;
        Ok(Self {
            files: files.to_vec(),
            sizes,
            index: 0,
            current: None,
            pos: 0,
            descriptions: Vec::new(),
        })
    }

    /// Sum of the file sizes at [`open`](Self::open).
    pub fn total_bytes(&self) -> u64 {
        self.sizes.iter().sum()
    }

    /// Read the next bytes of the stream (never across a file boundary, so
    /// every read starts aligned within its file). `Ok(0)`: the end of the
    /// last file. Errors name the file and the offset in it.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.current.is_none() {
                let Some(path) = self.files.get(self.index) else {
                    return Ok(0);
                };
                let file = File::open(path)
                    .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
                self.current = Some(UncachedReader::new(file, true));
                self.pos = 0;
            }
            let reader = self.current.as_mut().expect("opened above");
            let size = self.sizes[self.index];
            // The file is read up to its size at `open` (an unaligned read at
            // the end of a file would only bounce off O_DIRECT)
            let req = if size > self.pos {
                // Aligned request; the file's end gives the short count
                let rest = size - self.pos;
                round_up(rest.min(buf.len() as u64) as usize, 512).min(buf.len())
            } else {
                0
            };
            match if req == 0 {
                Ok(0)
            } else {
                reader.read_at(&mut buf[..req], self.pos)
            } {
                Ok(0) => {
                    self.descriptions.push(reader.describe());
                    self.current = None;
                    self.index += 1;
                }
                Ok(n) if self.pos + n as u64 > size => {
                    // Grown since `open`: the image is what it was then
                    let n = (size - self.pos) as usize;
                    self.pos = size;
                    return Ok(n);
                }
                Ok(n) => {
                    self.pos += n as u64;
                    return Ok(n);
                }
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!(
                            "{} at byte offset {}: {e}",
                            self.files[self.index].display(),
                            self.pos
                        ),
                    ))
                }
            }
        }
    }

    /// How the files were read (one statement when all were read alike).
    pub fn describe(&self) -> String {
        let mut all = self.descriptions.clone();
        if let Some(r) = &self.current {
            all.push(r.describe());
        }
        all.dedup();
        match all.len() {
            0 => "O_DIRECT (page cache bypassed)".to_string(),
            1 => all.remove(0),
            _ => all.join("; "),
        }
    }
}

// ---------------------------------------------------------------------------
// One file with progress reports
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HashProgress {
    pub bytes_hashed: u64,
    pub total_bytes: u64,
    pub speed_bps: f64,
    pub percentage: f64,
}

pub struct MultiHasher;

impl MultiHasher {
    /// Computes MD5, SHA-1, and SHA-256 simultaneously on a file or device
    pub async fn hash_stream(
        path: &Path,
        calc_md5: bool,
        calc_sha1: bool,
        calc_sha256: bool,
        progress_tx: Option<mpsc::Sender<HashProgress>>,
    ) -> Result<HashResults, String> {
        Self::hash_stream_with_capacity(
            path,
            calc_md5,
            calc_sha1,
            calc_sha256,
            None,
            progress_tx,
            None,
        )
        .await
    }

    /// Computes MD5, SHA-1, and SHA-256 simultaneously with an optional abort flag
    pub async fn hash_stream_with_abort(
        path: &Path,
        calc_md5: bool,
        calc_sha1: bool,
        calc_sha256: bool,
        progress_tx: Option<mpsc::Sender<HashProgress>>,
        abort_flag: Option<Arc<AtomicBool>>,
    ) -> Result<HashResults, String> {
        Self::hash_stream_with_capacity(
            path,
            calc_md5,
            calc_sha1,
            calc_sha256,
            None,
            progress_tx,
            abort_flag,
        )
        .await
    }

    /// Computes the selected digests of the whole file or device at `path`
    /// (read uncached, see [`UncachedReader`]); `known_size` (or the file
    /// size, or the block device size) is the progress total.
    pub async fn hash_stream_with_capacity(
        path: &Path,
        calc_md5: bool,
        calc_sha1: bool,
        calc_sha256: bool,
        known_size: Option<u64>,
        progress_tx: Option<mpsc::Sender<HashProgress>>,
        abort_flag: Option<Arc<AtomicBool>>,
    ) -> Result<HashResults, String> {
        let path_buf = path.to_path_buf();
        let selection = HashSelection {
            md5: calc_md5,
            sha1: calc_sha1,
            sha256: calc_sha256,
        };
        tokio::task::spawn_blocking(move || {
            let file = File::open(&path_buf)
                .map_err(|e| format!("Failed to open {}: {}", path_buf.display(), e))?;
            let total_bytes = match known_size {
                Some(n) if n > 0 => n,
                _ => size_of_file(&file),
            };
            let send = |bytes_hashed: u64, total: u64, start: Instant, done: bool| {
                if let Some(tx) = progress_tx.as_ref() {
                    let secs = start.elapsed().as_secs_f64();
                    let _ = tx.blocking_send(HashProgress {
                        bytes_hashed,
                        total_bytes: total,
                        speed_bps: if secs > 0.0 {
                            bytes_hashed as f64 / secs
                        } else {
                            0.0
                        },
                        percentage: if done {
                            100.0
                        } else if total > 0 {
                            bytes_hashed as f64 * 100.0 / total as f64
                        } else {
                            0.0
                        },
                    });
                }
            };

            let mut reader = UncachedReader::new(file, true);
            let mut hasher = StreamHasher::new(selection);
            let mut buffer = AlignedBuf::new(CHUNK_SIZE);
            let mut bytes_hashed: u64 = 0;
            let start = Instant::now();
            let mut last_report = Instant::now();
            loop {
                if abort_flag
                    .as_ref()
                    .is_some_and(|a| a.load(Ordering::Relaxed))
                {
                    return Err("Hashing aborted by user.".to_string());
                }
                let n = reader.read_at(&mut buffer, bytes_hashed).map_err(|e| {
                    format!(
                        "Read error while hashing {} at byte offset {}: {}",
                        path_buf.display(),
                        bytes_hashed,
                        e
                    )
                })?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                bytes_hashed += n as u64;
                if reader.mode() == ReadMode::Direct && n % 512 != 0 {
                    // O_DIRECT reads of a file end short only at its end
                    break;
                }
                if last_report.elapsed().as_millis() >= 100 {
                    send(bytes_hashed, total_bytes, start, false);
                    last_report = Instant::now();
                }
            }
            // The final report reaches 100 %
            let final_total = if total_bytes == 0 {
                bytes_hashed
            } else {
                total_bytes
            };
            send(bytes_hashed, final_total, start, true);
            Ok(hasher.finish())
        })
        .await
        .map_err(|e| format!("Hasher task failed: {}", e))?
    }
}

/// Size of a regular file, or of a block device (BLKGETSIZE64); 0 if unknown.
fn size_of_file(file: &File) -> u64 {
    let Ok(meta) = file.metadata() else {
        return 0;
    };
    if meta.file_type().is_block_device() {
        const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
        let mut size: u64 = 0;
        // SAFETY: BLKGETSIZE64 writes one u64 into `size`
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64 as _, &mut size) };
        return if rc == 0 { size } else { 0 };
    }
    meta.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn test_hash_stream_known_vector() {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("known_vector.txt");
        {
            let mut f = File::create(&test_file).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let (tx, mut rx) = mpsc::channel(10);
        let res = MultiHasher::hash_stream(&test_file, true, true, true, Some(tx))
            .await
            .expect("Hashing should succeed");

        assert_eq!(res.md5.as_deref(), Some("5eb63bbbe01eeed093cb22bb8f5acdc3"));
        assert_eq!(
            res.sha1.as_deref(),
            Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
        );
        assert_eq!(
            res.sha256.as_deref(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );

        // Verify final progress reaches 100%
        let mut last_progress = None;
        while let Some(prog) = rx.recv().await {
            last_progress = Some(prog);
        }
        let final_prog = last_progress.expect("Should have received progress");
        assert_eq!(final_prog.percentage, 100.0);
        assert_eq!(final_prog.bytes_hashed, 11);
    }

    #[tokio::test]
    async fn test_hash_stream_empty_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("empty.txt");
        {
            let _ = File::create(&test_file).unwrap();
        }

        let (tx, mut rx) = mpsc::channel(10);
        let res = MultiHasher::hash_stream(&test_file, true, false, false, Some(tx))
            .await
            .expect("Hashing should succeed");

        assert_eq!(res.md5.as_deref(), Some("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(res.sha1.is_none());
        assert!(res.sha256.is_none());

        let mut last_progress = None;
        while let Some(prog) = rx.recv().await {
            last_progress = Some(prog);
        }
        let final_prog = last_progress.expect("Should have received progress");
        assert_eq!(final_prog.percentage, 100.0);
        assert_eq!(final_prog.bytes_hashed, 0);
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn aligned_buffers_are_aligned_and_zeroed() {
        for len in [1, 511, 4096, CHUNK_SIZE + 3] {
            let mut b = AlignedBuf::new(len);
            assert_eq!(b.as_ptr() as usize % IO_ALIGN, 0);
            assert_eq!(b.len(), len);
            assert!(b.iter().all(|&x| x == 0));
            b[len - 1] = 7;
            assert_eq!(b[len - 1], 7);
        }
        assert_eq!(round_up(1, 512), 512);
        assert_eq!(round_up(512, 512), 512);
        assert_eq!(round_up(0, 512), 0);
    }

    #[test]
    fn uncached_reader_reads_exact_data_and_restores_the_flags() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("img");
        let data = sample(3 * 4096 + 100);
        std::fs::write(&p, &data).unwrap();
        let file = File::open(&p).unwrap();
        // SAFETY: F_GETFL on our descriptor
        let before = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        {
            let mut r = UncachedReader::new(&file, true);
            let mut buf = AlignedBuf::new(8192);
            assert_eq!(r.read_at(&mut buf, 0).unwrap(), 8192);
            assert_eq!(&buf[..], &data[..8192]);
            // The tail: an aligned request gives the short count
            let n = r.read_at(&mut buf, 8192).unwrap();
            assert_eq!(&buf[..n], &data[8192..]);
            assert_eq!(r.read_at(&mut buf, data.len() as u64 + 512).unwrap(), 0);
            // Whatever the file system does, the statement matches the mode
            match r.mode() {
                ReadMode::Direct => assert!(r.describe().starts_with("O_DIRECT")),
                ReadMode::Buffered => assert!(r.describe().contains("POSIX_FADV_DONTNEED")),
            }
        }
        // SAFETY: as above
        let after = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(before, after, "the descriptor's flags are restored");
    }

    #[test]
    fn misaligned_direct_reads_fall_back_to_buffered_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("img");
        let data = sample(64 * 1024);
        std::fs::write(&p, &data).unwrap();
        let mut r = UncachedReader::new(File::open(&p).unwrap(), true);
        let mut buf = AlignedBuf::new(4096);
        // Offset 100 is not sector aligned: O_DIRECT (where enforced) refuses
        let n = r.read_at(&mut buf[..1000], 100).unwrap();
        assert_eq!(&buf[..n], &data[100..100 + n]);
        if r.fallback_reason().is_some() {
            assert_eq!(r.mode(), ReadMode::Buffered);
            let d = r.describe();
            assert!(d.contains("up to byte offset 100, then buffered"), "{d}");
            assert!(d.contains("POSIX_FADV_DONTNEED"), "{d}");
        } else {
            assert_eq!(r.mode(), ReadMode::Direct);
        }
        // Reading continues correctly either way
        let n = r.read_at(&mut buf, 4096).unwrap();
        assert_eq!(&buf[..n], &data[4096..4096 + n]);
    }

    #[test]
    fn buffered_reader_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("img");
        std::fs::write(&p, sample(1000)).unwrap();
        let mut r = UncachedReader::new(File::open(&p).unwrap(), false);
        assert_eq!(r.mode(), ReadMode::Buffered);
        assert!(r.describe().starts_with("buffered reads"));
        let mut buf = vec![0u8; 2000];
        assert_eq!(r.read_at(&mut buf, 0).unwrap(), 1000);
    }

    #[test]
    fn image_reader_concatenates_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(10_000);
        let parts = [&data[..4096], &data[4096..4196], &data[4196..]];
        let files: Vec<PathBuf> = parts
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let p = tmp.path().join(format!("img.{:03}", i + 1));
                std::fs::write(&p, part).unwrap();
                p
            })
            .collect();
        let mut r = ImageReader::open(&files).unwrap();
        assert_eq!(r.total_bytes(), data.len() as u64);
        let mut buf = AlignedBuf::new(CHUNK_SIZE);
        let mut got = Vec::new();
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, data);
        assert!(!r.describe().is_empty());
        // A missing segment is an error naming it
        let e = ImageReader::open(&[tmp.path().join("nope")]).unwrap_err();
        assert!(e.to_string().contains("nope"), "{e}");
    }

    #[test]
    fn stream_hasher_computes_only_the_selection() {
        let mut h = StreamHasher::new(HashSelection {
            md5: false,
            sha1: true,
            sha256: false,
        });
        h.update(b"abc");
        let r = h.finish();
        assert!(r.md5.is_none() && r.sha256.is_none());
        assert_eq!(
            r.sha1.as_deref(),
            Some("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
    }
}
