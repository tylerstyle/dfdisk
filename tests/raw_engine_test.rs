//! The native RAW engine through its public API and through the session on
//! this host (regular files stand in for devices; no host disk is touched).

mod common;

use common::{audit_sandbox, case, file_device, sample, scratch};
use dfdisk::engines::hasher::ReadAt;
use dfdisk::engines::pieces::{read_pieces_file, verify_pieces, PieceHasher, PIECES_HEADER};
use dfdisk::engines::raw::{
    copy_source, CopyObserver, CopyPlan, NoObserver, StopKind, RAW_ERROR_HANDLING,
    RAW_TABLE_SOURCE, RAW_ZERO_FILL_HANDLING, SOURCE_LOSS_SECTORS,
};
use dfdisk::engines::session::{self, AcquisitionRequest};
use dfdisk::models::config::{AcquisitionConfig, EngineSettings, OnReadError};
use dfdisk::models::info_report::{sha256_file, ForensicInfoReport, HashResults, HashSelection};
use dfdisk::models::outcome::{Outcome, RangeKind, VerificationResult};
use digest::Digest;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const ALL: HashSelection = HashSelection {
    md5: true,
    sha1: true,
    sha256: true,
};
const MIB: usize = 1 << 20;

fn digests(data: &[u8]) -> HashResults {
    HashResults {
        md5: Some(hex::encode(md5::Md5::digest(data))),
        sha1: Some(hex::encode(sha1::Sha1::digest(data))),
        sha256: Some(hex::encode(sha2::Sha256::digest(data))),
    }
}

/// A block device with failing sectors: a read touching one fails as a
/// whole with EIO; reads touching `lost_from` or later fail with ENODEV.
struct Device {
    data: Vec<u8>,
    sector: u64,
    bad: BTreeSet<u64>,
    lost_from: Option<u64>,
}

impl ReadAt for Device {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        assert_eq!(offset % self.sector, 0);
        assert_eq!(buf.len() as u64 % self.sector, 0);
        let len = self.data.len() as u64;
        if offset >= len {
            return Ok(0);
        }
        let end = (offset + buf.len() as u64).min(len);
        if self.lost_from.is_some_and(|l| end > l) {
            return Err(io::Error::from_raw_os_error(libc::ENODEV));
        }
        if (offset / self.sector..end.div_ceil(self.sector)).any(|s| self.bad.contains(&s)) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let n = (end - offset) as usize;
        buf[..n].copy_from_slice(&self.data[offset as usize..end as usize]);
        Ok(n)
    }
}

/// Collects what the copy hands to observers.
#[derive(Default)]
struct Seen {
    pieces: Vec<dfdisk::engines::pieces::PieceRecord>,
    hasher: Option<PieceHasher>,
    unreadable: Vec<(u64, u64, bool)>,
}

impl CopyObserver for Seen {
    fn data(&mut self, _offset: u64, bytes: &[u8]) {
        let mut out = Vec::new();
        self.hasher
            .get_or_insert_with(|| PieceHasher::new(MIB as u64))
            .update(bytes, &mut |p| out.push(p));
        self.pieces.extend(out);
    }
    fn unreadable(&mut self, offset: u64, length: u64, _e: &io::Error, substituted: bool) {
        self.unreadable.push((offset, length, substituted));
    }
}

#[test]
fn zero_fill_on_512_and_4096_byte_sectors_lists_exact_ranges() {
    for sector in [512u64, 4096] {
        let data = sample(3 * MIB);
        let bad = [1u64, 2, 3, (MIB as u64 / sector) * 2 + 9];
        let mut dev = Device {
            data: data.clone(),
            sector,
            bad: bad.into_iter().collect(),
            lost_from: None,
        };
        let mut image = Vec::new();
        let mut seen = Seen::default();
        let plan = CopyPlan::new(
            sector as u32,
            Some(data.len() as u64),
            OnReadError::ZeroFill,
            ALL,
        );
        let r = copy_source(&mut dev, &mut image, &plan, &mut seen);

        let mut expected = data.clone();
        for s in bad {
            expected[(s * sector) as usize..((s + 1) * sector) as usize].fill(0);
        }
        assert_eq!(image, expected);
        assert_eq!(r.bytes_copied, data.len() as u64);
        assert_eq!(r.hashes, digests(&expected));
        assert!(r.stop.is_none());
        assert_eq!(r.read_errors.source, RAW_TABLE_SOURCE);
        assert_eq!(r.read_errors.sector_size, sector as u32);
        let ranges: Vec<_> = r
            .read_errors
            .ranges
            .iter()
            .map(|x| (x.offset, x.length, x.kind))
            .collect();
        assert_eq!(
            ranges,
            [
                (sector, 3 * sector, RangeKind::Substituted),
                (bad[3] * sector, sector, RangeKind::Substituted),
            ]
        );
        assert_eq!(r.unreadable_sectors, 4);
        assert_eq!(seen.unreadable.len(), 4);
        // The observer saw the substituted stream (what the pieces describe)
        let mut pieces = seen.pieces;
        seen.hasher.unwrap().finish(&mut |p| pieces.push(p));
        assert_eq!(pieces.len(), 3);
        assert_eq!(
            pieces[2].sha256,
            hex::encode(sha2::Sha256::digest(&expected[2 * MIB..]))
        );
    }
}

#[test]
fn stop_policy_and_source_loss_are_incomplete_with_the_rest_unread() {
    let data = sample(2 * MIB);
    let size = data.len() as u64;
    // Stop: the first bad sector ends it, exactly there
    let mut dev = Device {
        data: data.clone(),
        sector: 512,
        bad: [1000u64].into_iter().collect(),
        lost_from: None,
    };
    let mut image = Vec::new();
    let r = copy_source(
        &mut dev,
        &mut image,
        &CopyPlan::new(512, Some(size), OnReadError::Stop, ALL),
        &mut NoObserver,
    );
    let stop = r.stop.unwrap();
    assert_eq!((stop.kind, stop.offset), (StopKind::ReadError, 512_000));
    assert_eq!(image, &data[..512_000]);
    assert_eq!(r.read_errors.unread_bytes(), size - 512_000);
    assert_eq!(r.read_errors.substituted_bytes(), 0);

    // Zero-fill: a long unreadable run means the source is lost
    let data = sample(4 * MIB);
    let size = data.len() as u64;
    let mut dev = Device {
        data: data.clone(),
        sector: 512,
        bad: (10..).take(SOURCE_LOSS_SECTORS as usize + 10).collect(),
        lost_from: None,
    };
    let r = copy_source(
        &mut dev,
        &mut Vec::new(),
        &CopyPlan::new(512, Some(size), OnReadError::ZeroFill, ALL),
        &mut NoObserver,
    );
    let stop = r.stop.unwrap();
    assert_eq!(stop.kind, StopKind::SourceLost);
    let end = (10 + SOURCE_LOSS_SECTORS) * 512;
    assert_eq!(stop.offset, end);
    assert_eq!(r.read_errors.substituted_bytes(), SOURCE_LOSS_SECTORS * 512);
    assert_eq!(r.read_errors.unread_bytes(), size - end);

    // ENODEV: lost at once
    let mut dev = Device {
        data: data.clone(),
        sector: 512,
        bad: BTreeSet::new(),
        lost_from: Some(MIB as u64 + 4096),
    };
    let r = copy_source(
        &mut dev,
        &mut Vec::new(),
        &CopyPlan::new(512, Some(size), OnReadError::ZeroFill, ALL),
        &mut NoObserver,
    );
    let stop = r.stop.unwrap();
    assert_eq!((stop.kind, stop.offset), (StopKind::SourceLost, MIB as u64));
}

/// Fails like a full file system after `room` bytes.
struct Full {
    written: Vec<u8>,
    room: usize,
}

impl io::Write for Full {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let free = self.room - self.written.len();
        if free == 0 {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        let n = free.min(buf.len());
        self.written.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_full_destination_is_incomplete_at_the_exact_byte() {
    let data = sample(2 * MIB);
    let mut dev = Device {
        data: data.clone(),
        sector: 512,
        bad: BTreeSet::new(),
        lost_from: None,
    };
    let mut disk = Full {
        written: Vec::new(),
        room: 777_777,
    };
    let r = copy_source(
        &mut dev,
        &mut disk,
        &CopyPlan::new(512, Some(data.len() as u64), OnReadError::Stop, ALL),
        &mut NoObserver,
    );
    let stop = r.stop.unwrap();
    assert_eq!(stop.kind, StopKind::DestinationFull);
    assert!(
        stop.reason
            .starts_with("destination full at byte offset 777777"),
        "{}",
        stop.reason
    );
    assert_eq!(r.bytes_copied, 777_777);
    assert_eq!(disk.written, &data[..777_777]);
    assert_eq!(r.hashes, digests(&data[..777_777]));
}

// ---------------------------------------------------------------------------
// Through the session on this host
// ---------------------------------------------------------------------------

async fn run(
    src: &Path,
    serial: &str,
    config: AcquisitionConfig,
) -> Result<ForensicInfoReport, dfdisk::engines::AcquisitionError> {
    audit_sandbox();
    let size = std::fs::metadata(src).unwrap().len();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1000);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let r = session::run(
        AcquisitionRequest::new(file_device(src, size, Some(serial)), case(), config),
        tx,
        Arc::new(AtomicBool::new(false)),
    )
    .await;
    let _ = drain.await;
    r
}

fn raw_config(out: &Path) -> AcquisitionConfig {
    AcquisitionConfig {
        allow_tmpfs: true,
        ..AcquisitionConfig::raw(out)
    }
}

#[tokio::test]
async fn raw_acquisition_records_pieces_that_verify_pieces_rechecks() {
    let tmp = scratch();
    let data = sample(3 * MIB + 512);
    let src = tmp.path().join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let out = tmp.path().join("out");
    let config = AcquisitionConfig {
        piece_size: Some(MIB as u64),
        verify_source: true,
        ..raw_config(&out)
    };
    let report = run(&src, "PIECES01", config).await.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.acquisition_hashes, digests(&data));
    assert!(matches!(
        report.verification.source_reread,
        Some(VerificationResult::Matched { .. })
    ));
    let VerificationResult::Matched { method } = &report.verification.result else {
        panic!("{:?}", report.verification.result)
    };
    assert!(method.contains("4 pieces compared (SHA-256)"), "{method}");

    // The pieces file: listed, hashed, described, and it re-checks
    let pw = report.piecewise.clone().unwrap();
    let tsv = PathBuf::from(&pw.file);
    assert!(tsv.to_string_lossy().ends_with(".pieces.tsv"));
    assert_eq!((pw.piece_size, pw.count), (MIB as u64, 4));
    assert_eq!(pw.file_sha256, sha256_file(&tsv).unwrap());
    assert!(report
        .auxiliary_files
        .iter()
        .any(|f| f.path == pw.file && f.sha256 == pw.file_sha256));
    let text = std::fs::read_to_string(&tsv).unwrap();
    assert!(text.starts_with(&format!("{PIECES_HEADER}\n0\t0\t1048576\t")));
    assert_eq!(read_pieces_file(&tsv).unwrap().len(), 4);
    let EngineSettings::Raw(raw) = &report.effective_config.settings else {
        panic!()
    };
    assert_eq!(raw.piece_size, Some(MIB as u64));
    assert_eq!(raw.on_read_error, OnReadError::Stop);
    assert!(raw.source_io.is_some());
    let rendered = report.render_text();
    assert!(rendered.contains("Piecewise SHA-256"), "{rendered}");
    assert!(rendered.contains("4 pieces of 1 MiB in "), "{rendered}");
    assert!(rendered.contains("Source I/O"), "{rendered}");
    assert!(rendered.contains(RAW_ERROR_HANDLING), "{rendered}");

    let image = PathBuf::from(&report.image_files[0]);
    let never = AtomicBool::new(false);
    let check = verify_pieces(std::slice::from_ref(&image), &tsv, &never, |_| {}).unwrap();
    assert!(check.all_match(), "{}", check.summary());

    // One damaged byte in the last piece is found and named
    let mut damaged = data.clone();
    damaged[3 * MIB + 100] ^= 0xff;
    std::fs::write(&image, &damaged).unwrap();
    let check = verify_pieces(std::slice::from_ref(&image), &tsv, &never, |_| {}).unwrap();
    assert!(!check.all_match());
    assert_eq!(check.mismatch_count, 1);
    assert_eq!(check.mismatches[0].index, 3);
    assert_eq!(check.mismatches[0].offset, 3 * MIB as u64);
}

#[tokio::test]
async fn zero_fill_on_a_readable_source_is_verified_and_says_what_it_would_do() {
    let tmp = scratch();
    let data = sample(MIB + 1000);
    let src = tmp.path().join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let config = AcquisitionConfig {
        on_read_error: OnReadError::ZeroFill,
        ..raw_config(&tmp.path().join("out"))
    };
    let report = run(&src, "ZEROFILL01", config).await.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    assert!(report.read_errors.is_empty());
    assert_eq!(report.bytes_acquired, data.len() as u64);
    assert_eq!(
        std::fs::read(&report.image_files[0]).unwrap(),
        data,
        "a file whose size is not a multiple of 512 is copied exactly"
    );
    let text = report.render_text();
    assert!(text.contains(RAW_ZERO_FILL_HANDLING), "{text}");
    assert!(
        text.contains("replace each unreadable sector by zeros and continue"),
        "{text}"
    );
    // The default piece size (1 GiB) gives one piece for a small source
    assert_eq!(report.piecewise.as_ref().unwrap().count, 1);
}

#[tokio::test]
async fn a_source_that_shrank_is_incomplete_and_the_image_holds_what_was_read() {
    // The probe at the start sees the full file; it shrinks before the copy
    // cannot be arranged through the session (identity check), so this runs
    // the copy API on a real file through the uncached reader instead.
    use dfdisk::engines::hasher::UncachedReader;
    let tmp = scratch();
    let data = sample(MIB + 512);
    let src = tmp.path().join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let file = std::fs::File::open(&src).unwrap();
    let mut reader = UncachedReader::new(&file, true);
    let mut image = Vec::new();
    let r = copy_source(
        &mut reader,
        &mut image,
        &CopyPlan::new(512, Some(2 * MIB as u64), OnReadError::ZeroFill, ALL),
        &mut NoObserver,
    );
    assert_eq!(image, data);
    let stop = r.stop.unwrap();
    assert_eq!(stop.kind, StopKind::SourceEnded);
    assert!(stop.reason.contains("end of data"), "{}", stop.reason);
    assert_eq!(
        r.read_errors.unread_bytes(),
        2 * MIB as u64 - data.len() as u64
    );
}
