//! Piecewise SHA-256 hashes of an image (R5): `<base>.pieces.tsv` with the
//! header `index\toffset\tlength\tsha256`, written during a RAW acquisition
//! and re-checked by `dfdisk verify --pieces <file>`.
//!
//! RAW AGENT: [`verify_pieces`] is a placeholder with its final signature so
//! the CLI, TUI and verify code can be written against it. Implement the
//! writer, the reader and the check here; keep the signature.

use crate::engines::AcquisitionError;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

/// First line of every pieces file.
pub const PIECES_HEADER: &str = "index\toffset\tlength\tsha256";

/// One piece whose image digest differs from the recorded one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PieceMismatch {
    pub index: u64,
    pub offset: u64,
    pub length: u64,
    pub expected_sha256: String,
    pub computed_sha256: String,
}

/// Result of checking an image against a pieces file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PiecesReport {
    pub pieces_file: PathBuf,
    pub pieces_checked: u64,
    pub bytes_checked: u64,
    pub mismatches: Vec<PieceMismatch>,
}

impl PiecesReport {
    pub fn all_match(&self) -> bool {
        self.pieces_checked > 0 && self.mismatches.is_empty()
    }
}

/// Re-hashes `image_files` (one RAW image or the segments of a split RAW
/// image, in order) piece by piece and compares every piece with `tsv`.
pub fn verify_pieces(
    image_files: &[PathBuf],
    tsv: &Path,
    abort: &AtomicBool,
    progress: impl FnMut(u64),
) -> Result<PiecesReport, AcquisitionError> {
    // Placeholder until the RAW agent implements the check (see module docs)
    let _ = (image_files, abort, progress);
    Err(AcquisitionError::failed(format!(
        "checking {} is not implemented in this build",
        tsv.display()
    )))
}
