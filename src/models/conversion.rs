//! Request and result of an image conversion (§13 Converter).
//!
//! CONVERTER AGENT: these types are the seam the CLI (`convert`,
//! `--rescue-to-e01`) and the TUI converter screen are written against. Add
//! fields as needed; keep the existing ones and their meaning.

use crate::models::case::CaseMetadata;
use crate::models::config::{CompressionLevel, SplitSize};
use crate::models::info_report::HashResults;
use crate::models::outcome::{Outcome, VerificationResult};
use serde::Serialize;
use std::path::PathBuf;

/// Format the converter produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionTarget {
    /// RAW (or split RAW) image to E01
    E01,
    /// E01 segment family to one RAW image
    Raw,
}

/// One conversion as the CLI or the TUI asks for it.
#[derive(Debug, Clone)]
pub struct ConversionRequest {
    /// The image to convert: a RAW file, the first segment of a split RAW
    /// image (`.001`) or the first segment of an EWF family (`.E01`)
    pub source: PathBuf,
    pub target: ConversionTarget,
    pub output_dir: PathBuf,
    /// Case fields; `None` takes them from `<source>.info.json`, and a
    /// conversion without either is a usage error
    pub case: Option<CaseMetadata>,
    /// E01 target only
    pub compression: CompressionLevel,
    /// E01 target only
    pub split_size: SplitSize,
    /// Extra lines for the target's notes and report, e.g. the read-error
    /// summary of the rescue run an E01 is made from
    pub notes: Vec<String>,
    /// Report of the acquisition the source came from, referenced in the
    /// conversion report (and its digests used for the comparison)
    pub source_report: Option<PathBuf>,
}

/// What a conversion produced and how it was verified.
#[derive(Debug, Clone, Serialize)]
pub struct ConversionReport {
    pub source: PathBuf,
    pub target: ConversionTarget,
    pub output_files: Vec<PathBuf>,
    pub source_hashes: HashResults,
    pub output_hashes: HashResults,
    pub verification: VerificationResult,
    pub outcome: Outcome,
    pub report_file: PathBuf,
    pub report_json_file: PathBuf,
    pub notes: Vec<String>,
}

impl ConversionReport {
    pub fn exit_code(&self) -> i32 {
        self.outcome.exit_code()
    }
}
