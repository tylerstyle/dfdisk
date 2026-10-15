//! What the examiner asked for ([`AcquisitionConfig`]) and what an engine
//! actually applies ([`EffectiveConfig`], the only settings a report shows).

use crate::models::identity::{SourceIdentity, SourceKind};
use crate::models::text::format_iec;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ImageFormat {
    #[default]
    E01,
    Raw,
}

impl ImageFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ImageFormat::E01 => "e01",
            ImageFormat::Raw => "raw",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ImageFormat::E01 => "Expert Witness Format (E01)",
            ImageFormat::Raw => "Raw Disk Image (RAW/DD)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CompressionLevel {
    None,
    #[default]
    Fast,
    Best,
}

impl CompressionLevel {
    pub fn as_ewf_arg(&self) -> &'static str {
        match self {
            CompressionLevel::None => "none",
            CompressionLevel::Fast => "fast",
            CompressionLevel::Best => "best",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SplitSize {
    None,
    #[default]
    TwoGb,
    FourGb,
    Custom(u64),
}

impl SplitSize {
    pub fn bytes(&self) -> Option<u64> {
        match self {
            SplitSize::None => None,
            SplitSize::TwoGb => Some(2 * 1024 * 1024 * 1024),
            SplitSize::FourGb => Some(4 * 1024 * 1024 * 1024),
            SplitSize::Custom(b) => Some(*b),
        }
    }

    pub fn as_ewf_arg(&self) -> String {
        match self {
            SplitSize::None => "7900G".to_string(), // Unlimited (EnCase 6 max)
            SplitSize::TwoGb => "2048M".to_string(),
            SplitSize::FourGb => "4096M".to_string(),
            SplitSize::Custom(b) => format!("{}B", b),
        }
    }

    pub fn display_name(&self) -> String {
        match self {
            SplitSize::None => "Single File (No Split)".to_string(),
            SplitSize::TwoGb => "2.0 GiB (2048 MB)".to_string(),
            SplitSize::FourGb => "4.0 GiB (4096 MB)".to_string(),
            SplitSize::Custom(b) => format!("Custom ({} bytes)", b),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
}

impl HashAlgorithm {
    pub fn label(&self) -> &'static str {
        match self {
            HashAlgorithm::MD5 => "MD5",
            HashAlgorithm::SHA1 => "SHA-1",
            HashAlgorithm::SHA256 => "SHA-256",
        }
    }
}

/// Digests an acquisition computes and must verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HashSelection {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
}

impl HashSelection {
    /// Exactly what the configuration selects.
    pub fn from_config(config: &AcquisitionConfig) -> Self {
        Self {
            md5: config.calc_md5,
            sha1: config.calc_sha1,
            sha256: config.calc_sha256,
        }
    }

    /// What the engine computes: an E01 always carries MD5.
    pub fn for_engine(config: &AcquisitionConfig) -> Self {
        let mut s = Self::from_config(config);
        if EngineKind::from_config(config) == EngineKind::Ewf {
            s.md5 = true;
        }
        s
    }

    pub fn algorithms(&self) -> Vec<HashAlgorithm> {
        [
            (self.md5, HashAlgorithm::MD5),
            (self.sha1, HashAlgorithm::SHA1),
            (self.sha256, HashAlgorithm::SHA256),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, a)| a)
        .collect()
    }

    pub fn is_empty(&self) -> bool {
        !(self.md5 || self.sha1 || self.sha256)
    }
}

/// What the native RAW engine does with an unreadable sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnReadError {
    /// Stop at the first unreadable sector (outcome Incomplete, exact offset)
    #[default]
    Stop,
    /// Substitute zeros for each unreadable sector and continue (outcome
    /// CompletedWithReadErrors, every range listed)
    ZeroFill,
}

impl OnReadError {
    pub fn label(&self) -> &'static str {
        match self {
            OnReadError::Stop => "stop at the first unreadable sector",
            OnReadError::ZeroFill => "replace each unreadable sector by zeros and continue",
        }
    }
}

/// Which SMART commands are sent to the source (P4, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SmartPolicy {
    /// No SMART command
    Off,
    /// `smartctl -j -i -H -A -l error`
    #[default]
    Basic,
    /// basic plus the extended logs of `-x`, without SCT commands
    Full,
}

impl SmartPolicy {
    pub fn label(&self) -> &'static str {
        match self {
            SmartPolicy::Off => "off",
            SmartPolicy::Basic => "basic",
            SmartPolicy::Full => "full",
        }
    }
}

/// Whether dfdisk sets the block layer's read-only flag on the source (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriteProtectPolicy {
    /// Set BLKROSET where not already read-only; refuse if that fails
    #[default]
    Auto,
    /// Only record the state
    Off,
}

impl WriteProtectPolicy {
    pub fn label(&self) -> &'static str {
        match self {
            WriteProtectPolicy::Auto => "auto",
            WriteProtectPolicy::Off => "off",
        }
    }
}

/// Identity the examiner expects the source to have (`--expect-*`); any
/// difference refuses the acquisition.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectIdentity {
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub size: Option<u64>,
}

impl ExpectIdentity {
    pub fn is_empty(&self) -> bool {
        self.serial.is_none() && self.wwn.is_none() && self.size.is_none()
    }
}

/// The acquisition engine a configuration selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// Expert Witness Format through ewfacquire
    Ewf,
    /// Native RAW copy
    Raw,
    /// Damaged-media rescue through GNU ddrescue
    Rescue,
}

impl EngineKind {
    /// Rescue mode wins over the image format: ddrescue always writes RAW.
    pub fn from_config(config: &AcquisitionConfig) -> Self {
        if config.rescue_mode {
            EngineKind::Rescue
        } else {
            match config.format {
                ImageFormat::E01 => EngineKind::Ewf,
                ImageFormat::Raw => EngineKind::Raw,
            }
        }
    }

    /// Short machine name used in audit records ("e01", "raw", "rescue").
    pub fn tag(&self) -> &'static str {
        match self {
            EngineKind::Ewf => "e01",
            EngineKind::Raw => "raw",
            EngineKind::Rescue => "rescue",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            EngineKind::Ewf => "E01 (ewfacquire)",
            EngineKind::Raw => "RAW (native dfdisk engine)",
            EngineKind::Rescue => "RAW rescue (GNU ddrescue)",
        }
    }
}

/// Default piece size of piecewise SHA-256 (RAW): 1 GiB.
pub const DEFAULT_PIECE_SIZE: u64 = 1 << 30;
/// Smallest accepted piece size: 1 MiB.
pub const MIN_PIECE_SIZE: u64 = 1 << 20;
/// Highest retry count passed to ewfacquire / ddrescue.
pub const MAX_RETRIES: u32 = 255;
/// `--on-read-error zero-fill` (RAW): consecutive unreadable sectors after
/// which the source counts as lost (§13).
pub const SOURCE_LOSS_SECTORS: u64 = 4096;

fn default_piece_size() -> Option<u64> {
    Some(DEFAULT_PIECE_SIZE)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionConfig {
    pub format: ImageFormat,
    pub output_dir: PathBuf,
    /// E01 only
    pub compression: CompressionLevel,
    /// E01 only; RAW and rescue require `SplitSize::None`
    pub split_size: SplitSize,
    pub calc_md5: bool,
    pub calc_sha1: bool,
    pub calc_sha256: bool,
    /// ewfacquire `-r` / ddrescue `-r`, 0..=255
    pub error_retries: u32,
    /// ewfacquire `-w`: wipe the whole chunk around an unreadable sector
    pub wipe_bad_sectors: bool,
    pub rescue_mode: bool,
    /// Rescue only: continue an interrupted rescue from its map
    pub resume: bool,
    /// RAW only
    #[serde(default)]
    pub on_read_error: OnReadError,
    /// Read the source a second time after the acquisition and compare
    #[serde(default)]
    pub verify_source: bool,
    /// RAW piecewise SHA-256 piece size; `None` disables pieces
    #[serde(default = "default_piece_size")]
    pub piece_size: Option<u64>,
    #[serde(default)]
    pub smart: SmartPolicy,
    #[serde(default)]
    pub write_protect: WriteProtectPolicy,
    /// Accept a tmpfs/ramfs destination
    #[serde(default)]
    pub allow_tmpfs: bool,
    /// Accept an E01 destination with less free space than the source size
    #[serde(default)]
    pub allow_low_space: bool,
    /// Refuse when an HPA or DCO hides part of the disk
    #[serde(default)]
    pub refuse_hidden_areas: bool,
    #[serde(default)]
    pub expect: ExpectIdentity,
    /// Rescue only: convert the rescued RAW image to E01 afterwards
    #[serde(default)]
    pub rescue_to_e01: bool,
    /// E01 only: ewfacquire `-g` in sectors; default physical/logical ratio
    #[serde(default)]
    pub ewf_error_granularity: Option<u32>,
    /// Unmount the source tree (audited) before acquiring
    #[serde(default)]
    pub auto_unmount: bool,
}

impl Default for AcquisitionConfig {
    fn default() -> Self {
        Self {
            format: ImageFormat::E01,
            output_dir: PathBuf::from("."),
            compression: CompressionLevel::Fast,
            split_size: SplitSize::TwoGb,
            calc_md5: true,
            calc_sha1: true,
            calc_sha256: true,
            error_retries: 2,
            wipe_bad_sectors: true,
            rescue_mode: false,
            resume: false,
            on_read_error: OnReadError::Stop,
            verify_source: false,
            piece_size: Some(DEFAULT_PIECE_SIZE),
            smart: SmartPolicy::Basic,
            write_protect: WriteProtectPolicy::Auto,
            allow_tmpfs: false,
            allow_low_space: false,
            refuse_hidden_areas: false,
            expect: ExpectIdentity::default(),
            rescue_to_e01: false,
            ewf_error_granularity: None,
            auto_unmount: false,
        }
    }
}

impl AcquisitionConfig {
    /// Defaults for `engine` writing into `output_dir`, valid as they are
    /// ([`validate`](Self::validate) accepts them):
    /// - `Ewf`: E01, fast compression, 2 GiB segments (= [`Default`]);
    /// - `Raw`: RAW, one unsplit file;
    /// - `Rescue`: rescue mode (GNU ddrescue), RAW, one unsplit file.
    ///
    /// Build every configuration from this (or [`ewf`](Self::ewf),
    /// [`raw`](Self::raw), [`rescue`](Self::rescue)) and override fields with
    /// struct update syntax; `AcquisitionConfig { format: Raw,
    /// ..Default::default() }` keeps the E01 segment size and is refused.
    pub fn for_engine(engine: EngineKind, output_dir: impl Into<PathBuf>) -> Self {
        let base = Self {
            output_dir: output_dir.into(),
            ..Self::default()
        };
        match engine {
            EngineKind::Ewf => base,
            EngineKind::Raw => Self {
                format: ImageFormat::Raw,
                split_size: SplitSize::None,
                ..base
            },
            EngineKind::Rescue => Self {
                format: ImageFormat::Raw,
                split_size: SplitSize::None,
                rescue_mode: true,
                ..base
            },
        }
    }

    /// [`for_engine`](Self::for_engine)`(EngineKind::Ewf, output_dir)`.
    pub fn ewf(output_dir: impl Into<PathBuf>) -> Self {
        Self::for_engine(EngineKind::Ewf, output_dir)
    }

    /// [`for_engine`](Self::for_engine)`(EngineKind::Raw, output_dir)`.
    pub fn raw(output_dir: impl Into<PathBuf>) -> Self {
        Self::for_engine(EngineKind::Raw, output_dir)
    }

    /// [`for_engine`](Self::for_engine)`(EngineKind::Rescue, output_dir)`.
    pub fn rescue(output_dir: impl Into<PathBuf>) -> Self {
        Self::for_engine(EngineKind::Rescue, output_dir)
    }

    pub fn engine(&self) -> EngineKind {
        EngineKind::from_config(self)
    }

    /// Consistency of the options; every error is a usage error (exit 2).
    pub fn validate(&self) -> Result<(), String> {
        let engine = self.engine();
        let mut errors = Vec::new();
        if self.error_retries > MAX_RETRIES {
            errors.push(format!(
                "retries must be between 0 and {MAX_RETRIES} (got {})",
                self.error_retries
            ));
        }
        if HashSelection::for_engine(self).is_empty() {
            errors.push("select at least one digest (MD5, SHA-1 or SHA-256)".to_string());
        }
        if engine != EngineKind::Ewf && self.split_size != SplitSize::None {
            errors.push(
                "RAW images are written as one file and cannot be split into segments; use E01 for segmented images"
                    .to_string(),
            );
        }
        if let Some(p) = self.piece_size {
            if p < MIN_PIECE_SIZE || p % 512 != 0 {
                errors.push(format!(
                    "piece size must be a multiple of 512 bytes and at least {} (got {p} bytes)",
                    format_iec(MIN_PIECE_SIZE)
                ));
            }
        }
        if self.on_read_error == OnReadError::ZeroFill && engine != EngineKind::Raw {
            errors.push(
                "--on-read-error applies to the RAW engine only (ewfacquire and ddrescue always zero-fill unreadable sectors)"
                    .to_string(),
            );
        }
        if let Some(g) = self.ewf_error_granularity {
            if engine != EngineKind::Ewf {
                errors.push("the error granularity applies to E01 acquisitions only".to_string());
            } else if g == 0 {
                errors.push("the error granularity must be at least 1 sector".to_string());
            }
        }
        if self.rescue_to_e01 && engine != EngineKind::Rescue {
            errors.push("--rescue-to-e01 requires rescue mode".to_string());
        }
        if self.resume && engine != EngineKind::Rescue {
            errors.push("--resume applies to rescue mode only".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("Inconsistent options: {}", errors.join("; ")))
        }
    }
}

/// ewfacquire settings that were applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EwfSettings {
    /// `-f`, e.g. "encase6"
    pub ewf_format: String,
    /// `-c`
    pub compression: CompressionLevel,
    /// `-S`, human readable
    pub segment_size: String,
    /// `-S` in bytes, `None`: unlimited
    pub segment_bytes: Option<u64>,
    /// `-r`
    pub retries: u32,
    /// `-w`
    pub wipe_on_error: bool,
    /// `-g`, sectors
    pub error_granularity_sectors: u32,
    /// `-m`: "fixed" or "removable"
    pub media_type: String,
    /// `-M`: "physical" or "logical"
    pub media_flags: String,
}

/// Native RAW engine settings that were applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSettings {
    pub on_read_error: OnReadError,
    /// Piecewise SHA-256 piece size; `None`: no pieces
    pub piece_size: Option<u64>,
    /// How the source was read, filled in by the engine ("O_DIRECT",
    /// "buffered with POSIX_FADV_DONTNEED")
    pub source_io: Option<String>,
    /// `--on-read-error zero-fill`: consecutive unreadable sectors after
    /// which the source counts as lost and the acquisition ends
    #[serde(default)]
    pub source_loss_sectors: Option<u64>,
}

/// ddrescue settings that were applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RescueSettings {
    /// `-r`
    pub retries: u32,
    /// `-d` (direct disc access)
    pub direct_io: bool,
    /// `-b`
    pub sector_size: u32,
    /// `-I` resume run
    pub resume: bool,
    pub rescue_to_e01: bool,
}

/// Engine-specific part of [`EffectiveConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineSettings {
    Ewf(EwfSettings),
    Raw(RawSettings),
    Rescue(RescueSettings),
}

/// The settings an engine applied, and only those: a RAW report never shows
/// compression or segments, an E01 report always lists MD5, a rescue report
/// shows the ddrescue settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveConfig {
    pub engine: EngineKind,
    /// "EWF (EnCase 6)", "RAW (single file)"
    pub image_format: String,
    pub digests: Vec<HashAlgorithm>,
    pub verify_source: bool,
    pub smart: SmartPolicy,
    pub write_protect: WriteProtectPolicy,
    pub settings: EngineSettings,
    pub notes: Vec<String>,
}

impl EffectiveConfig {
    /// Settings for `config`; `source` supplies sector sizes, removable media
    /// and whether the source is a whole physical disk (defaults: 512-byte
    /// sectors, fixed, physical).
    pub fn build(config: &AcquisitionConfig, source: Option<&SourceIdentity>) -> Self {
        let engine = config.engine();
        let selection = HashSelection::for_engine(config);
        let logical = source.map(|s| s.logical_sector_size).unwrap_or(512).max(1);
        let physical = source.map(|s| s.physical_sector_size).unwrap_or(logical);
        let mut notes = Vec::new();
        let (image_format, settings) = match engine {
            EngineKind::Ewf => {
                if !config.calc_md5 {
                    notes.push("MD5 is always computed for E01 images".to_string());
                }
                let removable = source.is_some_and(|s| s.removable);
                let physical_disk = source.is_none_or(|s| s.kind == SourceKind::Disk);
                (
                    "EWF (EnCase 6)".to_string(),
                    EngineSettings::Ewf(EwfSettings {
                        ewf_format: "encase6".to_string(),
                        compression: config.compression,
                        segment_size: config.split_size.display_name(),
                        segment_bytes: config.split_size.bytes(),
                        retries: config.error_retries,
                        wipe_on_error: config.wipe_bad_sectors,
                        error_granularity_sectors: config
                            .ewf_error_granularity
                            .unwrap_or((physical / logical).max(1)),
                        media_type: if removable { "removable" } else { "fixed" }.to_string(),
                        media_flags: if physical_disk { "physical" } else { "logical" }.to_string(),
                    }),
                )
            }
            EngineKind::Raw => (
                "RAW (single file)".to_string(),
                EngineSettings::Raw(RawSettings {
                    on_read_error: config.on_read_error,
                    piece_size: config.piece_size,
                    source_io: None,
                    source_loss_sectors: (config.on_read_error == OnReadError::ZeroFill)
                        .then_some(SOURCE_LOSS_SECTORS),
                }),
            ),
            EngineKind::Rescue => (
                "RAW (single file, GNU ddrescue)".to_string(),
                EngineSettings::Rescue(RescueSettings {
                    retries: config.error_retries,
                    direct_io: true,
                    sector_size: logical.max(512),
                    resume: config.resume,
                    rescue_to_e01: config.rescue_to_e01,
                }),
            ),
        };
        Self {
            engine,
            image_format,
            digests: selection.algorithms(),
            verify_source: config.verify_source,
            smart: config.smart,
            write_protect: config.write_protect,
            settings,
            notes,
        }
    }

    /// (label, value) rows in report order.
    pub fn rows(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = vec![
            ("Engine".into(), self.engine.label().into()),
            ("Image Format".into(), self.image_format.clone()),
            (
                "Digests".into(),
                self.digests
                    .iter()
                    .map(HashAlgorithm::label)
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        ];
        match &self.settings {
            EngineSettings::Ewf(e) => {
                rows.push(("EWF Format".into(), e.ewf_format.clone()));
                rows.push(("Compression".into(), e.compression.as_ewf_arg().into()));
                rows.push(("Segment Size".into(), e.segment_size.clone()));
                rows.push(("Read Retries".into(), e.retries.to_string()));
                rows.push((
                    "On Read Error".into(),
                    format!(
                        "unreadable sectors are zero-filled by ewfacquire{}",
                        if e.wipe_on_error {
                            "; the whole error granularity block is wiped (-w)"
                        } else {
                            ""
                        }
                    ),
                ));
                rows.push((
                    "Error Granularity".into(),
                    format!("{} sector(s)", e.error_granularity_sectors),
                ));
                rows.push((
                    "Media".into(),
                    format!("{}, {}", e.media_type, e.media_flags),
                ));
            }
            EngineSettings::Raw(r) => {
                rows.push(("On Read Error".into(), r.on_read_error.label().into()));
                rows.push((
                    "Piecewise SHA-256".into(),
                    match r.piece_size {
                        Some(p) => format!("pieces of {}", format_iec(p)),
                        None => "off".into(),
                    },
                ));
                if let Some(n) = r.source_loss_sectors {
                    rows.push((
                        "Source Lost After".into(),
                        format!("{n} consecutive unreadable sectors"),
                    ));
                }
                if let Some(io) = &r.source_io {
                    rows.push(("Source I/O".into(), io.clone()));
                }
            }
            EngineSettings::Rescue(r) => {
                rows.push(("ddrescue Retries".into(), format!("{} (-r)", r.retries)));
                rows.push((
                    "Direct I/O".into(),
                    if r.direct_io { "yes (-d)" } else { "no" }.into(),
                ));
                rows.push((
                    "Sector Size".into(),
                    format!("{} bytes (-b)", r.sector_size),
                ));
                rows.push((
                    "Resumed".into(),
                    if r.resume { "yes (-I)" } else { "no" }.into(),
                ));
                if r.rescue_to_e01 {
                    rows.push(("Convert to E01".into(), "yes".into()));
                }
            }
        }
        rows.push((
            "Second Source Read".into(),
            if self.verify_source { "yes" } else { "no" }.into(),
        ));
        rows.push(("SMART Policy".into(), self.smart.label().into()));
        rows.push(("Write Protection".into(), self.write_protect.label().into()));
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> AcquisitionConfig {
        AcquisitionConfig {
            format: ImageFormat::Raw,
            split_size: SplitSize::None,
            ..Default::default()
        }
    }

    #[test]
    fn defaults_are_valid_and_conservative() {
        let c = AcquisitionConfig::default();
        assert!(c.validate().is_ok());
        assert_eq!(c.on_read_error, OnReadError::Stop);
        assert_eq!(c.smart, SmartPolicy::Basic);
        assert_eq!(c.write_protect, WriteProtectPolicy::Auto);
        assert_eq!(c.piece_size, Some(DEFAULT_PIECE_SIZE));
        assert!(!c.allow_tmpfs && !c.allow_low_space);
        assert!(raw().validate().is_ok());
        // Older JSON without the new options still loads, with defaults
        let old = r#"{"format":"Raw","output_dir":"/x","compression":"Fast","split_size":"None","calc_md5":true,"calc_sha1":false,"calc_sha256":true,"error_retries":2,"wipe_bad_sectors":true,"rescue_mode":false,"resume":false}"#;
        let c: AcquisitionConfig = serde_json::from_str(old).unwrap();
        assert_eq!(c.piece_size, Some(DEFAULT_PIECE_SIZE));
        assert_eq!(c.write_protect, WriteProtectPolicy::Auto);
    }

    #[test]
    fn inconsistent_options_are_usage_errors() {
        let cases: Vec<(AcquisitionConfig, &str)> = vec![
            (
                AcquisitionConfig {
                    error_retries: 256,
                    ..Default::default()
                },
                "between 0 and 255",
            ),
            (
                AcquisitionConfig {
                    format: ImageFormat::Raw,
                    ..Default::default()
                },
                "cannot be split",
            ),
            (
                AcquisitionConfig {
                    calc_md5: false,
                    calc_sha1: false,
                    calc_sha256: false,
                    ..raw()
                },
                "at least one digest",
            ),
            (
                AcquisitionConfig {
                    piece_size: Some(1000),
                    ..raw()
                },
                "piece size",
            ),
            (
                AcquisitionConfig {
                    on_read_error: OnReadError::ZeroFill,
                    ..Default::default()
                },
                "RAW engine only",
            ),
            (
                AcquisitionConfig {
                    ewf_error_granularity: Some(0),
                    ..Default::default()
                },
                "at least 1 sector",
            ),
            (
                AcquisitionConfig {
                    ewf_error_granularity: Some(8),
                    ..raw()
                },
                "E01 acquisitions only",
            ),
            (
                AcquisitionConfig {
                    rescue_to_e01: true,
                    ..Default::default()
                },
                "requires rescue mode",
            ),
            (
                AcquisitionConfig {
                    resume: true,
                    ..raw()
                },
                "rescue mode only",
            ),
        ];
        for (config, needle) in cases {
            let err = config.validate().unwrap_err();
            assert!(err.contains(needle), "{needle}: {err}");
        }
        // 255 retries is the documented maximum; E01 without MD5 still has MD5
        assert!(AcquisitionConfig {
            error_retries: 255,
            calc_md5: false,
            calc_sha1: false,
            calc_sha256: false,
            ..Default::default()
        }
        .validate()
        .is_ok());
        assert!(AcquisitionConfig {
            on_read_error: OnReadError::ZeroFill,
            ..raw()
        }
        .validate()
        .is_ok());
        let rescue = AcquisitionConfig {
            rescue_mode: true,
            resume: true,
            rescue_to_e01: true,
            ..raw()
        };
        assert!(rescue.validate().is_ok());
    }

    #[test]
    fn engine_constructors_are_valid_as_they_are() {
        for engine in [EngineKind::Ewf, EngineKind::Raw, EngineKind::Rescue] {
            let c = AcquisitionConfig::for_engine(engine, "/case");
            assert_eq!(c.engine(), engine);
            assert_eq!(c.output_dir, PathBuf::from("/case"));
            assert!(c.validate().is_ok(), "{engine:?}: {:?}", c.validate());
        }
        let e = AcquisitionConfig::ewf("/case");
        assert_eq!(e.split_size, SplitSize::TwoGb);
        assert_eq!(e.format, ImageFormat::E01);
        let r = AcquisitionConfig::raw("/case");
        assert_eq!(r.split_size, SplitSize::None);
        assert_eq!(r.format, ImageFormat::Raw);
        assert!(!r.rescue_mode);
        let s = AcquisitionConfig::rescue("/case");
        assert_eq!(s.split_size, SplitSize::None);
        assert!(s.rescue_mode);
        // Overrides keep the engine defaults
        let r = AcquisitionConfig {
            calc_sha1: false,
            on_read_error: OnReadError::ZeroFill,
            ..AcquisitionConfig::raw("/case")
        };
        assert!(r.validate().is_ok());
        // The pitfall the constructors avoid
        assert!(AcquisitionConfig {
            format: ImageFormat::Raw,
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn raw_effective_config_never_shows_compression_or_split() {
        let eff = EffectiveConfig::build(&raw(), None);
        assert_eq!(eff.engine, EngineKind::Raw);
        let labels: Vec<String> = eff.rows().into_iter().map(|(l, _)| l).collect();
        assert!(!labels.iter().any(|l| l.contains("Compression")));
        assert!(!labels.iter().any(|l| l.contains("Segment")));
        let json = serde_json::to_string(&eff).unwrap();
        assert!(
            !json.contains("compression") && !json.contains("segment"),
            "{json}"
        );
        assert!(labels.contains(&"Piecewise SHA-256".to_string()));
    }

    #[test]
    fn e01_effective_config_always_lists_md5() {
        let config = AcquisitionConfig {
            calc_md5: false,
            calc_sha1: false,
            ..Default::default()
        };
        let eff = EffectiveConfig::build(&config, None);
        assert_eq!(eff.digests, [HashAlgorithm::MD5, HashAlgorithm::SHA256]);
        assert_eq!(eff.notes, ["MD5 is always computed for E01 images"]);
        let EngineSettings::Ewf(e) = &eff.settings else {
            panic!("E01 settings expected")
        };
        assert_eq!(e.error_granularity_sectors, 1);
        assert_eq!(e.media_type, "fixed");
        assert_eq!(e.media_flags, "physical");
        assert!(eff
            .rows()
            .iter()
            .any(|(l, v)| l == "Digests" && v == "MD5, SHA-256"));
    }

    #[test]
    fn e01_granularity_and_media_follow_the_source() {
        let source = SourceIdentity {
            logical_sector_size: 512,
            physical_sector_size: 4096,
            removable: true,
            kind: SourceKind::Partition,
            ..Default::default()
        };
        let eff = EffectiveConfig::build(&AcquisitionConfig::default(), Some(&source));
        let EngineSettings::Ewf(e) = &eff.settings else {
            panic!()
        };
        assert_eq!(e.error_granularity_sectors, 8);
        assert_eq!(e.media_type, "removable");
        assert_eq!(e.media_flags, "logical");
        let overridden = AcquisitionConfig {
            ewf_error_granularity: Some(64),
            ..Default::default()
        };
        let EngineSettings::Ewf(e) = EffectiveConfig::build(&overridden, Some(&source)).settings
        else {
            panic!()
        };
        assert_eq!(e.error_granularity_sectors, 64);
    }

    #[test]
    fn rescue_effective_config_shows_ddrescue_settings() {
        let config = AcquisitionConfig {
            rescue_mode: true,
            error_retries: 3,
            calc_sha1: false,
            ..raw()
        };
        let eff = EffectiveConfig::build(&config, None);
        assert_eq!(eff.engine, EngineKind::Rescue);
        let rows = eff.rows();
        assert!(rows.contains(&("ddrescue Retries".into(), "3 (-r)".into())));
        assert!(rows.contains(&("Direct I/O".into(), "yes (-d)".into())));
        assert!(rows.contains(&("Sector Size".into(), "512 bytes (-b)".into())));
        assert!(!rows.iter().any(|(l, _)| l == "Compression"));
        assert_eq!(eff.digests, [HashAlgorithm::MD5, HashAlgorithm::SHA256]);
    }

    #[test]
    fn hash_selection_for_engine() {
        let c = AcquisitionConfig {
            calc_md5: false,
            ..Default::default()
        };
        assert!(HashSelection::for_engine(&c).md5);
        assert!(
            !HashSelection::for_engine(&AcquisitionConfig {
                calc_md5: false,
                ..raw()
            })
            .md5
        );
        assert!(HashSelection::default().is_empty());
    }
}
