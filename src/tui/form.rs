//! The forms of the TUI: case setup (case fields and acquisition options),
//! converter and re-verification. Fields that do not apply to the selected
//! engine are skipped by the focus order and shown greyed; MD5 is forced for
//! E01; placeholders are only drawn, never used as values (§16, review M8).

use crate::models::case::CaseMetadata;
use crate::models::config::{
    AcquisitionConfig, CompressionLevel, EngineKind, OnReadError, SmartPolicy, SplitSize,
    WriteProtectPolicy, MAX_RETRIES,
};
use crate::models::conversion::ConversionTarget;
use crate::tui::autocomplete::expand_tilde;
use std::path::{Path, PathBuf};

/// A field of the case setup form, in focus order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    CaseNumber,
    EvidenceNumber,
    Examiner,
    LocationEa,
    Authority,
    Description,
    Notes,
    SealNumber,
    SeizureTime,
    SeizureLocation,
    Destination,
    Engine,
    Compression,
    Segments,
    Md5,
    Sha1,
    Sha256,
    Retries,
    OnReadError,
    VerifySource,
    Smart,
    WriteProtect,
    Start,
}

impl Field {
    pub const ALL: [Field; 23] = [
        Field::CaseNumber,
        Field::EvidenceNumber,
        Field::Examiner,
        Field::LocationEa,
        Field::Authority,
        Field::Description,
        Field::Notes,
        Field::SealNumber,
        Field::SeizureTime,
        Field::SeizureLocation,
        Field::Destination,
        Field::Engine,
        Field::Compression,
        Field::Segments,
        Field::Md5,
        Field::Sha1,
        Field::Sha256,
        Field::Retries,
        Field::OnReadError,
        Field::VerifySource,
        Field::Smart,
        Field::WriteProtect,
        Field::Start,
    ];

    /// Case and evidence fields (left column).
    pub const CASE: [Field; 10] = [
        Field::CaseNumber,
        Field::EvidenceNumber,
        Field::Examiner,
        Field::LocationEa,
        Field::Authority,
        Field::Description,
        Field::Notes,
        Field::SealNumber,
        Field::SeizureTime,
        Field::SeizureLocation,
    ];

    /// Acquisition options (right column), without the start button.
    pub const OPTIONS: [Field; 12] = [
        Field::Destination,
        Field::Engine,
        Field::Compression,
        Field::Segments,
        Field::Md5,
        Field::Sha1,
        Field::Sha256,
        Field::Retries,
        Field::OnReadError,
        Field::VerifySource,
        Field::Smart,
        Field::WriteProtect,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Field::CaseNumber => "Case number",
            Field::EvidenceNumber => "Evidence no.",
            Field::Examiner => "Examiner",
            Field::LocationEa => "Location/EA",
            Field::Authority => "Authority",
            Field::Description => "Description",
            Field::Notes => "Notes",
            Field::SealNumber => "Seal number",
            Field::SeizureTime => "Seized at",
            Field::SeizureLocation => "Seized in",
            Field::Destination => "Destination",
            Field::Engine => "Engine",
            Field::Compression => "Compression",
            Field::Segments => "Segments",
            Field::Md5 => "MD5",
            Field::Sha1 => "SHA-1",
            Field::Sha256 => "SHA-256",
            Field::Retries => "Retries",
            Field::OnReadError => "Read errors",
            Field::VerifySource => "Re-read src",
            Field::Smart => "SMART",
            Field::WriteProtect => "Write-prot.",
            Field::Start => "Start",
        }
    }

    /// Example text drawn in an empty field (never a value).
    pub fn placeholder(&self) -> &'static str {
        match self {
            Field::CaseNumber => "e.g. 2026-0042",
            Field::EvidenceNumber => "e.g. HDD01",
            Field::Examiner => "name, badge no.",
            Field::LocationEa => "01 (default)",
            Field::Authority => "optional",
            Field::Description => "optional",
            Field::Notes => "optional",
            Field::SealNumber => "optional",
            Field::SeizureTime => "optional, free text",
            Field::SeizureLocation => "optional",
            Field::Destination => "directory, e.g. /mnt/evidence/case",
            _ => "",
        }
    }

    pub fn is_text(&self) -> bool {
        Field::CASE.contains(self) || *self == Field::Destination
    }

    pub fn is_required(&self) -> bool {
        matches!(
            self,
            Field::CaseNumber | Field::EvidenceNumber | Field::Examiner | Field::Destination
        )
    }

    /// Does the field apply to `engine`? Fields that do not are greyed and
    /// skipped (MD5 is forced for E01, so it cannot be changed there).
    pub fn applies(&self, engine: EngineKind) -> bool {
        match self {
            Field::Compression | Field::Segments => engine == EngineKind::Ewf,
            Field::Md5 => engine != EngineKind::Ewf,
            Field::Retries => engine != EngineKind::Raw,
            Field::OnReadError => engine == EngineKind::Raw,
            _ => true,
        }
    }

    /// The focusable fields for `engine`, in order.
    pub fn focus_order(engine: EngineKind) -> Vec<Field> {
        Field::ALL
            .into_iter()
            .filter(|f| f.applies(engine))
            .collect()
    }
}

/// The text of case field `field` in `case`.
pub fn case_text(case: &CaseMetadata, field: Field) -> Option<&String> {
    Some(match field {
        Field::CaseNumber => &case.case_number,
        Field::EvidenceNumber => &case.evidence_number,
        Field::Examiner => &case.examiner,
        Field::LocationEa => &case.location_ea,
        Field::Authority => &case.authority,
        Field::Description => &case.description,
        Field::Notes => &case.notes,
        Field::SealNumber => &case.seal_number,
        Field::SeizureTime => &case.seizure_time,
        Field::SeizureLocation => &case.seizure_location,
        _ => return None,
    })
}

/// Mutable text of case field `field`.
pub fn case_text_mut(case: &mut CaseMetadata, field: Field) -> Option<&mut String> {
    Some(match field {
        Field::CaseNumber => &mut case.case_number,
        Field::EvidenceNumber => &mut case.evidence_number,
        Field::Examiner => &mut case.examiner,
        Field::LocationEa => &mut case.location_ea,
        Field::Authority => &mut case.authority,
        Field::Description => &mut case.description,
        Field::Notes => &mut case.notes,
        Field::SealNumber => &mut case.seal_number,
        Field::SeizureTime => &mut case.seizure_time,
        Field::SeizureLocation => &mut case.seizure_location,
        _ => return None,
    })
}

/// The acquisition options of the case setup form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcqForm {
    pub engine: EngineKind,
    /// Destination directory as typed (`~` expanded when used)
    pub destination: String,
    pub compression: CompressionLevel,
    /// E01 segment size
    pub split: SplitSize,
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
    pub retries: u32,
    pub on_read_error: OnReadError,
    pub verify_source: bool,
    pub smart: SmartPolicy,
    pub write_protect: WriteProtectPolicy,
    /// Continue an interrupted rescue (set by the resume prompt)
    pub resume: bool,
    /// E01 with less free space than the source (confirmed on the sheet, R4)
    pub allow_low_space: bool,
}

impl Default for AcqForm {
    fn default() -> Self {
        let d = AcquisitionConfig::default();
        Self {
            engine: EngineKind::Ewf,
            destination: String::new(),
            compression: d.compression,
            split: d.split_size,
            md5: true,
            sha1: d.calc_sha1,
            sha256: d.calc_sha256,
            retries: d.error_retries,
            on_read_error: d.on_read_error,
            verify_source: d.verify_source,
            smart: d.smart,
            write_protect: d.write_protect,
            resume: false,
            allow_low_space: false,
        }
    }
}

impl AcqForm {
    /// The destination as a path (`~` expanded, trimmed).
    pub fn output_dir(&self) -> PathBuf {
        expand_tilde(Path::new(self.destination.trim()))
    }

    /// The configuration the form describes (built per engine, so RAW and
    /// rescue are never split and only the applicable options are set).
    pub fn config(&self) -> AcquisitionConfig {
        let base = AcquisitionConfig::for_engine(self.engine, self.output_dir());
        let ewf = self.engine == EngineKind::Ewf;
        AcquisitionConfig {
            compression: if ewf {
                self.compression
            } else {
                base.compression
            },
            split_size: if ewf { self.split } else { SplitSize::None },
            calc_md5: ewf || self.md5,
            calc_sha1: self.sha1,
            calc_sha256: self.sha256,
            error_retries: self.retries.min(MAX_RETRIES),
            on_read_error: if self.engine == EngineKind::Raw {
                self.on_read_error
            } else {
                OnReadError::Stop
            },
            verify_source: self.verify_source,
            smart: self.smart,
            write_protect: self.write_protect,
            resume: self.engine == EngineKind::Rescue && self.resume,
            allow_low_space: self.allow_low_space,
            ..base
        }
    }

    /// Digests that will be computed.
    pub fn digest_count(&self) -> usize {
        let md5 = self.engine == EngineKind::Ewf || self.md5;
        [md5, self.sha1, self.sha256].iter().filter(|b| **b).count()
    }

    /// Change a toggle field; `forward` cycles forward. Returns a message
    /// when the change was refused.
    pub fn toggle(&mut self, field: Field, forward: bool) -> Option<String> {
        if !field.applies(self.engine) {
            return None;
        }
        match field {
            Field::Engine => {
                self.engine = cycle(
                    &[EngineKind::Ewf, EngineKind::Raw, EngineKind::Rescue],
                    self.engine,
                    forward,
                );
                self.resume = false;
                self.allow_low_space = false;
            }
            Field::Compression => {
                self.compression = cycle(
                    &[
                        CompressionLevel::None,
                        CompressionLevel::Fast,
                        CompressionLevel::Best,
                    ],
                    self.compression,
                    forward,
                )
            }
            Field::Segments => {
                self.split = cycle(
                    &[SplitSize::TwoGb, SplitSize::FourGb, SplitSize::None],
                    if matches!(self.split, SplitSize::Custom(_)) {
                        SplitSize::TwoGb
                    } else {
                        self.split
                    },
                    forward,
                )
            }
            Field::Md5 | Field::Sha1 | Field::Sha256 => {
                let on = match field {
                    Field::Md5 => self.md5,
                    Field::Sha1 => self.sha1,
                    _ => self.sha256,
                };
                if on && self.digest_count() == 1 {
                    return Some(
                        "At least one digest must be computed; select another one first.".into(),
                    );
                }
                let flag = match field {
                    Field::Md5 => &mut self.md5,
                    Field::Sha1 => &mut self.sha1,
                    _ => &mut self.sha256,
                };
                *flag = !*flag;
            }
            Field::Retries => {
                self.retries = if forward {
                    (self.retries + 1).min(MAX_RETRIES)
                } else {
                    self.retries.saturating_sub(1)
                }
            }
            Field::OnReadError => {
                self.on_read_error = cycle(
                    &[OnReadError::Stop, OnReadError::ZeroFill],
                    self.on_read_error,
                    forward,
                )
            }
            Field::VerifySource => self.verify_source = !self.verify_source,
            Field::Smart => {
                self.smart = cycle(
                    &[SmartPolicy::Off, SmartPolicy::Basic, SmartPolicy::Full],
                    self.smart,
                    forward,
                )
            }
            Field::WriteProtect => {
                self.write_protect = cycle(
                    &[WriteProtectPolicy::Auto, WriteProtectPolicy::Off],
                    self.write_protect,
                    forward,
                )
            }
            _ => {}
        }
        None
    }

    /// The value of a non-text field as shown.
    pub fn value_text(&self, field: Field) -> String {
        let ewf = self.engine == EngineKind::Ewf;
        match field {
            Field::Engine => engine_choice(self.engine).into(),
            Field::Compression if ewf => format!("{:?}", self.compression).to_lowercase(),
            Field::Segments if ewf => match self.split {
                SplitSize::None => "one file (no split)".into(),
                other => other.display_name(),
            },
            Field::Compression | Field::Segments => "n/a (E01 only)".into(),
            Field::Md5 if ewf => "[x] always computed for E01".into(),
            Field::Md5 => check(self.md5),
            Field::Sha1 => check(self.sha1),
            Field::Sha256 => check(self.sha256),
            Field::Retries if self.engine == EngineKind::Raw => "n/a (RAW reads once)".into(),
            Field::Retries => self.retries.to_string(),
            Field::OnReadError if self.engine == EngineKind::Raw => match self.on_read_error {
                OnReadError::Stop => "stop (INCOMPLETE at the exact offset)".into(),
                OnReadError::ZeroFill => "zero-fill, continue, list ranges".into(),
            },
            Field::OnReadError => "tool substitutes zeros, ranges listed".into(),
            Field::VerifySource => {
                if self.verify_source {
                    "[x] second source read".into()
                } else {
                    "[ ] off".into()
                }
            }
            Field::Smart => match self.smart {
                SmartPolicy::Off => "off (no SMART command)".into(),
                SmartPolicy::Basic => "basic (-i -H -A -l error)".into(),
                SmartPolicy::Full => "full (extended logs, no SCT)".into(),
            },
            Field::WriteProtect => match self.write_protect {
                WriteProtectPolicy::Auto => "auto (BLKROSET)".into(),
                WriteProtectPolicy::Off => "off (record only)".into(),
            },
            _ => String::new(),
        }
    }
}

fn check(on: bool) -> String {
    if on { "[x]" } else { "[ ]" }.into()
}

/// Engine choice as shown in the form.
pub fn engine_choice(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::Ewf => "E01 (ewfacquire)",
        EngineKind::Raw => "RAW (dfdisk native)",
        EngineKind::Rescue => "RESCUE RAW (ddrescue)",
    }
}

/// File name extension of the image an engine writes.
pub fn image_extension(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::Ewf => "E01",
        EngineKind::Raw | EngineKind::Rescue => "raw",
    }
}

fn cycle<T: Copy + PartialEq>(values: &[T], current: T, forward: bool) -> T {
    let i = values.iter().position(|v| *v == current).unwrap_or(0);
    let n = values.len();
    if forward {
        values[(i + 1) % n]
    } else {
        values[(i + n - 1) % n]
    }
}

/// A field of the converter form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConvField {
    Source,
    Target,
    Destination,
    Compression,
    Segments,
    CaseNumber,
    EvidenceNumber,
    Examiner,
    Description,
    Notes,
    Start,
}

impl ConvField {
    pub const ALL: [ConvField; 11] = [
        ConvField::Source,
        ConvField::Target,
        ConvField::Destination,
        ConvField::Compression,
        ConvField::Segments,
        ConvField::CaseNumber,
        ConvField::EvidenceNumber,
        ConvField::Examiner,
        ConvField::Description,
        ConvField::Notes,
        ConvField::Start,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ConvField::Source => "Source image",
            ConvField::Target => "Convert to",
            ConvField::Destination => "Destination",
            ConvField::Compression => "Compression",
            ConvField::Segments => "Segments",
            ConvField::CaseNumber => "Case number",
            ConvField::EvidenceNumber => "Evidence no.",
            ConvField::Examiner => "Examiner",
            ConvField::Description => "Description",
            ConvField::Notes => "Notes",
            ConvField::Start => "Start",
        }
    }

    pub fn placeholder(&self) -> &'static str {
        match self {
            ConvField::Source => "image.raw / image.001 / image.E01",
            ConvField::Destination => "directory for the converted image",
            ConvField::CaseNumber | ConvField::EvidenceNumber | ConvField::Examiner => {
                "required (taken from the source's report when it has one)"
            }
            ConvField::Description | ConvField::Notes => "optional",
            _ => "",
        }
    }

    pub fn is_text(&self) -> bool {
        !matches!(
            self,
            ConvField::Target | ConvField::Compression | ConvField::Segments | ConvField::Start
        )
    }

    pub fn is_path(&self) -> bool {
        matches!(self, ConvField::Source | ConvField::Destination)
    }

    pub fn is_required(&self) -> bool {
        matches!(
            self,
            ConvField::Source
                | ConvField::Destination
                | ConvField::CaseNumber
                | ConvField::EvidenceNumber
                | ConvField::Examiner
        )
    }

    pub fn applies(&self, target: ConversionTarget) -> bool {
        match self {
            ConvField::Compression | ConvField::Segments => target == ConversionTarget::E01,
            _ => true,
        }
    }

    pub fn focus_order(target: ConversionTarget) -> Vec<ConvField> {
        ConvField::ALL
            .into_iter()
            .filter(|f| f.applies(target))
            .collect()
    }
}

/// What the source report of an image says (pre-fills the converter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReport {
    pub path: PathBuf,
    pub case: CaseMetadata,
    /// Serial of the acquired device, if any
    pub serial: Option<String>,
    /// "model (serial)" of the acquired device
    pub device: String,
    pub outcome: String,
}

/// Facts about a converter source, probed off the UI thread.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceFacts {
    pub path: PathBuf,
    pub exists: bool,
    pub size: Option<u64>,
    /// The file carries an EWF signature
    pub is_ewf: bool,
    pub report: Option<SourceReport>,
}

/// The converter form.
#[derive(Debug, Clone)]
pub struct ConvForm {
    pub source: String,
    pub target: ConversionTarget,
    pub destination: String,
    pub compression: CompressionLevel,
    pub split: SplitSize,
    pub case: CaseMetadata,
    pub field: ConvField,
    pub cursor: usize,
    /// Source facts of the current source text
    pub facts: Option<SourceFacts>,
    /// Extra notes (e.g. the read-error summary of a rescue)
    pub notes: Vec<String>,
    /// Case fields taken from a source's report, as taken
    pub prefilled: Option<Prefill>,
}

/// Case fields of the converter form that a source's report filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefill {
    /// The report the values came from
    pub report: PathBuf,
    /// Each field taken and the value it got
    pub fields: Vec<(ConvField, String)>,
}

/// The case fields with an input on the converter form that a report can
/// fill. The report's other case values (seal, seizure, authority, location)
/// have no input here: the converter takes them from the report itself.
pub const PREFILL_FIELDS: [ConvField; 4] = [
    ConvField::CaseNumber,
    ConvField::EvidenceNumber,
    ConvField::Examiner,
    ConvField::Description,
];

/// A case value by converter field (empty for fields that are not case
/// values).
pub fn conv_case_value(case: &CaseMetadata, field: ConvField) -> &str {
    match field {
        ConvField::CaseNumber => &case.case_number,
        ConvField::EvidenceNumber => &case.evidence_number,
        ConvField::Examiner => &case.examiner,
        ConvField::Description => &case.description,
        ConvField::Notes => &case.notes,
        _ => "",
    }
}

/// "case number, evidence number" (lower-case labels of the fields).
pub fn field_labels(fields: &[ConvField]) -> String {
    fields
        .iter()
        .map(|f| f.label().to_lowercase())
        .collect::<Vec<_>>()
        .join(", ")
}

impl Default for ConvForm {
    fn default() -> Self {
        Self {
            source: String::new(),
            target: ConversionTarget::E01,
            destination: String::new(),
            compression: CompressionLevel::Fast,
            split: SplitSize::TwoGb,
            case: CaseMetadata::default(),
            field: ConvField::Source,
            cursor: 0,
            facts: None,
            notes: Vec::new(),
            prefilled: None,
        }
    }
}

impl ConvForm {
    /// The source changed: empty the case fields a report filled in that the
    /// examiner left as they were (they belong to the previous image).
    /// Returns the report and the fields cleared.
    pub fn clear_prefill(&mut self) -> Option<(PathBuf, Vec<ConvField>)> {
        let p = self.prefilled.take()?;
        let mut cleared = Vec::new();
        for (field, value) in p.fields {
            if let Some(t) = self.text_mut(field) {
                if *t == value {
                    t.clear();
                    cleared.push(field);
                }
            }
        }
        Some((p.report, cleared))
    }

    /// Fill the empty case fields of [`PREFILL_FIELDS`] from `case` (the
    /// report at `report`) and remember them. Returns the fields filled and
    /// the fields whose (examiner's) value differs from the report's.
    pub fn prefill_from(
        &mut self,
        report: &Path,
        case: &CaseMetadata,
    ) -> (Vec<ConvField>, Vec<ConvField>) {
        let mut taken = Vec::new();
        let mut differing = Vec::new();
        for field in PREFILL_FIELDS {
            let value = conv_case_value(case, field).trim().to_string();
            if value.is_empty() {
                continue;
            }
            let Some(t) = self.text_mut(field) else {
                continue;
            };
            if t.trim().is_empty() {
                *t = value.clone();
                taken.push((field, value));
            } else if t.trim() != value {
                differing.push(field);
            }
        }
        let fields: Vec<ConvField> = taken.iter().map(|(f, _)| *f).collect();
        if !taken.is_empty() {
            self.prefilled = Some(Prefill {
                report: report.to_path_buf(),
                fields: taken,
            });
        }
        (fields, differing)
    }

    pub fn text(&self, field: ConvField) -> Option<&String> {
        Some(match field {
            ConvField::Source => &self.source,
            ConvField::Destination => &self.destination,
            ConvField::CaseNumber => &self.case.case_number,
            ConvField::EvidenceNumber => &self.case.evidence_number,
            ConvField::Examiner => &self.case.examiner,
            ConvField::Description => &self.case.description,
            ConvField::Notes => &self.case.notes,
            _ => return None,
        })
    }

    pub fn text_mut(&mut self, field: ConvField) -> Option<&mut String> {
        Some(match field {
            ConvField::Source => &mut self.source,
            ConvField::Destination => &mut self.destination,
            ConvField::CaseNumber => &mut self.case.case_number,
            ConvField::EvidenceNumber => &mut self.case.evidence_number,
            ConvField::Examiner => &mut self.case.examiner,
            ConvField::Description => &mut self.case.description,
            ConvField::Notes => &mut self.case.notes,
            _ => return None,
        })
    }

    /// Target from the source name (no file access: this runs on the UI
    /// thread): an EWF segment converts to RAW, anything else to E01. The
    /// background probe refines it from the file signature.
    pub fn detect_target(&mut self) {
        if is_ewf_name(self.source.trim()) {
            self.target = ConversionTarget::Raw;
        } else if !self.source.trim().is_empty() {
            self.target = ConversionTarget::E01;
        }
    }

    pub fn value_text(&self, field: ConvField) -> String {
        match field {
            ConvField::Target => match self.target {
                ConversionTarget::E01 => "E01 (Expert Witness, ewfacquire)".into(),
                ConversionTarget::Raw => "RAW (single file, ewfexport)".into(),
            },
            ConvField::Compression => format!("{:?}", self.compression).to_lowercase(),
            ConvField::Segments => match self.split {
                SplitSize::None => "one file (no split)".into(),
                other => other.display_name(),
            },
            _ => String::new(),
        }
    }

    pub fn toggle(&mut self, field: ConvField, forward: bool) {
        match field {
            ConvField::Target => {
                self.target = match self.target {
                    ConversionTarget::E01 => ConversionTarget::Raw,
                    ConversionTarget::Raw => ConversionTarget::E01,
                }
            }
            ConvField::Compression => {
                self.compression = cycle(
                    &[
                        CompressionLevel::None,
                        CompressionLevel::Fast,
                        CompressionLevel::Best,
                    ],
                    self.compression,
                    forward,
                )
            }
            ConvField::Segments => {
                self.split = cycle(
                    &[SplitSize::TwoGb, SplitSize::FourGb, SplitSize::None],
                    self.split,
                    forward,
                )
            }
            _ => {}
        }
    }
}

/// ".E01", ".e05", ".Ex01", ".s01", ".L01" (by name only).
pub fn is_ewf_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(ext) = lower.rsplit('.').next().filter(|_| lower.contains('.')) else {
        return false;
    };
    let b = ext.as_bytes();
    let digits = |s: &[u8]| s.len() == 2 && s.iter().all(|c| c.is_ascii_digit());
    match b.first() {
        Some(b'e') | Some(b's') | Some(b'l') => {
            digits(&b[1..]) || (b.len() == 4 && b[1] == b'x' && digits(&b[2..]))
        }
        _ => false,
    }
}

/// Where the dfdisk report of an image would be: the image name without its
/// image suffix (`.E01`, `.Ex01`, `.raw`, `.dd`, `.img`, `.001`, ...) plus
/// `.info.json`.
pub fn report_candidate(image: &Path) -> Option<PathBuf> {
    let name = image.file_name()?.to_string_lossy().to_string();
    let lower = name.to_ascii_lowercase();
    let stem_len = match lower.rfind('.') {
        Some(dot) => {
            let ext = &lower[dot + 1..];
            let known = matches!(ext, "raw" | "dd" | "img" | "bin" | "e01" | "ex01")
                || is_ewf_name(&lower)
                || (ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()));
            if known {
                dot
            } else {
                name.len()
            }
        }
        None => name.len(),
    };
    let stem = &name[..stem_len];
    if stem.is_empty() {
        return None;
    }
    Some(image.with_file_name(format!("{stem}.info.json")))
}

/// The re-verification form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerField {
    Image,
    Report,
    Start,
}

impl VerField {
    pub const ALL: [VerField; 3] = [VerField::Image, VerField::Report, VerField::Start];

    pub fn label(&self) -> &'static str {
        match self {
            VerField::Image => "Image",
            VerField::Report => "Report JSON",
            VerField::Start => "Start",
        }
    }

    pub fn placeholder(&self) -> &'static str {
        match self {
            VerField::Image => "image.E01 / image.raw",
            VerField::Report => "<base>.info.json with the expected digests (optional)",
            VerField::Start => "",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct VerifyForm {
    pub image: String,
    pub report: String,
    pub field: Option<VerField>,
    pub cursor: usize,
    /// The report path was filled in automatically from the image name
    pub report_auto: bool,
}

impl VerifyForm {
    pub fn field(&self) -> VerField {
        self.field.unwrap_or(VerField::Image)
    }

    pub fn text_mut(&mut self, field: VerField) -> Option<&mut String> {
        match field {
            VerField::Image => Some(&mut self.image),
            VerField::Report => Some(&mut self.report),
            VerField::Start => None,
        }
    }

    pub fn text(&self, field: VerField) -> Option<&String> {
        match field {
            VerField::Image => Some(&self.image),
            VerField::Report => Some(&self.report),
            VerField::Start => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_order_skips_fields_that_do_not_apply() {
        let ewf = Field::focus_order(EngineKind::Ewf);
        assert!(ewf.contains(&Field::Compression) && ewf.contains(&Field::Retries));
        assert!(!ewf.contains(&Field::Md5), "MD5 is forced for E01");
        assert!(!ewf.contains(&Field::OnReadError));
        let raw = Field::focus_order(EngineKind::Raw);
        assert!(!raw.contains(&Field::Compression) && !raw.contains(&Field::Segments));
        assert!(raw.contains(&Field::OnReadError) && raw.contains(&Field::Md5));
        assert!(!raw.contains(&Field::Retries));
        let rescue = Field::focus_order(EngineKind::Rescue);
        assert!(rescue.contains(&Field::Retries) && !rescue.contains(&Field::OnReadError));
        assert_eq!(*ewf.last().unwrap(), Field::Start);
    }

    #[test]
    fn config_per_engine_is_valid() {
        let mut form = AcqForm {
            destination: "/mnt/x".into(),
            ..Default::default()
        };
        for engine in [EngineKind::Ewf, EngineKind::Raw, EngineKind::Rescue] {
            form.engine = engine;
            let cfg = form.config();
            assert_eq!(cfg.engine(), engine);
            cfg.validate().unwrap();
            if engine != EngineKind::Ewf {
                assert_eq!(cfg.split_size, SplitSize::None);
            }
        }
        form.engine = EngineKind::Ewf;
        form.md5 = false;
        assert!(form.config().calc_md5, "E01 always computes MD5");
    }

    #[test]
    fn the_last_digest_cannot_be_disabled() {
        let mut form = AcqForm {
            engine: EngineKind::Raw,
            md5: false,
            sha1: false,
            sha256: true,
            ..Default::default()
        };
        assert!(form.toggle(Field::Sha256, true).is_some());
        assert!(form.sha256);
        assert!(form.toggle(Field::Md5, true).is_none());
        assert!(form.md5);
        assert!(form.toggle(Field::Sha256, true).is_none());
        assert!(!form.sha256);
        // MD5 does not apply to E01: no change
        form.engine = EngineKind::Ewf;
        let before = form.clone();
        form.toggle(Field::Md5, true);
        assert_eq!(form, before);
    }

    #[test]
    fn retries_are_bounded() {
        let mut form = AcqForm {
            retries: 255,
            ..Default::default()
        };
        form.toggle(Field::Retries, true);
        assert_eq!(form.retries, 255);
        form.retries = 0;
        form.toggle(Field::Retries, false);
        assert_eq!(form.retries, 0);
    }

    #[test]
    fn report_candidates() {
        let c = |p: &str| report_candidate(Path::new(p)).map(|p| p.display().to_string());
        assert_eq!(
            c("/c/A_01_E_S.E01").as_deref(),
            Some("/c/A_01_E_S.info.json")
        );
        assert_eq!(c("/c/A.Ex01").as_deref(), Some("/c/A.info.json"));
        assert_eq!(c("/c/A.e05").as_deref(), Some("/c/A.info.json"));
        assert_eq!(c("/c/A.raw").as_deref(), Some("/c/A.info.json"));
        assert_eq!(c("/c/A.001").as_deref(), Some("/c/A.info.json"));
        assert_eq!(c("/c/A.tar").as_deref(), Some("/c/A.tar.info.json"));
        assert_eq!(c("/"), None);
        assert!(is_ewf_name("x.E01") && is_ewf_name("x.ex01") && is_ewf_name("x.S02"));
        assert!(!is_ewf_name("x.raw") && !is_ewf_name("E01") && !is_ewf_name("x.e1"));
    }

    #[test]
    fn converter_target_detection() {
        let mut f = ConvForm {
            source: "/c/img.E01".into(),
            ..Default::default()
        };
        f.detect_target();
        assert_eq!(f.target, ConversionTarget::Raw);
        f.source = "/c/img.raw".into();
        f.detect_target();
        assert_eq!(f.target, ConversionTarget::E01);
        assert!(!ConvField::focus_order(ConversionTarget::Raw).contains(&ConvField::Compression));
    }
}
