//! Command line of `dfdisk` (§15). Every flag is documented here; `--help`
//! of every command that can end with a verdict lists its exit codes (§2).

use crate::cli::size::{parse_piece_size, parse_size, PieceSize};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// The exit-code table (§2) as a literal, so it can be `concat!`ed.
macro_rules! exit_code_table {
    () => {
        "Exit codes:
  0  verified: complete, and the re-read image matches the acquisition digests
  1  internal error
  2  usage error: missing, invalid or inconsistent arguments
  3  refused: a safety, identity or destination check failed; nothing was read
  4  failed: could not run, or the verification could not run or complete
  5  hash mismatch
  6  incomplete: not all of the source was acquired
  7  completed with read errors: unreadable sectors were replaced by zeros
  8  aborted by the examiner or a signal (SIGINT, SIGTERM)
  9  complete but not verified: no independent comparison was possible"
    };
}

/// The exit-code table (§2), shown by `dfdisk --help` and `acquire --help`.
pub const EXIT_CODES_HELP: &str = exit_code_table!();

const ACQUIRE_AFTER_HELP: &str = concat!(
    "Required: the source, --output-dir, --case, --evidence and --examiner. Nothing is
filled in for you: no case value is ever made up, and missing optional values are
recorded as \"(not provided)\".

Source: a path (/dev/sdb, /dev/disk/by-id/..., ./image.dd) or a bare device name
(sdb). A bare name means /dev/<name>; it is refused when ./<name> exists as well.
Regular files are accepted as sources (image files).

Signals: the first SIGINT (Ctrl+C) or a SIGTERM stops the acquisition gracefully;
the outputs are kept and the report says ABORTED (exit 8). A second SIGINT kills
external tools at once; the report is still written. SIGHUP (terminal closed)
keeps the acquisition running without terminal output until its report is written.

The exit code is the verdict of the report (0, 5-9), or 2, 3 or 4 when no
acquisition ran. With --rescue-to-e01 it is the more severe of the rescue and the
conversion, from most to least severe: 1, 2, 8, 5, 4, 3, 6, 7, 9, 0.

",
    exit_code_table!()
);

const CHECK_AFTER_HELP: &str = "\
check runs every step an acquisition runs before it reads the source (request,
identity, registry, system disk, swap, mounts, holders, exclusive open,
destination, capacity and SMART as configured) and writes nothing: no directory,
no file, no audit record, no read-only flag.

Exit codes:
  0  ready: the acquisition would start
  2  usage error: missing, invalid or inconsistent arguments
  3  refused: the acquisition would be refused (every reason is listed)
  4  a check could not run
  8  interrupted (SIGINT, SIGTERM)";

const VERIFY_AFTER_HELP: &str = "\
Expected digests come from --md5/--sha1/--sha256 or from a dfdisk report
(--report <base>.info.json). EWF images (.E01, .Ex01, .E02 ...) are re-read by
ewfverify and also compared with the digests they store; anything else (RAW,
split RAW .001 ...) is hashed by dfdisk, and with --pieces checked piece by
piece. A digest that was expected but not computed fails the verification; it
never passes. Every run writes an addendum <base>.verify-<UTC>.txt next to the
image (<base>: the image file name without its extension) and an audit record.

Exit codes:
  0  every digest compared (expected, stored in the E01, every piece) matches
  2  usage error
  4  verification failed: the image could not be read completely, or an expected
     digest was not computed
  5  hash mismatch (a digest or a piece differs)
  8  aborted (SIGINT, SIGTERM)
  9  digests computed, but nothing to compare them against";

const CONVERT_AFTER_HELP: &str = "\
Without case flags the case fields are taken from the source's dfdisk report;
without such a report --case, --evidence and --examiner are required. Existing
outputs are never overwritten. The conversion is verified and writes its own
report (<base>.conversion.info + <base>.conversion.info.json, <base>: the source
name without its extensions) and audit records. SIGINT/SIGTERM abort it (exit 8).

Exit codes: the verdict of the conversion report (0, 4, 5, 6, 7, 8, 9), or 2
(usage), 3 (refused) or 4 (failed) when no conversion ran; see dfdisk --help.";

const UNMOUNT_AFTER_HELP: &str = "\
Unmounts every filesystem of the device and of everything stacked on it
(partitions, device-mapper/LUKS mappings), deepest first, and verifies that
nothing stays mounted. Refused for devices protected by the dfnix registry, system
mounts and active swap. Never lazy, never forced. Holders (open LUKS/LVM/md) are
reported, not closed. Every unmount is recorded in the audit log.

Exit codes:
  0  nothing of the device is mounted any more (or nothing was mounted)
  2  usage error
  3  refused (protected device, system mount, swap, unidentifiable device)
  4  an unmount failed or a mount remained";

#[derive(Parser, Debug)]
#[command(
    name = "dfdisk",
    author = "dfdisk DFIR contributors",
    version = env!("CARGO_PKG_VERSION"),
    long_version = crate::models::provenance::LONG_VERSION,
    about = "Forensic disk imaging, damaged-media rescue and image conversion (CLI and TUI)",
    long_about = "Forensic disk imager for E01 (ewfacquire), native RAW and damaged-media rescue \
(GNU ddrescue) acquisitions. Every acquisition pins the source identity, enforces write \
protection, records an audit trail and writes a verdict-first report (<base>.info and \
<base>.info.json). Without a command, the interactive terminal UI starts.",
    after_help = EXIT_CODES_HELP
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the interactive terminal UI (the default without a command)
    Tui,

    /// List block devices with identity, attachment and safety state
    List(ListArgs),

    /// Acquire a device (or an image file) as E01 or RAW, verified and reported
    #[command(after_help = ACQUIRE_AFTER_HELP)]
    Acquire(AcquireArgs),

    /// Dry run of an acquisition: every check, nothing written or changed
    #[command(after_help = CHECK_AFTER_HELP)]
    Check(CheckArgs),

    /// Unmount everything of a device (audited) so it can be acquired
    #[command(after_help = UNMOUNT_AFTER_HELP)]
    Unmount(UnmountArgs),

    /// Re-verify an image against expected digests or its dfdisk report
    #[command(after_help = VERIFY_AFTER_HELP)]
    Verify(VerifyArgs),

    /// Convert a RAW image to E01 or an E01 image to RAW, verified and reported
    #[command(after_help = CONVERT_AFTER_HELP)]
    Convert(ConvertArgs),
}

impl Commands {
    /// Whether the command was asked for JSON output on stdout.
    pub fn json(&self) -> bool {
        match self {
            Commands::Tui => false,
            Commands::List(a) => a.json,
            Commands::Acquire(a) => a.json,
            Commands::Check(a) => a.json,
            Commands::Unmount(a) => a.json,
            Commands::Verify(a) => a.json,
            Commands::Convert(a) => a.json,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    /// Print the device list as JSON on stdout
    #[arg(long, short = 'j')]
    pub json: bool,

    /// Also query the SMART health of every whole disk (smartctl -j -i -H -A
    /// -l error -n standby: identify-class commands, a disk in standby is not
    /// woken; off by default, never part of a scan)
    #[arg(long)]
    pub smart: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliImageFormat {
    /// Expert Witness Format through ewfacquire (segments, compression, MD5 always)
    E01,
    /// One RAW file written by dfdisk's native engine
    Raw,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliCompression {
    None,
    Fast,
    Best,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliSplitSize {
    /// One segment (up to the EnCase 6 maximum)
    None,
    /// 2 GiB segments
    #[value(name = "2G")]
    TwoGb,
    /// 4 GiB segments
    #[value(name = "4G")]
    FourGb,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliDigest {
    Md5,
    Sha1,
    Sha256,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliOnReadError {
    /// Stop at the first unreadable sector (INCOMPLETE, exact offset)
    Stop,
    /// Replace each unreadable sector by zeros, list every range and continue
    /// (COMPLETED WITH READ ERRORS)
    ZeroFill,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliSmart {
    /// No SMART command is sent
    Off,
    /// smartctl -i -H -A -l error (identify, health, attributes, error log)
    Basic,
    /// basic plus the extended logs of -x, without SCT commands
    Full,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliWriteProtect {
    /// Set the kernel read-only flag (BLKROSET) on the disk and its partitions
    /// where it is not set; refuse when that fails. dfdisk leaves it set
    Auto,
    /// Only record the read-only state
    Off,
}

/// Case and chain-of-custody fields of an acquisition (§9). Case, evidence
/// and examiner are required; nothing is ever filled in.
#[derive(Args, Debug, Clone)]
pub struct CaseArgs {
    /// Case number (required), e.g. "VG 12345/26"
    #[arg(
        long,
        short = 'C',
        value_name = "CASE",
        help_heading = "Case (chain of custody)"
    )]
    pub case: String,

    /// Evidence (exhibit) number (required), e.g. hd01
    #[arg(
        long,
        short = 'E',
        value_name = "EVIDENCE",
        help_heading = "Case (chain of custody)"
    )]
    pub evidence: String,

    /// Examiner name or ID (required)
    #[arg(
        long,
        short = 'e',
        value_name = "EXAMINER",
        help_heading = "Case (chain of custody)"
    )]
    pub examiner: String,

    /// Location / EA number, part of the file name [default: 01]
    #[arg(long, value_name = "EA", help_heading = "Case (chain of custody)")]
    pub ea: Option<String>,

    /// Authority / agency
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub authority: Option<String>,

    /// Description of the evidence medium
    #[arg(
        long,
        short = 'D',
        value_name = "TEXT",
        help_heading = "Case (chain of custody)"
    )]
    pub description: Option<String>,

    /// Examiner notes
    #[arg(
        long,
        short = 'N',
        value_name = "TEXT",
        help_heading = "Case (chain of custody)"
    )]
    pub notes: Option<String>,

    /// Seal number of the evidence bag
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub seal: Option<String>,

    /// When the evidence was seized (free text, recorded as given)
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub seized_at: Option<String>,

    /// Where the evidence was seized
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub seized_location: Option<String>,
}

/// Everything `acquire` and `check` share besides the source and the case.
#[derive(Args, Debug, Clone)]
pub struct AcquisitionOptions {
    /// Destination directory (required) for the image, its reports and
    /// auxiliary files; created if missing, never on the source
    #[arg(long, short = 'o', value_name = "DIR", help_heading = "Output")]
    pub output_dir: PathBuf,

    /// Image format [default: e01]
    #[arg(long, value_enum, value_name = "FORMAT", help_heading = "Output")]
    pub format: Option<CliImageFormat>,

    /// Digests to compute and verify, comma separated (E01 always adds MD5)
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        value_name = "LIST",
        default_value = "md5,sha1,sha256",
        help_heading = "Output"
    )]
    pub digests: Vec<CliDigest>,

    /// E01 (and --rescue-to-e01) compression [default: fast]
    #[arg(long, value_enum, value_name = "LEVEL", help_heading = "Output")]
    pub compression: Option<CliCompression>,

    /// E01 (and --rescue-to-e01) segment size [default: 2G]
    #[arg(long, value_enum, value_name = "SIZE", help_heading = "Output")]
    pub split: Option<CliSplitSize>,

    /// RAW: piece size of the piecewise SHA-256 (<base>.pieces.tsv), at least 1M
    /// and a multiple of 512 bytes, or "off" [default: 1G]. K/M/G/T and
    /// KiB/MiB/GiB/TiB are powers of 1024, KB/MB/GB/TB powers of 1000
    #[arg(long, value_name = "SIZE", value_parser = parse_piece_size, help_heading = "Output")]
    pub piece_size: Option<PieceSize>,

    /// Use GNU ddrescue for damaged media (RAW image plus <base>.map)
    #[arg(long, help_heading = "Engine")]
    pub rescue: bool,

    /// Rescue: continue an interrupted rescue of the same device from its map
    #[arg(long, help_heading = "Engine")]
    pub resume: bool,

    /// Rescue: convert the rescued RAW image to E01 afterwards (verified, with
    /// its own report; the read-error summary goes into the E01 notes)
    #[arg(long, help_heading = "Engine")]
    pub rescue_to_e01: bool,

    /// E01 and rescue: read retries for unreadable sectors, 0-255 [default: 2]
    #[arg(long, short = 'r', value_name = "N", help_heading = "Engine")]
    pub retries: Option<u32>,

    /// E01: ewfacquire error granularity in sectors (-g) [default: physical /
    /// logical sector size]
    #[arg(long, value_name = "SECTORS", help_heading = "Engine")]
    pub error_granularity: Option<u32>,

    /// RAW: what to do with an unreadable sector [default: stop]
    #[arg(long, value_enum, value_name = "POLICY", help_heading = "Engine")]
    pub on_read_error: Option<CliOnReadError>,

    /// Read the source a second time after the acquisition and compare the
    /// digests (the only way to verify a rescue)
    #[arg(long, help_heading = "Engine")]
    pub verify_source: bool,

    /// SMART commands sent to the source before (and, for a rescue, after) the
    /// acquisition
    #[arg(
        long,
        value_enum,
        value_name = "POLICY",
        default_value = "basic",
        help_heading = "Safety"
    )]
    pub smart: CliSmart,

    /// Kernel read-only flag on the source
    #[arg(
        long,
        value_enum,
        value_name = "POLICY",
        default_value = "auto",
        help_heading = "Safety"
    )]
    pub write_protect: CliWriteProtect,

    /// Acquire a source with device-mapper/LVM/md/LUKS devices stacked on it
    #[arg(long, help_heading = "Safety")]
    pub allow_holders: bool,

    /// Accept a destination on tmpfs/ramfs (lost at power-off)
    #[arg(long, help_heading = "Safety")]
    pub allow_tmpfs: bool,

    /// E01: accept a destination with less free space than the source size
    #[arg(long, help_heading = "Safety")]
    pub allow_low_space: bool,

    /// Refuse when an HPA or DCO hides sectors of the disk (default: warn)
    #[arg(long, help_heading = "Safety")]
    pub refuse_hidden_areas: bool,

    /// Refuse unless the source reports this serial number
    #[arg(long, value_name = "SERIAL", help_heading = "Safety")]
    pub expect_serial: Option<String>,

    /// Refuse unless the source reports this WWN
    #[arg(long, value_name = "WWN", help_heading = "Safety")]
    pub expect_wwn: Option<String>,

    /// Refuse unless the source has exactly this size (bytes, or with K/M/G/T,
    /// KiB..., KB... as for --piece-size)
    #[arg(long, value_name = "SIZE", value_parser = parse_size, help_heading = "Safety")]
    pub expect_size: Option<u64>,
}

#[derive(Args, Debug, Clone)]
pub struct AcquireArgs {
    /// Source: device path, bare device name (sdb = /dev/sdb) or image file
    pub device: String,

    #[command(flatten)]
    pub case: CaseArgs,

    #[command(flatten)]
    pub options: AcquisitionOptions,

    /// Unmount the source and everything stacked on it first (audited, the same
    /// as `dfdisk unmount`); refused for system mounts and protected devices
    #[arg(long, help_heading = "Safety")]
    pub auto_unmount: bool,

    /// Print the final report (<base>.info.json) on stdout and every other line
    /// on stderr. With --rescue-to-e01 stdout is {"acquisition": <report>,
    /// "conversion": <conversion report> | null, "conversion_error": {..} | null,
    /// "conversion_skipped": <reason> | null, "exit_code": N}
    #[arg(long, help_heading = "Output")]
    pub json: bool,

    /// Print every log line of the engines and tools (default: warnings and
    /// phases only)
    #[arg(long, short = 'v', help_heading = "Output")]
    pub verbose: bool,
}

#[derive(Args, Debug, Clone)]
pub struct CheckArgs {
    /// Source: device path, bare device name (sdb = /dev/sdb) or image file
    pub device: String,

    #[command(flatten)]
    pub case: CaseArgs,

    #[command(flatten)]
    pub options: AcquisitionOptions,

    /// Print the readiness report as JSON on stdout
    #[arg(long, help_heading = "Output")]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct UnmountArgs {
    /// Device: path or bare device name (sdb = /dev/sdb)
    pub device: String,

    /// Print the result as JSON on stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Image: RAW file (.raw/.dd/.img, first segment .001 of a split RAW) or EWF
    /// segment (.E01/.Ex01)
    pub image: PathBuf,

    /// Expected MD5
    #[arg(long, value_name = "HEX")]
    pub md5: Option<String>,

    /// Expected SHA-1
    #[arg(long, value_name = "HEX")]
    pub sha1: Option<String>,

    /// Expected SHA-256
    #[arg(long, value_name = "HEX")]
    pub sha256: Option<String>,

    /// Take the expected digests from this dfdisk report (<base>.info.json)
    #[arg(long, value_name = "INFO_JSON", conflicts_with_all = ["md5", "sha1", "sha256"])]
    pub report: Option<PathBuf>,

    /// Also re-check a RAW image piece by piece against its <base>.pieces.tsv
    #[arg(long, value_name = "TSV")]
    pub pieces: Option<PathBuf>,

    /// Print the result as JSON on stdout
    #[arg(long)]
    pub json: bool,
}

/// Case fields of a conversion: all optional (the converter takes them from
/// the source's dfdisk report when none is given).
#[derive(Args, Debug, Clone, Default)]
pub struct ConvertCaseArgs {
    /// Case number [default: from the source's report]
    #[arg(
        long,
        short = 'C',
        value_name = "CASE",
        help_heading = "Case (chain of custody)"
    )]
    pub case: Option<String>,

    /// Evidence number [default: from the source's report]
    #[arg(
        long,
        short = 'E',
        value_name = "EVIDENCE",
        help_heading = "Case (chain of custody)"
    )]
    pub evidence: Option<String>,

    /// Examiner [default: from the source's report]
    #[arg(
        long,
        short = 'e',
        value_name = "EXAMINER",
        help_heading = "Case (chain of custody)"
    )]
    pub examiner: Option<String>,

    /// Location / EA number
    #[arg(long, value_name = "EA", help_heading = "Case (chain of custody)")]
    pub ea: Option<String>,

    /// Authority / agency
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub authority: Option<String>,

    /// Description of the evidence medium
    #[arg(
        long,
        short = 'D',
        value_name = "TEXT",
        help_heading = "Case (chain of custody)"
    )]
    pub description: Option<String>,

    /// Examiner notes
    #[arg(
        long,
        short = 'N',
        value_name = "TEXT",
        help_heading = "Case (chain of custody)"
    )]
    pub notes: Option<String>,

    /// Seal number of the evidence bag
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub seal: Option<String>,

    /// When the evidence was seized (free text)
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub seized_at: Option<String>,

    /// Where the evidence was seized
    #[arg(long, value_name = "TEXT", help_heading = "Case (chain of custody)")]
    pub seized_location: Option<String>,
}

impl ConvertCaseArgs {
    /// Whether any case flag was given.
    pub fn any(&self) -> bool {
        [
            &self.case,
            &self.evidence,
            &self.examiner,
            &self.ea,
            &self.authority,
            &self.description,
            &self.notes,
            &self.seal,
            &self.seized_at,
            &self.seized_location,
        ]
        .iter()
        .any(|v| v.is_some())
    }
}

#[derive(Args, Debug, Clone)]
pub struct ConvertArgs {
    /// Source image: RAW (.raw/.dd/.img, first segment .001 of a split RAW) or
    /// the first EWF segment (.E01)
    pub source: PathBuf,

    /// Target format
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub to: CliImageFormat,

    /// Destination directory (required) for the converted image and its report
    #[arg(long, short = 'o', value_name = "DIR")]
    pub output_dir: PathBuf,

    #[command(flatten)]
    pub case: ConvertCaseArgs,

    /// E01 target: compression [default: fast]
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub compression: Option<CliCompression>,

    /// E01 target: segment size [default: 2G]
    #[arg(long, value_enum, value_name = "SIZE")]
    pub split: Option<CliSplitSize>,

    /// The dfdisk report of the acquisition the source came from; referenced in
    /// the conversion report and its digests compared [default: <base>.info.json
    /// next to the source, when it exists]
    #[arg(long, value_name = "INFO_JSON")]
    pub report: Option<PathBuf>,

    /// Accept a destination on tmpfs/ramfs (lost at power-off)
    #[arg(long)]
    pub allow_tmpfs: bool,

    /// E01 target: accept a destination with less free space than the source
    /// image (the E01 fits only if compression saves the difference)
    #[arg(long)]
    pub allow_low_space: bool,

    /// Print the conversion report as JSON on stdout
    #[arg(long)]
    pub json: bool,
}
