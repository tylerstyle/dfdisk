use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "dfdisk",
    author = "dfdisk DFIR contributors",
    version = env!("CARGO_PKG_VERSION"),
    about = "Modern forensic disk imaging, rescue, and format conversion CLI/TUI",
    long_about = "A high-performance forensic disk imager and evidence management tool.\nSupports E01 (Expert Witness Format) and RAW imaging, damaged media rescue (ddrescue),\nauto-sanitized forensic naming, cryptographic verification (MD5/SHA1/SHA256),\nand forensic .info certificate generation."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch the interactive Terminal User Interface (TUI)
    Tui,

    /// List all connected storage media with hardware details and safety status
    List(ListArgs),

    /// Perform a forensic disk acquisition
    Acquire(AcquireArgs),

    /// Convert between RAW (.dd/.raw/.img) and E01 (.E01) forensic image formats
    Convert(ConvertArgs),

    /// Verify the cryptographic integrity of a forensic image against its hashes
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output the device list as formatted JSON
    #[arg(long, short = 'j')]
    pub json: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliImageFormat {
    E01,
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
    None,
    #[value(name = "2G")]
    TwoGb,
    #[value(name = "4G")]
    FourGb,
}

#[derive(Args, Debug)]
pub struct AcquireArgs {
    /// Source block device path (e.g. /dev/sdb, /dev/nvme1n1)
    pub device: String,

    /// Case number (e.g. VG12345/26)
    #[arg(long, short = 'C', default_value = "CASE001")]
    pub case: String,

    /// Location / Asservat / EA (e.g. 01, 02)
    #[arg(long, default_value = "01")]
    pub ea: String,

    /// Evidence number (e.g. cf01, mf01, hd01)
    #[arg(long, short = 'E', default_value = "cf01")]
    pub evidence: String,

    /// Authority / Agency (e.g. Police CID)
    #[arg(long, default_value = "Law Enforcement / DFIR Unit")]
    pub authority: String,

    /// Examiner name or ID (e.g. "J. Doe #4192")
    #[arg(long, short = 'e', default_value = "Forensic Examiner")]
    pub examiner: String,

    /// Description of the target media
    #[arg(long, short = 'D', default_value = "Physical Storage Media")]
    pub description: String,

    /// Additional examiner notes
    #[arg(long, short = 'N', default_value = "")]
    pub notes: String,

    /// Destination directory for evidence images and .info certificate
    #[arg(long, short = 'o', default_value = ".")]
    pub output_dir: PathBuf,

    /// Output image format
    #[arg(long, value_enum, default_value = "e01")]
    pub format: CliImageFormat,

    /// Segment split size
    #[arg(long, value_enum, default_value = "2G")]
    pub split: CliSplitSize,

    /// Compression level
    #[arg(long, value_enum, default_value = "fast")]
    pub compression: CliCompression,

    /// Retries on bad sectors
    #[arg(long, short = 'r', default_value_t = 2)]
    pub retries: u32,

    /// Use ddrescue engine for heavily damaged media
    #[arg(long)]
    pub rescue: bool,

    /// Automatically unmount mounted partitions on target device
    #[arg(long)]
    pub auto_unmount: bool,
}

#[derive(Args, Debug)]
pub struct ConvertArgs {
    /// Source image file (.raw, .dd, or .E01)
    pub source: PathBuf,

    /// Target conversion format (e01 or raw)
    #[arg(long, value_enum)]
    pub to: CliImageFormat,

    /// Destination directory for converted image
    #[arg(long, short = 'o', default_value = ".")]
    pub output_dir: PathBuf,

    /// Optional case number for E01 headers
    #[arg(long)]
    pub case: Option<String>,

    /// Optional evidence number for E01 headers
    #[arg(long)]
    pub evidence: Option<String>,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to forensic image file (.E01 or .raw)
    pub image: PathBuf,

    /// Expected MD5 hash to verify against
    #[arg(long)]
    pub md5: Option<String>,

    /// Expected SHA-1 hash to verify against
    #[arg(long)]
    pub sha1: Option<String>,

    /// Expected SHA-256 hash to verify against
    #[arg(long)]
    pub sha256: Option<String>,
}
