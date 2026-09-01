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
    #[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorHandling {
    WipeWithZero,
    NoWipe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionConfig {
    pub format: ImageFormat,
    pub output_dir: PathBuf,
    pub compression: CompressionLevel,
    pub split_size: SplitSize,
    pub calc_md5: bool,
    pub calc_sha1: bool,
    pub calc_sha256: bool,
    pub error_retries: u32,
    pub wipe_bad_sectors: bool,
    pub rescue_mode: bool,
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
        }
    }
}
