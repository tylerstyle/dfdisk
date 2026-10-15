//! Case profile of the examiner (§16, review F11): examiner, authority, last
//! destination and the last case and evidence numbers, kept in
//! `$XDG_CONFIG_HOME/dfdisk/profile.toml` (or `~/.config/dfdisk/profile.toml`).
//!
//! The values pre-fill the case setup form where they are the examiner's own
//! (examiner, authority, destination); the last case number and the next
//! evidence number are offered as suggestions only and become values when
//! the examiner accepts them. The file is a flat TOML table of strings,
//! written and read here without a TOML library (unknown keys are ignored).

use crate::models::text::sanitize_line;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// The persisted profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseProfile {
    pub examiner: String,
    pub authority: String,
    pub last_destination: String,
    pub last_case: String,
    pub last_evidence: String,
}

const KEYS: [&str; 5] = [
    "examiner",
    "authority",
    "last_destination",
    "last_case",
    "last_evidence",
];

/// `$XDG_CONFIG_HOME/dfdisk/profile.toml`, else `$HOME/.config/dfdisk/profile.toml`
/// (relative XDG paths are ignored, as the XDG spec says).
pub fn profile_path_from(
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    let base = xdg_config_home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            home.map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|h| h.join(".config"))
        })?;
    Some(base.join("dfdisk").join("profile.toml"))
}

/// The profile path of this user.
pub fn default_profile_path() -> Option<PathBuf> {
    profile_path_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Value of a TOML basic string starting after its opening quote; `None`
/// when it is malformed.
fn unescape(rest: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                'U' => {
                    let hex: String = chars.by_ref().take(8).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    None
}

impl CaseProfile {
    /// Parse the profile file; malformed lines and unknown keys are skipped.
    pub fn parse(content: &str) -> Self {
        let mut p = CaseProfile::default();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            let Some(rest) = value.strip_prefix('"') else {
                continue;
            };
            let Some(value) = unescape(rest) else {
                continue;
            };
            // Values are single-line text fields
            let value = sanitize_line(&value);
            match key.trim() {
                "examiner" => p.examiner = value,
                "authority" => p.authority = value,
                "last_destination" => p.last_destination = value,
                "last_case" => p.last_case = value,
                "last_evidence" => p.last_evidence = value,
                _ => {}
            }
        }
        p
    }

    /// The profile as TOML.
    pub fn to_toml(&self) -> String {
        let mut out = String::from(
            "# dfdisk case profile, written by the dfdisk TUI.\n\
             # Examiner, authority and destination pre-fill the case setup;\n\
             # the last case and evidence numbers are offered as suggestions.\n",
        );
        for (key, value) in KEYS.iter().zip([
            &self.examiner,
            &self.authority,
            &self.last_destination,
            &self.last_case,
            &self.last_evidence,
        ]) {
            out.push_str(&format!("{key} = \"{}\"\n", escape(value)));
        }
        out
    }

    /// Load from `path`; a missing file is an empty profile.
    pub fn load(path: &Path) -> io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(Self::parse(&content)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Write to `path` (directory created, temp file + rename).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, self.to_toml())?;
        std::fs::rename(&tmp, path)
    }

    /// The case number to suggest (the last one used).
    pub fn case_suggestion(&self) -> Option<String> {
        Some(self.last_case.clone()).filter(|c| !c.trim().is_empty())
    }

    /// The evidence number to suggest for `case`: the last evidence number
    /// of the same case, incremented. Nothing for another case.
    pub fn evidence_suggestion(&self, case: &str) -> Option<String> {
        if case.trim().is_empty() || case.trim() != self.last_case.trim() {
            return None;
        }
        increment_evidence(self.last_evidence.trim())
    }
}

/// "cf01" -> "cf02", "E9" -> "E10", "HDD-099" -> "HDD-100": the last run of
/// digits incremented, zero padding kept; `None` without digits.
pub fn increment_evidence(last: &str) -> Option<String> {
    let bytes = last.as_bytes();
    let end = bytes.iter().rposition(|b| b.is_ascii_digit())? + 1;
    let start = bytes[..end]
        .iter()
        .rposition(|b| !b.is_ascii_digit())
        .map(|i| i + 1)
        .unwrap_or(0);
    let digits = &last[start..end];
    let next = digits.parse::<u128>().ok()?.checked_add(1)?;
    let formatted = format!("{next:0width$}", width = digits.len());
    Some(format!("{}{}{}", &last[..start], formatted, &last[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_follows_xdg() {
        assert_eq!(
            profile_path_from(Some("/x/cfg".into()), Some("/home/u".into())),
            Some(PathBuf::from("/x/cfg/dfdisk/profile.toml"))
        );
        assert_eq!(
            profile_path_from(Some("relative".into()), Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.config/dfdisk/profile.toml"))
        );
        assert_eq!(profile_path_from(None, None), None);
    }

    #[test]
    fn round_trip_with_awkward_values() {
        let p = CaseProfile {
            examiner: "Det. \"J\" Doe \\ #4192".into(),
            authority: "Unit ü 世".into(),
            last_destination: "/mnt/evidence/case 1".into(),
            last_case: "2026/0042".into(),
            last_evidence: "HDD-009".into(),
        };
        assert_eq!(CaseProfile::parse(&p.to_toml()), p);
        // Control characters never survive into a value
        let q = CaseProfile {
            examiner: "a\nb\tc\u{1b}[31m".into(),
            ..Default::default()
        };
        let parsed = CaseProfile::parse(&q.to_toml());
        assert!(!parsed.examiner.chars().any(|c| c.is_control()));
        assert!(parsed.examiner.starts_with("a b c"));
    }

    #[test]
    fn parse_skips_garbage() {
        let p = CaseProfile::parse(
            "# c\n[table]\nexaminer = \"A\"\nbad line\nauthority = unquoted\nother = \"x\"\nlast_case = \"broken\\q\"\n",
        );
        assert_eq!(p.examiner, "A");
        assert_eq!(p.authority, "");
        assert_eq!(p.last_case, "");
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("profile.toml");
        assert_eq!(CaseProfile::load(&path).unwrap(), CaseProfile::default());
        let p = CaseProfile {
            examiner: "E".into(),
            ..Default::default()
        };
        p.save(&path).unwrap();
        assert_eq!(CaseProfile::load(&path).unwrap(), p);
    }

    #[test]
    fn evidence_numbers_increment() {
        assert_eq!(increment_evidence("cf01").as_deref(), Some("cf02"));
        assert_eq!(increment_evidence("E9").as_deref(), Some("E10"));
        assert_eq!(increment_evidence("HDD-099").as_deref(), Some("HDD-100"));
        assert_eq!(increment_evidence("7").as_deref(), Some("8"));
        assert_eq!(increment_evidence("A12b").as_deref(), Some("A13b"));
        assert_eq!(increment_evidence("none"), None);
        assert_eq!(increment_evidence(""), None);
        let p = CaseProfile {
            last_case: "C1".into(),
            last_evidence: "ev01".into(),
            ..Default::default()
        };
        assert_eq!(p.evidence_suggestion("C1").as_deref(), Some("ev02"));
        assert_eq!(p.evidence_suggestion("C2"), None);
        assert_eq!(p.case_suggestion().as_deref(), Some("C1"));
    }
}
