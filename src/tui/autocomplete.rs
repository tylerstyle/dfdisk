//! Path completion for the path inputs (destination, converter source,
//! re-verification image). The App runs [`find_path_completions`] off the UI
//! thread on an explicit key (F4) and shows the candidates as a list (§16).

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Expands a leading `~` or `~/` to the user's home directory.
pub fn expand_tilde(path: &Path) -> PathBuf {
    expand_tilde_with(path, std::env::var_os("HOME").as_deref())
}

/// [`expand_tilde`] with an explicit home directory (`None`: unchanged).
pub fn expand_tilde_with(path: &Path, home: Option<&OsStr>) -> PathBuf {
    let Some(home) = home.filter(|h| !h.is_empty()) else {
        return path.to_path_buf();
    };
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        PathBuf::from(home)
    } else if let Some(rest) = path_str.strip_prefix("~/") {
        PathBuf::from(home).join(rest)
    } else {
        path.to_path_buf()
    }
}

/// Finds the longest common prefix across a slice of strings, respecting UTF-8 char boundaries.
pub fn longest_common_prefix(strings: &[String]) -> String {
    if strings.is_empty() {
        return String::new();
    }
    let mut common = strings[0].clone();
    for s in &strings[1..] {
        let mut byte_len = 0;
        for (c1, c2) in common.chars().zip(s.chars()) {
            if c1 == c2 {
                byte_len += c1.len_utf8();
            } else {
                break;
            }
        }
        common.truncate(byte_len);
        if common.is_empty() {
            break;
        }
    }
    common
}

/// Finds matching path candidates in the filesystem for a given prefix string.
/// - If `dirs_only` is true, only directories (and symlinks to directories) are returned.
/// - Directories always have a trailing slash appended.
/// - If exact case matching yields no results, falls back to case-insensitive matching.
pub fn find_path_completions(prefix: &str, dirs_only: bool) -> Vec<String> {
    let (search_dir, dir_display, file_prefix) = if prefix == "~" {
        (
            expand_tilde(Path::new("~")),
            "~/".to_string(),
            "".to_string(),
        )
    } else if let Some(rest) = prefix.strip_prefix("~/") {
        let home = expand_tilde(Path::new("~"));
        if let Some(slash_idx) = rest.rfind('/') {
            let rel_dir = &rest[..=slash_idx];
            let file_pfx = &rest[slash_idx + 1..];
            (
                home.join(rel_dir),
                format!("~/{}", rel_dir),
                file_pfx.to_string(),
            )
        } else {
            (home, "~/".to_string(), rest.to_string())
        }
    } else if prefix.ends_with('/') {
        (PathBuf::from(prefix), prefix.to_string(), "".to_string())
    } else if let Some(slash_idx) = prefix.rfind('/') {
        let dir_part = &prefix[..=slash_idx];
        let file_pfx = &prefix[slash_idx + 1..];
        (
            PathBuf::from(dir_part),
            dir_part.to_string(),
            file_pfx.to_string(),
        )
    } else {
        (PathBuf::from("."), "".to_string(), prefix.to_string())
    };

    let entries = match fs::read_dir(&search_dir) {
        Ok(iter) => iter,
        Err(_) => return Vec::new(),
    };

    let mut exact_matches = Vec::new();
    let mut ci_matches = Vec::new();

    let file_prefix_lower = file_prefix.to_lowercase();
    let match_hidden = file_prefix.starts_with('.');

    for entry in entries.flatten() {
        let file_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };

        if file_name == "." || file_name == ".." {
            continue;
        }

        if !match_hidden && file_name.starts_with('.') {
            continue;
        }

        let is_dir = entry.path().is_dir();
        if dirs_only && !is_dir {
            continue;
        }

        let slash = if is_dir { "/" } else { "" };
        let candidate = format!("{}{}{}", dir_display, file_name, slash);

        if file_name.starts_with(&file_prefix) {
            exact_matches.push(candidate);
        } else if file_name.to_lowercase().starts_with(&file_prefix_lower) {
            ci_matches.push(candidate);
        }
    }

    let mut final_matches = if !exact_matches.is_empty() {
        exact_matches
    } else {
        ci_matches
    };

    final_matches.sort();
    final_matches.dedup();
    final_matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir, File};

    #[test]
    fn test_longest_common_prefix() {
        assert_eq!(longest_common_prefix(&[]), "");
        assert_eq!(
            longest_common_prefix(&["/path/to/alpha".to_string()]),
            "/path/to/alpha"
        );
        assert_eq!(
            longest_common_prefix(&[
                "/path/to/alpha".to_string(),
                "/path/to/alpine".to_string(),
                "/path/to/all".to_string(),
            ]),
            "/path/to/al"
        );
        assert_eq!(
            longest_common_prefix(&["/foo".to_string(), "/bar".to_string()]),
            "/"
        );
        assert_eq!(
            longest_common_prefix(&["/データ/ケース1".to_string(), "/データ/ケース2".to_string(),]),
            "/データ/ケース"
        );
    }

    #[test]
    fn test_expand_tilde() {
        let home = Some(OsStr::new("/custom/home"));
        assert_eq!(
            expand_tilde_with(Path::new("~"), home),
            PathBuf::from("/custom/home")
        );
        assert_eq!(
            expand_tilde_with(Path::new("~/cases/ev01"), home),
            PathBuf::from("/custom/home/cases/ev01")
        );
        assert_eq!(
            expand_tilde_with(Path::new("/var/log"), home),
            PathBuf::from("/var/log")
        );
        assert_eq!(
            expand_tilde_with(Path::new("relative/path"), home),
            PathBuf::from("relative/path")
        );
        assert_eq!(
            expand_tilde_with(Path::new("~/x"), None),
            PathBuf::from("~/x")
        );
        assert_eq!(
            expand_tilde_with(Path::new("~user/x"), home),
            PathBuf::from("~user/x")
        );
    }

    #[test]
    fn test_find_completions_in_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        let temp = tmp.path();

        create_dir(temp.join("evidence_dir")).unwrap();
        create_dir(temp.join("export_dir")).unwrap();
        File::create(temp.join("evidence.raw")).unwrap();
        File::create(temp.join("evidence.E01")).unwrap();
        File::create(temp.join(".hidden_file")).unwrap();

        let temp_str = temp.to_string_lossy().to_string();

        // 1. Dirs only on temp/e
        let dir_matches = find_path_completions(&format!("{}/e", temp_str), true);
        assert_eq!(dir_matches.len(), 2);
        assert!(dir_matches.contains(&format!("{}/evidence_dir/", temp_str)));
        assert!(dir_matches.contains(&format!("{}/export_dir/", temp_str)));

        // 2. Both files and dirs on temp/evi
        let all_matches = find_path_completions(&format!("{}/evi", temp_str), false);
        assert_eq!(all_matches.len(), 3);
        assert!(all_matches.contains(&format!("{}/evidence_dir/", temp_str)));
        assert!(all_matches.contains(&format!("{}/evidence.raw", temp_str)));
        assert!(all_matches.contains(&format!("{}/evidence.E01", temp_str)));

        // 3. Hidden file not included unless requested
        let without_hidden = find_path_completions(&format!("{}/", temp_str), false);
        assert!(!without_hidden.iter().any(|m| m.contains(".hidden_file")));
        let with_hidden = find_path_completions(&format!("{}/.", temp_str), false);
        assert!(with_hidden.iter().any(|m| m.contains(".hidden_file")));

        // 4. Case-insensitive fallback
        let ci_results = find_path_completions(&format!("{}/EVI", temp_str), false);
        assert_eq!(ci_results.len(), 3);

        // 5. Missing directory: nothing, no error
        assert!(find_path_completions(&format!("{}/missing/x", temp_str), false).is_empty());
    }
}
