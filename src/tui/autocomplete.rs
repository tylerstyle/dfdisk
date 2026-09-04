use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAutocompleteState {
    pub original_prefix: String,
    pub suffix: String,
    pub matches: Vec<String>,
    pub match_index: usize,
    pub has_cycled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutocompleteOutcome {
    /// Exactly one match was found and applied
    SingleMatch {
        completed: String,
        suffix: String,
    },
    /// Multiple matches found; input was extended to their longest common prefix
    PrefixExtended {
        common_prefix: String,
        suffix: String,
        total: usize,
    },
    /// Cycled to a candidate among multiple matches
    Cycled {
        candidate: String,
        suffix: String,
        index: usize,
        total: usize,
    },
    /// No matches were found
    NoMatches,
}

/// Expands a leading `~` or `~/` to the user's home directory.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = path_str.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
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
        (expand_tilde(Path::new("~")), "~/".to_string(), "".to_string())
    } else if let Some(rest) = prefix.strip_prefix("~/") {
        let home = expand_tilde(Path::new("~"));
        if let Some(slash_idx) = rest.rfind('/') {
            let rel_dir = &rest[..=slash_idx];
            let file_pfx = &rest[slash_idx + 1..];
            (home.join(rel_dir), format!("~/{}", rel_dir), file_pfx.to_string())
        } else {
            (home, "~/".to_string(), rest.to_string())
        }
    } else if prefix.ends_with('/') {
        (PathBuf::from(prefix), prefix.to_string(), "".to_string())
    } else if let Some(slash_idx) = prefix.rfind('/') {
        let dir_part = &prefix[..=slash_idx];
        let file_pfx = &prefix[slash_idx + 1..];
        (PathBuf::from(dir_part), dir_part.to_string(), file_pfx.to_string())
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

/// Performs path autocompletion on `text` at cursor position `cursor_pos`.
/// Repeated calls with an active `state` cycle through candidates.
pub fn complete_path(
    text: &str,
    cursor_pos: usize,
    dirs_only: bool,
    state: &mut Option<PathAutocompleteState>,
) -> Option<AutocompleteOutcome> {
    // Check if existing state is still relevant to current input
    if let Some(ref s) = state {
        let is_relevant = s.matches.iter().any(|m| text.starts_with(m))
            || (!s.original_prefix.is_empty() && text.starts_with(&s.original_prefix));
        if !is_relevant {
            *state = None;
        }
    }

    // If state is active with matches, continue cycling:
    if let Some(ref mut s) = state {
        if !s.matches.is_empty() {
            if !s.has_cycled {
                s.has_cycled = true;
                s.match_index = 0;
            } else {
                s.match_index = (s.match_index + 1) % s.matches.len();
            }
            let candidate = s.matches[s.match_index].clone();
            let suffix = s.suffix.clone();
            return Some(AutocompleteOutcome::Cycled {
                candidate,
                suffix,
                index: s.match_index + 1,
                total: s.matches.len(),
            });
        }
    }

    // New autocompletion attempt:
    let prefix = if cursor_pos <= text.len() {
        &text[..cursor_pos]
    } else {
        text
    };
    let suffix = if cursor_pos < text.len() {
        text[cursor_pos..].to_string()
    } else {
        String::new()
    };

    let candidates = find_path_completions(prefix, dirs_only);

    if candidates.is_empty() {
        *state = None;
        return Some(AutocompleteOutcome::NoMatches);
    }

    if candidates.len() == 1 {
        let completed = candidates[0].clone();
        *state = None;
        return Some(AutocompleteOutcome::SingleMatch { completed, suffix });
    }

    // Multiple candidates: compute longest common prefix
    let lcp = longest_common_prefix(&candidates);
    if lcp.len() > prefix.len() {
        *state = Some(PathAutocompleteState {
            original_prefix: prefix.to_string(),
            suffix: suffix.clone(),
            matches: candidates.clone(),
            match_index: 0,
            has_cycled: false,
        });
        Some(AutocompleteOutcome::PrefixExtended {
            common_prefix: lcp,
            suffix,
            total: candidates.len(),
        })
    } else {
        // Already at LCP: start cycling with first candidate
        *state = Some(PathAutocompleteState {
            original_prefix: prefix.to_string(),
            suffix: suffix.clone(),
            matches: candidates.clone(),
            match_index: 0,
            has_cycled: true,
        });
        Some(AutocompleteOutcome::Cycled {
            candidate: candidates[0].clone(),
            suffix,
            index: 1,
            total: candidates.len(),
        })
    }
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
        // Multibyte unicode
        assert_eq!(
            longest_common_prefix(&[
                "/データ/ケース1".to_string(),
                "/データ/ケース2".to_string(),
            ]),
            "/データ/ケース"
        );
    }

    #[test]
    fn test_expand_tilde() {
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/custom/home");

        let p1 = Path::new("~");
        assert_eq!(expand_tilde(p1), PathBuf::from("/custom/home"));

        let p2 = Path::new("~/cases/ev01");
        assert_eq!(expand_tilde(p2), PathBuf::from("/custom/home/cases/ev01"));

        let p3 = Path::new("/var/log");
        assert_eq!(expand_tilde(p3), PathBuf::from("/var/log"));

        let p4 = Path::new("relative/path");
        assert_eq!(expand_tilde(p4), PathBuf::from("relative/path"));

        if let Some(h) = original_home {
            std::env::set_var("HOME", h);
        }
    }

    #[test]
    fn test_find_completions_in_tempdir() {
        let temp = std::env::temp_dir().join(format!("dfdisk_test_ac_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        create_dir(temp.join("evidence_dir")).unwrap();
        create_dir(temp.join("export_dir")).unwrap();
        File::create(temp.join("evidence.raw")).unwrap();
        File::create(temp.join("evidence.E01")).unwrap();
        File::create(temp.join(".hidden_file")).unwrap();

        let temp_str = temp.to_string_lossy().to_string();

        // 1. Dirs only on temp/e
        let prefix = format!("{}/e", temp_str);
        let dir_matches = find_path_completions(&prefix, true);
        assert_eq!(dir_matches.len(), 2);
        assert!(dir_matches.contains(&format!("{}/evidence_dir/", temp_str)));
        assert!(dir_matches.contains(&format!("{}/export_dir/", temp_str)));

        // 2. Both files and dirs on temp/evi
        let prefix2 = format!("{}/evi", temp_str);
        let all_matches = find_path_completions(&prefix2, false);
        assert_eq!(all_matches.len(), 3);
        assert!(all_matches.contains(&format!("{}/evidence_dir/", temp_str)));
        assert!(all_matches.contains(&format!("{}/evidence.raw", temp_str)));
        assert!(all_matches.contains(&format!("{}/evidence.E01", temp_str)));

        // 3. Hidden file not included unless requested
        let prefix3 = format!("{}/", temp_str);
        let without_hidden = find_path_completions(&prefix3, false);
        assert!(!without_hidden.iter().any(|m| m.contains(".hidden_file")));

        let prefix_hidden = format!("{}/.", temp_str);
        let with_hidden = find_path_completions(&prefix_hidden, false);
        assert!(with_hidden.iter().any(|m| m.contains(".hidden_file")));

        // 4. Case-insensitive fallback
        let prefix_ci = format!("{}/EVI", temp_str);
        let ci_results = find_path_completions(&prefix_ci, false);
        assert_eq!(ci_results.len(), 3);

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_complete_path_cycle_and_lcp() {
        let temp = std::env::temp_dir().join(format!("dfdisk_test_cycle_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        create_dir(temp.join("case_alpha")).unwrap();
        create_dir(temp.join("case_beta")).unwrap();

        let temp_str = temp.to_string_lossy().to_string();
        let mut state = None;

        // First Tab on temp/c -> extends to temp/case_
        let input = format!("{}/c", temp_str);
        let outcome1 = complete_path(&input, input.len(), true, &mut state);
        match outcome1 {
            Some(AutocompleteOutcome::PrefixExtended { common_prefix, total, .. }) => {
                assert_eq!(common_prefix, format!("{}/case_", temp_str));
                assert_eq!(total, 2);
            }
            other => panic!("Expected PrefixExtended, got {:?}", other),
        }
        assert!(state.is_some());

        // Second Tab -> cycles to first match (case_alpha/)
        let outcome2 = complete_path(&format!("{}/case_", temp_str), format!("{}/case_", temp_str).len(), true, &mut state);
        match outcome2 {
            Some(AutocompleteOutcome::Cycled { candidate, index, total, .. }) => {
                assert_eq!(candidate, format!("{}/case_alpha/", temp_str));
                assert_eq!(index, 1);
                assert_eq!(total, 2);
            }
            other => panic!("Expected Cycled 1, got {:?}", other),
        }

        // Third Tab -> cycles to second match (case_beta/)
        let outcome3 = complete_path(&format!("{}/case_alpha/", temp_str), format!("{}/case_alpha/", temp_str).len(), true, &mut state);
        match outcome3 {
            Some(AutocompleteOutcome::Cycled { candidate, index, total, .. }) => {
                assert_eq!(candidate, format!("{}/case_beta/", temp_str));
                assert_eq!(index, 2);
                assert_eq!(total, 2);
            }
            other => panic!("Expected Cycled 2, got {:?}", other),
        }

        // Fourth Tab -> wraps back to first match (case_alpha/)
        let outcome4 = complete_path(&format!("{}/case_beta/", temp_str), format!("{}/case_beta/", temp_str).len(), true, &mut state);
        match outcome4 {
            Some(AutocompleteOutcome::Cycled { candidate, index, .. }) => {
                assert_eq!(candidate, format!("{}/case_alpha/", temp_str));
                assert_eq!(index, 1);
            }
            other => panic!("Expected Cycled wrap, got {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp);
    }
}
