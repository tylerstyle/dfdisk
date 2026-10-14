//! Text helpers shared by reports, headers and identity strings: sanitising
//! values for terminals and single-line fields, and exact binary-unit sizes.

/// Characters that must never reach a report line, an E01 header or a terminal
/// verbatim: C0/C1 control characters (tab, newline and ESC included), DEL, and
/// the Unicode bidirectional overrides and isolates that can make text display
/// in another order than it is stored.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// One line of text safe to print: every run of unsafe characters becomes a
/// single space, and the result is trimmed. Ordinary spaces are kept as given.
pub fn sanitize_line(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_run = false;
    for c in input.chars() {
        if is_unsafe_char(c) {
            if !in_run {
                out.push(' ');
                in_run = true;
            }
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out.trim().to_string()
}

/// [`sanitize_line`], `None` when nothing is left.
pub fn sanitize_opt(input: &str) -> Option<String> {
    Some(sanitize_line(input)).filter(|s| !s.is_empty())
}

/// Exact size in binary units for statements of fact, e.g. "64 KiB",
/// "1.50 MiB", "512 B". Whole numbers are printed without decimals.
pub fn format_iec(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    let mut unit = 0;
    let mut scale = 1024u64;
    while unit + 1 < UNITS.len() && bytes / scale >= 1024 {
        scale *= 1024;
        unit += 1;
    }
    if bytes.is_multiple_of(scale) {
        format!("{} {}", bytes / scale, UNITS[unit])
    } else {
        format!("{:.2} {}", bytes as f64 / scale as f64, UNITS[unit])
    }
}

/// "1 range" / "2 ranges".
pub fn plural(count: u64, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_become_single_spaces() {
        assert_eq!(sanitize_line("a\tb"), "a b");
        assert_eq!(sanitize_line("a\r\n\tb"), "a b");
        assert_eq!(sanitize_line("  lead and trail\n"), "lead and trail");
        assert_eq!(sanitize_line("esc\u{1b}[31mred"), "esc [31mred");
        assert_eq!(sanitize_line("del\u{7f}x"), "del x");
        assert_eq!(sanitize_line("c1\u{85}x"), "c1 x");
        assert_eq!(sanitize_line("rtl\u{202E}gpj.exe"), "rtl gpj.exe");
        assert_eq!(sanitize_line("two  spaces"), "two  spaces");
        assert_eq!(sanitize_line("\n\t\r"), "");
        assert_eq!(sanitize_opt(" \t "), None);
        assert_eq!(sanitize_opt(" x ").as_deref(), Some("x"));
        assert_eq!(sanitize_line("Müller 硬盘"), "Müller 硬盘");
    }

    #[test]
    fn binary_sizes_are_exact() {
        assert_eq!(format_iec(0), "0 B");
        assert_eq!(format_iec(512), "512 B");
        assert_eq!(format_iec(1024), "1 KiB");
        assert_eq!(format_iec(65536), "64 KiB");
        assert_eq!(format_iec(1536 * 1024), "1.50 MiB");
        assert_eq!(format_iec(1 << 30), "1 GiB");
        assert_eq!(format_iec(u64::MAX), "16.00 EiB");
        assert_eq!(plural(1, "range", "ranges"), "1 range");
        assert_eq!(plural(2, "range", "ranges"), "2 ranges");
    }
}
