//! Single-line text inputs: editing keys and horizontal scrolling by display
//! width (wide characters take two cells), so the cursor stays visible in a
//! narrow field (§16).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::text::Span;

/// Display width of a string in terminal cells.
pub fn str_width(s: &str) -> usize {
    Span::raw(s).width()
}

/// Display width of one character (0 for control characters).
pub fn char_width(c: char) -> usize {
    if c.is_control() {
        return 0;
    }
    let mut buf = [0u8; 4];
    str_width(c.encode_utf8(&mut buf))
}

/// Cut `s` to at most `width` cells, ending in "…" when it was cut.
pub fn truncate_to_width(s: &str, width: usize) -> String {
    if str_width(s) <= width {
        return s.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = char_width(c);
        if used + w > width.saturating_sub(1) {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

/// Wrap `text` to lines of at most `width` cells (breaking at spaces where
/// possible, inside long words otherwise). Existing line breaks are kept.
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for raw in text.split('\n') {
        if str_width(raw) <= width {
            lines.push(raw.to_string());
            continue;
        }
        let mut current = String::new();
        let mut current_w = 0;
        for word in raw.split_inclusive(' ') {
            let ww = str_width(word);
            if current_w + ww <= width {
                current.push_str(word);
                current_w += ww;
                continue;
            }
            if !current.is_empty() {
                lines.push(current.trim_end().to_string());
                current = String::new();
                current_w = 0;
            }
            if ww <= width {
                current.push_str(word);
                current_w = ww;
            } else {
                for c in word.chars() {
                    let cw = char_width(c);
                    if current_w + cw > width && !current.is_empty() {
                        lines.push(std::mem::take(&mut current));
                        current_w = 0;
                    }
                    current.push(c);
                    current_w += cw;
                }
            }
        }
        lines.push(current.trim_end().to_string());
    }
    lines
}

/// The visible part of an input of `width` cells whose cursor is at byte
/// `cursor` of `text`: (text before the cursor, character under the cursor or
/// None at the end, text after it). Scrolls so the cursor is always inside the
/// field; one cell is kept free for the cursor at the end.
pub fn visible_window(text: &str, cursor: usize, width: usize) -> (String, Option<char>, String) {
    if width == 0 {
        return (String::new(), None, String::new());
    }
    let mut cursor = cursor.min(text.len());
    while cursor > 0 && !text.is_char_boundary(cursor) {
        cursor -= 1;
    }
    let chars: Vec<(usize, char, usize)> = text
        .char_indices()
        .map(|(i, c)| (i, c, char_width(c)))
        .collect();
    let cursor_idx = chars
        .iter()
        .position(|(i, _, _)| *i >= cursor)
        .unwrap_or(chars.len());
    let cursor_col: usize = chars[..cursor_idx].iter().map(|(_, _, w)| w).sum();
    let cursor_cell = chars
        .get(cursor_idx)
        .map(|(_, _, w)| (*w).max(1))
        .unwrap_or(1);
    // First visible column: keep the cursor cell inside [offset, offset + width)
    let offset = (cursor_col + cursor_cell).saturating_sub(width);

    let mut before = String::new();
    let mut after = String::new();
    let mut under = None;
    let mut col = 0;
    let mut used = 0;
    for (idx, &(_, c, w)) in chars.iter().enumerate() {
        let start = col;
        col += w;
        if start < offset {
            continue; // scrolled out on the left (also a cut wide character)
        }
        // The cursor cell is at least one cell wide; the offset guarantees it fits
        let cost = if idx == cursor_idx { w.max(1) } else { w };
        if used + cost > width {
            break;
        }
        match idx.cmp(&cursor_idx) {
            std::cmp::Ordering::Less => before.push(c),
            std::cmp::Ordering::Equal => under = Some(c),
            std::cmp::Ordering::Greater => after.push(c),
        }
        used += cost;
    }
    (before, under, after)
}

/// Apply an editing key to `target` with the cursor at byte `cursor`.
pub fn edit_text(target: &mut String, cursor: &mut usize, key: KeyEvent) {
    // Clamp cursor and align to valid character boundary
    if *cursor > target.len() {
        *cursor = target.len();
    }
    while *cursor > 0 && !target.is_char_boundary(*cursor) {
        *cursor -= 1;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('u') | KeyCode::Char('k') => {
                target.clear();
                *cursor = 0;
            }
            KeyCode::Char('w') => {
                // Delete backward word
                if *cursor > 0 {
                    let before = &target[..*cursor];
                    // Skip any trailing delimiters
                    let last_non_delim = before
                        .char_indices()
                        .rfind(|&(_, c)| !c.is_whitespace() && c != '/' && c != '_');

                    if let Some((idx, c)) = last_non_delim {
                        let word_end = idx + c.len_utf8();
                        let before_word = &before[..word_end];
                        let new_len = before_word
                            .char_indices()
                            .filter(|&(_, ch)| ch.is_whitespace() || ch == '/' || ch == '_')
                            .map(|(i, ch)| i + ch.len_utf8())
                            .next_back()
                            .unwrap_or(0);
                        target.replace_range(new_len..*cursor, "");
                        *cursor = new_len;
                    } else {
                        target.replace_range(0..*cursor, "");
                        *cursor = 0;
                    }
                }
            }
            KeyCode::Char('a') => *cursor = 0,
            KeyCode::Char('e') => *cursor = target.len(),
            _ => {}
        }
        // Other control combinations never insert text
        return;
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
        return;
    }

    match key.code {
        KeyCode::Char(c) => {
            if c.is_control() {
                return;
            }
            if *cursor >= target.len() {
                target.push(c);
                *cursor = target.len();
            } else {
                target.insert(*cursor, c);
                *cursor += c.len_utf8();
            }
        }
        KeyCode::Backspace => {
            if *cursor > 0 && !target.is_empty() {
                if let Some((prev_idx, _)) = target[..*cursor].char_indices().next_back() {
                    target.remove(prev_idx);
                    *cursor = prev_idx;
                }
            }
        }
        KeyCode::Delete => {
            if *cursor < target.len() {
                target.remove(*cursor);
            }
        }
        KeyCode::Left => {
            if *cursor > 0 {
                if let Some((prev_idx, _)) = target[..*cursor].char_indices().next_back() {
                    *cursor = prev_idx;
                } else {
                    *cursor = 0;
                }
            }
        }
        KeyCode::Right => {
            if *cursor < target.len() {
                if let Some((next_offset, _)) = target[*cursor..].char_indices().nth(1) {
                    *cursor += next_offset;
                } else {
                    *cursor = target.len();
                }
            }
        }
        KeyCode::Home => *cursor = 0,
        KeyCode::End => *cursor = target.len(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn widths() {
        assert_eq!(str_width("abc"), 3);
        assert_eq!(str_width("世界"), 4);
        assert_eq!(char_width('世'), 2);
        assert_eq!(char_width('\u{1b}'), 0);
        assert_eq!(truncate_to_width("abcdef", 4), "abc…");
        assert_eq!(truncate_to_width("abc", 4), "abc");
        assert_eq!(truncate_to_width("世界世界", 5), "世界…");
    }

    #[test]
    fn wrapping_keeps_every_character() {
        let text = "a long sentence that needs wrapping\nsecond";
        let lines = wrap_text(text, 10);
        assert!(lines.iter().all(|l| str_width(l) <= 10), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "second");
        let joined: String = lines.concat().split_whitespace().collect();
        let expected: String = text.split_whitespace().collect();
        assert_eq!(joined, expected);
        let long = wrap_text("x".repeat(25).as_str(), 10);
        assert_eq!(long.len(), 3);
        assert_eq!(wrap_text("", 5), vec![String::new()]);
    }

    #[test]
    fn window_keeps_the_cursor_visible() {
        let text = "/mnt/evidence/case-2026-0042/drive-01";
        for cursor in 0..=text.len() {
            for width in 1..12 {
                let (before, under, after) = visible_window(text, cursor, width);
                let shown = str_width(&before)
                    + under.map(char_width).unwrap_or(1).max(1)
                    + str_width(&after);
                assert!(
                    shown <= width.max(1),
                    "{cursor} {width}: {before:?} {under:?} {after:?}"
                );
                if cursor < text.len() {
                    assert_eq!(under, text[cursor..].chars().next());
                } else {
                    assert_eq!(under, None);
                }
                assert!(text[..cursor].ends_with(&before));
            }
        }
        // Short text: everything visible
        assert_eq!(
            visible_window("abc", 1, 10),
            ("a".into(), Some('b'), "c".into())
        );
    }

    #[test]
    fn window_with_wide_characters() {
        let text = "ケース世界データ";
        for cursor in text.char_indices().map(|(i, _)| i).chain([text.len()]) {
            for width in 2..9 {
                let (before, under, after) = visible_window(text, cursor, width);
                let shown =
                    str_width(&before) + under.map(char_width).unwrap_or(1) + str_width(&after);
                assert!(shown <= width, "{cursor} {width}");
            }
        }
        assert_eq!(
            visible_window("abc", 0, 0),
            (String::new(), None, String::new())
        );
    }

    #[test]
    fn test_edit_text_multibyte_insert_and_cursor() {
        let mut s = String::new();
        let mut cursor = 0;
        edit_text(&mut s, &mut cursor, key(KeyCode::Char('ä')));
        assert_eq!((s.as_str(), cursor), ("ä", 2));
        edit_text(&mut s, &mut cursor, key(KeyCode::Char('世')));
        assert_eq!((s.as_str(), cursor), ("ä世", 5));
        edit_text(&mut s, &mut cursor, key(KeyCode::Char('🚀')));
        assert_eq!((s.as_str(), cursor), ("ä世🚀", 9));
    }

    #[test]
    fn test_edit_text_multibyte_navigation_and_deletion() {
        let mut s = "ä世🚀".to_string();
        let mut cursor = 9;
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 5);
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 2);
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 0);
        edit_text(&mut s, &mut cursor, key(KeyCode::Left));
        assert_eq!(cursor, 0);
        edit_text(&mut s, &mut cursor, key(KeyCode::Right));
        assert_eq!(cursor, 2);
        edit_text(&mut s, &mut cursor, key(KeyCode::Backspace));
        assert_eq!((s.as_str(), cursor), ("世🚀", 0));
        edit_text(&mut s, &mut cursor, key(KeyCode::Delete));
        assert_eq!((s.as_str(), cursor), ("🚀", 0));
    }

    #[test]
    fn test_edit_text_ctrl_w() {
        let mut s = "/var/log/ケース_01/データ/image.raw".to_string();
        let mut cursor = s.len();
        for expected in [
            "/var/log/ケース_01/データ/",
            "/var/log/ケース_01/",
            "/var/log/ケース_",
            "/var/log/",
            "/var/",
            "/",
            "",
        ] {
            edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('w')));
            assert_eq!(s, expected);
            assert_eq!(cursor, s.len());
        }
        let mut d = "/// ___   ///".to_string();
        let mut c = d.len();
        edit_text(&mut d, &mut c, ctrl_key(KeyCode::Char('w')));
        assert_eq!((d.as_str(), c), ("", 0));
    }

    #[test]
    fn control_combinations_never_insert() {
        let mut s = "abc".to_string();
        let mut cursor = 3;
        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('x')));
        edit_text(
            &mut s,
            &mut cursor,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::ALT),
        );
        edit_text(&mut s, &mut cursor, key(KeyCode::Char('\u{7}')));
        assert_eq!(s, "abc");
        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('a')));
        assert_eq!(cursor, 0);
        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('e')));
        assert_eq!(cursor, 3);
        edit_text(&mut s, &mut cursor, ctrl_key(KeyCode::Char('u')));
        assert_eq!((s.as_str(), cursor), ("", 0));
    }

    #[test]
    fn test_edit_text_stress_adversarial() {
        let s = "ä世🚀".to_string();
        for invalid_cursor in 0..=s.len() + 3 {
            for k in [
                key(KeyCode::Left),
                key(KeyCode::Right),
                key(KeyCode::Backspace),
                key(KeyCode::Delete),
                key(KeyCode::Char('x')),
                ctrl_key(KeyCode::Char('w')),
            ] {
                let mut cur = invalid_cursor;
                let mut copy = s.clone();
                edit_text(&mut copy, &mut cur, k);
                assert!(copy.is_char_boundary(cur), "{invalid_cursor} {k:?}");
            }
        }
    }
}
