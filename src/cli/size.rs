//! Sizes on the command line (`--piece-size`, `--expect-size`): exact byte
//! counts only. A plain number is bytes; K/M/G/T and KiB/MiB/GiB/TiB are
//! powers of 1024, KB/MB/GB/TB powers of 1000 (case-insensitive). Fractions
//! are refused: an expected size must be exact.

use crate::models::text::format_iec;

/// `--piece-size`: a size, or `off` (no piecewise hashes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PieceSize(pub Option<u64>);

/// Parse an exact size ("4096", "1G", "64MiB", "500GB").
pub fn parse_size(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (digits, unit) = t.split_at(split);
    if digits.is_empty() {
        return Err(format!(
            "'{text}' is not a size: expected a whole number of bytes, optionally with K, M, G, T (powers of 1024) or KB, MB, GB, TB (powers of 1000)"
        ));
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("'{text}' is too large"))?;
    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kib" => 1 << 10,
        "m" | "mib" => 1 << 20,
        "g" | "gib" => 1 << 30,
        "t" | "tib" => 1 << 40,
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "tb" => 1_000_000_000_000,
        other => {
            return Err(format!(
                "'{text}': unknown unit '{other}' (use K, M, G, T, KiB ... TiB or KB ... TB; fractions are not accepted)"
            ))
        }
    };
    n.checked_mul(multiplier)
        .ok_or_else(|| format!("'{text}' is too large"))
}

/// Parse `--piece-size`: `off` or a size (the 1 MiB minimum and the 512-byte
/// multiple are checked by the configuration, with every other option).
pub fn parse_piece_size(text: &str) -> Result<PieceSize, String> {
    if text.trim().eq_ignore_ascii_case("off") {
        return Ok(PieceSize(None));
    }
    let bytes = parse_size(text)?;
    if bytes == 0 {
        return Err("a piece size of 0 is not possible; use \"off\" to disable pieces".into());
    }
    Ok(PieceSize(Some(bytes)))
}

/// "1073741824 bytes (1 GiB)".
pub fn describe_bytes(bytes: u64) -> String {
    format!("{bytes} bytes ({})", format_iec(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_sizes_with_binary_and_decimal_units() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size(" 512b "), Ok(512));
        assert_eq!(parse_size("1K"), Ok(1024));
        assert_eq!(parse_size("1k"), Ok(1024));
        assert_eq!(parse_size("64MiB"), Ok(64 << 20));
        assert_eq!(parse_size("1G"), Ok(1 << 30));
        assert_eq!(parse_size("2t"), Ok(2 << 40));
        assert_eq!(parse_size("500GB"), Ok(500_000_000_000));
        assert_eq!(parse_size("1kb"), Ok(1000));
        assert_eq!(parse_size("8 MiB"), Ok(8 << 20));
    }

    #[test]
    fn inexact_or_unknown_sizes_are_refused() {
        for bad in [
            "",
            "G",
            "1.5G",
            "-1",
            "1X",
            "1 GiBs",
            "0x10",
            "99999999999999999999",
        ] {
            assert!(parse_size(bad).is_err(), "{bad:?} accepted");
        }
        assert!(parse_size("20000000T").unwrap_err().contains("too large"));
    }

    #[test]
    fn piece_size_off_or_size() {
        assert_eq!(parse_piece_size("off"), Ok(PieceSize(None)));
        assert_eq!(parse_piece_size("OFF"), Ok(PieceSize(None)));
        assert_eq!(parse_piece_size("1G"), Ok(PieceSize(Some(1 << 30))));
        assert!(parse_piece_size("0").is_err());
        assert!(parse_piece_size("nope").is_err());
        assert_eq!(describe_bytes(1 << 30), "1073741824 bytes (1 GiB)");
    }
}
