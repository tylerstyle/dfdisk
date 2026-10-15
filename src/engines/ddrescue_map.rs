//! GNU ddrescue mapfiles (§13 Rescue): the parser, and what a map says about
//! the image it describes.
//!
//! A mapfile is text. Lines starting with `#` are comments (ddrescue writes
//! its version, the command line, the start and current time and the phase
//! there). The first other line is the current-position line
//! `current_pos current_status [current_pass]`; every further line is a block
//! `pos size status`. Numbers are hexadecimal (`0x...`) as ddrescue writes
//! them; decimal and octal are accepted as in C.
//!
//! Block statuses:
//! - `?` non-tried: not read yet
//! - `*` non-trimmed: a read error happened somewhere in it; not read sector by sector
//! - `/` non-scraped: trimmed, but its sectors were not read one by one yet
//! - `-` bad-sector: a sector that failed every read attempt
//! - `+` finished: read and written to the image
//!
//! Only the map decides what was rescued: never ddrescue's screen output,
//! whose numbers are rounded (SI prefixes) and say nothing about where the
//! bad areas are.

use crate::models::outcome::{RangeKind, ReadErrorTable};
use crate::models::text::{format_iec, plural};
use std::fmt;
use std::path::Path;

/// `ReadErrorTable::source` of ranges taken from a ddrescue map.
pub const MAP_SOURCE: &str = "ddrescue mapfile";

/// Status of one block of a mapfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockStatus {
    /// `?`
    NonTried,
    /// `*`
    NonTrimmed,
    /// `/`
    NonScraped,
    /// `-`
    BadSector,
    /// `+`
    Finished,
}

impl BlockStatus {
    pub const ALL: [BlockStatus; 5] = [
        BlockStatus::Finished,
        BlockStatus::BadSector,
        BlockStatus::NonTried,
        BlockStatus::NonTrimmed,
        BlockStatus::NonScraped,
    ];

    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '?' => Some(BlockStatus::NonTried),
            '*' => Some(BlockStatus::NonTrimmed),
            '/' => Some(BlockStatus::NonScraped),
            '-' => Some(BlockStatus::BadSector),
            '+' => Some(BlockStatus::Finished),
            _ => None,
        }
    }

    pub fn as_char(&self) -> char {
        match self {
            BlockStatus::NonTried => '?',
            BlockStatus::NonTrimmed => '*',
            BlockStatus::NonScraped => '/',
            BlockStatus::BadSector => '-',
            BlockStatus::Finished => '+',
        }
    }

    /// ddrescue's own name for the status.
    pub fn label(&self) -> &'static str {
        match self {
            BlockStatus::NonTried => "non-tried",
            BlockStatus::NonTrimmed => "non-trimmed",
            BlockStatus::NonScraped => "non-scraped",
            BlockStatus::BadSector => "bad-sector",
            BlockStatus::Finished => "rescued",
        }
    }

    /// How a block of this status is represented in the image (inside the
    /// image file): finished blocks hold source data (`None`), bad sectors
    /// hold zeros (`Substituted`: ddrescue never writes them, and the rescue
    /// engine writes zeros over them after every ddrescue run, so data an
    /// interrupted earlier session left there does not stay), and areas that
    /// were not tried or not finished are
    /// `Unread`: running the rescue again may still read them.
    pub fn range_kind(&self) -> Option<RangeKind> {
        match self {
            BlockStatus::Finished => None,
            BlockStatus::BadSector => Some(RangeKind::Substituted),
            BlockStatus::NonTried | BlockStatus::NonTrimmed | BlockStatus::NonScraped => {
                Some(RangeKind::Unread)
            }
        }
    }
}

/// What ddrescue was doing when it wrote the map (the current-position line).
pub fn phase_label(current_status: char) -> &'static str {
    match current_status {
        '?' => "copying non-tried blocks",
        '*' => "trimming non-trimmed blocks",
        '/' => "scraping non-scraped blocks",
        '-' => "retrying bad sectors",
        'F' => "filling specified blocks",
        'G' => "generating an approximate mapfile",
        '+' => "finished",
        _ => "unknown",
    }
}

/// One block (`pos size status`) of a mapfile, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapBlock {
    pub pos: u64,
    pub size: u64,
    pub status: BlockStatus,
}

impl MapBlock {
    pub fn end(&self) -> u64 {
        self.pos + self.size
    }
}

/// A parsed mapfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapfile {
    pub current_pos: u64,
    /// Status of the current-position line (see [`phase_label`])
    pub current_status: char,
    /// Pass number (written by ddrescue 1.21 and later)
    pub current_pass: Option<u32>,
    /// Blocks in ascending order, never overlapping (gaps are possible)
    pub blocks: Vec<MapBlock>,
    /// Comment lines without the leading `#`, trimmed
    pub comments: Vec<String>,
}

/// Why a mapfile could not be parsed (line numbers start at 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            f.write_str(&self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

impl std::error::Error for MapError {}

/// A number as ddrescue reads it: `0x` hexadecimal, a leading `0` octal,
/// otherwise decimal. No sign, no suffix.
pub fn parse_number(token: &str) -> Option<u64> {
    let t = token.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if t.len() > 1 && t.starts_with('0') {
        return u64::from_str_radix(&t[1..], 8).ok();
    }
    t.parse().ok()
}

fn status_char(token: &str) -> Option<char> {
    let mut chars = token.chars();
    let c = chars.next()?;
    chars.next().is_none().then_some(c)
}

/// Parse a mapfile. Strict where a mistake would change what the report
/// says: unknown block statuses, malformed numbers, empty or overlapping
/// blocks and a missing current-position line are errors.
pub fn parse(text: &str) -> Result<Mapfile, MapError> {
    let mut comments = Vec::new();
    let mut status_line: Option<(u64, char, Option<u32>)> = None;
    let mut blocks: Vec<MapBlock> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let err = |message: String| MapError {
            line: line_no,
            message,
        };
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            comments.push(comment.trim().to_string());
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if status_line.is_none() {
            if !(2..=3).contains(&fields.len()) {
                return Err(err(format!(
                    "expected the current-position line `current_pos current_status [current_pass]`, found `{line}`"
                )));
            }
            let pos = parse_number(fields[0])
                .ok_or_else(|| err(format!("invalid current position `{}`", fields[0])))?;
            let status = status_char(fields[1])
                .filter(|c| "?*/-FG+".contains(*c))
                .ok_or_else(|| err(format!("invalid current status `{}`", fields[1])))?;
            let pass = match fields.get(2) {
                Some(p) => Some(
                    p.parse::<u32>()
                        .map_err(|_| err(format!("invalid current pass `{p}`")))?,
                ),
                None => None,
            };
            status_line = Some((pos, status, pass));
            continue;
        }
        if fields.len() != 3 {
            return Err(err(format!(
                "expected a block line `pos size status`, found `{line}`"
            )));
        }
        let pos = parse_number(fields[0])
            .ok_or_else(|| err(format!("invalid block position `{}`", fields[0])))?;
        let size = parse_number(fields[1])
            .ok_or_else(|| err(format!("invalid block size `{}`", fields[1])))?;
        let status = status_char(fields[2])
            .and_then(BlockStatus::from_char)
            .ok_or_else(|| err(format!("invalid block status `{}`", fields[2])))?;
        if size == 0 {
            return Err(err(format!("block at {pos:#x} has size 0")));
        }
        if pos.checked_add(size).is_none() {
            return Err(err(format!(
                "block at {pos:#x} with size {size:#x} ends beyond 2^64"
            )));
        }
        if let Some(prev) = blocks.last() {
            if pos < prev.end() {
                return Err(err(format!(
                    "block at {pos:#x} overlaps or precedes the block ending at {:#x}",
                    prev.end()
                )));
            }
        }
        blocks.push(MapBlock { pos, size, status });
    }
    let (current_pos, current_status, current_pass) = status_line.ok_or(MapError {
        line: 0,
        message: "the mapfile has no current-position line".into(),
    })?;
    Ok(Mapfile {
        current_pos,
        current_status,
        current_pass,
        blocks,
        comments,
    })
}

/// Read and parse the mapfile at `path`.
pub fn read(path: &Path) -> Result<Mapfile, String> {
    let text = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&text);
    parse(&text).map_err(|e| format!("{} is not a valid ddrescue map ({e})", path.display()))
}

/// Bytes per status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MapCounts {
    pub rescued: u64,
    pub bad_sector: u64,
    pub non_tried: u64,
    pub non_trimmed: u64,
    pub non_scraped: u64,
    /// Number of bad-sector blocks
    pub bad_areas: usize,
}

impl MapCounts {
    fn add(&mut self, status: BlockStatus, bytes: u64) {
        match status {
            BlockStatus::Finished => self.rescued += bytes,
            BlockStatus::BadSector => {
                self.bad_sector += bytes;
                self.bad_areas += 1;
            }
            BlockStatus::NonTried => self.non_tried += bytes,
            BlockStatus::NonTrimmed => self.non_trimmed += bytes,
            BlockStatus::NonScraped => self.non_scraped += bytes,
        }
    }

    pub fn get(&self, status: BlockStatus) -> u64 {
        match status {
            BlockStatus::Finished => self.rescued,
            BlockStatus::BadSector => self.bad_sector,
            BlockStatus::NonTried => self.non_tried,
            BlockStatus::NonTrimmed => self.non_trimmed,
            BlockStatus::NonScraped => self.non_scraped,
        }
    }

    /// Bytes not tried or not finished (`?`, `*`, `/`).
    pub fn unfinished(&self) -> u64 {
        self.non_tried + self.non_trimmed + self.non_scraped
    }

    /// "rescued 1 MiB (1048576 bytes), bad-sector 1.50 KiB (1536 bytes) in 2 areas, ..."
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        for status in BlockStatus::ALL {
            let bytes = self.get(status);
            if bytes == 0 && status != BlockStatus::Finished {
                continue;
            }
            let mut part = format!(
                "{} {} ({})",
                status.label(),
                format_iec(bytes),
                plural(bytes, "byte", "bytes")
            );
            if status == BlockStatus::BadSector {
                part.push_str(&format!(
                    " in {}",
                    plural(self.bad_areas as u64, "area", "areas")
                ));
            }
            parts.push(part);
        }
        parts.join(", ")
    }
}

/// What a map says about an image of a source of `expected` bytes whose
/// image file is `image_len` bytes long (see [`Mapfile::assess`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapAssessment {
    /// Bad sectors inside the image (`Substituted`), and everything of the
    /// source the image does not hold as read (`Unread`): non-tried,
    /// non-trimmed and non-scraped blocks, areas the map does not list, and
    /// listed areas beyond the end of the image file
    pub read_errors: ReadErrorTable,
    /// Bytes of the source the image represents: rescued plus bad-sector
    /// bytes inside the image file and the source
    pub bytes_acquired: u64,
    /// Bytes per status, within the source
    pub counts: MapCounts,
    /// Bytes of the source the map does not list
    pub not_listed: u64,
    /// Bytes the map lists beyond the end of the source
    pub beyond_source: u64,
    /// Rescued bytes the map lists beyond the end of the image file
    pub rescued_beyond_image: u64,
    /// Bad-sector bytes beyond the end of the image file (the image was not
    /// extended over them)
    pub bad_beyond_image: u64,
    /// Report statements
    pub notes: Vec<String>,
}

impl Mapfile {
    /// "GNU ddrescue version 1.30", from the first comment line.
    pub fn created_by(&self) -> Option<&str> {
        self.comments.iter().find_map(|c| {
            c.strip_prefix("Mapfile. Created by ")
                .map(|v| v.trim_end_matches('.').trim())
        })
    }

    /// The ddrescue command line recorded in the map.
    pub fn command_line(&self) -> Option<&str> {
        self.comments
            .iter()
            .find_map(|c| c.strip_prefix("Command line:").map(str::trim))
    }

    /// End of the last block (0 for an empty map).
    pub fn end(&self) -> u64 {
        self.blocks.last().map(MapBlock::end).unwrap_or(0)
    }

    /// Bytes of blocks with `status`.
    pub fn bytes(&self, status: BlockStatus) -> u64 {
        self.blocks
            .iter()
            .filter(|b| b.status == status)
            .map(|b| b.size)
            .sum()
    }

    /// Every block is rescued or bad-sector: nothing is left to try.
    pub fn is_finished(&self) -> bool {
        self.blocks
            .iter()
            .all(|b| matches!(b.status, BlockStatus::Finished | BlockStatus::BadSector))
    }

    /// The blocks list `[0, size)` exactly, without gaps.
    pub fn covers(&self, size: u64) -> bool {
        let mut cursor = 0u64;
        for b in &self.blocks {
            if b.pos != cursor {
                return false;
            }
            cursor = b.end();
        }
        cursor == size
    }

    /// Bad-sector sectors of `sector_size` (sectors touched by `-` blocks),
    /// for live progress.
    pub fn bad_sectors(&self, sector_size: u32) -> u64 {
        let s = u64::from(sector_size.max(1));
        self.blocks
            .iter()
            .filter(|b| b.status == BlockStatus::BadSector)
            .map(|b| b.end().div_ceil(s) - b.pos / s)
            .sum()
    }

    /// What the map says about an image of a source of `expected` bytes
    /// whose image file is `image_len` bytes long. Within the image, bad
    /// sectors are substituted (zeros) and unfinished blocks unread; beyond
    /// the image file nothing is in the image, so every listed byte there
    /// counts as unread, as does every byte of the source the map does not
    /// list. Blocks beyond the end of the source are ignored (noted).
    pub fn assess(&self, expected: u64, image_len: u64, sector_size: u32) -> MapAssessment {
        let mut table = ReadErrorTable::new(sector_size, MAP_SOURCE);
        let mut a = MapAssessment {
            read_errors: ReadErrorTable::default(),
            bytes_acquired: 0,
            counts: MapCounts::default(),
            not_listed: 0,
            beyond_source: 0,
            rescued_beyond_image: 0,
            bad_beyond_image: 0,
            notes: Vec::new(),
        };
        let mut cursor = 0u64;
        for b in &self.blocks {
            if b.pos > cursor && cursor < expected {
                let gap_end = b.pos.min(expected);
                table.push(cursor, gap_end - cursor, RangeKind::Unread);
                a.not_listed += gap_end - cursor;
            }
            let start = b.pos.min(expected);
            let end = b.end().min(expected);
            if end > start {
                a.counts.add(b.status, end - start);
                match b.status.range_kind() {
                    Some(RangeKind::Unread) => table.push(start, end - start, RangeKind::Unread),
                    kind => {
                        // In the image up to its end; beyond it, not in the image
                        let in_image_end = end.min(image_len).max(start);
                        if in_image_end > start {
                            a.bytes_acquired += in_image_end - start;
                            if kind == Some(RangeKind::Substituted) {
                                table.push(start, in_image_end - start, RangeKind::Substituted);
                            }
                        }
                        if end > in_image_end {
                            table.push(in_image_end, end - in_image_end, RangeKind::Unread);
                            if kind.is_none() {
                                a.rescued_beyond_image += end - in_image_end;
                            } else {
                                a.bad_beyond_image += end - in_image_end;
                            }
                        }
                    }
                }
            }
            if b.end() > expected {
                a.beyond_source += b.end() - b.pos.max(expected);
            }
            cursor = cursor.max(b.end());
        }
        if cursor < expected {
            table.push(cursor, expected - cursor, RangeKind::Unread);
            a.not_listed += expected - cursor;
        }
        a.read_errors = table;

        if a.not_listed > 0 {
            a.notes.push(format!(
                "the ddrescue map does not list {} ({}) of the source; those areas were not read and count as not acquired",
                format_iec(a.not_listed),
                plural(a.not_listed, "byte", "bytes")
            ));
        }
        if a.beyond_source > 0 {
            a.notes.push(format!(
                "the ddrescue map lists {} beyond the end of the source ({} bytes); that part is ignored",
                plural(a.beyond_source, "byte", "bytes"),
                expected
            ));
        }
        if a.rescued_beyond_image > 0 {
            a.notes.push(format!(
                "the ddrescue map lists {} as rescued beyond the end of the image file ({} bytes); they are not in the image and count as not acquired",
                plural(a.rescued_beyond_image, "byte", "bytes"),
                image_len
            ));
        }
        if a.bad_beyond_image > 0 {
            a.notes.push(format!(
                "{} of bad sectors lie beyond the end of the image file ({} bytes), which was not extended over them because the rescue is not finished; they count as not acquired",
                plural(a.bad_beyond_image, "byte", "bytes"),
                image_len
            ));
        }
        a
    }
}

/// Fixtures in `tests/fixtures/ddrescue/` are real output of GNU ddrescue
/// 1.30 on regular files (1 MiB of random data, 4 MiB for the interrupted
/// run), byte for byte:
/// - `clean.map`: `ddrescue -r 0 -b 512 src.bin img.raw img.map`
/// - `bad_middle.map`: `ddrescue -d -r 0 -b 512 -H testmode_bad_middle.map ...`
///   (two bad areas, 1024 and 512 bytes)
/// - `bad_tail.map`: `ddrescue -r 0 -b 512 ...` under an LD_PRELOAD shim that
///   fails every read of the last 1024 bytes with EIO; ddrescue left an image
///   of 1047552 bytes (it never writes the unreadable tail). ddrescue's test
///   mode treats bad blocks after the last good one as beyond the end of the
///   input, so a bad tail cannot be made with `-H`.
/// - `interrupted.map`: `ddrescue -r 0 -b 512 -Z 262144 -H testmode_4mib.map ...`,
///   SIGINT after 1.5 s (map saved, image 655360 bytes)
/// - `non_trimmed.map`: `--no-trim` with `testmode_bad_middle.map`
/// - `non_scraped.map`: `--no-scrape` with `testmode_non_scraped.map`
/// - `screen_*.txt`: ddrescue's status screen (stdout; stderr too for the
///   interrupted run) of the bad_middle and interrupted runs
/// - `testmode_*.map`: hand-written test-mode maps (`-H`): `+` blocks read
///   normally, every other block fails
#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = include_str!("../../tests/fixtures/ddrescue/clean.map");
    const BAD_MIDDLE: &str = include_str!("../../tests/fixtures/ddrescue/bad_middle.map");
    const BAD_TAIL: &str = include_str!("../../tests/fixtures/ddrescue/bad_tail.map");
    const INTERRUPTED: &str = include_str!("../../tests/fixtures/ddrescue/interrupted.map");
    const NON_TRIMMED: &str = include_str!("../../tests/fixtures/ddrescue/non_trimmed.map");
    const NON_SCRAPED: &str = include_str!("../../tests/fixtures/ddrescue/non_scraped.map");

    const MIB: u64 = 1 << 20;

    #[test]
    fn numbers_as_c_reads_them() {
        assert_eq!(parse_number("0x00010000"), Some(0x10000));
        assert_eq!(parse_number("0XfF"), Some(255));
        assert_eq!(parse_number("4096"), Some(4096));
        assert_eq!(parse_number("010"), Some(8));
        assert_eq!(parse_number("0"), Some(0));
        for bad in ["", "0x", "-1", "+1", "1k", "0x1g", "08", "1.5"] {
            assert_eq!(parse_number(bad), None, "{bad}");
        }
    }

    #[test]
    fn real_clean_map() {
        let m = parse(CLEAN).unwrap();
        assert_eq!(m.created_by(), Some("GNU ddrescue version 1.30"));
        assert!(m.command_line().unwrap().starts_with("ddrescue "));
        assert_eq!(m.current_status, '+');
        assert_eq!(m.current_pass, Some(1));
        assert_eq!(m.blocks.len(), 1);
        assert!(m.covers(MIB) && m.is_finished());
        let a = m.assess(MIB, MIB, 512);
        assert!(a.read_errors.is_empty());
        assert_eq!(a.bytes_acquired, MIB);
        assert_eq!(a.counts.rescued, MIB);
        assert!(a.notes.is_empty());
    }

    #[test]
    fn real_map_with_bad_sectors_in_the_middle() {
        let m = parse(BAD_MIDDLE).unwrap();
        assert!(m.covers(MIB) && m.is_finished());
        assert_eq!(m.bytes(BlockStatus::BadSector), 0x600);
        assert_eq!(m.bad_sectors(512), 3);
        let a = m.assess(MIB, MIB, 512);
        let t = &a.read_errors;
        assert_eq!(t.source, MAP_SOURCE);
        assert_eq!(t.ranges.len(), 2);
        assert_eq!(
            (t.ranges[0].offset, t.ranges[0].length, t.ranges[0].kind),
            (0x10000, 0x400, RangeKind::Substituted)
        );
        assert_eq!(
            (t.ranges[1].offset, t.ranges[1].length, t.ranges[1].kind),
            (0x90000, 0x200, RangeKind::Substituted)
        );
        assert_eq!(t.substituted_sectors(), 3);
        assert_eq!(t.unread_bytes(), 0);
        assert_eq!(a.bytes_acquired, MIB);
        assert_eq!(a.counts.bad_areas, 2);
        assert_eq!(
            a.counts.describe(),
            "rescued 1022.50 KiB (1047040 bytes), bad-sector 1.50 KiB (1536 bytes) in 2 areas"
        );
    }

    #[test]
    fn real_map_with_a_bad_tail_and_a_short_image() {
        // ddrescue never writes the unreadable last sectors: the image ends early
        let m = parse(BAD_TAIL).unwrap();
        assert!(m.covers(MIB) && m.is_finished());
        let short = MIB - 0x400;
        let a = m.assess(MIB, short, 512);
        assert_eq!(a.bytes_acquired, short);
        assert_eq!(a.read_errors.unread_bytes(), 0x400);
        assert_eq!(a.read_errors.substituted_bytes(), 0);
        assert_eq!(a.bad_beyond_image, 0x400);
        assert!(
            a.notes[0].contains("beyond the end of the image file"),
            "{:?}",
            a.notes
        );
        // Extended to the source size, the tail is zeros: substituted
        let a = m.assess(MIB, MIB, 512);
        assert_eq!(a.bytes_acquired, MIB);
        assert_eq!(a.read_errors.substituted_bytes(), 0x400);
        assert_eq!(a.read_errors.unread_bytes(), 0);
    }

    #[test]
    fn real_interrupted_map() {
        let m = parse(INTERRUPTED).unwrap();
        assert_eq!(m.current_status, '?');
        assert_eq!(phase_label(m.current_status), "copying non-tried blocks");
        assert!(m
            .comments
            .iter()
            .any(|c| c.starts_with("Copying non-tried")));
        let size = 4 * MIB;
        assert!(m.covers(size));
        assert!(!m.is_finished());
        let a = m.assess(size, 0xA0000, 512);
        assert_eq!(a.bytes_acquired, 0xA0000);
        assert_eq!(a.read_errors.unread_bytes(), size - 0xA0000);
        assert_eq!(a.counts.non_tried, size - 0xA0000);
        assert_eq!(a.read_errors.ranges.len(), 1);
    }

    #[test]
    fn real_maps_with_unfinished_areas() {
        let m = parse(NON_TRIMMED).unwrap();
        assert_eq!(m.bytes(BlockStatus::NonTrimmed), 0x20000);
        assert!(m.covers(MIB) && !m.is_finished());
        let a = m.assess(MIB, MIB, 512);
        assert_eq!(a.counts.non_trimmed, 0x20000);
        assert_eq!(a.read_errors.unread_bytes(), 0x20000);
        assert_eq!(a.read_errors.substituted_bytes(), 0);
        assert_eq!(a.bytes_acquired, MIB - 0x20000);

        let m = parse(NON_SCRAPED).unwrap();
        let a = m.assess(MIB, MIB, 512);
        assert_eq!(a.counts.non_scraped, 0x400);
        assert_eq!(a.counts.bad_sector, 0x400);
        // -, /, - are adjacent: one substituted, one unread, one substituted
        let kinds: Vec<_> = a
            .read_errors
            .ranges
            .iter()
            .map(|r| (r.offset, r.length, r.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (0x10000, 0x200, RangeKind::Substituted),
                (0x10200, 0x400, RangeKind::Unread),
                (0x10600, 0x200, RangeKind::Substituted),
            ]
        );
    }

    #[test]
    fn every_status_and_old_two_field_position_line() {
        let text = "# hand-written: a map as ddrescue before 1.21 wrote it\r\n\
                    0x200 -\r\n\
                    0x0 0x200 +\r\n\
                    0x200 0x200 -\r\n\
                    1024 512 ?\r\n\
                    0x600 0x200 *\r\n\
                    0x800 0x200 /\r\n";
        let m = parse(text).unwrap();
        assert_eq!(m.current_pass, None);
        assert_eq!(m.current_status, '-');
        assert_eq!(m.blocks.len(), 5);
        assert!(m.covers(0xA00));
        let a = m.assess(0xA00, 0xA00, 512);
        assert_eq!(a.counts.rescued, 0x200);
        assert_eq!(a.counts.bad_sector, 0x200);
        assert_eq!(a.counts.non_tried, 0x200);
        assert_eq!(a.counts.non_trimmed, 0x200);
        assert_eq!(a.counts.non_scraped, 0x200);
        assert_eq!(a.read_errors.substituted_bytes(), 0x200);
        // ?, *, / are adjacent: one unread range
        assert_eq!(a.read_errors.unread_bytes(), 0x600);
        assert_eq!(a.read_errors.count(RangeKind::Unread), 1);
        assert_eq!(a.bytes_acquired, 0x400);
    }

    #[test]
    fn gaps_and_blocks_beyond_the_source() {
        // Gap 0x200..0x400 and a map longer than the source
        let m = parse("0x0 +\n0x0 0x200 +\n0x400 0x400 +\n").unwrap();
        assert!(!m.covers(0x800));
        let a = m.assess(0x600, 0x800, 512);
        assert_eq!(a.not_listed, 0x200);
        assert_eq!(a.beyond_source, 0x200);
        assert_eq!(a.bytes_acquired, 0x400);
        assert_eq!(a.read_errors.unread_bytes(), 0x200);
        assert_eq!(a.notes.len(), 2);
        // A map shorter than the source: the rest is not listed
        let a = m.assess(0x1000, 0x800, 512);
        assert_eq!(a.not_listed, 0x200 + 0x800);
        // An image shorter than what the map calls rescued
        let a = m.assess(0x800, 0x500, 512);
        assert_eq!(a.rescued_beyond_image, 0x300);
        assert_eq!(a.bytes_acquired, 0x200 + 0x100);
    }

    #[test]
    fn empty_map_lists_nothing() {
        let m = parse("# only a position line\n0x0 ?\n").unwrap();
        assert!(m.blocks.is_empty());
        assert!(!m.covers(512) && m.covers(0));
        let a = m.assess(4096, 0, 512);
        assert_eq!(a.bytes_acquired, 0);
        assert_eq!(a.read_errors.unread_bytes(), 4096);
    }

    #[test]
    fn malformed_maps_are_errors() {
        let cases = [
            ("", "no current-position line"),
            ("# comment only\n", "no current-position line"),
            ("0x0\n", "current-position line"),
            ("0x0 x\n", "invalid current status"),
            ("0x0 + one\n", "invalid current pass"),
            ("zz +\n", "invalid current position"),
            ("0x0 +\n0x0 0x200\n", "block line"),
            ("0x0 +\n0x0 0x200 X\n", "invalid block status"),
            ("0x0 +\n0x0 0x200 ++\n", "invalid block status"),
            ("0x0 +\n0x0 0 +\n", "size 0"),
            ("0x0 +\n0xg 0x200 +\n", "invalid block position"),
            ("0x0 +\n0x0 -5 +\n", "invalid block size"),
            ("0x0 +\n0x0 0x400 +\n0x200 0x200 -\n", "overlaps"),
            (
                "0x0 +\n0x400 0x200 +\n0x0 0x200 -\n",
                "overlaps or precedes",
            ),
            ("0x0 +\n0xFFFFFFFFFFFFFFFF 0x2 +\n", "beyond 2^64"),
        ];
        for (text, want) in cases {
            let e = parse(text).unwrap_err();
            assert!(e.to_string().contains(want), "{text:?}: {e}");
        }
        assert_eq!(parse("0x0 +\n0x0 0x200 X\n").unwrap_err().line, 2);
    }

    #[test]
    fn statuses_round_trip() {
        for s in BlockStatus::ALL {
            assert_eq!(BlockStatus::from_char(s.as_char()), Some(s));
        }
        assert_eq!(BlockStatus::from_char('F'), None);
        assert_eq!(
            BlockStatus::BadSector.range_kind(),
            Some(RangeKind::Substituted)
        );
        assert_eq!(BlockStatus::Finished.range_kind(), None);
        for c in ['?', '*', '/', '-', 'F', 'G', '+'] {
            assert_ne!(phase_label(c), "unknown");
        }
    }

    #[test]
    fn read_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.map");
        let e = read(&p).unwrap_err();
        assert!(e.contains("cannot read"), "{e}");
        std::fs::write(&p, "garbage\n").unwrap();
        let e = read(&p).unwrap_err();
        assert!(e.contains("is not a valid ddrescue map"), "{e}");
        std::fs::write(&p, CLEAN).unwrap();
        assert!(read(&p).is_ok());
    }
}
