//! Every real ddrescue map in tests/fixtures/ddrescue parses through the
//! public API, covers its source exactly, and its read-error table accounts
//! for every byte that is not rescued (see the provenance list in
//! src/engines/ddrescue_map.rs).

use dfdisk::engines::ddrescue_map::{self, BlockStatus};
use dfdisk::models::outcome::RangeKind;
use std::path::Path;

const MIB: u64 = 1 << 20;

/// (fixture, source size)
const REAL_MAPS: &[(&str, u64)] = &[
    ("clean.map", MIB),
    ("bad_middle.map", MIB),
    ("bad_tail.map", MIB),
    ("interrupted.map", 4 * MIB),
    ("non_trimmed.map", MIB),
    ("non_scraped.map", MIB),
];

#[test]
fn every_real_map_accounts_for_every_byte() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ddrescue");
    for (name, size) in REAL_MAPS {
        let map = ddrescue_map::read(&dir.join(name)).unwrap();
        assert_eq!(
            map.created_by(),
            Some("GNU ddrescue version 1.30"),
            "{name}"
        );
        assert!(map.covers(*size), "{name}");
        let total: u64 = BlockStatus::ALL.iter().map(|s| map.bytes(*s)).sum();
        assert_eq!(total, *size, "{name}");

        // With an image of full length: rescued + substituted + unread = size
        let a = map.assess(*size, *size, 512);
        assert_eq!(
            a.counts.rescued + a.counts.bad_sector + a.counts.unfinished(),
            *size
        );
        assert_eq!(
            a.read_errors.substituted_bytes(),
            a.counts.bad_sector,
            "{name}"
        );
        assert_eq!(
            a.read_errors.unread_bytes(),
            a.counts.unfinished(),
            "{name}"
        );
        assert_eq!(
            a.bytes_acquired,
            a.counts.rescued + a.counts.bad_sector,
            "{name}"
        );
        assert_eq!(a.read_errors.source, ddrescue_map::MAP_SOURCE);
        // Ranges are exactly the map's non-rescued blocks
        let blocks: u64 = map
            .blocks
            .iter()
            .filter(|b| b.status != BlockStatus::Finished)
            .map(|b| b.size)
            .sum();
        let ranges: u64 = a.read_errors.ranges.iter().map(|r| r.length).sum();
        assert_eq!(ranges, blocks, "{name}");
        for r in &a.read_errors.ranges {
            let kinds: Vec<RangeKind> = map
                .blocks
                .iter()
                .filter(|b| b.pos < r.end() && b.end() > r.offset)
                .filter_map(|b| b.status.range_kind())
                .collect();
            assert!(kinds.iter().all(|k| *k == r.kind), "{name}: {r:?}");
        }
        // Finished maps describe a complete rescue apart from bad sectors
        assert_eq!(map.is_finished(), a.counts.unfinished() == 0, "{name}");
    }
}
