//! The pieces file contract other code relies on (`dfdisk verify --pieces`):
//! format, split images, the report and its JSON form.

use dfdisk::engines::pieces::{
    parse_pieces, verify_pieces, PieceHasher, PiecesOutput, PiecesReport, PIECES_HEADER,
};
use dfdisk::engines::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}

/// Write `data` as a pieces file through the acquisition writer.
fn record(dir: &std::path::Path, data: &[u8], piece: u64) -> PathBuf {
    let path = dir.join("case.pieces.tsv");
    let mut out = PiecesOutput::create(&path, piece).unwrap();
    for part in data.chunks(100_000) {
        out.update(part);
    }
    let done = out.finish().unwrap();
    assert_eq!(done.path, path);
    path
}

#[test]
fn the_file_format_is_the_documented_one() {
    let tmp = tempfile::tempdir().unwrap();
    let data = sample(2 * 65536 + 10);
    let tsv = record(tmp.path(), &data, 65536);
    let text = std::fs::read_to_string(&tsv).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], PIECES_HEADER);
    assert_eq!(lines[0], "index\toffset\tlength\tsha256");
    assert_eq!(lines.len(), 4);
    let fields: Vec<&str> = lines[3].split('\t').collect();
    assert_eq!(&fields[..3], ["2", "131072", "10"]);
    assert_eq!(
        fields[3],
        hex::encode(<sha2::Sha256 as digest::Digest>::digest(&data[131072..]))
    );
    assert_eq!(parse_pieces(&text).unwrap().len(), 3);
    // The writer and an independent hasher agree
    let mut h = PieceHasher::new(65536);
    let mut pieces = Vec::new();
    h.update(&data, &mut |p| pieces.push(p));
    h.finish(&mut |p| pieces.push(p));
    assert_eq!(parse_pieces(&text).unwrap(), pieces);
}

#[test]
fn split_raw_segments_are_checked_as_one_image() {
    let tmp = tempfile::tempdir().unwrap();
    let data = sample(300_000);
    let tsv = record(tmp.path(), &data, 65536);
    let segments: Vec<PathBuf> = data
        .chunks(128 * 1024)
        .enumerate()
        .map(|(i, part)| {
            let p = tmp.path().join(format!("case.{:03}", i + 1));
            std::fs::write(&p, part).unwrap();
            p
        })
        .collect();
    assert_eq!(segments.len(), 3);
    let never = AtomicBool::new(false);
    let mut progress = 0;
    let r = verify_pieces(&segments, &tsv, &never, |n| progress = n).unwrap();
    assert!(r.all_match(), "{}", r.summary());
    assert_eq!(progress, data.len() as u64);
    assert_eq!(
        (
            r.pieces_checked,
            r.bytes_checked,
            r.covered_bytes,
            r.image_bytes
        ),
        (5, 300_000, 300_000, 300_000)
    );

    // A missing segment: the image is short, the later pieces do not match
    let r = verify_pieces(&segments[..2], &tsv, &never, |_| {}).unwrap();
    assert!(!r.all_match());
    assert_eq!(r.mismatch_count, 1);
    assert_eq!(r.mismatches[0].index, 4);
    assert_eq!(r.mismatches[0].bytes_present, 262_144 - 4 * 65536);

    // Segments in the wrong order
    let swapped = vec![
        segments[1].clone(),
        segments[0].clone(),
        segments[2].clone(),
    ];
    let r = verify_pieces(&swapped, &tsv, &never, |_| {}).unwrap();
    assert!(r.mismatch_count >= 2, "{}", r.details(10));
}

#[test]
fn the_report_serialises_for_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let data = sample(70_000);
    let tsv = record(tmp.path(), &data, 65536);
    let img = tmp.path().join("case.raw");
    let mut damaged = data.clone();
    damaged[1] ^= 1;
    std::fs::write(&img, &damaged).unwrap();
    let r: PiecesReport = verify_pieces(
        std::slice::from_ref(&img),
        &tsv,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["pieces_checked"], 2);
    assert_eq!(json["mismatch_count"], 1);
    assert_eq!(json["mismatches"][0]["index"], 0);
    assert_eq!(json["mismatches"][0]["bytes_present"], 65536);
    assert_eq!(json["covered_bytes"], 70_000);
    assert_eq!(json["image_bytes"], 70_000);
    assert!(r
        .details(5)
        .starts_with("1 of 2 pieces differs; piece 0 (bytes 0-65535)"));
}

#[test]
fn unusable_inputs_are_errors_with_kinds() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("case.raw");
    std::fs::write(&img, sample(1000)).unwrap();
    let never = AtomicBool::new(false);
    let missing = tmp.path().join("none.pieces.tsv");
    let e = verify_pieces(std::slice::from_ref(&img), &missing, &never, |_| {}).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
    assert!(e.message.contains("does not exist"), "{e}");
    let bad = tmp.path().join("bad.pieces.tsv");
    std::fs::write(&bad, format!("{PIECES_HEADER}\n0\t0\t1000\tnot-a-digest\n")).unwrap();
    let e = verify_pieces(std::slice::from_ref(&img), &bad, &never, |_| {}).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Failed);
    assert!(e.message.contains("line 2"), "{e}");
}
