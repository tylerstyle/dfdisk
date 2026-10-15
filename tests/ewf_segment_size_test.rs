//! E-4: every `-S` value dfdisk passes to ewfacquire is applied as given by
//! the installed libewf (measured with 20231119 and 20140816). `--split none`
//! passes the largest EnCase 6 segment size both accept, so the image is one
//! segment as the report says; one byte more is refused by libewf and
//! silently replaced by 1.4 GiB segments.
//!
//! Runs when ewfacquire is installed; fails without it when
//! DFDISK_REQUIRE_TOOLS=1.

mod support;

use dfdisk::models::config::{SplitSize, EWF_MAX_SEGMENT_BYTES};
use std::path::Path;
use std::process::Command;

/// Run ewfacquire on `src` with `-S <split>`; (standard error, segments).
fn acquire(dir: &Path, name: &str, src: &Path, split: &str) -> (String, usize) {
    let out = Command::new("ewfacquire")
        .env("LC_ALL", "C")
        .args(["-u", "-c", "none", "-f", "encase6", "-S", split])
        .args(["-C", "c", "-E", "e", "-e", "x", "-t"])
        .arg(dir.join(name))
        .arg(src)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("ewfacquire: SUCCESS"), "{stdout}");
    let segments = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(&format!("{name}.E"))
        })
        .count();
    (String::from_utf8_lossy(&out.stderr).into_owned(), segments)
}

#[test]
fn every_segment_size_dfdisk_passes_is_applied_by_ewfacquire() {
    if !support::tool_available(&["ewfacquire"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src.raw");
    let data: Vec<u8> = (0..(3usize << 19)).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&src, data).unwrap();
    for (i, (split, segments)) in [
        (SplitSize::None, 1),
        (SplitSize::TwoGb, 1),
        (SplitSize::FourGb, 1),
        (SplitSize::Custom(1 << 20), 2),
    ]
    .into_iter()
    .enumerate()
    {
        let arg = split.as_ewf_arg();
        let (stderr, n) = acquire(tmp.path(), &format!("t{i}"), &src, &arg);
        assert!(
            !stderr.contains("Unsupported maximum segment size"),
            "-S {arg}: {stderr}"
        );
        assert_eq!(n, segments, "-S {arg}");
    }
    // The measured boundary: one byte more is not applied
    let (stderr, _) = acquire(
        tmp.path(),
        "over",
        &src,
        &format!("{}B", EWF_MAX_SEGMENT_BYTES + 1),
    );
    assert!(
        stderr.contains("Unsupported maximum segment size defaulting to"),
        "{stderr}"
    );
}
