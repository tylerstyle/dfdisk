//! `dfdisk verify` semantics (engines::verify) against real EWF images made
//! by the real ewfacquire: stored digests count as a comparison, expected
//! digests from the command line or a dfdisk report, segment families, a
//! tampered image is a mismatch, a missing segment is refused.
//!
//! These run when libewf exists; with DFDISK_REQUIRE_TOOLS=1 a missing tool
//! fails them.

mod support;

use dfdisk::engines::verify::{
    self, CheckStatus, ExpectedHashes, VerifiedFormat, VerifyOptions, STORED_IN_IMAGE,
};
use dfdisk::engines::ErrorKind;
use dfdisk::models::config::{AcquisitionConfig, EffectiveConfig, EngineKind};
use dfdisk::models::info_report::ForensicInfoReport;
use dfdisk::models::outcome::VerificationResult;
use dfdisk::signals::StopFlags;
use digest::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;

const SIZE: usize = 4 * 1024 * 1024;

fn content(seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..SIZE)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// An uncompressed E01 of fresh content in 1 MiB segments (x.E01 .. x.E05).
fn make_e01(dir: &Path, seed: u64) -> (Vec<u8>, PathBuf) {
    let data = content(seed);
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let out = Command::new("ewfacquire")
        .args([
            "-u",
            "-c",
            "none",
            "-S",
            "1048576",
            "-d",
            "sha1,sha256",
            "-t",
        ])
        .arg(dir.join("x"))
        .arg(&src)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    (data, dir.join("x.E01"))
}

fn options(dir: &Path) -> VerifyOptions {
    VerifyOptions {
        write_addendum: true,
        audit_log: Some(dir.join("audit.jsonl")),
        ..Default::default()
    }
}

fn md5(data: &[u8]) -> String {
    hex::encode(md5::Md5::digest(data))
}

fn sha256(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}

#[tokio::test]
async fn stored_digests_are_compared_and_count_as_verification() {
    if !support::tool_available(&["ewfacquire", "ewfverify"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (data, e01) = make_e01(tmp.path(), 11);
    // Any segment of the family: ewfverify reads from the first
    let v = verify::verify_image(
        &tmp.path().join("x.E03"),
        &ExpectedHashes::given(None, None, None),
        &options(tmp.path()),
        &StopFlags::new(),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(v.format, VerifiedFormat::Ewf);
    assert_eq!(v.read_path, e01);
    assert_eq!(v.segments.len(), 5);
    assert_eq!(v.computed.md5, Some(md5(&data)));
    assert_eq!(v.computed.sha256, Some(sha256(&data)));
    assert_eq!(v.stored.md5, Some(md5(&data)));
    assert!(v.passed(), "{:?}", v.result);
    assert_eq!(v.exit_code, 0);
    assert!(v.checks.iter().all(|c| c.reference == STORED_IN_IMAGE));
    assert!(v.checks.iter().all(|c| c.status == CheckStatus::Match));
    let text = std::fs::read_to_string(v.addendum.as_ref().unwrap()).unwrap();
    assert!(text.contains("Segments              : 5 files"), "{text}");
    assert!(text.contains(STORED_IN_IMAGE), "{text}");
}

#[tokio::test]
async fn expected_digests_from_the_command_line_and_a_report() {
    if !support::tool_available(&["ewfacquire", "ewfverify"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (data, e01) = make_e01(tmp.path(), 23);
    let stop = StopFlags::new();
    let given = ExpectedHashes::given(None, None, Some(sha256(&data).to_uppercase()));
    let v = verify::verify_image(&e01, &given, &options(tmp.path()), &stop, |_| {})
        .await
        .unwrap();
    assert!(v.passed(), "{:?}", v.result);
    assert!(v
        .checks
        .iter()
        .any(|c| c.reference == "command line" && c.status == CheckStatus::Match));

    // A wrong expected digest is a mismatch even though the image is intact
    let wrong = ExpectedHashes::given(Some("0".repeat(32)), None, None);
    let v = verify::verify_image(&e01, &wrong, &options(tmp.path()), &stop, |_| {})
        .await
        .unwrap();
    assert_eq!(v.exit_code, 5);
    assert!(matches!(v.result, VerificationResult::Mismatched { .. }));

    // Digests from a dfdisk report (.info.json)
    let mut report = ForensicInfoReport::new(
        EngineKind::Ewf,
        &Default::default(),
        Default::default(),
        EffectiveConfig::build(&AcquisitionConfig::ewf(tmp.path()), None),
    );
    report.acquisition_hashes.md5 = Some(md5(&data));
    report.acquisition_hashes.sha256 = Some(sha256(&data));
    report.image_files = vec![e01.to_string_lossy().into_owned()];
    let json = tmp.path().join("x.info.json");
    std::fs::write(&json, report.to_json()).unwrap();
    let expected = ExpectedHashes::from_report_json(&json).unwrap();
    let v = verify::verify_image(&e01, &expected, &options(tmp.path()), &stop, |_| {})
        .await
        .unwrap();
    assert!(v.passed(), "{:?}", v.result);
    assert!(v.warnings.is_empty(), "{:?}", v.warnings);
    assert!(v
        .checks
        .iter()
        .any(|c| c.reference == json.display().to_string()));
}

#[tokio::test]
async fn tampered_image_is_a_mismatch_and_a_missing_segment_is_refused() {
    if !support::tool_available(&["ewfacquire", "ewfverify"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (_, e01) = make_e01(tmp.path(), 37);
    // Overwrite media data inside the second segment
    let e02 = tmp.path().join("x.E02");
    let mut bytes = std::fs::read(&e02).unwrap();
    let at = bytes.len() / 2;
    for b in &mut bytes[at..at + 16] {
        *b ^= 0xff;
    }
    std::fs::write(&e02, &bytes).unwrap();
    let v = verify::verify_image(
        &e01,
        &ExpectedHashes::given(None, None, None),
        &options(tmp.path()),
        &StopFlags::new(),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(v.exit_code, 5, "{:?}", v.result);
    assert!(!v.passed());
    assert!(v.verdict().starts_with("HASH MISMATCH"), "{}", v.verdict());

    std::fs::remove_file(&e02).unwrap();
    let err = verify::verify_image(
        &e01,
        &ExpectedHashes::given(None, None, None),
        &options(tmp.path()),
        &StopFlags::new(),
        |_| {},
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Usage);
    assert!(err.message.contains("gap"), "{err}");
}
