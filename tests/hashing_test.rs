#![allow(unused_imports, dead_code)]

#[path = "../src/models/mod.rs"]
mod models;

#[path = "../src/engines/mod.rs"]
mod engines;

use engines::hasher::{HashProgress, MultiHasher};
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_rfc_test_vectors_empty() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("dfdisk_test_rfc_empty.dat");
    {
        let _ = File::create(&test_file).expect("Failed to create empty test file");
    }

    let (tx, mut rx) = mpsc::channel(20);
    let results = MultiHasher::hash_stream(&test_file, true, true, true, Some(tx))
        .await
        .expect("Empty file hashing must succeed");

    // RFC 1321 empty string MD5: d41d8cd98f00b204e9800998ecf8427e
    assert_eq!(
        results.md5.as_deref(),
        Some("d41d8cd98f00b204e9800998ecf8427e")
    );

    // RFC 3174 empty string SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    assert_eq!(
        results.sha1.as_deref(),
        Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    );

    // FIPS 180-2 empty string SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        results.sha256.as_deref(),
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );

    // Progress for empty file must reach 100.0%
    let mut last_progress = None;
    while let Some(prog) = rx.recv().await {
        last_progress = Some(prog);
    }
    let final_prog = last_progress.expect("Must emit at least final progress");
    assert_eq!(final_prog.percentage, 100.0);
    assert_eq!(final_prog.bytes_hashed, 0);

    let _ = std::fs::remove_file(test_file);
}

#[tokio::test]
async fn test_rfc_standard_vectors() {
    let test_cases = [
        (
            "a",
            "0cc175b9c0f1b6a831c399e269772661",
            "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        ),
        (
            "abc",
            "900150983cd24fb0d6963f7d28e17f72",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "message digest",
            "f96b697d7cb7938d525a2f31aaf161d0",
            "c12252ceda8be8994d5fa0290a47231c1d16aae3",
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
            "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
        ),
    ];

    let temp_dir = std::env::temp_dir();
    for (i, (input, exp_md5, exp_sha1, exp_sha256)) in test_cases.iter().enumerate() {
        let test_file = temp_dir.join(format!("dfdisk_rfc_vector_{}.dat", i));
        {
            let mut f = File::create(&test_file).unwrap();
            f.write_all(input.as_bytes()).unwrap();
        }

        // Dynamically compute independently using cryptographic digest primitives
        let mut exp_md5_h = Md5::new();
        exp_md5_h.update(input.as_bytes());
        let calc_md5 = hex::encode(exp_md5_h.finalize());
        assert_eq!(&calc_md5, exp_md5);

        let mut exp_sha1_h = Sha1::new();
        exp_sha1_h.update(input.as_bytes());
        let calc_sha1 = hex::encode(exp_sha1_h.finalize());
        assert_eq!(&calc_sha1, exp_sha1);

        let mut exp_sha256_h = Sha256::new();
        exp_sha256_h.update(input.as_bytes());
        let calc_sha256 = hex::encode(exp_sha256_h.finalize());
        assert_eq!(&calc_sha256, exp_sha256);

        let res = MultiHasher::hash_stream(&test_file, true, true, true, None)
            .await
            .unwrap();

        assert_eq!(
            res.md5.as_deref(),
            Some(*exp_md5),
            "MD5 mismatch for input: '{}'",
            input
        );
        assert_eq!(
            res.sha1.as_deref(),
            Some(*exp_sha1),
            "SHA-1 mismatch for input: '{}'",
            input
        );
        assert_eq!(
            res.sha256.as_deref(),
            Some(*exp_sha256),
            "SHA-256 mismatch for input: '{}'",
            input
        );

        let _ = std::fs::remove_file(test_file);
    }
}

#[tokio::test]
async fn test_streaming_progress_and_completion() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("dfdisk_test_streaming_2_5mb.bin");
    // Create 2.5 MB (2,621,440 bytes) to ensure multiple 1MB buffer chunks
    let total_size: usize = 2_621_440;
    let pattern = [0x5au8; 1024]; // 1 KB repeating pattern
    {
        let mut f = File::create(&test_file).expect("Failed to create 2.5MB file");
        for _ in 0..(total_size / 1024) {
            f.write_all(&pattern).unwrap();
        }
    }

    // Compute expected hashes independently
    let mut expected_md5_hasher = Md5::new();
    let mut expected_sha256_hasher = Sha256::new();
    for _ in 0..(total_size / 1024) {
        expected_md5_hasher.update(pattern);
        expected_sha256_hasher.update(pattern);
    }
    let expected_md5 = hex::encode(expected_md5_hasher.finalize());
    let expected_sha256 = hex::encode(expected_sha256_hasher.finalize());

    let (tx, mut rx) = mpsc::channel(100);
    let results = MultiHasher::hash_stream(&test_file, true, false, true, Some(tx))
        .await
        .expect("Streaming hashing should succeed");

    assert_eq!(results.md5.as_deref(), Some(expected_md5.as_str()));
    assert!(results.sha1.is_none());
    assert_eq!(results.sha256.as_deref(), Some(expected_sha256.as_str()));

    let mut progress_events: Vec<HashProgress> = Vec::new();
    while let Some(prog) = rx.recv().await {
        progress_events.push(prog);
    }

    assert!(
        !progress_events.is_empty(),
        "Must have received at least one progress update"
    );

    // Verify properties of progress stream
    for p in &progress_events {
        assert!(
            p.bytes_hashed <= p.total_bytes,
            "bytes_hashed {} must not exceed total_bytes {}",
            p.bytes_hashed,
            p.total_bytes
        );
        assert!(
            (0.0..=100.0).contains(&p.percentage),
            "percentage must be in [0.0, 100.0], got {}",
            p.percentage
        );
    }

    // Final progress must reach exactly 100.0%
    let final_prog = progress_events.last().unwrap();
    assert_eq!(
        final_prog.percentage, 100.0,
        "Final progress must reach 100.0%"
    );
    assert_eq!(final_prog.bytes_hashed, total_size as u64);
    assert_eq!(final_prog.total_bytes, total_size as u64);

    let _ = std::fs::remove_file(test_file);
}

#[tokio::test]
async fn test_seek_capacity_calculation() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("dfdisk_test_seek_capacity.bin");
    let target_size: u64 = 1_048_576; // 1 MB

    // Create file and extend via set_len and seek
    {
        let mut f = File::create(&test_file).expect("Failed to create seek test file");
        f.set_len(target_size).expect("Failed to set file length");
        // Write byte at beginning and end
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(b"\xaa").unwrap();
        f.seek(SeekFrom::End(-1)).unwrap();
        f.write_all(b"\xbb").unwrap();
    }

    // Verify seek end pos matches target_size
    {
        let mut f = File::open(&test_file).unwrap();
        let end_pos = f.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(end_pos, target_size);
    }

    let (tx, mut rx) = mpsc::channel(10);
    let results = MultiHasher::hash_stream(&test_file, true, true, true, Some(tx))
        .await
        .expect("Hashing seek-sized file must succeed");

    assert!(results.md5.is_some());
    assert!(results.sha1.is_some());
    assert!(results.sha256.is_some());

    let mut final_prog = None;
    while let Some(prog) = rx.recv().await {
        final_prog = Some(prog);
    }
    let final_p = final_prog.expect("Must have final progress");
    assert_eq!(final_p.percentage, 100.0);
    assert_eq!(final_p.total_bytes, target_size);
    assert_eq!(final_p.bytes_hashed, target_size);

    let _ = std::fs::remove_file(test_file);
}

#[tokio::test]
async fn test_selective_algorithm_hashing() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("dfdisk_test_selective.bin");
    {
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"forensic selective algorithm test").unwrap();
    }

    // MD5 only
    let r_md5 = MultiHasher::hash_stream(&test_file, true, false, false, None)
        .await
        .unwrap();
    assert!(r_md5.md5.is_some());
    assert!(r_md5.sha1.is_none());
    assert!(r_md5.sha256.is_none());

    // SHA-1 only
    let r_sha1 = MultiHasher::hash_stream(&test_file, false, true, false, None)
        .await
        .unwrap();
    assert!(r_sha1.md5.is_none());
    assert!(r_sha1.sha1.is_some());
    assert!(r_sha1.sha256.is_none());

    // SHA-256 only
    let r_sha256 = MultiHasher::hash_stream(&test_file, false, false, true, None)
        .await
        .unwrap();
    assert!(r_sha256.md5.is_none());
    assert!(r_sha256.sha1.is_none());
    assert!(r_sha256.sha256.is_some());

    // None selected
    let r_none = MultiHasher::hash_stream(&test_file, false, false, false, None)
        .await
        .unwrap();
    assert!(r_none.md5.is_none());
    assert!(r_none.sha1.is_none());
    assert!(r_none.sha256.is_none());

    let _ = std::fs::remove_file(test_file);
}
