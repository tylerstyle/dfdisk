use md5::{Digest, Md5};
use sha2::Sha256;
use std::fs::File;
use std::io::Write;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_dfdisk");

#[test]
fn test_cli_version() {
    let output = Command::new(BIN)
        .arg("--version")
        .output()
        .expect("Failed to execute dfdisk --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("dfdisk "),
        "Expected version output to start with 'dfdisk ', got: {}",
        stdout
    );
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));

    // Test short flag -V
    let output_short = Command::new(BIN)
        .arg("-V")
        .output()
        .expect("Failed to execute dfdisk -V");
    assert!(output_short.status.success());
    let stdout_short = String::from_utf8_lossy(&output_short.stdout);
    assert_eq!(stdout, stdout_short);
}

#[test]
fn test_cli_help() {
    let output = Command::new(BIN)
        .arg("--help")
        .output()
        .expect("Failed to execute dfdisk --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("A high-performance forensic disk imager"));
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("list"));
    assert!(stdout.contains("acquire"));
    assert!(stdout.contains("convert"));
    assert!(stdout.contains("verify"));
    assert!(stdout.contains("tui"));

    // Test short flag -h
    let output_short = Command::new(BIN)
        .arg("-h")
        .output()
        .expect("Failed to execute dfdisk -h");
    assert!(output_short.status.success());
    let stdout_short = String::from_utf8_lossy(&output_short.stdout);
    assert!(stdout_short.contains("Modern forensic disk imaging"));
}

#[test]
fn test_subcommand_help() {
    // 1. list --help
    let list_out = Command::new(BIN)
        .args(["list", "--help"])
        .output()
        .expect("Failed to execute list --help");
    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("--json"));
    assert!(list_str.contains("List all connected storage media"));

    // 2. acquire --help
    let acq_out = Command::new(BIN)
        .args(["acquire", "--help"])
        .output()
        .expect("Failed to execute acquire --help");
    assert!(acq_out.status.success());
    let acq_str = String::from_utf8_lossy(&acq_out.stdout);
    assert!(acq_str.contains("<DEVICE>"));
    assert!(acq_str.contains("--case"));
    assert!(acq_str.contains("--evidence"));
    assert!(acq_str.contains("--format"));
    assert!(acq_str.contains("--split"));
    assert!(acq_str.contains("--compression"));
    assert!(acq_str.contains("--rescue"));
    assert!(acq_str.contains("--auto-unmount"));

    // 3. convert --help
    let conv_out = Command::new(BIN)
        .args(["convert", "--help"])
        .output()
        .expect("Failed to execute convert --help");
    assert!(conv_out.status.success());
    let conv_str = String::from_utf8_lossy(&conv_out.stdout);
    assert!(conv_str.contains("<SOURCE>"));
    assert!(conv_str.contains("--to"));
    assert!(conv_str.contains("--output-dir"));

    // 4. verify --help
    let ver_out = Command::new(BIN)
        .args(["verify", "--help"])
        .output()
        .expect("Failed to execute verify --help");
    assert!(ver_out.status.success());
    let ver_str = String::from_utf8_lossy(&ver_out.stdout);
    assert!(ver_str.contains("<IMAGE>"));
    assert!(ver_str.contains("--md5"));
    assert!(ver_str.contains("--sha1"));
    assert!(ver_str.contains("--sha256"));
}

#[test]
fn test_clap_argument_validation() {
    // Missing required positional argument: acquire
    let missing_acq = Command::new(BIN)
        .arg("acquire")
        .output()
        .expect("Failed to execute acquire without args");
    assert_eq!(
        missing_acq.status.code(),
        Some(2),
        "Expected exit code 2 for missing required arguments"
    );
    let stderr_acq = String::from_utf8_lossy(&missing_acq.stderr);
    assert!(
        stderr_acq.contains("required") || stderr_acq.contains("<DEVICE>"),
        "Expected error mentioning missing required args: {}",
        stderr_acq
    );

    // Missing required positional argument: convert (missing source and --to)
    let missing_conv = Command::new(BIN)
        .arg("convert")
        .output()
        .expect("Failed to execute convert without args");
    assert_eq!(missing_conv.status.code(), Some(2));

    // Missing required positional argument: verify (missing image)
    let missing_ver = Command::new(BIN)
        .arg("verify")
        .output()
        .expect("Failed to execute verify without args");
    assert_eq!(missing_ver.status.code(), Some(2));

    // Invalid enum value for --format
    let invalid_fmt = Command::new(BIN)
        .args(["acquire", "/dev/null", "--format", "invalid"])
        .output()
        .expect("Failed to execute with invalid format");
    assert_eq!(invalid_fmt.status.code(), Some(2));
    let stderr_fmt = String::from_utf8_lossy(&invalid_fmt.stderr);
    assert!(
        stderr_fmt.contains("invalid value 'invalid'"),
        "Expected enum validation message: {}",
        stderr_fmt
    );

    // Invalid enum value for --split
    let invalid_split = Command::new(BIN)
        .args(["acquire", "/dev/null", "--split", "invalid_split"])
        .output()
        .expect("Failed to execute with invalid split");
    assert_eq!(invalid_split.status.code(), Some(2));

    // Invalid enum value for --compression
    let invalid_comp = Command::new(BIN)
        .args(["acquire", "/dev/null", "--compression", "ultra_max"])
        .output()
        .expect("Failed to execute with invalid compression");
    assert_eq!(invalid_comp.status.code(), Some(2));

    // Unexpected flag
    let unexpected_flag = Command::new(BIN)
        .arg("--unsupported-forensic-flag")
        .output()
        .expect("Failed to execute with unexpected flag");
    assert_eq!(unexpected_flag.status.code(), Some(2));
    let stderr_unexp = String::from_utf8_lossy(&unexpected_flag.stderr);
    assert!(
        stderr_unexp.contains("unexpected argument") || stderr_unexp.contains("not expected"),
        "Expected unexpected argument error: {}",
        stderr_unexp
    );
}

#[test]
fn test_verify_subcommand_exit_codes() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("dfdisk_cli_verify_test.bin");
    let test_payload = b"CRIME_SCENE_FORENSIC_ACQUISITION_VERIFICATION_PAYLOAD_2026";
    {
        let mut f = File::create(&test_file).expect("Failed to create test file");
        f.write_all(test_payload).expect("Failed to write payload");
    }

    // Compute expected hashes dynamically
    let mut md5_h = Md5::new();
    md5_h.update(test_payload);
    let expected_md5 = hex::encode(md5_h.finalize());

    let mut sha256_h = Sha256::new();
    sha256_h.update(test_payload);
    let expected_sha256 = hex::encode(sha256_h.finalize());

    // 1. Verify with matching MD5 (must exit 0)
    let verify_md5_match = Command::new(BIN)
        .args([
            "verify",
            test_file.to_str().unwrap(),
            "--md5",
            &expected_md5,
        ])
        .output()
        .expect("Failed to run verify with matching MD5");
    assert!(
        verify_md5_match.status.success(),
        "Expected exit code 0 on matching MD5, got: {:?}",
        verify_md5_match.status.code()
    );
    let stdout_match = String::from_utf8_lossy(&verify_md5_match.stdout);
    assert!(stdout_match.contains("VERIFICATION RESULT: PASSED"));

    // 2. Verify with matching SHA-256 (must exit 0)
    let verify_sha256_match = Command::new(BIN)
        .args([
            "verify",
            test_file.to_str().unwrap(),
            "--sha256",
            &expected_sha256,
        ])
        .output()
        .expect("Failed to run verify with matching SHA256");
    assert!(verify_sha256_match.status.success());
    let stdout_sha_match = String::from_utf8_lossy(&verify_sha256_match.stdout);
    assert!(stdout_sha_match.contains("VERIFICATION RESULT: PASSED"));

    // 3. Verify with dual matching hashes (must exit 0)
    let verify_dual_match = Command::new(BIN)
        .args([
            "verify",
            test_file.to_str().unwrap(),
            "--md5",
            &expected_md5,
            "--sha256",
            &expected_sha256,
        ])
        .output()
        .expect("Failed to run verify with dual matching hashes");
    assert!(verify_dual_match.status.success());

    // 4. Verify with mismatched MD5 (must exit non-zero / 1)
    let mismatched_md5 = "00000000000000000000000000000000";
    let verify_md5_mismatch = Command::new(BIN)
        .args([
            "verify",
            test_file.to_str().unwrap(),
            "--md5",
            mismatched_md5,
        ])
        .output()
        .expect("Failed to run verify with mismatched MD5");
    assert_eq!(
        verify_md5_mismatch.status.code(),
        Some(1),
        "Expected exit code 1 on mismatched hash"
    );
    let stdout_mismatch = String::from_utf8_lossy(&verify_md5_mismatch.stdout);
    assert!(stdout_mismatch.contains("MISMATCH"));
    assert!(stdout_mismatch.contains("VERIFICATION RESULT: FAILED"));

    // 5. Verify with mismatched SHA-256 (must exit 1)
    let mismatched_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let verify_sha256_mismatch = Command::new(BIN)
        .args([
            "verify",
            test_file.to_str().unwrap(),
            "--sha256",
            mismatched_sha256,
        ])
        .output()
        .expect("Failed to run verify with mismatched SHA256");
    assert_eq!(verify_sha256_mismatch.status.code(), Some(1));

    // Cleanup
    let _ = std::fs::remove_file(test_file);
}

#[test]
fn test_list_json_output_structure() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = std::env::temp_dir().join("dfdisk_cli_test_mock_bin");
    std::fs::create_dir_all(&temp_dir).expect("Failed to create mock bin dir");
    let mock_lsblk = temp_dir.join("lsblk");

    // Hermetic mock for lsblk returning standard JSON block device structure
    let mock_script = r#"#!/bin/sh
cat << 'EOF'
{
  "blockdevices": [
    {
      "name": "nvme0n1",
      "path": "/dev/nvme0n1",
      "size": 1000204886016,
      "type": "disk",
      "model": "Samsung SSD 980 PRO 1TB",
      "vendor": "Samsung",
      "serial": "S5GXNF0R123456",
      "tran": "nvme",
      "mountpoints": []
    }
  ]
}
EOF
"#;
    std::fs::write(&mock_lsblk, mock_script).expect("Failed to write mock lsblk");
    std::fs::set_permissions(&mock_lsblk, std::fs::Permissions::from_mode(0o755))
        .expect("Failed to set executable permissions");

    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", temp_dir.display(), current_path);

    let output = Command::new(BIN)
        .args(["list", "--json"])
        .env("PATH", new_path)
        .output()
        .expect("Failed to execute dfdisk list --json");

    assert!(
        output.status.success(),
        "Expected exit 0 for list --json, got: {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Stdout must be valid JSON");

    let devices_array = parsed
        .as_array()
        .expect("Top-level output must be a JSON array of devices");

    assert!(
        !devices_array.is_empty(),
        "Expected at least one device in list --json output"
    );

    // Validate schema of elements
    for dev in devices_array {
        assert!(
            dev.get("name").and_then(|v| v.as_str()).is_some(),
            "Device must have 'name'"
        );
        assert!(
            dev.get("path").and_then(|v| v.as_str()).is_some(),
            "Device must have 'path'"
        );
        assert!(
            dev.get("size_bytes").and_then(|v| v.as_u64()).is_some(),
            "Device must have numeric 'size_bytes'"
        );
        assert!(
            dev.get("bus_type").and_then(|v| v.as_str()).is_some(),
            "Device must have 'bus_type'"
        );
        assert!(
            dev.get("safety").is_some(),
            "Device must have 'safety' classification"
        );
    }

    let _ = std::fs::remove_dir_all(temp_dir);
}
