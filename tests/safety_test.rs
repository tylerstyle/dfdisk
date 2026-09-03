#![allow(unused_imports, dead_code)]

#[path = "../src/models/mod.rs"]
mod models;

#[path = "../src/discovery/mod.rs"]
mod discovery;

use discovery::safety::SafetyChecker;
use models::device::DeviceSafety;

#[test]
fn test_critical_os_directories_categorization() {
    let critical_roots = ["/", "/boot", "/nix", "/home", "/var", "/usr", "/etc"];

    for root in &critical_roots {
        // Direct root path
        assert!(
            SafetyChecker::is_critical_mount(root),
            "Directory '{}' must be categorized as critical OS directory",
            root
        );

        let mounts = vec![root.to_string()];
        match SafetyChecker::evaluate_safety(&mounts, false) {
            DeviceSafety::SystemDisk(crit) => {
                assert!(
                    crit.contains(&root.to_string()),
                    "SystemDisk must include '{}'",
                    root
                );
            }
            other => panic!("Expected SystemDisk for root '{}', got: {:?}", root, other),
        }
    }
}

#[test]
fn test_critical_os_subdirectories_categorization() {
    let critical_subdirs = [
        "/boot/efi",
        "/boot/grub",
        "/boot/loader/entries",
        "/nix/store",
        "/nix/var/nix/profiles/system",
        "/home/examiner",
        "/home/alice/.ssh",
        "/home/bob/evidence",
        "/var/log",
        "/var/log/audit",
        "/var/lib/docker",
        "/var/spool/mail",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/lib/systemd",
        "/etc/shadow",
        "/etc/fstab",
        "/etc/systemd/system",
    ];

    for subdir in &critical_subdirs {
        assert!(
            SafetyChecker::is_critical_mount(subdir),
            "Subdirectory '{}' must be categorized as critical OS directory",
            subdir
        );

        let mounts = vec![subdir.to_string()];
        match SafetyChecker::evaluate_safety(&mounts, false) {
            DeviceSafety::SystemDisk(crit) => {
                assert!(crit.contains(&subdir.to_string()));
            }
            other => panic!("Expected SystemDisk for '{}', got: {:?}", subdir, other),
        }
    }
}

#[test]
fn test_safe_mountpoints_and_prefix_boundary_defense() {
    let safe_paths = [
        "/mnt/usb",
        "/mnt/forensic_target",
        "/media/external",
        "/media/sdcard1",
        "/run/media/examiner/FLASH_DRIVE",
        "/tmp/mount_test",
        // Critical prefix boundary defense (must NOT match startswith prefix without / boundary)
        "/homebrew",
        "/homebrew/bin",
        "/variable_data",
        "/usrobotics",
        "/bootloader_backup",
        "/nixos_configs",
        "/etcetera",
    ];

    for safe in &safe_paths {
        assert!(
            !SafetyChecker::is_critical_mount(safe),
            "Path '{}' must NOT be categorized as critical OS directory",
            safe
        );

        let mounts = vec![safe.to_string()];
        match SafetyChecker::evaluate_safety(&mounts, false) {
            DeviceSafety::Mounted(normal) => {
                assert_eq!(normal, vec![safe.to_string()]);
            }
            other => panic!("Expected Mounted for '{}', got: {:?}", safe, other),
        }
    }

    // Completely unmounted device is Safe
    let empty: Vec<String> = Vec::new();
    assert_eq!(
        SafetyChecker::evaluate_safety(&empty, false),
        DeviceSafety::Safe
    );
}

#[test]
fn test_unmount_all_critical_refusal() {
    let critical_targets = [
        "/",
        "/boot",
        "/boot/efi",
        "/nix",
        "/nix/store",
        "/home",
        "/home/examiner",
        "/var",
        "/var/log",
        "/usr",
        "/usr/bin",
        "/etc",
        "/etc/shadow",
    ];

    for crit in &critical_targets {
        // Direct refusal on single critical mountpoint
        let res_single = SafetyChecker::unmount_all(&[crit.to_string()]);
        assert!(
            res_single.is_err(),
            "unmount_all must REFUSE critical mount '{}'",
            crit
        );
        let err_single = res_single.unwrap_err();
        assert!(
            err_single.contains("REFUSING to unmount critical OS mountpoint"),
            "Error must contain explicit refusal: {}",
            err_single
        );
        assert!(err_single.contains(crit));

        // Mixed list: safe mount + critical mount -> must refuse BEFORE executing any umount
        let mixed = vec![
            "/mnt/usb_safe".to_string(),
            crit.to_string(),
            "/media/external".to_string(),
        ];
        let res_mixed = SafetyChecker::unmount_all(&mixed);
        assert!(
            res_mixed.is_err(),
            "Must refuse mixed list containing '{}'",
            crit
        );
        let err_mixed = res_mixed.unwrap_err();
        assert!(err_mixed.contains("REFUSING to unmount critical OS mountpoint"));
        assert!(err_mixed.contains(crit));
    }
}

#[test]
fn test_descending_path_length_sorting_logic() {
    // In Linux filesystem semantics, child/leaf mountpoints must be unmounted
    // before parent mountpoints to prevent "target is busy" errors.
    let mut mounts = vec![
        "/media/target".to_string(),
        "/media/target/nested/deep/leaf".to_string(),
        "/media/target/nested".to_string(),
        "/media/target/nested/deep".to_string(),
    ];

    // Reproduce the exact sorting algorithm applied in unmount_all
    mounts.sort_by_key(|b| std::cmp::Reverse(b.len()));

    assert_eq!(
        mounts,
        vec![
            "/media/target/nested/deep/leaf".to_string(),
            "/media/target/nested/deep".to_string(),
            "/media/target/nested".to_string(),
            "/media/target".to_string(),
        ],
        "Mountpoints must be strictly sorted by descending path length"
    );

    // Verify lengths are strictly non-increasing
    for i in 0..mounts.len() - 1 {
        assert!(
            mounts[i].len() >= mounts[i + 1].len(),
            "Mount length at {} ({}) must be >= {} ({})",
            i,
            mounts[i].len(),
            i + 1,
            mounts[i + 1].len()
        );
    }
}
