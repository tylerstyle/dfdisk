use crate::models::device::DeviceSafety;
use std::process::Command;

pub struct SafetyChecker;

impl SafetyChecker {
    /// Checks whether a mountpoint belongs to critical OS infrastructure
    pub fn is_critical_mount(mountpoint: &str) -> bool {
        let m = mountpoint.trim();
        if m.is_empty() {
            return false;
        }

        m == "/"
            || m == "/boot"
            || m.starts_with("/boot/")
            || m == "/nix"
            || m.starts_with("/nix/")
            || m == "/home"
            || m.starts_with("/home/")
            || m == "/etc"
            || m.starts_with("/etc/")
            || m == "/var"
            || m.starts_with("/var/")
            || m == "/usr"
            || m.starts_with("/usr/")
    }

    /// Evaluates whether a list of mountpoints or device attributes constitutes a system disk
    pub fn evaluate_safety(mountpoints: &[String], swap_active: bool) -> DeviceSafety {
        let mut critical_mounts = Vec::new();
        let mut normal_mounts = Vec::new();

        for mp in mountpoints {
            let m = mp.trim();
            if m.is_empty() {
                continue;
            }

            if Self::is_critical_mount(m) {
                critical_mounts.push(m.to_string());
            } else {
                normal_mounts.push(m.to_string());
            }
        }

        if swap_active {
            critical_mounts.push("[SWAP ACTIVE]".to_string());
        }

        if !critical_mounts.is_empty() {
            DeviceSafety::SystemDisk(critical_mounts)
        } else if !normal_mounts.is_empty() {
            DeviceSafety::Mounted(normal_mounts)
        } else {
            DeviceSafety::Safe
        }
    }

    /// Unmounts all mounted partitions on a target device in descending path length order
    pub fn unmount_all(mountpoints: &[String]) -> Result<(), String> {
        // Refuse to unmount any critical OS mountpoints
        for mp in mountpoints {
            if Self::is_critical_mount(mp) {
                return Err(format!(
                    "REFUSING to unmount critical OS mountpoint: {}",
                    mp
                ));
            }
        }

        // Sort mountpoints in descending length order so nested child mounts are unmounted before parent mounts
        let mut sorted_mounts = mountpoints.to_vec();
        sorted_mounts.sort_by_key(|b| std::cmp::Reverse(b.len()));

        let mut errors = Vec::new();

        for mp in &sorted_mounts {
            let output = Command::new("umount")
                .arg(mp)
                .output()
                .map_err(|e| format!("Failed to execute umount: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                errors.push(format!("Failed to unmount {}: {}", mp, stderr.trim()));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Enables software write-protection on block device
    #[allow(dead_code)]
    pub fn set_read_only(device_path: &str) -> Result<(), String> {
        let output = Command::new("blockdev")
            .arg("--setro")
            .arg(device_path)
            .output()
            .map_err(|e| format!("Failed to execute blockdev: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_critical_mount() {
        assert!(SafetyChecker::is_critical_mount("/"));
        assert!(SafetyChecker::is_critical_mount("/boot"));
        assert!(SafetyChecker::is_critical_mount("/boot/efi"));
        assert!(SafetyChecker::is_critical_mount("/nix"));
        assert!(SafetyChecker::is_critical_mount("/nix/store"));
        assert!(SafetyChecker::is_critical_mount("/home"));
        assert!(SafetyChecker::is_critical_mount("/home/user"));
        assert!(SafetyChecker::is_critical_mount("/var"));
        assert!(SafetyChecker::is_critical_mount("/var/log"));
        assert!(SafetyChecker::is_critical_mount("/usr"));
        assert!(SafetyChecker::is_critical_mount("/usr/local"));
        assert!(SafetyChecker::is_critical_mount("/etc"));

        // Non-critical mounts
        assert!(!SafetyChecker::is_critical_mount("/mnt/usb"));
        assert!(!SafetyChecker::is_critical_mount("/media/data"));
        assert!(!SafetyChecker::is_critical_mount("/run/media/external"));
    }

    #[test]
    fn test_evaluate_safety() {
        let sys_mounts = vec!["/home".to_string(), "/mnt/data".to_string()];
        match SafetyChecker::evaluate_safety(&sys_mounts, false) {
            DeviceSafety::SystemDisk(critical) => {
                assert_eq!(critical, vec!["/home".to_string()]);
            }
            _ => panic!("Expected SystemDisk"),
        }

        let swap_mounts = vec!["/mnt/data".to_string()];
        match SafetyChecker::evaluate_safety(&swap_mounts, true) {
            DeviceSafety::SystemDisk(critical) => {
                assert!(critical.contains(&"[SWAP ACTIVE]".to_string()));
            }
            _ => panic!("Expected SystemDisk on swap"),
        }

        let normal_mounts = vec!["/mnt/usb1".to_string()];
        match SafetyChecker::evaluate_safety(&normal_mounts, false) {
            DeviceSafety::Mounted(mounts) => {
                assert_eq!(mounts, vec!["/mnt/usb1".to_string()]);
            }
            _ => panic!("Expected Mounted"),
        }

        let empty_mounts: Vec<String> = Vec::new();
        assert_eq!(
            SafetyChecker::evaluate_safety(&empty_mounts, false),
            DeviceSafety::Safe
        );
    }

    #[test]
    fn test_unmount_all_critical_refusal() {
        for critical in [
            "/",
            "/boot",
            "/boot/efi",
            "/nix",
            "/home",
            "/var",
            "/usr",
            "/etc",
        ] {
            let res = SafetyChecker::unmount_all(&[critical.to_string()]);
            assert!(res.is_err());
            assert!(
                res.unwrap_err()
                    .contains("REFUSING to unmount critical OS mountpoint"),
                "Should refuse {}",
                critical
            );
        }
    }

    #[test]
    fn test_is_critical_mount_stress() {
        let critical_cases = [
            "/",
            "/boot",
            "/boot/",
            "/boot/efi",
            "/boot/loader/entries",
            "/nix",
            "/nix/",
            "/nix/store",
            "/nix/var/nix/profiles/system",
            "/home",
            "/home/",
            "/home/alice",
            "/home/alice/.ssh",
            "/var",
            "/var/",
            "/var/log",
            "/var/lib/docker",
            "/usr",
            "/usr/",
            "/usr/bin",
            "/usr/local/bin",
            "/usr/lib/systemd",
            "/etc",
            "/etc/",
            "/etc/fstab",
            "/etc/systemd/system",
            " /home/user ",
            " /nix/store\t",
        ];

        for c in &critical_cases {
            assert!(
                SafetyChecker::is_critical_mount(c),
                "Should be critical: {}",
                c
            );
        }

        let safe_cases = [
            "",
            " ",
            "/mnt",
            "/mnt/usb",
            "/mnt/data",
            "/media",
            "/media/user/DRIVE",
            "/run/media/user/USB_STICK",
            "/tmp",
            "/tmp/mount",
            "/homebrew",     // must not prefix-match /home
            "/variable",     // must not prefix-match /var
            "/usrobotics",   // must not prefix-match /usr
            "/bootloader",   // must not prefix-match /boot
            "/nixos-config", // must not prefix-match /nix
            "/etc-backup",   // must not prefix-match /etc
        ];

        for s in &safe_cases {
            assert!(
                !SafetyChecker::is_critical_mount(s),
                "Should NOT be critical: {}",
                s
            );
        }
    }

    #[test]
    fn test_unmount_all_critical_refusal_exhaustive() {
        let critical_mounts = [
            "/",
            "/boot/efi",
            "/nix/store",
            "/home/user",
            "/var/log",
            "/usr/local",
            "/etc",
        ];

        for crit in &critical_mounts {
            // Mixed list with safe mounts and one critical mount
            let mixed = vec![
                "/mnt/external".to_string(),
                crit.to_string(),
                "/media/usb".to_string(),
            ];

            let res = SafetyChecker::unmount_all(&mixed);
            assert!(
                res.is_err(),
                "Must refuse unmount when {} is in mount list",
                crit
            );
            let err = res.unwrap_err();
            assert!(
                err.contains("REFUSING to unmount critical OS mountpoint"),
                "Error message should clearly state refusal: {}",
                err
            );
            assert!(err.contains(crit));
        }
    }
}
