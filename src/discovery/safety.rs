use crate::models::device::DeviceSafety;
use std::process::Command;

pub struct SafetyChecker;

impl SafetyChecker {
    /// Evaluates whether a list of mountpoints or device attributes constitutes a system disk
    pub fn evaluate_safety(mountpoints: &[String], swap_active: bool) -> DeviceSafety {
        let mut critical_mounts = Vec::new();
        let mut normal_mounts = Vec::new();

        for mp in mountpoints {
            let m = mp.trim();
            if m.is_empty() {
                continue;
            }

            if m == "/"
                || m == "/boot"
                || m.starts_with("/boot/")
                || m == "/nix"
                || m == "/nix/store"
                || m == "/home"
                || m.starts_with("/home/")
                || m == "/etc"
                || m == "/var"
                || m == "/usr"
            {
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

    /// Unmounts all mounted partitions on a target device
    pub fn unmount_all(mountpoints: &[String]) -> Result<(), String> {
        let mut errors = Vec::new();

        for mp in mountpoints {
            if mp == "/" || mp.starts_with("/boot") || mp == "/nix" {
                return Err(format!("REFUSING to unmount critical OS mountpoint: {}", mp));
            }

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
