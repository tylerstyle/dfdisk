//! Acquisition records in the dfnix audit log (dfcore). A "started" record is
//! written before the source is read; its hash is the report's audit anchor. The
//! "finished" record carries the outcome, the hashes and the SHA-256 of the report.

use crate::models::{
    config::AcquisitionConfig, device::BlockDevice, info_report::ForensicInfoReport,
};
use dfcore::audit::{self, Event, Outcome};
use dfcore::lsblk::DeviceIdentity;
use sha2::{Digest, Sha256};

const TOOL: &str = "dfdisk";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn identity(device: &BlockDevice) -> DeviceIdentity {
    DeviceIdentity {
        path: device.path.clone(),
        kernel_name: device.name.clone(),
        maj_min: None,
        serial: device.serial.clone().filter(|s| !s.trim().is_empty()),
        wwn: device.wwn.clone().filter(|s| !s.trim().is_empty()),
        model: Some(device.display_name()),
        size: Some(device.size_bytes.to_string()),
    }
}

fn record(event: Event) -> Option<String> {
    match audit::append(event) {
        Ok(rec) => rec.hash,
        Err(e) => {
            eprintln!("[!] WARNING: audit log not written: {e:#}");
            None
        }
    }
}

/// Record the start of an acquisition; returns the anchor for the report.
pub fn started(engine: &str, device: &BlockDevice, config: &AcquisitionConfig) -> Option<String> {
    record(
        Event::new(TOOL, VERSION, "acquisition_started")
            .device(identity(device))
            .detail("engine", engine)
            .detail("format", format!("{:?}", config.format))
            .detail(
                "output_dir",
                config.output_dir.to_string_lossy().to_string(),
            )
            .detail(
                "hashes",
                serde_json::json!({
                    "md5": config.calc_md5, "sha1": config.calc_sha1, "sha256": config.calc_sha256
                }),
            ),
    )
}

/// Record how the acquisition ended, then copy the verified log and its head into
/// the case directory: /run is lost at power-off, the case drive is not.
pub fn finished(
    engine: &str,
    device: &BlockDevice,
    output_dir: &std::path::Path,
    result: &Result<ForensicInfoReport, String>,
) {
    let mut event = Event::new(TOOL, VERSION, "acquisition_finished")
        .device(identity(device))
        .detail("engine", engine);
    match result {
        Ok(report) => {
            event = event
                .detail("verification", format!("{:?}", report.verification_status))
                .detail("bad_sectors", report.bad_sectors_count)
                .detail(
                    "source_hashes",
                    serde_json::to_value(&report.source_hashes).unwrap_or_default(),
                )
                .detail(
                    "image_hashes",
                    serde_json::to_value(&report.destination_hashes).unwrap_or_default(),
                )
                .detail("files", report.generated_files.clone())
                .detail(
                    "report_sha256",
                    hex::encode(Sha256::digest(report.render_text().as_bytes())),
                );
        }
        Err(e) => {
            let refused = e.contains("Refusing")
                || e.contains("Critical Safety Error")
                || e.contains("ABORT");
            event = event.outcome(
                if refused {
                    Outcome::Refused
                } else {
                    Outcome::Error
                },
                Some(e.clone()),
            );
        }
    }
    record(event);
    if output_dir.is_dir() {
        if let Err(e) = audit::export(&audit::path(), output_dir) {
            eprintln!(
                "[!] WARNING: audit log not copied to {}: {e:#}",
                output_dir.display()
            );
        }
    }
}
