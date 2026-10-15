//! Everything the TUI asks of the host, as one trait ([`TuiBackend`]) so the
//! App state machine is driven in tests with scripted results and never
//! touches a host disk. [`HostBackend`] is the real host: the discovery scan,
//! `session::check_with` / `session::run_with`, the audited unmount, the
//! converter and the image verification.
//!
//! Every method is either blocking (the App calls it on a blocking thread) or
//! returns a `'static` future (the App spawns it); none runs on the UI thread.

use crate::discovery::safety::{self, UnmountResult};
use crate::discovery::{capacity, identity, DeviceScanner};
use crate::engines::converter;
use crate::engines::preflight::{self, DestinationFacts};
use crate::engines::process::StopControl;
use crate::engines::session::{self, AcquisitionRequest, CheckReport, HostSystem};
use crate::engines::verify::{self, ExpectedHashes, ImageVerification, VerifyEvent, VerifyOptions};
use crate::engines::AcquisitionError;
use crate::models::capacity::CapacityInfo;
use crate::models::conversion::{ConversionReport, ConversionRequest};
use crate::models::device::BlockDevice;
use crate::models::info_report::ForensicInfoReport;
use crate::models::telemetry::ProgressTelemetry;
use crate::signals::StopFlags;
use futures::future::BoxFuture;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// Progress channel of an acquisition or conversion.
pub type ProgressTx = mpsc::Sender<ProgressTelemetry>;

/// The host as the TUI sees it.
pub trait TuiBackend: Send + Sync {
    /// Discovery scan (lsblk + sysfs, no SMART). Blocking.
    fn scan(&self) -> Result<Vec<BlockDevice>, String>;

    /// Facts about a destination directory: filesystem, free space (writes
    /// nothing). Blocking.
    fn destination(&self, dir: &Path) -> Result<DestinationFacts, String>;

    /// The explicit, audited unmount of the source tree of `device` (§10).
    /// Blocking.
    fn unmount(&self, device: &BlockDevice) -> Result<UnmountResult, AcquisitionError>;

    /// Capacity / hidden-area probe of the disk of `device`, on the
    /// examiner's explicit request only (§7).
    fn capacity(&self, device: BlockDevice) -> BoxFuture<'static, Result<CapacityInfo, String>>;

    /// Dry run of the acquisition (`session::check_with`): writes nothing.
    fn check(&self, request: AcquisitionRequest) -> BoxFuture<'static, CheckReport>;

    /// The acquisition (`session::run_with`).
    fn acquire(
        &self,
        request: AcquisitionRequest,
        progress: ProgressTx,
        stop: StopFlags,
    ) -> BoxFuture<'static, Result<ForensicInfoReport, AcquisitionError>>;

    /// An image conversion (`engines::converter::convert`).
    fn convert(
        &self,
        request: ConversionRequest,
        progress: ProgressTx,
        stop: StopFlags,
    ) -> BoxFuture<'static, Result<ConversionReport, AcquisitionError>>;

    /// Re-verification of an image (`engines::verify::verify_image`, with
    /// addendum and audit record).
    fn verify(
        &self,
        image: PathBuf,
        expected: ExpectedHashes,
        stop: StopFlags,
        events: mpsc::UnboundedSender<VerifyEvent>,
    ) -> BoxFuture<'static, Result<ImageVerification, AcquisitionError>>;
}

/// This host.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostBackend;

impl TuiBackend for HostBackend {
    fn scan(&self) -> Result<Vec<BlockDevice>, String> {
        DeviceScanner::scan_devices()
    }

    fn destination(&self, dir: &Path) -> Result<DestinationFacts, String> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| format!("cannot read /proc/self/mountinfo: {e}"))?;
        preflight::probe_destination(dir, &mountinfo).map_err(|e| e.to_string())
    }

    fn unmount(&self, device: &BlockDevice) -> Result<UnmountResult, AcquisitionError> {
        // Unmount only the device the examiner selected: probe it and compare
        // with the scan entry first
        let id = identity::probe(&device.path).map_err(AcquisitionError::refused)?;
        id.same_attachment(&device.device_identity())
            .map_err(AcquisitionError::refused)?;
        safety::unmount_source_tree(&id)
    }

    fn capacity(&self, device: BlockDevice) -> BoxFuture<'static, Result<CapacityInfo, String>> {
        Box::pin(async move {
            let path = device.path.clone();
            let id = tokio::task::spawn_blocking(move || identity::probe(&path))
                .await
                .map_err(|e| format!("identity probe stopped: {e}"))??;
            id.same_attachment(&device.device_identity())?;
            Ok(capacity::probe(&id, &StopControl::none(), None).await)
        })
    }

    fn check(&self, request: AcquisitionRequest) -> BoxFuture<'static, CheckReport> {
        Box::pin(async move { session::check_with(&HostSystem, request).await })
    }

    fn acquire(
        &self,
        request: AcquisitionRequest,
        progress: ProgressTx,
        stop: StopFlags,
    ) -> BoxFuture<'static, Result<ForensicInfoReport, AcquisitionError>> {
        Box::pin(async move { session::run_with(&HostSystem, request, progress, stop).await })
    }

    fn convert(
        &self,
        request: ConversionRequest,
        progress: ProgressTx,
        stop: StopFlags,
    ) -> BoxFuture<'static, Result<ConversionReport, AcquisitionError>> {
        Box::pin(converter::convert(request, progress, stop))
    }

    fn verify(
        &self,
        image: PathBuf,
        expected: ExpectedHashes,
        stop: StopFlags,
        events: mpsc::UnboundedSender<VerifyEvent>,
    ) -> BoxFuture<'static, Result<ImageVerification, AcquisitionError>> {
        Box::pin(async move {
            verify::verify_image(
                &image,
                &expected,
                &VerifyOptions::recorded(),
                &stop,
                |event| {
                    let _ = events.send(event);
                },
            )
            .await
        })
    }
}

/// A backend over a fixed device list that runs nothing: scans return the
/// list, every other request fails. `App::with_devices` uses it (tests,
/// screenshots), so such an App never touches the host.
#[derive(Debug, Clone, Default)]
pub struct OfflineBackend {
    pub devices: Vec<BlockDevice>,
}

fn offline() -> AcquisitionError {
    AcquisitionError::failed("this TUI instance has no host backend (offline)")
}

impl TuiBackend for OfflineBackend {
    fn scan(&self) -> Result<Vec<BlockDevice>, String> {
        Ok(self.devices.clone())
    }

    fn destination(&self, _dir: &Path) -> Result<DestinationFacts, String> {
        Err(offline().message)
    }

    fn unmount(&self, _device: &BlockDevice) -> Result<UnmountResult, AcquisitionError> {
        Err(offline())
    }

    fn capacity(&self, _device: BlockDevice) -> BoxFuture<'static, Result<CapacityInfo, String>> {
        Box::pin(async { Err(offline().message) })
    }

    fn check(&self, request: AcquisitionRequest) -> BoxFuture<'static, CheckReport> {
        Box::pin(async move {
            let engine = request.engine();
            CheckReport {
                ready: false,
                device: request.device.path.clone(),
                engine,
                output_dir: request.config.output_dir.clone(),
                base_name: None,
                identity: None,
                tool_source_path: None,
                effective_config: None,
                write_protection: None,
                write_protection_plan: None,
                destination: None,
                capacity: None,
                smart: None,
                problems: vec![crate::engines::session::CheckProblem {
                    step: "request".into(),
                    kind: crate::engines::ErrorKind::Failed,
                    message: offline().message,
                }],
                notes: Vec::new(),
            }
        })
    }

    fn acquire(
        &self,
        _request: AcquisitionRequest,
        _progress: ProgressTx,
        _stop: StopFlags,
    ) -> BoxFuture<'static, Result<ForensicInfoReport, AcquisitionError>> {
        Box::pin(async { Err(offline()) })
    }

    fn convert(
        &self,
        _request: ConversionRequest,
        _progress: ProgressTx,
        _stop: StopFlags,
    ) -> BoxFuture<'static, Result<ConversionReport, AcquisitionError>> {
        Box::pin(async { Err(offline()) })
    }

    fn verify(
        &self,
        _image: PathBuf,
        _expected: ExpectedHashes,
        _stop: StopFlags,
        _events: mpsc::UnboundedSender<VerifyEvent>,
    ) -> BoxFuture<'static, Result<ImageVerification, AcquisitionError>> {
        Box::pin(async { Err(offline()) })
    }
}
