//! The pipeline end to end against a fake host: every refusal, every outcome,
//! the written reports, the reservation, the audit trail and its export. No
//! host disk is touched: the "device" is a regular file held as the source
//! descriptor, sysfs is a fake tree, lsblk/mountinfo/swaps are fixtures.

use super::*;
use crate::discovery::sysfs::fake::FakeSysfs;
use crate::models::capacity::AtaCapacity;
use crate::models::config::OnReadError;
use crate::models::device::{SmartHealth, SmartInfo};
use crate::models::identity::SourceKind;
use crate::models::info_report::{sha256_file, sha256_hex};
use crate::models::outcome::{Outcome, RangeKind};
use crate::models::provenance::{TimedatectlInfo, ToolProvenance};
use dfcore::protected::{ProtectedDevice, Registry, Role};
use digest::Digest;
use futures::future::BoxFuture;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

const SATA: &str = "pci0000:00/0000:00:17.0/ata3/host2/target2:0:0/2:0:0:0";
const CASE_SATA: &str = "pci0000:00/0000:00:17.0/ata4/host3/target3:0:0/3:0:0:0";
const SIZE: u64 = 64 * 1024;
const BASE: &str = "c_1_ea01_e1_SER1";

type EngineFn = Box<dyn Fn(&EngineContext) -> Result<EngineOutput, AcquisitionError> + Send + Sync>;
type VerifyFn =
    Box<dyn Fn(&EngineContext, &EngineOutput) -> (VerificationResult, HashResults) + Send + Sync>;

fn sample(len: u64) -> Vec<u8> {
    (0..len).map(|i| (i * 13 % 251) as u8).collect()
}

fn hashes(data: &[u8]) -> HashResults {
    HashResults {
        md5: Some(hex::encode(md5::Md5::digest(data))),
        sha1: Some(hex::encode(sha1::Sha1::digest(data))),
        sha256: Some(hex::encode(sha2::Sha256::digest(data))),
    }
}

fn disk_identity(size: u64) -> SourceIdentity {
    let mut id = SourceIdentity {
        path: "/dev/sdx".into(),
        canonical_path: "/dev/sdx".into(),
        kernel_name: "sdx".into(),
        maj_min: Some("8:16".into()),
        diskseq: Some(7),
        kind: SourceKind::Disk,
        size_bytes: size,
        logical_sector_size: 512,
        physical_sector_size: 512,
        model: Some("Fake Disk".into()),
        transport: Some("sata".into()),
        read_only: Some(false),
        ..Default::default()
    };
    id.add_serial_candidate("SER1", SerialSource::VpdPage80);
    id
}

fn device(size: u64) -> BlockDevice {
    BlockDevice {
        name: "sdx".into(),
        path: "/dev/sdx".into(),
        size_bytes: size,
        serial: Some("SER1".into()),
        maj_min: Some("8:16".into()),
        diskseq: Some(7),
        logical_sector_size: 512,
        physical_sector_size: 512,
        ..Default::default()
    }
}

fn case() -> CaseMetadata {
    CaseMetadata {
        case_number: "C-1".into(),
        evidence_number: "E1".into(),
        examiner: "Examiner".into(),
        ..Default::default()
    }
}

const LSBLK: &str = r#"{"blockdevices":[
  {"name":"sda","path":"/dev/sda","maj:min":"8:0","type":"disk","serial":"SYS","mountpoints":[null],"children":[
    {"name":"sda1","path":"/dev/sda1","maj:min":"8:1","type":"part","mountpoints":["/"]}]},
  {"name":"sdx","path":"/dev/sdx","maj:min":"8:16","type":"disk","serial":"SER1","mountpoints":[null],"children":[
    {"name":"sdx1","path":"/dev/sdx1","maj:min":"8:17","type":"part","mountpoints":[null]}]},
  {"name":"sdy","path":"/dev/sdy","maj:min":"8:32","type":"disk","serial":"CASE","mountpoints":[null],"children":[
    {"name":"sdy1","path":"/dev/sdy1","maj:min":"8:33","type":"part","mountpoints":["/media/case"]}]}
]}"#;

/// A host with a 64 KiB "disk" sdx (8:16) holding one partition, and a case
/// drive sdy1 (8:33) at /media/case.
struct Fake {
    tmp: tempfile::TempDir,
    sys: FakeSysfs,
    data: Vec<u8>,
    identity: SourceIdentity,
    /// Identity probed at the end; `None`: the start identity
    end_identity: Mutex<Option<Result<SourceIdentity, String>>>,
    probes: AtomicUsize,
    probe_error: Option<String>,
    registry: Result<Option<Registry>, String>,
    lsblk: String,
    swaps: Vec<SwapEntry>,
    mountinfo: String,
    open_error: Option<AcquisitionError>,
    fs_type: String,
    free: Option<u64>,
    backing: String,
    wp_error: Option<String>,
    capacity: CapacityInfo,
    log: PathBuf,
    engine: Option<EngineFn>,
    verify: Option<VerifyFn>,
    reread: Option<Result<HashResults, AcquisitionError>>,
    /// Step 10 fails to fsync (or to evict) files whose name ends with this
    fsync_fail: Option<&'static str>,
    evict_fail: Option<&'static str>,
    calls: Mutex<Vec<&'static str>>,
}

impl Fake {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let data = sample(SIZE);
        std::fs::write(tmp.path().join("sdx.img"), &data).unwrap();
        let sys = FakeSysfs::new();
        sys.add_disk(SATA, "sdx", (8, 16), SIZE / 512);
        sys.add_partition("sdx", "sdx1", (8, 17), 1, 2048, 64);
        sys.add_disk(CASE_SATA, "sdy", (8, 32), 1 << 30);
        sys.add_partition("sdy", "sdy1", (8, 33), 1, 2048, 1 << 29);
        let log = tmp.path().join("audit/audit.jsonl");
        Self {
            sys,
            identity: disk_identity(SIZE),
            end_identity: Mutex::new(None),
            probes: AtomicUsize::new(0),
            probe_error: None,
            registry: Ok(None),
            lsblk: LSBLK.into(),
            swaps: Vec::new(),
            mountinfo: "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n40 22 8:33 / /media/case rw - ext4 /dev/sdy1 rw\n".into(),
            open_error: None,
            fs_type: "ext4".into(),
            free: Some(10 << 30),
            backing: "8:33".into(),
            wp_error: None,
            capacity: CapacityInfo {
                reported_bytes: SIZE,
                probed_device: Some("/dev/sdx".into()),
                method: "fake".into(),
                ..Default::default()
            },
            log,
            engine: None,
            verify: None,
            reread: None,
            fsync_fail: None,
            evict_fail: None,
            calls: Mutex::new(Vec::new()),
            data,
            tmp,
        }
    }

    fn out(&self) -> PathBuf {
        self.tmp.path().join("case/out")
    }

    fn source_file(&self) -> PathBuf {
        self.tmp.path().join("sdx.img")
    }

    fn request(&self, config: AcquisitionConfig) -> AcquisitionRequest {
        AcquisitionRequest::new(device(self.identity.size_bytes), case(), config)
    }

    fn raw(&self) -> AcquisitionConfig {
        AcquisitionConfig::raw(self.out())
    }

    fn call(&self, what: &'static str) {
        self.calls.lock().unwrap().push(what);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn records(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn actions(&self) -> Vec<(String, String)> {
        self.records()
            .iter()
            .map(|r| {
                (
                    r["action"].as_str().unwrap().to_string(),
                    r["outcome"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }
}

impl SessionHost for Fake {
    fn probe_identity(&self, _path: &str) -> Result<SourceIdentity, String> {
        let n = self.probes.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = &self.probe_error {
            return Err(e.clone());
        }
        if n > 0 {
            if let Some(end) = self.end_identity.lock().unwrap().clone() {
                return end;
            }
        }
        Ok(self.identity.clone())
    }

    fn sysfs(&self) -> crate::discovery::sysfs::SysRoot {
        self.sys.root()
    }

    fn mountinfo(&self) -> Result<String, String> {
        Ok(self.mountinfo.clone())
    }

    fn swaps(&self) -> Result<Vec<SwapEntry>, String> {
        Ok(self.swaps.clone())
    }

    fn registry(&self) -> Result<Option<Registry>, String> {
        self.registry.clone()
    }

    fn lsblk(&self) -> Result<Vec<dfcore::lsblk::FlatDevice>, String> {
        dfcore::lsblk::parse(self.lsblk.as_bytes()).map_err(|e| e.to_string())
    }

    fn open_source(&self, _identity: &SourceIdentity) -> Result<File, AcquisitionError> {
        if let Some(e) = &self.open_error {
            return Err(e.clone());
        }
        Ok(File::open(self.source_file()).unwrap())
    }

    fn destination(&self, output_dir: &Path) -> io::Result<DestinationFacts> {
        Ok(DestinationFacts {
            output_dir: output_dir.to_path_buf(),
            existing_ancestor: dfcore::sysfs::existing_ancestor(output_dir),
            ancestor_is_dir: true,
            mount_point: Some("/media/case".into()),
            fs_type: Some(self.fs_type.clone()),
            mount_source: Some("/dev/sdy1".into()),
            read_only_mount: false,
            free_bytes: self.free,
            backing_device: Some(self.backing.clone()),
        })
    }

    fn tool_source_path(&self, _identity: &SourceIdentity) -> String {
        "/dev/disk/by-diskseq/7".into()
    }

    fn enforce_write_protection(
        &self,
        _identity: &SourceIdentity,
        wp: &mut WriteProtection,
    ) -> Result<(), String> {
        self.call("write_protect");
        if let Some(e) = &self.wp_error {
            return Err(e.clone());
        }
        wp.set_by_dfdisk = true;
        wp.method = Some("BLKROSET ioctl".into());
        wp.nodes_set = vec!["/dev/sdx".into(), "/dev/sdx1".into()];
        Ok(())
    }

    fn capacity<'a>(
        &'a self,
        _identity: &'a SourceIdentity,
        _control: &'a StopControl,
        _recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, CapacityInfo> {
        self.call("capacity");
        Box::pin(async move { self.capacity.clone() })
    }

    fn smart<'a>(
        &'a self,
        _identity: &'a SourceIdentity,
        policy: SmartPolicy,
        json_file: Option<&'a Path>,
        _control: &'a StopControl,
        _recorder: &'a ProvenanceRecorder,
    ) -> BoxFuture<'a, Option<SmartSnapshot>> {
        self.call("smart");
        Box::pin(async move {
            if let Some(f) = json_file {
                std::fs::write(f, b"{\"smart_status\":{\"passed\":true}}").unwrap();
            }
            Some(SmartSnapshot {
                policy,
                command: vec!["smartctl".into(), "-j".into()],
                smartctl_version: Some("smartctl 7.4".into()),
                exit_status: Some(0),
                taken_at: chrono::Utc::now(),
                summary: SmartInfo::default(),
                json_file: json_file.map(|p| p.to_string_lossy().into_owned()),
                json_sha256: None,
                note: None,
                device_serial: Some("SER1".into()),
            })
        })
    }

    fn clock(&self) -> BoxFuture<'static, ClockInfo> {
        Box::pin(async {
            ClockInfo::from_parts(
                chrono::Utc::now(),
                &TimedatectlInfo {
                    ntp_synchronized: Some(false),
                    ..Default::default()
                },
                Some("UTC".into()),
                Some(2),
                Some("+00:00".into()),
            )
        })
    }

    fn provenance(&self) -> ToolProvenance {
        ToolProvenance::default()
    }

    fn tool_versions<'a>(&'a self, tools: Vec<String>) -> BoxFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            tools
                .into_iter()
                .map(|t| (t.clone(), format!("{t} 1.0")))
                .collect()
        })
    }

    fn audit_log(&self) -> PathBuf {
        self.log.clone()
    }

    fn export_audit(&self, log: &Path, dir: &Path) -> Result<PathBuf, String> {
        dfcore::audit::export_for_boot(log, dir, "testboot")
            .map(|i| i.jsonl)
            .map_err(|e| format!("{e:#}"))
    }

    fn acquire<'a>(
        &'a self,
        ctx: &'a EngineContext,
    ) -> BoxFuture<'a, Result<EngineOutput, AcquisitionError>> {
        self.call("acquire");
        match &self.engine {
            Some(f) => Box::pin(async move { f(ctx) }),
            None => Box::pin(super::acquire(ctx)),
        }
    }

    fn verify<'a>(
        &'a self,
        ctx: &'a EngineContext,
        out: &'a EngineOutput,
    ) -> BoxFuture<'a, (VerificationResult, HashResults)> {
        self.call("verify");
        match &self.verify {
            Some(f) => Box::pin(async move { f(ctx, out) }),
            None => Box::pin(super::verify(ctx, out)),
        }
    }

    fn flush(&self, files: &[PathBuf], dir: &Path) -> FlushReport {
        let mut report = flush_files(files, dir);
        let ends = |f: &FileFlush, suffix: Option<&str>| {
            suffix.is_some_and(|s| f.path.to_string_lossy().ends_with(s))
        };
        for f in &mut report.files {
            if ends(f, self.fsync_fail) {
                f.not_durable = Some(format!(
                    "fsync of {} failed: Input/output error (os error 5)",
                    f.path.display()
                ));
            }
            if ends(f, self.evict_fail) {
                f.not_evicted = Some(format!(
                    "{} could not be evicted from the page cache: Invalid argument (os error 22)",
                    f.path.display()
                ));
            }
        }
        report
    }

    fn reread_source<'a>(
        &'a self,
        ctx: &'a EngineContext,
        bytes: u64,
    ) -> BoxFuture<'a, Result<HashResults, AcquisitionError>> {
        self.call("reread");
        match &self.reread {
            Some(r) => {
                let r = r.clone();
                Box::pin(async move { r })
            }
            None => Box::pin(super::reread_source(ctx, bytes)),
        }
    }
}

async fn run_on(
    fake: &Fake,
    config: AcquisitionConfig,
    stop: StopFlags,
) -> (
    Result<ForensicInfoReport, AcquisitionError>,
    ProgressTelemetry,
) {
    let (tx, mut rx) = mpsc::channel(4096);
    let consumer = tokio::spawn(async move {
        let mut t = ProgressTelemetry::default();
        while let Some(u) = rx.recv().await {
            t.apply_update(u);
        }
        t
    });
    let r = run_with(fake, fake.request(config), tx, stop).await;
    (r, consumer.await.unwrap())
}

async fn run_fake(
    fake: &Fake,
    config: AcquisitionConfig,
) -> (
    Result<ForensicInfoReport, AcquisitionError>,
    ProgressTelemetry,
) {
    run_on(fake, config, StopFlags::new()).await
}

/// A fake engine that writes `data` as `<base>.raw` and reports `out`.
fn writes_image(data: Vec<u8>, out: EngineOutput) -> EngineFn {
    Box::new(move |ctx| {
        let p = ctx.output_path(".raw");
        std::fs::write(&p, &data).unwrap();
        let mut o = out.clone();
        o.image_files = vec![p];
        Ok(o)
    })
}

fn complete(data: &[u8]) -> EngineOutput {
    EngineOutput {
        bytes_acquired: data.len() as u64,
        expected_bytes: data.len() as u64,
        acquisition_hashes: hashes(data),
        ..Default::default()
    }
}

fn read_report(fake: &Fake) -> (String, ForensicInfoReport) {
    let text = std::fs::read_to_string(fake.out().join(format!("{BASE}.info"))).unwrap();
    let json = std::fs::read_to_string(fake.out().join(format!("{BASE}.info.json"))).unwrap();
    (text, ForensicInfoReport::from_json(&json).unwrap())
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

// ---------------------------------------------------------------------------
// The whole pipeline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verified_raw_acquisition_end_to_end_with_the_real_engine() {
    let fake = Fake::new();
    let config = AcquisitionConfig {
        verify_source: true,
        ..fake.raw()
    };
    let (r, progress) = run_fake(&fake, config).await;
    let report = r.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    assert_eq!(report.exit_code, 0);

    // Order of R7: protection, capacity, SMART, engine, verification, re-read
    assert_eq!(
        fake.calls(),
        [
            "write_protect",
            "capacity",
            "smart",
            "acquire",
            "verify",
            "reread"
        ]
    );

    // The image is the source, and the reports say so
    let out = fake.out();
    assert_eq!(
        std::fs::read(out.join(format!("{BASE}.raw"))).unwrap(),
        fake.data
    );
    let (text, json) = read_report(&fake);
    assert_eq!(text, report.render_text());
    assert_eq!(json.outcome, Outcome::Verified);
    assert_eq!(json.acquisition_hashes, hashes(&fake.data));
    assert_eq!(json.image_hashes, hashes(&fake.data));
    assert!(text.contains("VERIFIED - ALL HASHES MATCH"), "{text}");
    assert!(matches!(
        report.verification.source_reread,
        Some(VerificationResult::Matched { .. })
    ));
    assert!(report.verification.method.contains("page-cache eviction"));
    assert_eq!(report.identity_check.end_ok, Some(true));
    assert!(report.identity_check.start_ok);
    let wp = report.write_protection.as_ref().unwrap();
    assert!(wp.set_by_dfdisk && wp.exclusive_open);
    assert_eq!(report.capacity.as_ref().unwrap().method, "fake");
    // The RAW engine states what it applied: a piece size only with pieces
    let EngineSettings::Raw(raw) = &report.effective_config.settings else {
        panic!()
    };
    assert_eq!(raw.piece_size.is_some(), report.piecewise.is_some());
    assert!(report
        .notes
        .iter()
        .any(|n| n.starts_with("destination: ext4")));
    // SMART snapshot saved and listed with its digest
    let smart = out.join(format!("{BASE}.smart-before.json"));
    assert!(report
        .auxiliary_files
        .iter()
        .any(|f| f.path == smart.to_string_lossy() && f.sha256 == sha256_file(&smart).unwrap()));
    assert!(report.smart_after.is_none());
    // Timestamps are labelled as unsynchronised host time (R9)
    assert!(
        text.contains("host system time, NOT synchronized"),
        "{text}"
    );

    // The reservation is gone, nothing temporary is left
    assert!(!out.join(format!("{BASE}{RESERVE_SUFFIX}")).exists());
    let mut names: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut expected = vec![
        "audit-testboot.head".to_string(),
        "audit-testboot.jsonl".to_string(),
        format!("{BASE}.info"),
        format!("{BASE}.info.json"),
        format!("{BASE}.raw"),
        format!("{BASE}.smart-before.json"),
    ];
    if report.piecewise.is_some() {
        expected.push(format!("{BASE}.pieces.tsv"));
        expected.sort();
    }
    assert_eq!(names, expected);

    // Audit trail: started (the report's anchor) and finished (the report's digests)
    let recs = fake.records();
    assert_eq!(
        fake.actions(),
        [
            pair("acquisition_started", "ok"),
            pair("acquisition_finished", "ok")
        ]
    );
    assert_eq!(recs[0]["hash"], serde_json::json!(report.audit.anchor));
    assert_eq!(recs[0]["device"]["maj_min"], "8:16");
    assert_eq!(
        recs[0]["details"]["tool_source_path"],
        "/dev/disk/by-diskseq/7"
    );
    let fin = &recs[1]["details"];
    assert_eq!(fin["report_sha256"], sha256_hex(text.as_bytes()));
    assert_eq!(
        fin["report_json_sha256"],
        sha256_file(&out.join(format!("{BASE}.info.json"))).unwrap()
    );
    assert_eq!(fin["outcome"], "verified");
    assert_eq!(fin["exit_code"], 0);
    assert_eq!(
        fin["acquisition_hashes"]["sha256"],
        serde_json::json!(hashes(&fake.data).sha256)
    );
    assert_eq!(fin["anchor"], serde_json::json!(report.audit.anchor));

    // The case directory's copy of the log, named in the report, holds both records
    let export = out.join("audit-testboot.jsonl");
    assert_eq!(
        report.audit.export_file.as_deref(),
        Some(export.to_string_lossy().as_ref())
    );
    let copied = dfcore::audit::verify(&export).unwrap();
    assert_eq!(copied.records, 2);
    assert_eq!(copied.head, recs[1]["hash"].as_str().unwrap());

    // The UI saw the phases, no warning, and the verdict
    assert_eq!(progress.status, AcquisitionStatus::Completed);
    assert_eq!(progress.outcome, Some(Outcome::Verified));
    assert!(
        !progress
            .log_messages
            .iter()
            .any(|l| l.starts_with("WARNING")),
        "{:?}",
        progress.log_messages
    );
    assert!(progress.log_messages.iter().any(|l| l.contains("Flushing")));
}

// ---------------------------------------------------------------------------
// Refusals: nothing written, exit codes, audit records
// ---------------------------------------------------------------------------

/// A refusal before the first write: the error, nothing in the destination,
/// and an "acquisition_refused" record (none for usage errors).
async fn assert_refused_before_writing(
    fake: &Fake,
    config: AcquisitionConfig,
    kind: ErrorKind,
    needle: &str,
) {
    let (r, progress) = run_fake(fake, config).await;
    let e = r.unwrap_err();
    assert_eq!(e.kind, kind, "{e}");
    assert!(e.message.contains(needle), "{needle}: {e}");
    assert!(!fake.out().exists(), "nothing may be written: {e}");
    assert!(!fake.calls().contains(&"acquire"));
    assert!(!fake.calls().contains(&"write_protect"));
    let expected: Vec<(String, String)> = if kind == ErrorKind::Refused {
        vec![pair("acquisition_refused", "refused")]
    } else {
        vec![]
    };
    assert_eq!(fake.actions(), expected, "{e}");
    if kind == ErrorKind::Refused {
        assert_eq!(fake.records()[0]["details"]["exit_code"], 3);
    }
    assert!(matches!(progress.status, AcquisitionStatus::Failed(_)));
    assert_eq!(e.exit_code(), kind.exit_code());
}

#[tokio::test]
async fn usage_errors_write_and_record_nothing() {
    let fake = Fake::new();
    let config = AcquisitionConfig {
        split_size: crate::models::config::SplitSize::TwoGb,
        ..fake.raw()
    };
    assert_refused_before_writing(&fake, config, ErrorKind::Usage, "cannot be split").await;
    let fake = Fake::new();
    let config = AcquisitionConfig {
        error_retries: 300,
        ..fake.raw()
    };
    assert_refused_before_writing(&fake, config, ErrorKind::Usage, "between 0 and 255").await;

    // Missing required case fields
    let fake = Fake::new();
    let (tx, _rx) = mpsc::channel(100);
    let mut request = fake.request(fake.raw());
    request.case.examiner = " ".into();
    let e = run_with(&fake, request, tx, StopFlags::new())
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
    assert!(e.message.contains("examiner (--examiner)"), "{e}");
    assert!(fake.records().is_empty());
    // No device selected
    let (tx, _rx) = mpsc::channel(100);
    let mut request = fake.request(fake.raw());
    request.device = BlockDevice::default();
    let e = run_with(&fake, request, tx, StopFlags::new())
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Usage);
}

#[tokio::test]
async fn identity_refusals() {
    let mut fake = Fake::new();
    fake.probe_error = Some("no sysfs entry".into());
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "cannot be identified").await;

    // Another disk on the node since it was selected
    let mut fake = Fake::new();
    fake.identity.serial_candidates.clear();
    fake.identity
        .add_serial_candidate("OTHER", SerialSource::VpdPage80);
    fake.identity.diskseq = Some(8);
    let config = fake.raw();
    assert_refused_before_writing(
        &fake,
        config,
        ErrorKind::Refused,
        "source changed since it was selected",
    )
    .await;

    // --expect-serial
    let fake = Fake::new();
    let mut config = fake.raw();
    config.expect.serial = Some("SOMETHING-ELSE".into());
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "not the expected device")
        .await;

    // An empty source (no medium, unknown size) is refused for every engine,
    // and the dry run says so too
    for config in [
        AcquisitionConfig::raw(Fake::new().out()),
        AcquisitionConfig::rescue(Fake::new().out()),
        AcquisitionConfig::for_engine(EngineKind::Ewf, Fake::new().out()),
    ] {
        let mut fake = Fake::new();
        fake.identity = disk_identity(0);
        let config = AcquisitionConfig {
            output_dir: fake.out(),
            ..config
        };
        assert_refused_before_writing(&fake, config.clone(), ErrorKind::Refused, "size of 0 bytes")
            .await;
        let check = check_with(&fake, fake.request(config)).await;
        assert_eq!(check.exit_code(), 3);
        assert!(check.problems[0].message.contains("size of 0 bytes"));
    }
}

fn protecting_registry() -> Registry {
    Registry {
        schema: 1,
        generated_at: "2026-10-14T00:00:00Z".into(),
        boot_id: None,
        devices: vec![ProtectedDevice {
            role: Role::SystemDisk,
            identity: dfcore::lsblk::DeviceIdentity {
                path: "/dev/sdx".into(),
                kernel_name: "sdx".into(),
                maj_min: Some("8:16".into()),
                serial: Some("SER1".into()),
                ..Default::default()
            },
            reasons: vec!["/dev/sdx1 mounted at /nix".into()],
        }],
    }
}

#[tokio::test]
async fn registry_and_system_disk_refusals() {
    // Registry present but unreadable: fail closed
    let mut fake = Fake::new();
    fake.registry = Err("Corrupt protected-device registry".into());
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "fail closed").await;

    // The registry protects the source (matched by device number and serial)
    let mut fake = Fake::new();
    fake.registry = Ok(Some(protecting_registry()));
    let config = fake.raw();
    assert_refused_before_writing(
        &fake,
        config,
        ErrorKind::Refused,
        "protected by the dfnix registry",
    )
    .await;

    // A block device lsblk does not list cannot be checked: refused
    let mut fake = Fake::new();
    fake.lsblk = r#"{"blockdevices":[]}"#.into();
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "not listed by lsblk").await;

    // A disk of the running system (dfcore rule and dfdisk's critical mounts)
    for mount in ["/", "/home"] {
        let mut fake = Fake::new();
        fake.lsblk = LSBLK.replace(
            r#""maj:min":"8:17","type":"part","mountpoints":[null]"#,
            &format!(r#""maj:min":"8:17","type":"part","mountpoints":["{mount}"]"#),
        );
        let config = fake.raw();
        assert_refused_before_writing(&fake, config, ErrorKind::Refused, "running system").await;
    }
}

#[tokio::test]
async fn swap_mount_holder_and_busy_refusals() {
    // Active swap on a partition of the source (R8): named, never swapped off
    let mut fake = Fake::new();
    fake.swaps = vec![SwapEntry {
        path: "/dev/sdx1".into(),
        kind: "partition".into(),
        dev: Some((8, 17)),
    }];
    let config = fake.raw();
    assert_refused_before_writing(
        &fake,
        config,
        ErrorKind::Refused,
        "active swap on the source: /dev/sdx1 (partition)",
    )
    .await;
    // Swap elsewhere does not matter
    let mut fake = Fake::new();
    fake.swaps = vec![SwapEntry {
        path: "/swapfile".into(),
        kind: "file".into(),
        dev: Some((8, 1)),
    }];
    let config = fake.raw();
    assert!(run_fake(&fake, config).await.0.is_ok());

    // A mounted partition, found by device number in mountinfo
    let mut fake = Fake::new();
    fake.mountinfo
        .push_str("50 22 8:17 / /mnt/evidence rw - ntfs3 /dev/sdx1 rw\n");
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "/mnt/evidence").await;

    // Holders (dm on the source) refuse; there is no override (a holder
    // claims the source exclusively): they have to be closed first
    let fake = Fake::new();
    fake.sys.add_virtual("dm-0", (254, 0), SIZE / 512);
    fake.sys.stack("dm-0", "sdx1");
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "Close them first").await;
    let e = run_fake(&fake, fake.raw()).await.0.unwrap_err();
    assert!(!e.message.contains("--allow-holders"), "{e}");

    // In use (O_EXCL: EBUSY)
    let mut fake = Fake::new();
    fake.open_error = Some(AcquisitionError::refused(
        "cannot open the source /dev/sdx: /dev/sdx is in use: mounted or claimed",
    ));
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "in use").await;
}

#[tokio::test]
async fn destination_refusals() {
    let mut fake = Fake::new();
    fake.fs_type = "tmpfs".into();
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "--allow-tmpfs").await;
    let mut fake = Fake::new();
    fake.fs_type = "tmpfs".into();
    let config = AcquisitionConfig {
        allow_tmpfs: true,
        ..fake.raw()
    };
    let report = run_fake(&fake, config).await.0.unwrap();
    assert!(report
        .notes
        .iter()
        .any(|n| n.contains("allowed by --allow-tmpfs")));

    // On the disk being acquired (a partition of it)
    let mut fake = Fake::new();
    fake.backing = "8:17".into();
    let config = fake.raw();
    assert_refused_before_writing(
        &fake,
        config,
        ErrorKind::Refused,
        "shares physical disk sdx",
    )
    .await;

    // Not enough room for RAW, unknown free space
    let mut fake = Fake::new();
    fake.free = Some(SIZE);
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "margin").await;
    let mut fake = Fake::new();
    fake.free = None;
    let config = fake.raw();
    assert_refused_before_writing(&fake, config, ErrorKind::Refused, "cannot be determined").await;

    // An existing output, even spelled differently
    let fake = Fake::new();
    std::fs::create_dir_all(fake.out()).unwrap();
    let old = fake.out().join(format!("{}.RAW", BASE.to_uppercase()));
    std::fs::write(&old, b"old").unwrap();
    let (r, _) = run_fake(&fake, fake.raw()).await;
    let e = r.unwrap_err();
    assert!(e.is_refusal());
    assert!(e.message.contains("already exists"), "{e}");
    assert_eq!(std::fs::read(&old).unwrap(), b"old");
    assert!(!fake.out().join(format!("{BASE}{RESERVE_SUFFIX}")).exists());
    assert_eq!(fake.actions(), [pair("acquisition_refused", "refused")]);
}

#[tokio::test]
async fn refusals_after_started_are_finished_records_and_leave_nothing() {
    // Write protection cannot be set (§6): refused after "started"
    let mut fake = Fake::new();
    fake.wp_error = Some("cannot set /dev/sdx read-only (BLKROSET): permission denied".into());
    let (r, _) = run_fake(&fake, fake.raw()).await;
    let e = r.unwrap_err();
    assert!(e.is_refusal());
    assert!(e.message.contains("BLKROSET"), "{e}");
    assert_eq!(
        fake.actions(),
        [
            pair("acquisition_started", "ok"),
            pair("acquisition_finished", "refused")
        ]
    );
    assert_eq!(fake.records()[1]["details"]["error_kind"], "refused");
    assert!(
        !fake.out().exists(),
        "reservation and created directories are removed"
    );
    assert_eq!(fake.calls(), ["write_protect"]);

    // A hidden area with --refuse-hidden-areas
    let hpa = || {
        Some(AtaCapacity {
            native_max_sectors: Some(200),
            current_max_sectors: Some(128),
            hpa_present: Some(true),
            ..Default::default()
        })
    };
    let mut fake = Fake::new();
    fake.capacity.ata = hpa();
    let config = AcquisitionConfig {
        refuse_hidden_areas: true,
        ..fake.raw()
    };
    let (r, _) = run_fake(&fake, config).await;
    let e = r.unwrap_err();
    assert!(e.message.contains("--refuse-hidden-areas"), "{e}");
    assert_eq!(fake.actions()[1].1, "refused");
    assert!(!fake.out().exists());
    // ... and without it: a loud warning, and the report says it
    let mut fake = Fake::new();
    fake.capacity.ata = hpa();
    let (r, progress) = run_fake(&fake, fake.raw()).await;
    let report = r.unwrap();
    assert!(report.notes.iter().any(|n| n.contains("HIDDEN AREA")));
    assert!(progress
        .log_messages
        .iter()
        .any(|l| l.starts_with("WARNING: HIDDEN AREA")));
}

#[tokio::test]
async fn audit_log_failure_refuses_on_dfnix_and_warns_elsewhere() {
    // dfnix (registry present): no acquisition without its "started" record
    let mut fake = Fake::new();
    let blocker = fake.tmp.path().join("blocker");
    std::fs::write(&blocker, b"x").unwrap();
    fake.log = blocker.join("audit.jsonl");
    fake.registry = Ok(Some(Registry {
        schema: 1,
        generated_at: "2026-10-14T00:00:00Z".into(),
        boot_id: None,
        devices: vec![],
    }));
    let (r, _) = run_fake(&fake, fake.raw()).await;
    let e = r.unwrap_err();
    assert!(e.is_refusal());
    assert!(e.message.contains("on dfnix"), "{e}");
    assert!(!fake.out().exists());
    assert!(fake.calls().is_empty(), "nothing was sent to the source");

    // Elsewhere: the acquisition runs; report and UI say the log was not written
    let mut fake = Fake::new();
    fake.log = blocker.join("audit.jsonl");
    let (r, progress) = run_fake(&fake, fake.raw()).await;
    let report = r.unwrap();
    assert_eq!(report.outcome, Outcome::Verified);
    assert!(matches!(
        report.audit.status,
        AuditStatus::NotWritten { .. }
    ));
    assert!(report.audit.anchor.is_none());
    assert!(report.audit.export_file.is_none());
    assert!(report.render_text().contains("NOT WRITTEN"));
    let warnings: Vec<&String> = progress
        .log_messages
        .iter()
        .filter(|l| l.starts_with("WARNING"))
        .collect();
    assert!(
        warnings.iter().any(|w| w.contains("audit log not written")),
        "{warnings:?}"
    );
    assert!(
        warnings.iter().any(|w| w.contains("acquisition_finished")),
        "{warnings:?}"
    );
}

// ---------------------------------------------------------------------------
// Every outcome, from the facts the engine measured
// ---------------------------------------------------------------------------

#[tokio::test]
async fn short_source_is_incomplete_with_the_real_engine() {
    // The probe says twice the size the source delivers
    let mut fake = Fake::new();
    fake.identity = disk_identity(2 * SIZE);
    let (r, _) = run_fake(&fake, fake.raw()).await;
    let report = r.unwrap();
    assert_eq!(report.outcome, Outcome::Incomplete);
    assert_eq!(report.exit_code, 6);
    assert_eq!(report.bytes_acquired, SIZE);
    assert!(report
        .stop_reason
        .as_deref()
        .unwrap()
        .contains("end of data"));
    // The partial image is kept and verified for what it holds
    assert_eq!(
        std::fs::read(fake.out().join(format!("{BASE}.raw"))).unwrap(),
        fake.data
    );
    assert!(report.verification.result.is_matched());
    let (_, json) = read_report(&fake);
    assert_eq!(json.outcome, Outcome::Incomplete);
    assert_eq!(fake.records()[1]["details"]["exit_code"], 6);
}

#[tokio::test]
async fn an_image_that_cannot_be_flushed_is_never_verified() {
    // fsync of the image fails: VERIFICATION FAILED (exit 4), and the method
    // does not claim an fsync or eviction that did not happen
    let mut fake = Fake::new();
    fake.fsync_fail = Some(".raw");
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::VerificationFailed, "{report:?}");
    assert_eq!(report.exit_code, 4);
    assert!(
        report
            .outcome_reason
            .contains("the image could not be flushed durably to the destination: fsync of"),
        "{}",
        report.outcome_reason
    );
    let method = &report.verification.method;
    assert!(!method.contains("page-cache eviction"), "{method}");
    assert!(method.contains("could not be fsynced"), "{method}");
    let (text, _) = read_report(&fake);
    assert!(!text.contains("ALL HASHES MATCH"), "{text}");
    // The finished record carries the verdict
    let finished = fake.records().pop().unwrap();
    assert_eq!(finished["details"]["exit_code"], 4);

    // Eviction fails: still verified (the data is durable), but the method
    // says the re-read may have come from memory
    let mut fake = Fake::new();
    fake.evict_fail = Some(".raw");
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    let method = &report.verification.method;
    assert!(method.contains("may have come from memory"), "{method}");
    assert!(
        !method.contains("page-cache eviction of the image"),
        "{method}"
    );

    // An auxiliary file that cannot be fsynced is a note, not a verdict
    let mut fake = Fake::new();
    fake.fsync_fail = Some(".smart-before.json");
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("fsync of") && n.contains("smart-before.json")),
        "{:?}",
        report.notes
    );
    assert!(report
        .verification
        .method
        .ends_with("after fsync and page-cache eviction of the image"));

    // An aborted run never claims a verification method
    let mut fake = Fake::new();
    fake.fsync_fail = Some(".raw");
    let stop = StopFlags::new();
    let flags = stop.clone();
    fake.engine = Some(Box::new(move |ctx| {
        flags.abort.store(true, Ordering::SeqCst);
        let p = ctx.output_path(".raw");
        std::fs::write(&p, b"partial").unwrap();
        Ok(EngineOutput {
            bytes_acquired: 7,
            aborted: true,
            image_files: vec![p],
            ..Default::default()
        })
    }));
    let report = run_on(&fake, fake.raw(), stop).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::Aborted);
    assert!(
        report.verification.method.starts_with("none"),
        "{}",
        report.verification.method
    );
}

#[tokio::test]
async fn substituted_sectors_are_completed_with_read_errors() {
    let mut fake = Fake::new();
    let mut out = complete(&fake.data);
    out.read_errors = ReadErrorTable::new(512, "fake engine");
    out.read_errors.push(4096, 1024, RangeKind::Substituted);
    fake.engine = Some(writes_image(fake.data.clone(), out));
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert!(report.verification.result.is_matched());
    assert_eq!(report.outcome, Outcome::CompletedWithReadErrors);
    assert_eq!(report.exit_code, 7);
    let fin = &fake.records()[1]["details"];
    assert_eq!(fin["read_errors"]["substituted_sectors"], 2);
    assert_eq!(fin["read_errors"]["ranges"], 1);
    let (text, _) = read_report(&fake);
    assert!(
        text.contains("2 sectors (1 KiB) in 1 range were unreadable and replaced by zeros"),
        "{text}"
    );
}

#[tokio::test]
async fn image_that_differs_is_a_mismatch_and_failed_verification_is_reported() {
    let mut fake = Fake::new();
    let mut out = complete(&fake.data);
    out.acquisition_hashes = hashes(b"something else");
    fake.engine = Some(writes_image(fake.data.clone(), out));
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::Mismatch);
    assert_eq!(report.exit_code, 5);
    assert!(!read_report(&fake).0.contains("ALL HASHES MATCH"));

    let mut fake = Fake::new();
    fake.engine = Some(writes_image(fake.data.clone(), complete(&fake.data)));
    fake.verify = Some(Box::new(|_, _| {
        (
            VerificationResult::Failed {
                reason: "ewfverify exited with status 1".into(),
            },
            HashResults::default(),
        )
    }));
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::VerificationFailed);
    assert_eq!(report.exit_code, 4);
}

#[tokio::test]
async fn second_source_read_that_differs_is_source_changed() {
    let mut fake = Fake::new();
    fake.reread = Some(Ok(hashes(b"changed")));
    let config = AcquisitionConfig {
        verify_source: true,
        ..fake.raw()
    };
    let report = run_fake(&fake, config).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::Mismatch);
    let VerificationResult::Mismatched { details, .. } = &report.verification.result else {
        panic!("{:?}", report.verification.result)
    };
    assert!(
        details.starts_with("the source changed or reads unstably: MD5 acquisition "),
        "{details}"
    );
    assert!(details.contains(" but second read "), "{details}");
    let banner = report.verdict_lines().join("\n");
    assert!(
        banner.contains("a second read of the source differ from those computed while reading it"),
        "{banner}"
    );

    // Rescue (no acquisition digests): the second read is compared with the
    // image, and the labels and the explanation say so (R-4)
    let mut fake = Fake::new();
    fake.engine = Some(rescue_engine(fake.data.clone()));
    fake.reread = Some(Ok(hashes(b"changed")));
    let config = AcquisitionConfig {
        verify_source: true,
        smart: SmartPolicy::Off,
        ..AcquisitionConfig::rescue(fake.out())
    };
    let report = run_fake(&fake, config).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::Mismatch);
    let VerificationResult::Mismatched { details, .. } = &report.verification.result else {
        panic!("{:?}", report.verification.result)
    };
    assert!(
        details.starts_with("the image differs from the source as read a second time"),
        "{details}"
    );
    assert!(details.contains("MD5 image "), "{details}");
    assert!(!details.contains("acquisition"), "{details}");
    let banner = report.verdict_lines().join("\n");
    assert!(
        banner.contains(
            "The digests of the written image differ from those of a second read of the source"
        ),
        "{banner}"
    );
    assert!(!banner.contains("computed during acquisition"), "{banner}");

    // A second read that fails fails the verification
    let mut fake = Fake::new();
    fake.reread = Some(Err(AcquisitionError::failed(
        "read error at byte offset 512",
    )));
    let config = AcquisitionConfig {
        verify_source: true,
        ..fake.raw()
    };
    let report = run_fake(&fake, config).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::VerificationFailed);
}

fn rescue_engine(data: Vec<u8>) -> EngineFn {
    Box::new(move |ctx| {
        let img = ctx.output_path(".raw");
        let map = ctx.output_path(".map");
        std::fs::write(&img, &data).unwrap();
        std::fs::write(&map, b"# Mapfile\n0x00000000 +\n").unwrap();
        Ok(EngineOutput {
            bytes_acquired: data.len() as u64,
            expected_bytes: data.len() as u64,
            image_files: vec![img],
            auxiliary_files: vec![map],
            ..Default::default()
        })
    })
}

#[tokio::test]
async fn rescue_is_unverified_unless_the_source_is_read_again() {
    let mut fake = Fake::new();
    fake.engine = Some(rescue_engine(fake.data.clone()));
    let config = AcquisitionConfig {
        smart: SmartPolicy::Off,
        ..AcquisitionConfig::rescue(fake.out())
    };
    let report = run_fake(&fake, config).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::CompleteUnverified);
    assert_eq!(report.exit_code, 9);
    assert!(report.acquisition_hashes.is_empty());
    assert_eq!(report.image_hashes, hashes(&fake.data));
    // The map is listed with its digest
    assert!(report
        .auxiliary_files
        .iter()
        .any(|f| f.path.ends_with(".map")));
    assert!(!fake.calls().contains(&"smart"));

    // Without --verify-source the explanation names the remedy
    let banner = report.verdict_lines().join("\n");
    assert!(banner.contains("acquire with --verify-source"), "{banner}");

    // --verify-source: the second read matches the image -> verified, and the
    // explanation says what was compared (no stream digest exists, T2)
    let mut fake = Fake::new();
    fake.engine = Some(rescue_engine(fake.data.clone()));
    let config = AcquisitionConfig {
        verify_source: true,
        ..AcquisitionConfig::rescue(fake.out())
    };
    let report = run_fake(&fake, config).await.0.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    let banner = report.verdict_lines().join("\n");
    assert!(
        banner.contains("equal those of a second, independent read of the source"),
        "{banner}"
    );
    assert!(
        !banner.contains("computed while reading the source"),
        "{banner}"
    );
    // SMART before and after a rescue
    assert_eq!(fake.calls().iter().filter(|c| **c == "smart").count(), 2);
    assert!(report.smart_after.is_some());
    assert!(fake.out().join(format!("{BASE}.smart-after.json")).exists());
}

#[tokio::test]
async fn abort_keeps_outputs_and_reports_aborted() {
    let mut fake = Fake::new();
    let half = fake.data[..1024].to_vec();
    fake.engine = Some(Box::new(move |ctx| {
        std::fs::write(ctx.output_path(".raw"), &half).unwrap();
        ctx.abort.store(true, Ordering::SeqCst);
        Err(AcquisitionError::aborted("aborted by the examiner"))
    }));
    let (r, progress) = run_fake(&fake, fake.raw()).await;
    let report = r.unwrap();
    assert_eq!(report.outcome, Outcome::Aborted);
    assert_eq!(report.exit_code, 8);
    assert!(report.aborted);
    assert!(matches!(
        report.verification.result,
        VerificationResult::NotPossible { .. }
    ));
    assert!(
        !fake.calls().contains(&"verify"),
        "an aborted image is not verified"
    );
    assert!(fake.out().join(format!("{BASE}.raw")).exists());
    assert_eq!(fake.records()[1]["details"]["outcome"], "aborted");
    assert_eq!(progress.outcome, Some(Outcome::Aborted));

    // Aborted before anything was written: an error, finished record, no files
    let mut fake = Fake::new();
    fake.engine = Some(Box::new(|_| Err(AcquisitionError::aborted("aborted"))));
    let config = AcquisitionConfig {
        smart: SmartPolicy::Off,
        ..fake.raw()
    };
    let (r, progress) = run_fake(&fake, config).await;
    let e = r.unwrap_err();
    assert_eq!(e.exit_code(), 8);
    assert_eq!(fake.actions()[1], pair("acquisition_finished", "error"));
    assert_eq!(fake.records()[1]["details"]["exit_code"], 8);
    assert!(!fake.out().exists());
    assert_eq!(progress.status, AcquisitionStatus::Aborted);

    // Abort requested before the first write
    let fake = Fake::new();
    let stop = StopFlags::new();
    stop.abort.store(true, Ordering::SeqCst);
    let (r, _) = run_on(&fake, fake.raw(), stop).await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Aborted);
    assert!(!fake.out().exists());
    assert!(fake.records().is_empty());
}

#[tokio::test]
async fn engine_failures_report_what_exists() {
    // Nothing written: the error stands (exit 4), the directories go
    let mut fake = Fake::new();
    fake.engine = Some(Box::new(|_| {
        Err(AcquisitionError::failed(
            "cannot start ewfacquire (is libewf installed?)",
        ))
    }));
    let config = AcquisitionConfig {
        smart: SmartPolicy::Off,
        ..fake.raw()
    };
    let e = run_fake(&fake, config).await.0.unwrap_err();
    assert_eq!(e.exit_code(), 4);
    assert!(!fake.out().exists());
    assert_eq!(fake.actions()[1], pair("acquisition_finished", "error"));

    // A partial image: a report, Incomplete, the error as stop reason
    let mut fake = Fake::new();
    fake.engine = Some(Box::new(|ctx| {
        std::fs::write(ctx.output_path(".raw"), b"partial").unwrap();
        Err(AcquisitionError::failed(
            "ewfacquire failed with exit code Some(1)",
        ))
    }));
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::Incomplete);
    assert!(report
        .stop_reason
        .as_deref()
        .unwrap()
        .contains("exit code Some(1)"));
    assert_eq!(report.image_files.len(), 1);
    assert!(report.image_files[0].ends_with(".raw"));
}

#[tokio::test]
async fn a_source_that_disappears_is_incomplete() {
    let fake = Fake::new();
    *fake.end_identity.lock().unwrap() = Some(Err("no such device".into()));
    let (r, progress) = run_fake(&fake, fake.raw()).await;
    let report = r.unwrap();
    assert_eq!(report.outcome, Outcome::Incomplete);
    assert_eq!(report.identity_check.end_ok, Some(false));
    assert!(report.identity_at_end.is_none());
    assert!(progress
        .log_messages
        .iter()
        .any(|l| l.contains("could not be identified at the end")));

    // Re-attached as another device (diskseq changed)
    let fake = Fake::new();
    let mut other = disk_identity(SIZE);
    other.diskseq = Some(99);
    *fake.end_identity.lock().unwrap() = Some(Ok(other));
    let report = run_fake(&fake, fake.raw()).await.0.unwrap();
    assert_eq!(report.outcome, Outcome::Incomplete);
    assert!(report
        .identity_check
        .details
        .iter()
        .any(|d| d.contains("disk sequence number 99, was 7")));
}

#[tokio::test]
async fn a_panic_after_started_still_writes_the_finished_record() {
    let mut fake = Fake::new();
    fake.engine = Some(Box::new(|_| panic!("engine bug")));
    let fake = std::sync::Arc::new(fake);
    let f2 = fake.clone();
    let config = AcquisitionConfig {
        smart: SmartPolicy::Off,
        ..fake.raw()
    };
    let joined = tokio::spawn(async move {
        let (tx, _rx) = mpsc::channel(100);
        let request = f2.request(config);
        run_with(&*f2, request, tx, StopFlags::new()).await
    })
    .await;
    assert!(joined.unwrap_err().is_panic());
    let recs = fake.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[1]["action"], "acquisition_finished");
    assert_eq!(recs[1]["outcome"], "error");
    assert!(recs[1]["message"].as_str().unwrap().contains("panic"));
    assert!(!fake.out().join(format!("{BASE}{RESERVE_SUFFIX}")).exists());
}

#[tokio::test]
async fn zero_fill_runs_with_the_real_raw_engine() {
    // A readable source: zero-fill substitutes nothing, and the report says
    // which policy was applied
    let fake = Fake::new();
    let config = AcquisitionConfig {
        on_read_error: OnReadError::ZeroFill,
        smart: SmartPolicy::Off,
        ..fake.raw()
    };
    let report = run_fake(&fake, config).await.0.unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Verified,
        "{}",
        report.outcome_reason
    );
    assert!(report.read_errors.is_empty());
    let EngineSettings::Raw(raw) = &report.effective_config.settings else {
        panic!()
    };
    assert_eq!(raw.on_read_error, OnReadError::ZeroFill);
}

// ---------------------------------------------------------------------------
// check(): the dry run
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_writes_nothing_and_lists_every_problem() {
    let fake = Fake::new();
    let report = check_with(&fake, fake.request(fake.raw())).await;
    assert!(report.ready, "{:?}", report.problems);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.base_name.as_deref(), Some(BASE));
    assert_eq!(
        report.tool_source_path.as_deref(),
        Some("/dev/disk/by-diskseq/7")
    );
    assert!(report
        .write_protection_plan
        .as_deref()
        .unwrap()
        .contains("would set read-only (BLKROSET): /dev/sdx, /dev/sdx1"));
    assert!(report.capacity.is_some());
    assert!(report.smart.as_ref().unwrap().json_file.is_none());
    assert!(report.render_text().contains("READY"));
    // Nothing written, nothing set, nothing recorded
    assert!(!fake.out().exists());
    assert!(fake.records().is_empty());
    assert!(!fake.calls().contains(&"write_protect"));
    assert!(!fake.calls().contains(&"acquire"));

    // A mounted source on a tmpfs destination: both problems, no SMART
    let mut fake = Fake::new();
    fake.mountinfo
        .push_str("50 22 8:17 / /mnt/x rw - ext4 /dev/sdx1 rw\n");
    fake.fs_type = "tmpfs".into();
    let report = check_with(&fake, fake.request(fake.raw())).await;
    assert!(!report.ready);
    assert_eq!(report.exit_code(), 3);
    let steps: Vec<&str> = report.problems.iter().map(|p| p.step.as_str()).collect();
    assert_eq!(steps, ["source safety", "destination"]);
    assert!(report.smart.is_none() && report.capacity.is_none());
    assert!(report.render_text().contains("NOT READY"));
    assert_eq!(report.first_error().unwrap().kind, ErrorKind::Refused);
    assert!(!fake.out().exists());

    // Usage errors stop the check at once (exit 2)
    let fake = Fake::new();
    let mut request = fake.request(fake.raw());
    request.case.case_number.clear();
    let report = check_with(&fake, request).await;
    assert_eq!(report.exit_code(), 2);
    assert!(report.identity.is_none());
}

// ---------------------------------------------------------------------------
// Pieces
// ---------------------------------------------------------------------------

#[test]
fn proc_swaps_parsing() {
    let content = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
/dev/sdb2                               partition\t8388604\t\t0\t\t-2\n\
/mnt/my\\040swap                         file\t\t1048572\t\t0\t\t-3\n";
    let swaps = parse_proc_swaps(content, &|path, kind| {
        Some(if kind == "partition" {
            (8, 18)
        } else if path == "/mnt/my swap" {
            (8, 33)
        } else {
            (0, 0)
        })
    });
    assert_eq!(swaps.len(), 2);
    assert_eq!(swaps[0].path, "/dev/sdb2");
    assert_eq!(swaps[0].kind, "partition");
    assert_eq!(swaps[0].dev, Some((8, 18)));
    assert_eq!(swaps[1].path, "/mnt/my swap");
    assert_eq!(swaps[1].dev, Some((8, 33)));
    assert!(parse_proc_swaps("Filename Type Size Used Priority\n", &|_, _| None).is_empty());
}

#[test]
fn verification_and_second_read_combine() {
    let matched = |m: &str| VerificationResult::Matched { method: m.into() };
    let not_possible = VerificationResult::NotPossible {
        reason: "rescue".into(),
    };
    let failed = VerificationResult::Failed {
        reason: "io".into(),
    };
    let mismatched = VerificationResult::Mismatched {
        method: "second read".into(),
        details: "MD5 differs".into(),
    };
    assert_eq!(combine_verification(matched("img"), None), matched("img"));
    assert_eq!(
        combine_verification(matched("img"), Some(&not_possible)),
        matched("img")
    );
    assert_eq!(
        combine_verification(not_possible.clone(), Some(&matched("re"))),
        matched("re")
    );
    assert_eq!(
        combine_verification(matched("img"), Some(&matched("re"))),
        matched("img")
    );
    assert!(matches!(
        combine_verification(matched("img"), Some(&failed)),
        VerificationResult::Failed { .. }
    ));
    // The second read's mismatch is passed on as compare_second_read
    // labelled it
    assert_eq!(
        combine_verification(matched("img"), Some(&mismatched)),
        mismatched
    );
    let sel = HashSelection::for_engine(&AcquisitionConfig::raw("/x"));
    let VerificationResult::Mismatched { details, .. } =
        compare_second_read(sel, &hashes(b"a"), &hashes(b"a"), &hashes(b"b"))
    else {
        panic!()
    };
    assert!(details.starts_with("the source changed or reads unstably: MD5 acquisition"));
    let VerificationResult::Mismatched { details, .. } =
        compare_second_read(sel, &HashResults::default(), &hashes(b"a"), &hashes(b"b"))
    else {
        panic!()
    };
    assert!(details.starts_with("the image differs from the source"));
    assert!(details.contains("MD5 image "), "{details}");
    assert!(
        compare_second_read(sel, &HashResults::default(), &hashes(b"a"), &hashes(b"a"))
            .is_matched()
    );
    // An image mismatch stays a mismatch when the second read failed
    assert!(matches!(
        combine_verification(mismatched.clone(), Some(&failed)),
        VerificationResult::Mismatched { .. }
    ));
}

#[test]
fn flush_reports_problems_and_smart_names_never_collide() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("a.raw");
    std::fs::write(&f, b"x").unwrap();
    assert!(flush_and_evict(std::slice::from_ref(&f), tmp.path()).is_empty());
    let problems = flush_and_evict(&[tmp.path().join("missing")], tmp.path());
    assert_eq!(problems.len(), 1);
    // Per file: an image that cannot be opened is not durable; a problem of
    // another file is only a note
    let report = flush_files(&[f.clone(), tmp.path().join("missing")], tmp.path());
    assert_eq!(
        report.files[0],
        FileFlush {
            path: f.clone(),
            ..Default::default()
        }
    );
    assert!(report.files[1].not_durable.is_some());
    let as_image = ImageFlush::of(&report, &[tmp.path().join("missing")]);
    assert_eq!(as_image.not_durable.len(), 1);
    assert!(as_image.notes.is_empty());
    assert!(matches!(
        as_image.apply(VerificationResult::Matched { method: "m".into() }),
        VerificationResult::Failed { .. }
    ));
    let as_aux = ImageFlush::of(&report, std::slice::from_ref(&f));
    assert!(as_aux.not_durable.is_empty());
    assert_eq!(as_aux.notes.len(), 1);

    let p = smart_json_path(tmp.path(), "b", "before");
    assert!(p.ends_with("b.smart-before.json"));
    std::fs::write(&p, b"{}").unwrap();
    assert!(smart_json_path(tmp.path(), "b", "before").ends_with("b.smart-before-2.json"));
    // A resumed rescue may keep both
    assert!(preflight::resume_may_exist("b", "b.smart-before-2.json"));
}

#[test]
fn engine_context_helpers() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::write(&src, b"abc").unwrap();
    let request = AcquisitionRequest::new(device(3), case(), AcquisitionConfig::raw(tmp.path()));
    let mut ctx = EngineContext::new(request, disk_identity(3), BASE);
    assert_eq!(ctx.engine, EngineKind::Raw);
    assert_eq!(
        ctx.output_path(".raw"),
        tmp.path().join(format!("{BASE}.raw"))
    );
    assert_eq!(ctx.expected_bytes(), 3);
    assert_eq!(ctx.sector_size(), 512);
    assert_eq!(ctx.tool_source_path, "/dev/sdx");
    assert!(ctx.dup_source().is_err());
    ctx.source_fd = Some(File::open(&src).unwrap());
    assert!(ctx.dup_source().is_ok());
    assert!(!ctx.is_aborted());
    ctx.abort.store(true, Ordering::SeqCst);
    assert!(ctx.stop_control().abort.unwrap().load(Ordering::SeqCst));
}

#[test]
fn descriptor_must_be_the_probed_file() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    let id = crate::discovery::identity::probe_file(&a.to_string_lossy()).unwrap();
    assert!(host::check_descriptor(&File::open(&a).unwrap(), &id).is_ok());
    assert!(host::check_descriptor(&File::open(&b).unwrap(), &id)
        .unwrap_err()
        .is_refusal());
    // A "block device" identity held through a regular file is refused
    let e = host::check_descriptor(&File::open(&a).unwrap(), &disk_identity(1)).unwrap_err();
    assert!(
        e.message.contains("no longer refers to the probed device"),
        "{e}"
    );
}

#[tokio::test]
async fn unprobeable_capacity_and_unknown_smart_never_refuse_or_fail() {
    // A virtio disk (or a dm mapping over one): no HPA/DCO query applies and
    // smartctl cannot read it. Even with --refuse-hidden-areas the run goes
    // on; the report states what could not be established.
    let mut fake = Fake::new();
    fake.capacity = CapacityInfo::not_probed(
        SIZE,
        "HPA/DCO probing applies to ATA disks (hdparm) and NVMe namespaces (nvme-cli); /dev/vdb is neither",
    );
    let config = AcquisitionConfig {
        refuse_hidden_areas: true,
        ..fake.raw()
    };
    let (r, _) = run_fake(&fake, config).await;
    let report = r.unwrap();
    assert_eq!(report.outcome, Outcome::Verified, "{:?}", report.notes);
    let capacity = report.capacity.as_ref().unwrap();
    assert_eq!(capacity.hidden_area(), None);
    assert!(capacity.summary().contains("/dev/vdb is neither"));
    let smart = report.smart_before.as_ref().unwrap();
    assert_eq!(smart.summary.health, SmartHealth::Unknown);
    assert!(report.render_text().contains("/dev/vdb is neither"));
}
