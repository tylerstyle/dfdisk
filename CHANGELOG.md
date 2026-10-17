# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-10-17

### Fixed

- **A closed terminal no longer costs a CPU core.** When the TUI's terminal
  goes away (the window is closed, SSH drops), a running job continues headless
  to its report, as before. But crossterm's event stream then spun at full CPU
  on the dead terminal for the rest of the job: one core lost to an acquisition
  that is bound by hashing. The TUI now reads the terminal on a thread of its
  own that checks for the hang-up before it asks crossterm for input; that
  thread ends at once and the job has the machine to itself.
- **Exit code after a headless job.** When a job finished headless, dropping
  the terminal made ratatui write to the dead terminal, which panicked, and
  dfdisk exited 1 (internal error) instead of with the job's code. Nothing is
  written to a terminal that is gone any more; the exit code is the job's (0
  for a verified image).
- An idle TUI whose terminal goes away without a SIGHUP reaching it exits 0
  instead of 1.

## [0.2.0] - 2026-10-15

dfdisk 0.2.0 is a rework driven by a review of 0.1.10 (items C1-C2,
H1-H10, M1-M12 and feature proposals F1-F12 below). Its reports are meant to be
read in court: every statement a report makes is derived from measured facts,
and when something was not done the report says so.

### Breaking changes

- **Required output directory.** `acquire` and `convert` require
  `-o/--output-dir`; 0.1.10 wrote to the current directory (`.`) when it was
  missing.
- **Options for another engine are usage errors.** An option given explicitly
  for an engine it does not apply to (for example `--compression`, `--split` or
  `--retries` with `--format raw`, which 0.1.10 accepted and ignored; likewise
  the new RAW-only and rescue-only options with another engine, and
  `--compression`/`--split` with `convert --to raw`) exits 2, so a report never
  shows a setting that was not applied.
- **Required case fields.** `acquire` (and the TUI) require `--case`,
  `--evidence` and `--examiner`. The 0.1 placeholder defaults (`CASE001`, `cf01`,
  `Forensic Examiner`, `Law Enforcement / DFIR Unit`, `Physical Storage Media`)
  are gone; no placeholder is ever recorded. `convert` takes the case fields from
  the source image's report (and an E01's header) or requires them.
- **Exit codes.** One documented table (docs/exit-codes.md): 0 verified,
  1 internal error, 2 usage, 3 refused, 4 failed, 5 mismatch, 6 incomplete,
  7 completed with read errors, 8 aborted, 9 complete but not verified. In 0.1
  refusals, failures, mismatches and incomplete runs all exited 1, and E01
  acquisitions with read errors and rescues exited 0. `verify` exits 5 on a
  mismatch (was 1) and 9 when there was nothing to compare against.
- **Verdicts.** Seven outcomes (VERIFIED, COMPLETE NOT VERIFIED, COMPLETED WITH
  READ ERRORS, INCOMPLETE, HASH MISMATCH, VERIFICATION FAILED, ABORTED) replace
  the 0.1 statuses; "DamagedMedia" is gone. A clean rescue is COMPLETE, NOT
  VERIFIED (exit 9) unless `--verify-source` confirmed it.
- **Report schema 2.** `<base>.info` starts with a verdict banner and has new
  sections (write protection, capacity, SMART, applied settings, clock,
  read-error table, provenance, audit); `<base>.info.json` is its new
  machine-readable twin (`schema_version: 2`, docs/report-format.md).
- **Audit export file name.** The audit log copy in the output directory is
  `audit-<boot_id>.jsonl` with `audit-<boot_id>.head` (one per boot, never
  overwriting another boot's copy) instead of `audit.jsonl` / `audit.head`.
- **dfcore 0.2.0** is required (registry matching by device number, typed
  refusals, per-boot audit export, `DeviceIdentity::same_attachment`).
- **Stricter refusals.** Mounted sources are refused (unmounting is the explicit
  `dfdisk unmount` / `--auto-unmount`), as are sources with holders
  (device-mapper, LVM, md, or a loop device set up over the source, or over its
  disk with a byte range that includes the source; they have to be closed
  first), sources with active swap, sources in use (`O_EXCL`), tmpfs
  destinations (unless `--allow-tmpfs`), E01 destinations with less free space
  than the source (unless `--allow-low-space`) and empty sources (size 0: no
  medium, or the size is unknown).
- **Write protection on by default.** `--write-protect auto` sets the kernel
  read-only flag (BLKROSET) on the source, the nodes it sits on and the disk it
  is stored on with all its partitions (except nodes another mounted filesystem
  needs writable, which the report names) and leaves it set; `off` only
  records.
- **SMART** is no longer queried during device scans; `list --smart` asks for it
  (with `-n standby`, so a sleeping disk is not woken).
- **`list --json`** prints one object (`schema_version` 1: registry state,
  active swap, scan notes, `devices` with partitions and stacked devices nested
  in `children`) instead of 0.1's array of devices.
- **TUI exit code.** The TUI exits with the exit code of a result the examiner
  did not acknowledge on screen (for example a run that finished after SIGHUP),
  0 otherwise, 1 on a terminal failure or an internal error of the UI itself,
  and 4 when the signal handlers cannot be installed. A run that stops on an
  internal error (a panic) is shown as FAILED (INTERNAL ERROR), exit code 4.
  After an internal error of the UI itself, a job still running is aborted
  and writes its report and audit record, and an unmount still running ends,
  before dfdisk exits (within 6 minutes; otherwise dfdisk says so and exits
  without them).
- **TUI keys.** Esc never aborts; aborting needs a y/N confirmation; Tab and
  Shift-Tab always move between fields and path completion has its own key.
- **Packaging.** The .deb depends on `$auto, ewf-tools, gddrescue, smartmontools,
  util-linux, mount, udev, hdparm, nvme-cli`; the Arch and nixpkgs files under
  `packaging/` are gone (there is no AUR package). Minimum Rust version 1.88
  (`rust-version`).

### Fixed (review of 0.1.10)

- **C1** E01 read errors were invisible and certified VERIFIED: ewfacquire's
  read-error block is parsed from stdout and stderr, cross-checked with the
  error list stored in the image (`ewfinfo -e`), and reported as exact
  zero-filled ranges with verdict COMPLETED WITH READ ERRORS (exit 7); the media
  size in the image is compared with the device size; ewfacquire's log
  (`-l <base>.ewfacquire.log`) is kept and hashed; `-g` follows the physical
  sector size.
- **C2** Source identity was never re-checked: the identity (major:minor,
  diskseq, serial, WWN, size) is pinned when the device is selected and checked
  again at the start and at the end; the source is held open with `O_EXCL` for
  the whole run; external tools read through `/dev/disk/by-diskseq/<N>` when it
  points at the pinned device; the TUI keys its selection on the identity and
  shows a confirmation sheet. An E01 acquisition of a source that ends before
  its size while it stays attached no longer waits forever: after 60 s without
  progress dfdisk checks the source and, when it is gone or smaller, stops
  ewfacquire (INCOMPLETE, "source lost at offset X"). When ewfacquire
  zero-filled to the end of the medium and the source is gone or smaller
  afterwards (presence and size are checked), those zeros are listed as not
  acquired ("source lost at offset X"); only a source still present with its
  full size makes them read errors of the medium.
- **H1** The TUI hid the verdict: the result screen starts with the verdict
  banner, coloured by outcome, shows the key numbers and paths, scrolls the full
  report and stays until acknowledged; errors no longer expire. Notices are
  wrapped instead of cut at the terminal width, the ones that do not fit are
  counted, and Ctrl+X dismisses only the notices shown (none on the "terminal
  too small" screen, none that arrived after the last screen was drawn).
- **H2** No signal handling: SIGINT, SIGTERM and SIGQUIT abort gracefully
  (SIGINT to the tool's process group, grace period, then SIGTERM and SIGKILL),
  a second SIGINT kills at once, SIGHUP lets the run finish headless; every
  engine keeps its partial output; the report and the audit "finished" record
  are written on every path. A tool started by dfdisk gets SIGTERM when dfdisk
  dies in a way it cannot handle (SIGKILL, the OOM killer, a crash:
  `PR_SET_PDEATHSIG`) and does not run on unsupervised.
- **H3** The converter overwrote outputs and verified nothing: existing outputs
  are refused before any tool writes, destination checks apply, the output is
  verified against the source digests, it writes `<base>.conversion.info` /
  `.conversion.info.json` and audit records, abort works, sizes that are not a
  multiple of 512 bytes are refused, split RAW inputs are converted completely
  or refused. An E01 that ewfinfo reports as corrupted (segments missing, or
  never finalized) is INCOMPLETE (exit 6), and the sectors ewfexport could not
  read correctly are listed as the conversion's own read errors (libewf
  20140816 exports such an image with zeros and "SUCCESS"); segments beyond
  `.EZZ` (`.FAA` …) are listed, flushed and refused like the others; a source
  image whose report says HASH MISMATCH or VERIFICATION FAILED gives at best
  COMPLETE, NOT VERIFIED (exit 9); a report found next to the image that
  describes another image is ignored with a note (only a report given with
  `--report` must describe it).
- **H4** Rescue reports were not truthful: read-error ranges and counts come
  from the ddrescue mapfile, untried areas make the run INCOMPLETE, the map is
  hashed and listed, a resume requires the same device (identity sidecar) and
  passes `-I`, the earlier report is kept as `<base>.info.session-N`, and the TUI
  offers to resume. A resume refuses an identity record whose SHA-256 differs
  from the one the last report lists, and behind a USB bridge without a WWN it
  ties the drive only by its own ATA IDENTIFY serial (recorded when SMART runs)
  or the same attachment, not by the bridge's serial; a refused resume leaves
  the previous report as `<base>.info`. After every ddrescue run dfdisk writes
  zeros over the bad-sector areas of the map, so they are zeros in the image
  also after an interrupted session was resumed; sectors there that held data
  (left by a session killed before ddrescue saved its map, also sectors a retry
  pass read) are first copied to `<base>.zeroed-N.bin`, with their image
  offsets and SHA-256 in `<base>.zeroed-N.tsv` (N: the rescue session, or one
  past the highest such file a session that ended without its report left;
  created new and fsynced before the first zero, never overwritten), and both
  are listed with the report's files. When the zeros cannot be written, those
  areas count as not acquired (`unread`), not as zeros. The verdict explanation
  follows what happened: a rescue is INCOMPLETE "because the map lists
  unfinished areas" only when it does and nothing else stopped it, a VERIFIED
  rescue names the second read of the source it was compared with, and a second
  read that differs is labelled by what was compared (acquisition digests or
  the image). An image that cannot be re-read keeps its own read error as the
  reason of VERIFICATION FAILED (also next to a failed flush), with the second
  read's result appended, and
  the report's HASHES section says that the re-read failed and why; a rescue
  image without digests is not compared with a second read ("nothing to compare
  with"; the source is not read again), and "the second source read failed"
  names only a second read that failed itself. The explanation of an INCOMPLETE
  run whose image has the full length of the source but that did not end
  cleanly (for example ddrescue ending with an error status after a complete
  run) says so and does not call the image partial.
- **H5** Write protection was not checked or recorded: the read-only state of
  the source and its partitions, holders, mounts and the exclusive open are
  recorded; BLKROSET is set by default on the source, its partitions, the nodes
  it sits on (the partition and intermediate dm/md devices under a LUKS, LVM or
  md source) and its disk with every partition; a node that has to stay
  writable because of another mount is named in the report. A loop device set
  up over the source or its partitions is a holder and its mounts are mounts
  of the source; so is a loop device over a device below the source (its disk,
  the partition under a LUKS source) whose byte range (`loop/offset`,
  `loop/sizelimit`) includes part of the source, with those of its partitions
  that do (`losetup -P /dev/sdb; mount /dev/loop0p2` for a source `sdb2`); a
  loop or md source's own partitions belong to it. A dm or md device stacked
  on such a loop device that covers more than the source (kpartx over
  `losetup /dev/sdb` for `sdb2`) may or may not map the source (its mapping
  is not read): its mounts refuse the acquisition without being called mounts
  of the source, and `dfdisk unmount` refuses to unmount them.
- **H6** Audit trail gaps: (a) the export is per boot and never replaces another
  boot's chain; (b) refusals are recognised by type, not by message text;
  (c) the "finished" record always carries the outcome, the digests known and
  the SHA-256 of both reports, and when the report cannot be written it still
  carries the verdict, digests, read errors and files (`report_written: false`);
  records of MISMATCH, INCOMPLETE, ABORTED and VERIFICATION FAILED runs,
  verifications and conversions have the outcome `error` and the verdict as
  message; (d) an unwritable audit log refuses on dfnix and
  is stated in the report and the UI elsewhere; (e) tests no longer mirror
  records into the host journal (dfcore 0.2.0); (f) a refused conversion is
  recorded (`conversion_refused`), as a refused acquisition is.
- **H7** Unmount: `dfdisk unmount` and `--auto-unmount` collect the mounts of
  the source and all its descendants by device number, check the registry and
  system mounts before unmounting anything, unmount deepest first, verify that
  nothing remains and write an audit record (loop devices set up over the
  source and a loop or md source's own partitions included). SIGINT, SIGTERM,
  SIGQUIT, SIGHUP or a quit do not cut an unmount short: it is finished,
  checked and recorded before dfdisk exits. The output directory is created
  only after every destination check. The registry is matched by device number
  (device-mapper paths), and an ambiguous bare device name is refused.
- **H8** TUI start and abort hazards: required fields, typed confirmation
  (last four characters of the serial, the whole serial when shorter, the
  evidence number without a serial), source identity on every screen, a
  scrolling device table that keeps the serial visible, abort with confirmation.
  The confirmation sheet shows the settings the run uses and says "refused"
  only for a refusal (a missing tool is named); nothing starts while a run or
  an unmount is in progress. A conversion's sheet shows the case values the
  conversion records (E01 header < source report < form), each with where it
  comes from; the TUI takes an image's report by the converter's rule (it must
  list the image), so a report of another image pre-fills nothing and never
  chooses the typed confirmation.
- **H9** Exit codes: see Breaking changes; errors are printed once; a panic
  exits 1 (internal error) with a message instead of Rust's 101; a tool the
  engine runs that is not installed fails the run (exit 4) before anything is
  written, sent to the device or recorded as started, and `check` reports it.
- **H10** Release and packaging: releases are built only after the test job
  passed; tag, Cargo.toml, Cargo.lock and package.nix versions must agree;
  pinned Rust toolchain; `cargo install --locked --version` for cross and
  cargo-deb; binaries and the .deb are built on Ubuntu 22.04 and the .deb
  declares its C library dependency (`$auto`) and depends on `ewf-tools` (not the
  nonexistent `libewf-tools`); the .deb is installed and run in CI before
  publishing; README asset names are the real ones; stale packaging removed;
  `cargo install --git` is documented as unsupported.
- **M1** SMART ran on every disk at every scan with SCT commands and no timeout:
  no SMART in scans, `--smart off|basic|full` without SCT commands, 30 s timeout,
  snapshots recorded in the report with the raw JSON, inaccessible SMART is
  UNKNOWN (not FAILED), NVMe wear from `percentage_used`.
- **M2** HPA/DCO and NVMe capacity were not detected: `hdparm -N`,
  `hdparm --dco-identify` and `nvme id-ns` (read-only, on the physical disk,
  with timeouts) are recorded; `--refuse-hidden-areas` refuses.
- **M3** Verification read the page cache: images, auxiliary files and the
  directory are fsynced and evicted from the page cache before verification. An
  image (or a conversion's output) that cannot be fsynced fails the
  verification (exit 4); one that cannot be evicted is noted in the
  verification method ("the re-read may have come from memory"); the method
  states the fsync and eviction only when they happened.
- **M4** Metadata: control characters are sanitised (no shifted E01 header
  fields), placeholders are never recorded, file names are capped at 255 bytes
  (refused, never truncated), tokens are NFC-normalised, existing outputs are
  compared case-insensitively.
- **M5** Serial provenance: every serial candidate is kept with its source,
  device-reported serials are preferred, empty values are ignored, and a note
  warns when a USB bridge may report its own serial.
- **M6** Partition and device-mapper sources are labelled as such, with parent
  disk, start sector and an explicit note for decrypted dm-crypt plaintext;
  hot-pluggable and removable are told apart.
- **M7** Destination preflight: free space, FAT file size limit, tmpfs/ramfs,
  read-only mounts and dfnix evidence mounts are checked before anything is
  written; a 1 MiB reservation keeps room for the report.
- **M8** The TUI and the reports state only the settings that were applied (no
  compression or split for RAW, MD5 always for E01, at least one digest), and
  progress is shown per phase (acquire, flush, verify, source re-read).
- **M9** TUI ergonomics: probes run off the UI thread, Tab moves between fields,
  path completion has its own key, modals fit their content, help overlay, no
  mouse capture, partitions can be selected (a partition whose LUKS or LVM
  mapping is mounted is shown MOUNTED and IN-USE and can be unmounted with U; a
  device on several disks borrows no disk's serial). The converter fills only
  the case fields it shows from the image's report, names them, and empties
  the ones not edited when the source changes.
- **M10** Tests: no host disks, fake tools on PATH, tool tests fail instead of
  skipping when `DFDISK_REQUIRE_TOOLS=1` (set in the Nix build and in CI),
  modules are compiled once (the binary uses the library).
- **M11** RAW: source reads use `O_DIRECT` with aligned buffers (buffered reads
  with page-cache eviction where unsupported, noted in the report), a bad
  sector is located exactly, interrupted reads are retried, and
  `--on-read-error zero-fill` continues over unreadable sectors.
- **M12** `dfdisk verify`: a requested digest that was not computed is a failure,
  never a pass; `.Ex01` and `.E02` segment families are recognised as EWF; an
  expected digest that is not 32/40/64 hex digits is a usage error (exit 2)
  instead of a mismatch.
- **E01 with Ubuntu's ewf-tools.** ewfacquire 20140807 (Ubuntu 22.04's
  `ewf-tools`, which the .deb depends on) crashes on any `-r`, and 0.1.10
  always gave `-r`, so it could not take an E01 there. dfdisk gives `-r` only
  for a retry count other than ewfacquire's own default of 2 (the report states
  "2 (ewfacquire's default; -r not given)"); another count with an ewfacquire
  that crashes on `-r` (libewf 20101105 to 20140808 and 20141002 to 20200210,
  by the version `ewfacquire -V` prints) is a usage error (exit 2), in `check`
  too, before anything is written or sent to the source. CI runs the whole
  test suite against Ubuntu 22.04's `ewf-tools` and `gddrescue` 1.23.
- Low: `--split none` passes the largest segment size both libewf lines accept
  (9223372036854775806 bytes; 0.1.10 passed 7900 GiB, so a larger source got
  several segments); `-r` above 255 is a usage error instead of silently
  becoming 2; `-m` and `-M` (media type and flags) are set from the source;
  firmware and other device strings are sanitised; false README claims removed;
  runtime tools are no longer build inputs of the Nix package; the Debian
  copyright covers both licenses; `rust-version` is declared; active swap files
  on the source are refused by name; `/iso`, `/run/initramfs` and swap join the
  system-mount list.

### Added

- **F1** One verdict model and read-error table for all engines (ranges from
  `ewfinfo -e`, the ddrescue map or the RAW engine), one function deciding the
  verdict.
- **F2** Identity pinning and a confirmation sheet with a typed serial suffix.
- **F3** Write-protection capture and enforcement (sysfs read-only state,
  holders, `O_EXCL`, BLKROSET), recorded in the report and the audit log.
- **F4** HPA/DCO and NVMe capacity detection.
- **F5** `<base>.info.json`, tool versions and command lines, kernel, host and
  dfnix revision, dfdisk and dfcore git revisions (`dfdisk --version`; "-dirty"
  when built with uncommitted changes to tracked files), clock and NTP state
  with the RTC offset, documented exit codes, `dfdisk check` (dry run),
  `acquire --json`, `list --json`; `check`, `verify` and `unmount` with
  `--json` and the error object carry `schema_version` 1 and are documented in
  docs/report-format.md. With `--json` an argument error (an unknown option, a
  malformed digest) is printed as that error object too.
- **F6** Re-verification as an audited addendum (`dfdisk verify`, TUI re-verify
  screen, `--report`, `--pieces`) and an optional second read of the source
  (`--verify-source`).
- **F7** Piecewise SHA-256 (`--piece-size`, `<base>.pieces.tsv`) in the report
  and the audit record.
- **F8** Persistent result screen; SIGHUP-resilient headless completion and a
  warning when the TUI runs over SSH outside tmux or screen.
- **F10** `--rescue-to-e01`: a finished rescue is converted to E01 next to the
  rescue image; the rescue's verdict, read-error summary and zero-filled sector
  ranges (in the notes the first 20, with the number of ranges) go into the E01
  notes and the conversion report, which names the rescue report by path and
  SHA-256. The ddrescue map is not imported into the E01 as EWF error ranges:
  converted back to RAW without a report that lists those ranges, such an E01
  is at best COMPLETE, NOT VERIFIED (exit 9), and the report quotes its notes.
- **F11** Chain-of-custody fields `--seal`, `--seized-at`, `--seized-location`;
  required examiner, case and evidence number; a TUI case profile
  (`$XDG_CONFIG_HOME/dfdisk/profile.toml`) with an evidence-number suggestion.
- **F12** SMART policy `--smart off|basic|full`, before and (rescue) after the
  acquisition.
- `--expect-serial`, `--expect-wwn`, `--expect-size`,
  `--allow-tmpfs`, `--allow-low-space` (also for `convert`),
  `--write-protect auto|off`, `--on-read-error stop|zero-fill`.
- Sources are selected from the device scan by device number: partitions,
  device-mapper (dm-linear, dm-crypt, LVM), md and loop devices carry their own
  facts and the hardware identity of the one disk they are stored on; the
  virtio-blk serial is read from sysfs, so a virtio disk matches its selection.
  A device stored on a loop device (a LUKS or kpartx mapping of an image file,
  a partition of a loop device) has no hardware identity: the walk down to the
  disk stops at the loop device, so the host disk that holds the image file
  never lends its serial, model or WWN to the report, the file names or
  `--expect-serial`, and SMART, `hdparm`, `nvme` and BLKROSET never reach it
  (the loop node is set read-only as the disk).
- The flake check `libewf-legacy` builds and tests dfdisk against libewf
  20140816, the release line of the Debian/Ubuntu `ewf-tools` package.
- `scripts/test-ubuntu.sh` runs the whole test suite in an Ubuntu 22.04
  container (podman or docker) against its `ewf-tools` 20140807 and `gddrescue`
  1.23, as a non-root user, like CI.

### Not in 0.2.0

- AFF4 output: little value for the effort.
- Splitting RAW images into segments: refused with guidance (use E01).
- Detachable acquisitions that can be re-attached: 0.2.0 finishes headless after
  SIGHUP and warns about SSH sessions outside tmux/screen instead.
- `cargo install --git`: dfdisk builds against a sibling dfcore checkout (D1).
- **F9** Dual destination (`ewfacquire -2`) was not taken up.

---

## [0.1.10] - 2026-10-11

### Added
- **dfcore integration**: disk topology for the destination-on-source check
  comes from dfcore; sources listed in the dfnix boot-time protected-device
  registry are refused.
- **Audit records**: each acquisition appends `acquisition_started` (its hash is
  the report's Audit Anchor) and `acquisition_finished` (outcome, hashes, files,
  report SHA-256) to the dfnix audit log, and copies the verified log and its
  head into the case directory (not for refused acquisitions).

### Fixed
- Existing outputs of an acquisition are refused instead of being overwritten
  (ewfacquire `-u` overwrote silently).
- Output directories on the source's own physical disk are refused.
- E01 digests are computed in ewfacquire's single read pass; only the selected
  digests are verified.
- RAW stops at the first unreadable sector, keeps the partial image and writes
  an INCOMPLETE report with the exact offset.

---

## [0.1.9] - 2026-10-11

### Changed
- **Software Stack Base Update**: Upgraded Rust dependencies to latest compatible patch releases (`tokio 1.53.2`, `clap 4.6.7`, `serde_json 1.0.152`, `thiserror 2.0.21`, `libc 0.2.190`, `mio 1.2.4`, `rustix 1.1.5`, `smallvec 1.16.3`, `uuid 1.28.0`).
- **Packaging Synchronization**: Synchronized package specifications, manifests, and changelogs across Arch Linux (`PKGBUILD`, `.SRCINFO`), Debian (`changelog`), and Nixpkgs derivations (`package.nix`, `packaging/nixpkgs/package.nix`).

---

## [0.1.8] - 2026-09-29

### Added
- **Responsive Small-Terminal Action Buttons**: Added wrapping and multi-row button rendering for action buttons on compact or narrow terminal displays.
- **Persistent Busy Status**: Added persistent footer busy indicator and operational state cues during active background operations.
- **Documentation Screenshots**: Added `examples/render_screenshots.rs` for capturing standardized high-fidelity TUI screenshots.
- **Trait Implementations**: Implemented `Default` for `App` struct.

---

## [0.1.7] - 2026-09-27

### Added
- **Automated NUR Distribution**: Integrated automated release workflow in GitHub Actions to compute SRI source hashes and vendor `cargoHash`, automatically updating `tylerstyle/nur-packages` and triggering NUR index webhooks.
- **Pipeline Hardening**: Pinned and verified Nix channel resolution for release automation.

---

## [0.1.6] - 2026-09-18

### Added
- **Native RAW Acquisition Engine**: Direct streaming disk imaging engine (`RawAcquireEngine`) with in-flight cryptographic multi-hashing (MD5, SHA-1, SHA-256), destination read-back verification pass, and court-ready `.info` sidecar generation.

### Refactored
- **Acquisition Routing**: Routed raw image acquisition (`--format raw` and TUI format selection) directly to `RawAcquireEngine`.
- **Forensic Verification Semantics**: Introduced `VerificationStatus` enum (`Verified`, `Mismatch`, `DamagedMedia`, `Failed`, `NotVerified`) across reports and CLI handlers, with non-zero exit codes on verification failure.
- **Rescue Progress & Error Telemetry**: Updated `ddrescue` stream parsing for modern bad-sector and read-error metrics, calculating bad sector counts via ceiling division.
- **EWF Segment Matching**: Hardened segment file matching in `EwfAcquireEngine` with strict EWF extension validation (`.E01`–`.E99`, `.EAA`–`.EZZ`, `.s01`–`.sZZ`, `.001`–`.999`).
- **Device Capacity Detection**: Linux `ioctl(BLKGETSIZE64)` block device size probing and explicit capacity support in `MultiHasher`.
- **SMART Temperature Normalization**: Standardized temperature parsing with Kelvin and Celsius boundary normalization and ATA attribute fallback.

---

## [0.1.5] - 2026-09-08

### Changed
- **Persistent Bottom Shortcut Hints**: Completely decoupled keybind hints from notification messages across all views (`DeviceExplorer`, `CaseSetup`, `AcquisitionRunning`, `ReportSummary`, `Converter`, `UnmountPrompt`, `SystemDiskWarning`). Shortcut hints remain permanently visible on every frame and are never obscured or replaced by status or refresh feedback.
- **Header Status & Telemetry Bar**: Re-engineered the top header bar to host transient status, error, and engine telemetry feedback right-aligned:
  - Informational and refresh notices rendered in light blue (`Color::Cyan`) with bold styling and auto-expiry after 4 seconds.
  - Error and abort alerts rendered in bold red (`Color::Red`).
  - Responsive title abbreviation on compact terminals to prevent message truncation.
- **Shortcut Nomenclature & Usability**:
  - Renamed Device Explorer action from `[Enter/A] Setup` to `[Enter/A] Select Disk`.
  - Renamed quit hint from `[Q] Quit` to `[Esc/Q] Quit`.
  - Renamed summary return hint to `[Enter / Esc / Q] Return to Explorer`.
  - Added <kbd>A</kbd> / <kbd>a</kbd> abort shortcut handler alongside <kbd>Esc</kbd> and <kbd>Ctrl+C</kbd>, with `[Ctrl+C / Esc / A] Abort Acquisition` permanently displayed during active disk imaging.

---

## [0.1.4] - 2026-09-04

### Added
- **Interactive Destination Directory in Converter**: Made the Destination Dir field fully selectable and editable in the Forensic Image Format Converter screen, supporting arrow/Tab navigation, text editing, and cursor rendering.
- **Tab Path Autocompletion**: Integrated an intelligent filesystem path completion engine for path fields (`Target Dir` in Case Setup, `Source Image Path` and `Destination Dir` in Converter):
  - Expands tilde (`~` and `~/`) to user home directory.
  - Contextual directory-only filtering for target directories and dual file/directory matching for source images.
  - Common prefix expansion and cyclic candidate navigation on repeated <kbd>Tab</kbd> presses.
  - Case-insensitive matching fallback and hidden file protection.
- **Converter Guidance & Shortcuts**: Added an in-dashboard instruction panel explaining RAW/E01 conversion modes and navigation shortcuts, plus auto-detection of conversion modes based on source file extensions (`.raw`, `.dd`, `.img`, `.E01`).

---

## [0.1.3] - 2026-09-04

### Changed
- **Permissive Dual-Licensing (`MIT OR Apache-2.0`)**: Relicensed `dfdisk` from GPL-3.0-or-later to dual `MIT OR Apache-2.0` (standard Rust open-source licensing) to maximize adoption across incident response, DFIR laboratories, enterprise, and community ecosystems.
- **Nixpkgs & NUR Integration**:
  - Modernized Nix derivations to use the `(finalAttrs: { ... })` fixpoint pattern.
  - Replaced commit revision references with explicit release `tag` pinning in `fetchFromGitHub`.
  - Qualified `lib.maintainers` and `lib.platforms` attribute scopes and updated `meta.license` to dual `[ mit asl20 ]`.
  - Added official support for the Nix User Repository (NUR) under `nur.repos.tylerstyle.dfdisk`.
- **Packaging Metadata**: Synchronized dual-licensing definitions across Arch Linux (`PKGBUILD`), Debian (`copyright`, `changelog`), and Nix Flakes.

---

## [0.1.2] - 2026-09-03

### Added
- **Integration Test Suite**: Added 6 comprehensive integration test suites (`cli_test.rs`, `hashing_test.rs`, `discovery_test.rs`, `safety_test.rs`, `case_naming_test.rs`, `engine_robustness_test.rs`) and mock test fixtures, bringing total test coverage to 151 passing tests.
- **Terminal State Recovery**: Added global panic hook to reliably restore terminal state (raw mode and mouse capture) upon abnormal exit.

### Changed
- **Dependencies Upgrade**: Upgraded crate dependencies to latest compatible versions:
  - `tokio` upgraded to `1.53`
  - `clap` upgraded to `4.6`
  - `regex` upgraded to `1.13`
  - Updated transitive dependencies (`lru`, `mio`, `smallvec`, `unicode-width`).
- **Nix Packaging**: Expanded `package.nix` fileset to include `tests/` for hermetic Nix sandbox test execution.

### Fixed
- **Asynchronous Child Process Draining**: Resolved pipe buffer deadlocks in E01 (`ewfacquire`) and rescue (`ddrescue`) engines by asynchronously draining process output streams.
- **Block Device Capacity Probing**: Enhanced `MultiHasher` capacity determination via seek/ioctl inspection, ensuring accurate progress calculation and hash verification on raw physical disks.
- **System Disk Guardrails**: Hardened recursive device inspection to detect nested LVM logical volumes, LUKS containers, and active swap volumes (with `/proc/swaps` fallbacks).
- **TUI UTF-8 Safety**: Prevented multi-byte UTF-8 boundary slicing panics across text input and status line renders in the Ratatui interface.

---

## [0.1.1] - 2026-09-01

### Changed
- **Dependencies Upgrade**: Upgraded all crate dependencies to their latest major/minor releases:
  - `ratatui` upgraded to `0.30.2`
  - `crossterm` upgraded to `0.29.0`
  - `thiserror` upgraded to `2.0.20`
  - `md-5`, `sha1`, `sha2`, and `digest` upgraded to `0.11.x`
  - `tokio` upgraded to `1.44`
  - `regex` upgraded to `1.11`
- **Nixpkgs Compliance**: Added `__structuredAttrs = true;` (RFC 140 / NPV-166) and formatted all Nix derivations with `nixfmt`.

---

## [0.1.0] - 2026-09-01

### Added
- Initial public release of `dfdisk`.
- Standard Forensic E01 disk acquisition via `libewf` with compression and segment splitting.
- Damaged media recovery mode using `ddrescue` with mapfile tracking.
- Interactive Ratatui cyber TUI dashboard with live speedometer and telemetry.
- Automatic case-based forensic evidence naming convention.
- Parallel cryptographic multi-hasher (MD5, SHA-1, SHA-256) and court-ready `.info` reports.
- Bi-directional format converter (`RAW <-> E01`).
- Multi-distro packaging: Debian (`.deb`), Arch Linux (`PKGBUILD`), and Nixpkgs / Nix Flakes.
