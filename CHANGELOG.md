# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

dfdisk 0.2.0 is a rework driven by a review of 0.1.10 (items C1-C2,
H1-H10, M1-M12 and feature proposals F1-F12 below). Its reports are meant to be
read in court: every statement a report makes is derived from measured facts,
and when something was not done the report says so.

### Breaking changes

- **Required case fields.** `acquire` (and the TUI) require `--case`,
  `--evidence` and `--examiner`. The 0.1 placeholder defaults (`CASE001`, `cf01`,
  `Forensic Examiner`, `Law Enforcement / DFIR Unit`, `Physical Storage Media`)
  are gone; no placeholder is ever recorded. `convert` takes the case fields from
  `<source>.info.json` or requires them.
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
  `dfdisk unmount` / `--auto-unmount`), as are sources with holders (they have
  to be closed first), sources with active swap, sources in use (`O_EXCL`), tmpfs
  destinations (unless `--allow-tmpfs`), E01 destinations with less free space
  than the source (unless `--allow-low-space`) and empty sources (size 0: no
  medium, or the size is unknown).
- **Write protection on by default.** `--write-protect auto` sets the kernel
  read-only flag (BLKROSET) on the source and leaves it set; `off` only records.
- **SMART** is no longer queried during device scans; `list --smart` asks for it
  (with `-n standby`, so a sleeping disk is not woken).
- **`list --json`** prints one object (`schema_version` 1: registry state,
  active swap, scan notes, `devices` with partitions and stacked devices nested
  in `children`) instead of 0.1's array of devices.
- **TUI exit code.** The TUI exits with the exit code of a result the examiner
  did not acknowledge on screen (for example a run that finished after SIGHUP),
  0 otherwise, and 1 on a terminal failure.
- **TUI keys.** Esc never aborts; aborting needs a y/N confirmation; Tab and
  Shift-Tab always move between fields and path completion has its own key.
- **Packaging.** The .deb depends on `$auto, ewf-tools, gddrescue, smartmontools,
  util-linux, udev, hdparm, nvme-cli`; the Arch and nixpkgs files under
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
  shows a confirmation sheet.
- **H1** The TUI hid the verdict: the result screen starts with the verdict
  banner, coloured by outcome, shows the key numbers and paths, scrolls the full
  report and stays until acknowledged; errors no longer expire.
- **H2** No signal handling: SIGINT/SIGTERM abort gracefully (SIGINT to the
  tool's process group, grace period, then SIGTERM and SIGKILL), a second SIGINT
  kills at once, SIGHUP lets the run finish headless; every engine keeps its
  partial output; the report and the audit "finished" record are written on
  every path.
- **H3** The converter overwrote outputs and verified nothing: existing outputs
  are refused before any tool runs, destination checks apply, the output is
  verified against the source digests, it writes `<base>.conversion.info` /
  `.conversion.info.json` and audit records, abort works, sizes that are not a
  multiple of 512 bytes are refused, split RAW inputs are converted completely
  or refused.
- **H4** Rescue reports were not truthful: read-error ranges and counts come
  from the ddrescue mapfile, untried areas make the run INCOMPLETE, the map is
  hashed and listed, a resume requires the same device (identity sidecar) and
  passes `-I`, the earlier report is kept as `<base>.info.session-N`, and the TUI
  offers to resume. The verdict explanation follows what happened: a rescue is
  INCOMPLETE "because the map lists unfinished areas" only when it does and
  nothing else stopped it, a VERIFIED rescue names the second read of the
  source it was compared with, and a second read that differs is labelled by
  what was compared (acquisition digests or the image).
- **H5** Write protection was not checked or recorded: the read-only state of
  the source and its partitions, holders, mounts and the exclusive open are
  recorded; BLKROSET is set by default.
- **H6** Audit trail gaps: (a) the export is per boot and never replaces another
  boot's chain; (b) refusals are recognised by type, not by message text;
  (c) the "finished" record always carries the outcome, the digests known and
  the SHA-256 of both reports; (d) an unwritable audit log refuses on dfnix and
  is stated in the report and the UI elsewhere; (e) tests no longer mirror
  records into the host journal (dfcore 0.2.0).
- **H7** Unmount: `dfdisk unmount` and `--auto-unmount` collect the mounts of
  the source and all its descendants by device number, check the registry and
  system mounts before unmounting anything, unmount deepest first, verify that
  nothing remains and write an audit record. The output directory is created
  only after every destination check. The registry is matched by device number
  (device-mapper paths), and an ambiguous bare device name is refused.
- **H8** TUI start and abort hazards: required fields, typed confirmation
  (last four characters of the serial, the whole serial when shorter, the
  evidence number without a serial), source identity on every screen, a
  scrolling device table that keeps the serial visible, abort with confirmation.
- **H9** Exit codes: see Breaking changes; errors are printed once.
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
  image that cannot be fsynced fails the verification (exit 4); one that cannot
  be evicted is noted in the verification method ("the re-read may have come
  from memory"); the method states the fsync and eviction only when they
  happened.
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
  mouse capture, partitions can be selected.
- **M10** Tests: no host disks, fake tools on PATH, tool tests fail instead of
  skipping when `DFDISK_REQUIRE_TOOLS=1` (set in the Nix build and in CI),
  modules are compiled once (the binary uses the library).
- **M11** RAW: source reads use `O_DIRECT` with aligned buffers (buffered reads
  with page-cache eviction where unsupported, noted in the report), a bad
  sector is located exactly, interrupted reads are retried, and
  `--on-read-error zero-fill` continues over unreadable sectors.
- **M12** `dfdisk verify`: a requested digest that was not computed is a failure,
  never a pass; `.Ex01` and `.E02` segment families are recognised as EWF.
- Low: `-r` above 255 is a usage error instead of silently becoming 2; `-m` and
  `-M` (media type and flags) are set from the source; firmware and other device
  strings are sanitised; false README claims removed; runtime tools are no longer
  build inputs of the Nix package; the Debian copyright covers both licenses;
  `rust-version` is declared; active swap files on the source are refused by
  name; `/iso`, `/run/initramfs` and swap join the system-mount list.

### Added

- **F1** One verdict model and read-error table for all engines (ranges from
  `ewfinfo -e`, the ddrescue map or the RAW engine), one function deciding the
  verdict.
- **F2** Identity pinning and a confirmation sheet with a typed serial suffix.
- **F3** Write-protection capture and enforcement (sysfs read-only state,
  holders, `O_EXCL`, BLKROSET), recorded in the report and the audit log.
- **F4** HPA/DCO and NVMe capacity detection.
- **F5** `<base>.info.json`, tool versions and command lines, kernel, host and
  dfnix revision, dfdisk and dfcore git revisions (`dfdisk --version`), clock and
  NTP state with the RTC offset, documented exit codes, `dfdisk check` (dry run),
  `acquire --json`, `list --json`.
- **F6** Re-verification as an audited addendum (`dfdisk verify`, TUI re-verify
  screen, `--report`, `--pieces`) and an optional second read of the source
  (`--verify-source`).
- **F7** Piecewise SHA-256 (`--piece-size`, `<base>.pieces.tsv`) in the report
  and the audit record.
- **F8** Persistent result screen; SIGHUP-resilient headless completion and a
  warning when the TUI runs over SSH outside tmux or screen.
- **F10** `--rescue-to-e01`: a finished rescue is converted to E01 next to the
  rescue image; the rescue's verdict, read-error summary and zero-filled sector
  ranges go into the E01 notes and the conversion report, which names the rescue
  report by path and SHA-256. The ddrescue map is not imported into the E01 as
  EWF error ranges.
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
- The flake check `libewf-legacy` builds and tests dfdisk against libewf
  20140816, the release line of the Debian/Ubuntu `ewf-tools` package.

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
