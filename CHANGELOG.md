# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
