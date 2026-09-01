# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
