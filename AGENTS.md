# AGENTS.md — `dfdisk`

`dfdisk` is a forensic disk imaging, damaged-media rescue (GNU `ddrescue`), conversion (E01 via `libewf` / RAW), and hash-verification CLI/TUI tool in Rust (Ratatui + clap, MIT OR Apache-2.0). Detailed build/CI notes live in [`DEVELOPER.md`](DEVELOPER.md).

## Multi-Repo & Dependency Context
- Part of the **df-suite** integrated into `~/git/dfnix`.
- Uses sibling Cargo path dependency `../dfcore` (`~/git/dfcore`). Keep local `../dfcore` aligned with the revision in `flake.lock` when testing/releasing.
- Push/release order when `dfcore` changes: `dfcore` -> `dfdisk` -> `dfnix` (`nix flake update dfdisk`).

## Build & Verification
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
# With real libewf/ddrescue tools (both modern & legacy lines):
DFDISK_REQUIRE_TOOLS=1 nix shell nixpkgs#libewf nixpkgs#ddrescue nixpkgs#gcc -c cargo test --locked
DFDISK_REQUIRE_TOOLS=1 nix shell nixpkgs#libewf-legacy nixpkgs#ddrescue nixpkgs#gcc -c cargo test --locked
# Full Nix checks (runs both libewf & libewf-legacy):
nix flake check
```

## Safety Invariants (NEVER Break)
- **Tests must never touch host disks or require root**: keep sysfs/udev/SMART/device probes injectable and use temporary paths for `DFNIX_AUDIT_LOG` and `DFNIX_PROTECTED_FILE`.
- **Source protection**: Refuse mounted, claimed, protected-registry, and system devices; enforce kernel read-only flag on source media by default.
- **Casework provenance**: Reports embed git revisions of `dfdisk` and `dfcore` (`-dirty` if uncommitted); release builds must be clean.

## Compact Instructions
When compacting, always preserve: `dfcore` revision compatibility, test/clippy/flake check results (including `libewf-legacy`), forensic safety constraints touched, and open TODOs.
