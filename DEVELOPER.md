# Developing dfdisk

This page is for people who build dfdisk from source, change it or release it.
If you only want to use dfdisk, the [README](README.md) is the place to start.

## Building from source

dfdisk uses [dfcore](https://github.com/tylerstyle/dfcore), the shared safety
core of the df-suite, as the Cargo path dependency `../dfcore`. Check both
repositories out side by side, with dfcore at the revision locked in dfdisk's
`flake.lock`. That is also why `cargo install --git` does not work. You need
Rust 1.88 or newer (`rust-version` in Cargo.toml).

```bash
git clone https://github.com/tylerstyle/dfcore.git
git clone https://github.com/tylerstyle/dfdisk.git
git -C dfcore checkout "$(jq -r '.nodes.dfcore.locked.rev' dfdisk/flake.lock)"
cd dfdisk
cargo build --release --locked
sudo install -m 755 target/release/dfdisk /usr/local/bin/
```

Install the [tools dfdisk runs](README.md#required-tools) as well.

`dfdisk --version` prints the git revisions of dfdisk and dfcore it was built
from, with "-dirty" when a tracked file differed from that commit. Every report
records them too, so keep builds that go into casework clean.

With Nix, `nix build` builds the package (dfcore comes from the flake input),
and `nix develop` gives you a shell with the Rust toolchain, clippy, rustfmt,
cargo-deb and every runtime tool. Cargo in that shell still needs the dfcore
checkout next to dfdisk.

## Checks

Run these before you send a change; CI runs the same:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Tests with the real tools

Some tests run the real ewfacquire and ddrescue, and a C compiler for small
`LD_PRELOAD` shims (one injects read errors). They skip when a tool is missing;
`DFDISK_REQUIRE_TOOLS=1` makes them fail instead.

The tool output differs between libewf release lines, so run them against both:

```bash
DFDISK_REQUIRE_TOOLS=1 nix shell nixpkgs#libewf nixpkgs#ddrescue nixpkgs#gcc -c cargo test --locked
DFDISK_REQUIRE_TOOLS=1 nix shell nixpkgs#libewf-legacy nixpkgs#ddrescue nixpkgs#gcc -c cargo test --locked
```

nixpkgs' `libewf-legacy` (20140816) belongs to the same release line as the
`ewf-tools` that Debian and Ubuntu ship, but it is a later, maintained version.
It does not have the bugs of the older releases, for example the crash of
ewfacquire 20140807 (Ubuntu 22.04) on any `-r` option. To test against Ubuntu
22.04's real `ewf-tools` 20140807 and `gddrescue` 1.23, run:

```bash
scripts/test-ubuntu.sh                  # every test binary
scripts/test-ubuntu.sh ewf_e2e_test     # only binaries whose name starts with this
```

The script builds the test binaries on your host, then runs them as your user in
an Ubuntu 22.04 container (podman, else docker) with those packages. The
binaries must run on Ubuntu 22.04: a Nix toolchain works (`/nix/store` is
mounted read-only), so does a host with glibc 2.35 or older.

### Package builds

```bash
nix build .#default .#checks.x86_64-linux.libewf-legacy
```

Both builds run the whole test suite with the real tools
(`DFDISK_REQUIRE_TOOLS=1`), once with libewf 20231119 and once with
libewf-legacy. `nix flake check` runs both.

### How the tests stay off your disks

Tests never touch host disks and never need root. Device scans, sysfs, udev,
SMART and capacity probes are injectable, CLI tests put fake tools on PATH, and
`DFNIX_AUDIT_LOG` and `DFNIX_PROTECTED_FILE` point at temporary files. Keep it
that way in new tests.

## CI

`.github/workflows/ci.yml` runs on pushes and pull requests to main:

- formatting, clippy with `-D warnings` and the tests (`--locked`, tool tests
  required) on Ubuntu 22.04 with its own `ewf-tools` and `gddrescue`, with a
  pinned toolchain;
- a build with the minimum supported Rust version (`rust-version` in
  Cargo.toml);
- the Nix builds (default and libewf-legacy).

The CI checks out dfcore next to dfdisk at the revision locked in `flake.lock`.

## Source layout

```
src/
├── main.rs            exit codes, error printing
├── signals.rs         SIGINT/SIGTERM/SIGQUIT/SIGHUP handling shared by CLI and TUI
├── cli/               argument parsing and subcommands
├── tui/               ratatui interface
├── discovery/         device scan, identity probe, sysfs, write protection,
│                      unmount, SMART and capacity probes
├── engines/           session pipeline (one path for every engine), E01, RAW,
│                      rescue, converter, verify, piecewise hashes, external
│                      process runner, audit records, destination preflight
└── models/            outcome and exit codes, report (schema 2), case fields,
                       configuration, identity, provenance and clock
```

## Documentation

- [README.md](README.md) is written for examiners: installing and using
  dfdisk. It ships in the release tarballs and the .deb.
- [docs/exit-codes.md](docs/exit-codes.md),
  [docs/report-format.md](docs/report-format.md) and
  [docs/safety.md](docs/safety.md) are the exact reference. The exit codes are
  also documented in `--help` and the CHANGELOG; keep all of them in step with
  `src/models/outcome.rs`.
- [CHANGELOG.md](CHANGELOG.md) follows Keep a Changelog. The release workflow
  requires a dated section for the version it releases.

## Screenshots

The PNG files in `assets/screenshots/` are rendered from the TUI with invented
example data by `examples/render_screenshots.rs`. It needs ImageMagick for the
PNG files:

```bash
nix shell nixpkgs#imagemagick -c cargo run --example render_screenshots -- assets/screenshots --png
```

Keep only the PNG files. Regenerate them when the TUI changes and after a
version bump (the TUI header shows the version), and check that the README
still describes what they show.

## Releasing

[docs/RELEASING.md](docs/RELEASING.md) describes the release workflow, the
packages it builds and the NUR update.
