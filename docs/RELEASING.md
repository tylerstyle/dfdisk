# Releasing dfdisk

A release is a pushed tag `v<version>`. The Release workflow
(`.github/workflows/release.yml`) then checks the version, runs the full test job,
builds every asset, publishes the GitHub release and updates the NUR recipe.
Nothing is published unless every check and build passed.

## 1. dfcore first

dfdisk builds against the dfcore checkout locked in `flake.lock` (D1: `dfcore` is
the Cargo path dependency `../dfcore`). CI, the release builds and the NUR recipe
all use that locked revision.

1. Release and push dfcore.
2. In dfdisk: `nix flake update dfcore` and commit `flake.lock`.
3. Check that `../dfcore` is at the same revision for local builds
   (`dfdisk --version` prints both revisions).

## 2. Version and changelog

The workflow refuses to run unless these agree:

- `version` in `Cargo.toml` (`[package]`)
- the `dfdisk` entry in `Cargo.lock` (run `cargo check` after editing `Cargo.toml`)
- `version` in `package.nix`
- the tag (`v` + version)
- a section `## [<version>] - <YYYY-MM-DD>` in `CHANGELOG.md` (a section still
  headed `- Unreleased` is refused); its text becomes the release notes

## 3. Dry run

Start the Release workflow by hand (Actions → Release → Run workflow) on the
commit to be tagged. It runs the version check (without a tag), the tests and
every build, including the .deb installation test, and publishes nothing.
Locally, `nix build .#default .#checks.x86_64-linux.libewf-legacy` builds and
tests the package against both libewf release lines, and
`scripts/test-ubuntu.sh` runs the whole test suite against Ubuntu 22.04's tools
(see below) in a podman or docker container as a non-root user, like CI.

## 4. Tag

```bash
git tag -a v0.2.0 -m "dfdisk 0.2.0"
git push origin v0.2.0
```

## What the workflow produces

| Asset | Built by |
|-------|----------|
| `dfdisk-v<version>-x86_64-unknown-linux-gnu.tar.gz` (+ `.sha256`) | cargo on ubuntu-22.04 |
| `dfdisk-v<version>-x86_64-unknown-linux-musl.tar.gz` (+ `.sha256`) | cross (static binary) |
| `dfdisk-v<version>-aarch64-unknown-linux-gnu.tar.gz` (+ `.sha256`) | cross |
| `dfdisk_<version>-1_amd64.deb` (+ `.deb.sha256`) | cargo-deb on ubuntu-22.04 |

Each tarball holds the binary, README.md, CHANGELOG.md, the license files and
`docs/`. The .deb job checks that `Depends` names libc6 and every external tool,
installs the package with apt on Ubuntu 22.04 and runs `dfdisk --version`.

## libewf releases the E01 engine runs with

The tests run against three libewf releases, and a release needs all three
green: 20231119 (`nix build .#default`), 20140816
(`.#checks.x86_64-linux.libewf-legacy`) and 20140807, Ubuntu 22.04's
`ewf-tools`, which the .deb depends on (the CI and release test jobs on
`ubuntu-22.04`, `scripts/test-ubuntu.sh`). 20140807 is not 20140816:

- ewfacquire 20140807 crashes (SIGSEGV) on any `-r`: its option parser hands
  the `-b` value to the retry setting. The same holds for every libewf from
  20101105 to 20140808 and from 20141002 to 20200210 (libewf history; run with
  the ewf-tools of Ubuntu 18.04, Debian 10, Debian 11, Ubuntu 20.04 and 22.04);
  20140813 (Debian 12), 20140814 (Ubuntu 24.04), 20140816 and 20231119 take
  `-r`. dfdisk therefore gives `-r` only for a retry count other than
  ewfacquire's default of 2 (the report then states "2 (ewfacquire's default;
  -r not given)"), and an E01 with another count and such a release (by the
  version `ewfacquire -V` prints) is a usage error (exit 2) at the tools step,
  in `check` too, before anything is written or sent to the source
  (`ewf::retries_option_crashes`, `ewf::check_retries_option`).
- ewfacquire 20140807 does not notice that the source's node disappeared after
  a read error (its libsmdev has no such check): it zero-fills to the end and
  reports SUCCESS, and dfdisk's presence check after the run reports "source
  lost at offset X" instead of "source lost during the acquisition".

Whatever changes how dfdisk runs a libewf tool (options, parsed output) has to
pass `scripts/test-ubuntu.sh` before it is merged, not only the Nix builds.

## Pinned tools

| What | Where | Value |
|------|-------|-------|
| Rust toolchain for fmt, clippy, tests and release builds | `RUST_TOOLCHAIN` in `ci.yml` and `release.yml` | keep both equal |
| cross | `CROSS_VERSION` in `release.yml` | `cargo install --locked --version` |
| cargo-deb | `CARGO_DEB_VERSION` in `release.yml` | `cargo install --locked --version` |
| Minimum supported Rust | `rust-version` in `Cargo.toml` | checked by the CI job "MSRV" |

To move to a newer toolchain, run `cargo clippy --all-targets -- -D warnings`
and `cargo test` with it first: new clippy lints fail CI. Raising `rust-version`
is a change worth a CHANGELOG line.

## NUR recipe (manual step)

The `update-nur` job rewrites only `version`, the source hash, `cargoHash`, the
dfcore `rev`/`hash` and `DFDISK_GIT_REV` in `pkgs/dfdisk/default.nix` of
`tylerstyle/nur-packages`. `DFDISK_GIT_REV` becomes the commit the tag names
(`git rev-parse "<tag>^{commit}"`; the recipe fetches the source by tag, so it
cannot take the commit from the fetch). The job fails when it cannot set it.
Everything else in that recipe is maintained by hand and has to follow
`package.nix` whenever it changes:

- the wrapper PATH: `wrapProgram $out/bin/dfdisk --prefix PATH : (lib.makeBinPath
  [ libewf ddrescue smartmontools util-linux systemd hdparm nvme-cli ])`
  (`package.nix` exposes the list as `passthru.runtimeTools`); hdparm and
  nvme-cli are new in 0.2.0;
- no `buildInputs` (nothing links the tools; pkg-config is not needed);
- `nativeCheckInputs = [ libewf ddrescue stdenv.cc ]` and
  `preCheck = "export DFDISK_REQUIRE_TOOLS=1"`, so the tool tests run instead of
  skipping;
- `env = { DFDISK_GIT_REV = "<commit>"; DFCORE_GIT_REV = dfcoreSrc.rev; }`,
  because build.rs cannot run git in the sandbox: the job writes the dfdisk
  commit, the dfcore revision follows the dfcore fetch it pins (a literal
  dfcore revision there is rewritten with the pin);
- the combined source tree with dfcore next to dfdisk (`sourceRoot` in the
  dfdisk directory) so that `path = "../dfcore"` resolves.

The job prints a warning for every runtime tool the recipe does not mention.
Push the recipe changes to nur-packages before the tag: the job's guard fails
on a recipe without `DFDISK_GIT_REV`. If update-nur fails, fix the recipe and
re-run the job.

## dfnix

dfnix consumes dfdisk through its flake input (`packages.<system>.default`) and
makes dfcore follow its own dfcore input. After a release, update the dfnix lock
in the dfnix repository and run its checks there.

## Screenshots

`assets/screenshots/` is rendered by `examples/render_screenshots.rs`
(`nix shell nixpkgs#imagemagick -c cargo run --example render_screenshots --
assets/screenshots --png`, then keep only the PNG files). Regenerate them when
the TUI changes and after the version bump (the TUI header shows the version),
and check that the README still describes them.
