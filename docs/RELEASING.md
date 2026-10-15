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
tests the package against both libewf release lines.

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
Update the recipe in nur-packages before or right after pushing the tag.

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
