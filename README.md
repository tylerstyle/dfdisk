# dfdisk

<p align="center">
  <a href="https://github.com/tylerstyle/dfdisk/releases/latest">
    <img src="https://img.shields.io/github/v/release/tylerstyle/dfdisk?style=flat-square&color=blue" alt="Latest Release">
  </a>
  <a href="https://github.com/tylerstyle/dfdisk/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/tylerstyle/dfdisk/ci.yml?branch=main&style=flat-square&label=CI" alt="CI Status">
  </a>
  <a href="https://ratatui.rs/">
    <img src="https://img.shields.io/badge/Built_With_Ratatui-000?logo=ratatui&logoColor=fff&style=flat-square" alt="Built With Ratatui">
  </a>
  <a href="https://github.com/nix-community/NUR">
    <img src="https://img.shields.io/badge/NUR-nur.repos.tylerstyle.dfdisk-5277C3?style=flat-square&logo=nixos" alt="NUR Package">
  </a>
  <a href="#license">
    <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square" alt="License">
  </a>
</p>

dfdisk makes forensic images of disks on Linux. You pick a drive, enter the case
details, and dfdisk images it as E01 or RAW, checks the copy against what it read
and writes a report. The report starts with a verdict that says plainly what was
acquired and what was verified, and it lists every sector that could not be read.

You can work in an interactive terminal UI or script it from the command line.
For drives with bad sectors, dfdisk can run GNU ddrescue for you and keep the
same reporting.

<p align="center">
  <img src="assets/screenshots/device_explorer.png" alt="dfdisk device explorer with badges" width="95%">
</p>

<sub>All screenshots show invented example data.</sub>

dfdisk is part of the df-suite, next to [dfcore](https://github.com/tylerstyle/dfcore)
(the shared safety core), dfmount, dfnet and the dfnix forensic live system. It
runs on any Linux host. On dfnix it also honours the boot-time protected-device
registry and writes to the hash-chained dfnix audit log.

> **Upgrading from 0.1?** 0.2.0 is a breaking release: case number, evidence
> number and examiner are now required, and the exit codes and the report format
> changed. See [CHANGELOG.md](CHANGELOG.md).

## Contents

- [Installation](#installation)
- [Your first acquisition](#your-first-acquisition)
- [The terminal UI](#the-terminal-ui)
- [The command line](#the-command-line)
- [Damaged drives](#damaged-drives)
- [Reading the result](#reading-the-result)
- [Checking and converting images later](#checking-and-converting-images-later)
- [How dfdisk protects the evidence](#how-dfdisk-protects-the-evidence)
- [What dfdisk does not do](#what-dfdisk-does-not-do)
- [More documentation](#more-documentation)
- [License](#license)
- [Disclaimers](#disclaimers)

## Installation

You need Linux and root rights to read block devices. dfdisk runs a few
standard tools (libewf's ewf-tools, GNU ddrescue, smartmontools and others).
The Nix and Debian packages bring them along; with a prebuilt binary you install
them yourself (see [Required tools](#required-tools)).

### Debian and Ubuntu

Every release has an amd64 package with a checksum next to it. It is built on
Ubuntu 22.04, so it needs Ubuntu 22.04 or Debian 12 or newer.

```bash
VERSION=0.2.1
wget "https://github.com/tylerstyle/dfdisk/releases/download/v${VERSION}/dfdisk_${VERSION}-1_amd64.deb"{,.sha256}
sha256sum -c "dfdisk_${VERSION}-1_amd64.deb.sha256"
sudo apt install "./dfdisk_${VERSION}-1_amd64.deb"
```

apt pulls in everything dfdisk runs: `ewf-tools`, `gddrescue`, `smartmontools`,
`util-linux`, `mount`, `udev`, `hdparm` and `nvme-cli`.

### Nix and NixOS

```bash
# Try it without installing
nix run github:tylerstyle/dfdisk -- --help

# Install it into your profile
nix profile install github:tylerstyle/dfdisk
```

sudo may not find programs in your Nix profile; `sudo "$(command -v dfdisk)"`
works either way.

On NixOS, add it as a flake input:

```nix
inputs.dfdisk.url = "github:tylerstyle/dfdisk";
# environment.systemPackages = [ inputs.dfdisk.packages.${pkgs.stdenv.hostPlatform.system}.default ];
```

or take it from the [NUR](https://github.com/nix-community/NUR), which is
updated with every release:

```nix
environment.systemPackages = [ config.nur.repos.tylerstyle.dfdisk ];
```

The Nix package has all the tools it needs on its own PATH.

### Other distributions: prebuilt binaries

Every release has tarballs with the binary, this README, the changelog, the
licenses and `docs/`, each with a checksum:

- `x86_64-unknown-linux-musl`: statically linked, runs on any x86_64 Linux
- `x86_64-unknown-linux-gnu`: built on Ubuntu 22.04
- `aarch64-unknown-linux-gnu`: 64-bit ARM

```bash
VERSION=0.2.1
TARGET=x86_64-unknown-linux-musl
wget "https://github.com/tylerstyle/dfdisk/releases/download/v${VERSION}/dfdisk-v${VERSION}-${TARGET}.tar.gz"{,.sha256}
sha256sum -c "dfdisk-v${VERSION}-${TARGET}.tar.gz.sha256"
tar -xzf "dfdisk-v${VERSION}-${TARGET}.tar.gz"
sudo install -m 755 "dfdisk-v${VERSION}-${TARGET}/dfdisk" /usr/local/bin/
```

Then install the [required tools](#required-tools) with your package manager.

### Building from source

dfdisk builds against a checkout of dfcore next to it, so
`cargo install --git` does not work. [DEVELOPER.md](DEVELOPER.md#building-from-source)
has the steps.

### Required tools

| Tool | Debian / Ubuntu package | Nix package | What dfdisk uses it for |
|------|-------------------------|-------------|-------------------------|
| `ewfacquire`, `ewfverify`, `ewfinfo`, `ewfexport` | `ewf-tools` | `libewf` | E01 images: acquiring, verifying, converting |
| `ddrescue` | `gddrescue` | `ddrescue` | damaged drives (`--rescue`) |
| `smartctl` | `smartmontools` | `smartmontools` | SMART snapshots in the report |
| `hdparm` | `hdparm` | `hdparm` | finding hidden areas (HPA/DCO), read-only |
| `nvme` | `nvme-cli` | `nvme-cli` | NVMe namespace capacity |
| `lsblk` | `util-linux` | `util-linux` | finding devices |
| `umount` | `mount` | `util-linux` | `dfdisk unmount`, `--auto-unmount` |
| `udevadm` | `udev` | `systemd` | device identity |
| `timedatectl` (optional) | `systemd` | `systemd` | whether the clock is NTP-synchronised |

If a tool the chosen engine needs is missing, dfdisk stops with exit code 4
before it writes anything or touches the device. `dfdisk check` tells you up
front.

> **Older ewf-tools.** Some ewf-tools releases, among them 20140807 in Ubuntu
> 22.04, crash when ewfacquire is given a retry count. With those, dfdisk
> leaves ewfacquire at its default of 2 read retries and refuses another
> `--retries` value for E01 images before it starts (exit 2). Ubuntu 24.04,
> Debian 12 and Nix are not affected.

### Checking the installation

```bash
dfdisk --version   # versions and git revisions of dfdisk and dfcore
dfdisk list        # the disks and partitions dfdisk sees
```

## Your first acquisition

1. Connect the evidence drive, ideally through a hardware write blocker.
2. Mount the drive you want to store the image on, for example at
   `/mnt/evidence`. It must not be tmpfs, and it needs room for the image.
3. Start dfdisk as root: `sudo dfdisk`.
4. Pick the evidence drive and press Enter. If it shows MOUNTED, press U first
   to unmount it.
5. Fill in case number, evidence number and examiner (the other fields are
   optional), choose the destination, and press F5.
6. Check the confirmation sheet: is this the drive you meant? Compare the serial
   number with the label on the drive. Type the characters dfdisk asks for and
   press Enter.
7. Wait for the result. The verdict comes first, and the full report is in the
   destination folder.

The same on the command line, first as a dry run and then for real:

```bash
sudo dfdisk check /dev/sdb -o /mnt/evidence/case-4192 \
  --case "VG-2026/4192" --evidence SSD01 --examiner "J. Doe #4192"

sudo dfdisk acquire /dev/sdb -o /mnt/evidence/case-4192 \
  --case "VG-2026/4192" --evidence SSD01 --examiner "J. Doe #4192"
```

This writes an E01 image, verifies it, and leaves files like
`vg_2026_4192_ea01_ssd01_EXS970A0004192E.E01` and
`vg_2026_4192_ea01_ssd01_EXS970A0004192E.info` (the report) in
`/mnt/evidence/case-4192`.

## The terminal UI

Run `sudo dfdisk` (or `sudo dfdisk tui`). Press F1 on any screen to see its
keys (or `?`, when you are not typing in a text field).

**Device explorer.** Lists every disk and partition. Badges tell you what you
are looking at:

| Badge | Meaning |
|-------|---------|
| SYSTEM | holds the running system; refused |
| PROTECTED | protected by the dfnix registry; refused |
| MOUNTED | has mounted filesystems; refused until unmounted (U) |
| IN-USE | held open by LUKS, LVM, md or a loop device; close that first |
| RO | already read-only |
| HPA / DCO | a hidden area was found (press H to probe a disk) |

Enter or A acquires the selected device, U unmounts it (audited, asks first),
H probes it for hidden areas, R refreshes, C opens the converter, V re-verifies
an image, L shows the last result and Q quits.

**Case setup.** Case number, evidence number, examiner and destination are
required. Grey text is only an example, never a value. In an empty case or
evidence field, → or End takes the suggestion from your last acquisition. Here
you also choose the engine (E01, RAW or RESCUE), compression, digests and the
other options; the ones that do not apply to the engine are greyed out. F4
completes paths, F5 opens the confirmation sheet.

<p align="center">
  <img src="assets/screenshots/case_setup.png" alt="dfdisk case setup" width="95%">
</p>

**Confirmation sheet.** Shows what the checks found: source identity, write
protection, hidden areas, destination and settings. Nothing has been written
yet. To start, type the last four characters of the serial number (the whole
serial if it is shorter, the evidence number if the drive has none) and press
Enter. If the destination has less free space than the drive holds, F6 lets you
accept that for an E01 image (compression may make it fit).

<p align="center">
  <img src="assets/screenshots/confirmation.png" alt="dfdisk confirmation sheet" width="95%">
</p>

**Acquisition.** Shows progress. Esc never aborts. A asks before aborting; an
aborted run still writes its report. If the terminal goes away, the run carries
on and writes its report.

<p align="center">
  <img src="assets/screenshots/acquisition.png" alt="dfdisk acquisition progress" width="95%">
</p>

**Result.** The verdict comes first and the full report scrolls below it. The
screen stays until you acknowledge it with Enter or Esc. V re-verifies the
image, C converts a rescue image to E01.

<p align="center">
  <img src="assets/screenshots/result.png" alt="dfdisk result screen with the verdict first" width="95%">
</p>

**Converter (C) and verifier (V).** The converter turns RAW into E01 and E01
into RAW. It fills empty case fields from the image's dfdisk report and tells
you which ones it took; the confirmation sheet shows where each recorded value
comes from. The verifier re-checks an image against its report.

dfdisk remembers examiner, authority, the last destination and the last case and
evidence numbers in `$XDG_CONFIG_HOME/dfdisk/profile.toml` (usually
`~/.config/dfdisk/profile.toml` of the user dfdisk runs as) and offers them next
time.

Ctrl+X dismisses the messages on screen. Ctrl+C quits, and asks first while a
run or an unmount is busy.

## The command line

### Acquiring

`acquire` needs the source, a destination directory (`-o`) and the three case
fields `--case`, `--evidence` and `--examiner`. To try a command first, run it
with `check` instead of `acquire`: it makes every check an acquisition would
make and writes nothing, not even the read-only flag.

```bash
# E01 (the default), with chain-of-custody details
sudo dfdisk acquire /dev/sdb -o /mnt/evidence/case-4192 \
  --case "VG-2026/4192" --evidence SSD01 --examiner "J. Doe #4192" \
  --authority "Cybercrime Unit" --seal "S-123456"

# RAW, carrying on over unreadable sectors, and reading the drive a second time
sudo dfdisk acquire /dev/sdb -o /mnt/evidence/case-4192 \
  --case "VG-2026/4192" --evidence SSD01 --examiner "J. Doe #4192" \
  --format raw --on-read-error zero-fill --verify-source
```

The source can be a device path (`/dev/sdb`, `/dev/nvme0n1`,
`/dev/disk/by-id/...`), a bare device name (`sdb`, refused if a file `./sdb`
exists too) or an image file.

dfdisk never invents case values. Fields you leave out are recorded as "(not
provided)". The E01 header and the report hold the same values.

### Choosing a format

| | E01 (`--format e01`, default) | RAW (`--format raw`) | Rescue (`--rescue`) |
|---|---|---|---|
| Best for | everyday acquisitions | tools that want a plain image | drives with bad sectors |
| Output | `<base>.E01`, `.E02`, … (compressed, segmented) | one `<base>.raw` file, never split | `<base>.raw` plus ddrescue's `<base>.map` |
| Digests | MD5 always, SHA-1 and SHA-256 by choice; checked with `ewfverify` | MD5, SHA-1, SHA-256 while reading, plus a SHA-256 per piece (1 GiB by default); the image is re-read and hashed | computed from the image afterwards; `--verify-source` compares them with a second read of the drive |
| Unreadable sectors | zeros in the image, every range in the report | `stop` (default): stops at the first one and reports its offset; `zero-fill`: zeros, every range in the report | zeros in the image, every range in the report; can be resumed |

Before verifying, dfdisk flushes the image to the destination and drops it from
the page cache, so the check reads it back from the disk rather than from
memory.

If the drive drops out during an E01 acquisition, the result is INCOMPLETE with
the offset where the drive was lost. dfdisk stops ewfacquire once it has made no
progress for 60 seconds and the drive is gone or smaller.

### Options

`dfdisk acquire --help` lists every option with its default. The ones you will
use most:

| Option | Meaning |
|--------|---------|
| `-o, --output-dir <DIR>` | where the image and reports go (created if missing) |
| `--case`, `--evidence`, `--examiner` | required case fields |
| `--ea`, `--authority`, `--description`, `--notes`, `--seal`, `--seized-at`, `--seized-location` | optional case and chain-of-custody fields; EA defaults to `01` |
| `--format e01\|raw` | image format (default `e01`) |
| `--compression none\|fast\|best`, `--split none\|2G\|4G` | E01 compression and segment size (default `fast`, `2G`; `none` writes one segment) |
| `--digests md5,sha1,sha256` | digests to compute and verify (default all three; E01 always includes MD5) |
| `-r, --retries <N>` | read retries for bad sectors, E01 and rescue (default 2) |
| `--on-read-error stop\|zero-fill` | RAW: stop at the first unreadable sector, or zero it and go on (default `stop`) |
| `--piece-size <SIZE>` | RAW: size of the piecewise SHA-256 pieces, or `off` (default 1 GiB) |
| `--verify-source` | read the drive a second time and compare |
| `--rescue`, `--resume`, `--rescue-to-e01` | see [Damaged drives](#damaged-drives) |
| `--expect-serial`, `--expect-wwn`, `--expect-size` | refuse unless the drive has this serial, WWN or size |
| `--refuse-hidden-areas` | refuse when an HPA or DCO is found (default: warn) |
| `--smart off\|basic\|full` | SMART queries before (and after a rescue) (default `basic`) |
| `--write-protect auto\|off` | set the kernel read-only flag (default) or only record it |
| `--auto-unmount` | unmount the drive's filesystems first (audited) |
| `--allow-tmpfs`, `--allow-low-space` | accept a tmpfs destination, or an E01 destination with less free space than the drive |
| `--error-granularity <SECTORS>` | E01: ewfacquire's error granularity |
| `--json` | print the final report as JSON on stdout; progress goes to stderr |
| `-v, --verbose` | show every log line of the engines and tools |

### Mounted drives

Many desktops mount a USB drive the moment you plug it in, and dfdisk refuses
mounted drives. `dfdisk unmount` unmounts everything on the drive, deepest
first, checks that nothing stayed mounted and records it in the audit log:

```bash
sudo dfdisk unmount /dev/sdb
```

It never forces or lazily unmounts, and it leaves system mounts and protected
devices alone. Open LUKS, LVM or md devices on the drive are reported but not
closed; close them yourself. `--auto-unmount` does the same as part of
`acquire`, and U does it in the TUI.

### Other commands

```bash
dfdisk list                                  # disks and partitions with their state
dfdisk list --json                           # the same for scripts
sudo dfdisk list --smart                     # with SMART health (does not wake disks in standby)
dfdisk verify <image> --report <base>.info.json
dfdisk convert <image> --to e01|raw -o <dir>
```

### Scripting

Every command exits with a [documented code](#exit-codes), and `--json` prints a
versioned JSON result on stdout while progress and messages go to stderr:

```bash
sudo dfdisk acquire /dev/sdb -o /mnt/evidence/case-4192 \
  --case "VG-2026/4192" --evidence SSD01 --examiner "J. Doe #4192" \
  --json > result.json
echo "exit code $?"
```

[docs/report-format.md](docs/report-format.md#other-json-output---json) describes
the JSON of every command.

### Long runs, SSH and Ctrl+C

- **Ctrl+C** (or SIGTERM, SIGQUIT) stops an acquisition cleanly. ewfacquire gets
  15 seconds and ddrescue 30 seconds to finish (so ddrescue can save its map).
  The partial image is kept, the report says ABORTED and dfdisk exits with 8. A
  second Ctrl+C stops the tool at once; the report is still written.
- **A closed terminal or SSH session** does not stop the acquisition. It finishes
  without a terminal and writes its report. You cannot re-attach to it, so run
  long acquisitions over SSH in tmux or screen.
- **If dfdisk itself is killed** (SIGKILL, out of memory, a crash), the tool it
  runs is stopped too, but no report can be written.
- **An unmount is never cut short.** dfdisk finishes it, checks it and records
  it before it exits.

## Damaged drives

For a drive with bad sectors, use the rescue engine. It runs GNU ddrescue, which
reads the healthy areas first, comes back for the difficult ones and keeps track
of everything in a map file.

```bash
sudo dfdisk acquire /dev/sdc -o /mnt/evidence/case-4192 \
  --case "VG-2026/4192" --evidence HDD02 --examiner "J. Doe #4192" \
  --rescue --rescue-to-e01
```

What to expect:

- **Bad sectors** end up as zeros in the image and are listed in the report.
  If nothing else is missing, the result is COMPLETED WITH READ ERRORS.
- **Areas ddrescue never got to** make the result INCOMPLETE.
- **Verification.** ddrescue does not hash while it reads, so a clean rescue is
  COMPLETE, NOT VERIFIED. Only `--verify-source`, a second full read of the
  drive, can make it VERIFIED. Weigh that against the state of the drive.
- **Interrupted?** Run the same command again with `--resume` added. dfdisk makes sure
  it is the same drive (see [docs/safety.md](docs/safety.md#resuming-a-rescue))
  and keeps the earlier session's report. The TUI offers to resume when it finds
  a map for the same evidence.
- **Zeros are written by dfdisk.** After every ddrescue run, dfdisk itself
  writes zeros over the bad areas, so leftovers of an interrupted session cannot
  stay in the image. If those areas held any data, dfdisk saves it first in
  `<base>.zeroed-N.bin`, with offsets and SHA-256 in `<base>.zeroed-N.tsv`.
- **`--rescue-to-e01`** converts the finished image into an E01 next to it, with
  its own verified report. The E01 notes carry the rescue's bad-sector summary
  (the first 20 ranges); the E01's own error list stays empty, because
  ewfacquire read a file without errors. Keep the rescue reports with the E01:
  they are the full record of what was unreadable.

## Reading the result

### Verdicts and exit codes

Every acquisition ends with one verdict. It is worked out from what the run
measured, the same way for every engine, and it is also the exit code.

| Verdict | Exit | What it means |
|---------|-----:|---------------|
| VERIFIED | 0 | The whole drive was read without errors, and the image digests match the ones computed while reading (for a rescue: a second read of the drive). |
| COMPLETE, NOT VERIFIED | 9 | Everything was read without errors, but there was nothing independent to compare with, for example a rescue without `--verify-source`. |
| COMPLETED WITH READ ERRORS | 7 | The image has the full length, but some sectors could not be read and are zeros. The digests describe the image with those zeros, not the drive. |
| INCOMPLETE | 6 | Part of the drive is not in the image: the run stopped early, areas were never read, the drive disappeared or changed, or the destination filled up. |
| HASH MISMATCH | 5 | A digest computed again (from the image, or from a second read of the drive) differs. |
| VERIFICATION FAILED | 4 | The check could not run or could not finish. |
| ABORTED | 8 | You or a signal stopped the run. The partial output and the report are kept. |

"ALL HASHES MATCH" appears only with VERIFIED.

#### Exit codes

Codes 1 to 3 mean that no acquisition ran. The full list:

| Code | Meaning |
|-----:|---------|
| 0 | verified |
| 1 | internal error; please report it |
| 2 | usage error; nothing written |
| 3 | refused by a safety check; nothing acquired, the message says why |
| 4 | failed: could not run, or the verification could not run or finish |
| 5 | hash mismatch |
| 6 | incomplete |
| 7 | completed with read errors (sectors replaced by zeros) |
| 8 | aborted |
| 9 | complete but not verified |

[docs/exit-codes.md](docs/exit-codes.md) has the precedence rules, every refusal
and the codes of each subcommand.

### What you find in the destination

Files are named `{case}_{ea}_{evidence}_{serial}`, for example
`vg_2026_4192_ea01_ssd01_EXS970A0004192E`. dfdisk never overwrites an existing
file and refuses names longer than 255 bytes rather than shortening them.

| File | What it is |
|------|------------|
| `<base>.E01`, `.E02`, … or `<base>.raw` | the image |
| `<base>.info` | the report, starting with the verdict |
| `<base>.info.json` | the same report for scripts and tools |
| `<base>.pieces.tsv` | RAW: SHA-256 of every piece, to locate a change later |
| `<base>.map`, `<base>.identity.json` | rescue: ddrescue's map and the drive's identity |
| `<base>.zeroed-N.bin`, `.tsv` | rescue, only when needed: data that dfdisk replaced with zeros |
| `<base>.ewfacquire.log` | E01: ewfacquire's own log |
| `<base>.smart-before.json`, `<base>.smart-after.json` | the raw SMART output |
| `audit-<boot_id>.jsonl`, `.head` | a copy of the audit log and its head hash |

The report records the drive's identity (and where its serial came from), write
protection, hidden areas, SMART, the settings used, timestamps with the clock's
NTP state, every unreadable range, all digests, every external command with its
exit status, the versions of dfdisk, dfcore and the tools, and the audit anchor.
Unreadable ranges are marked `substituted` (zeros in the image) or `unread` (not
in the image at all). The text report lists the first 200, the JSON report all
of them.

[docs/report-format.md](docs/report-format.md) describes every file, section and
field.

## Checking and converting images later

### Verifying

```bash
dfdisk verify <base>.E01 --report <base>.info.json   # against the report
dfdisk verify <base>.raw --sha256 <hex>              # against digests you give
dfdisk verify <base>.raw --pieces <base>.pieces.tsv  # piece by piece
```

E01 images are also checked against the digests they store. Split RAW images
(`.001`, `.002`, …) work too. A digest you asked for that could not be computed
counts as a failure, never as a pass. The result goes into an addendum
`<image>.verify-<time>.txt` next to the image; the original report is never
changed.

### Converting

```bash
dfdisk convert <base>.raw --to e01 -o /mnt/evidence/case-4192
dfdisk convert <base>.E01 --to raw -o /mnt/export
```

A conversion is verified and gets its own report, `<base>.conversion.info`
and `.conversion.info.json`, which points to the original report. libewf's log
goes to `<base>.conversion.log`.

Case details come from the image's dfdisk report next to it (or from the E01
header). Without one, give `--case`, `--evidence` and `--examiner`.

A few things to know:

- The unreadable ranges of the original acquisition carry over into the
  conversion report.
- A damaged or unfinished E01 is converted as far as libewf can read it. The
  result is INCOMPLETE, and the parts it could not read are listed.
- An image whose own report says HASH MISMATCH or VERIFICATION FAILED converts
  to at best COMPLETE, NOT VERIFIED.
- RAW images must be a whole number of 512-byte sectors.
- An E01 made by `--rescue-to-e01`, converted back to RAW without the rescue
  report next to it, is at best COMPLETE, NOT VERIFIED, because its bad-sector
  list lives only in its notes. The conversion report quotes those notes.

## How dfdisk protects the evidence

In short:

- **It never writes to the drive.** dfdisk only reads, plus identify-style
  queries (hdparm, smartctl, nvme) that the report records. `--smart off` sends
  no SMART command.
- **It makes sure it is the right drive.** The identity is checked when you
  pick the drive, right before the start and at the end. A drive that changed is
  refused; one that changes or disappears during the run makes the result
  INCOMPLETE. `--expect-serial` and friends pin it to what is written on the
  label.
- **It refuses rather than guessing.** System disks, devices protected on dfnix,
  mounted drives, drives with active swap and drives held by LUKS, LVM, md or a
  loop device are refused, with no override. Unmounting is always a separate,
  audited step.
- **It holds the drive exclusively** for the whole run, so nothing can mount it
  in the meantime.
- **It sets the kernel read-only flag** on the drive, its partitions and
  everything it sits on, and leaves it set afterwards
  (`blockdev --setrw /dev/sdb` clears it for one device node). This is not a
  hardware write blocker; use one where your procedures require it.
- **It checks the destination first:** not on the source, not tmpfs, enough
  space, file size limits of FAT, no existing files of the same name. It keeps
  1 MiB in reserve so the report always fits.
- **It reports hidden areas** (HPA and DCO) loudly and never changes them.
  `--refuse-hidden-areas` turns the warning into a refusal.
- **It writes an audit trail.** Acquisitions, refusals, unmounts, verifications
  and conversions go into the hash-chained audit log (`/run/dfnix/audit.jsonl`,
  or wherever `DFNIX_AUDIT_LOG` points). On dfnix an acquisition that cannot be
  recorded does not start. Elsewhere the report says when the log could not be
  written.
- **It labels the clock.** Timestamps say whether the clock was
  NTP-synchronised.

[docs/safety.md](docs/safety.md) has the exact rules.

## What dfdisk does not do

- No AFF4 images. RAW images are never split; use E01 for segmented images.
- It does not remove or change HPA/DCO areas. An image covers what the drive
  reports as its size.
- It does not make a drive read-only in hardware. It sets the kernel flag and
  records what it found.
- A rescue is VERIFIED only after a second read of the drive matched, because
  ddrescue does not hash while it reads.
- An acquisition survives a closed terminal but cannot be re-attached; use tmux
  or screen over SSH.
- Optical drives (`/dev/sr*`) are not listed and not acquired.
- Linux only.

## More documentation

- [docs/exit-codes.md](docs/exit-codes.md): exit codes, refusals and signals in
  detail
- [docs/report-format.md](docs/report-format.md): every output file and report
  field
- [docs/safety.md](docs/safety.md): the safety rules in detail
- [CHANGELOG.md](CHANGELOG.md): what changed in each release
- [DEVELOPER.md](DEVELOPER.md): building, testing and contributing

## License

dfdisk is dual-licensed under either of

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Disclaimers

### Validation and chain of custody

dfdisk is not a certified or independently validated tool. Its tests cover the
logic described here, and the dfnix project runs it in virtual-machine tests on
prepared evidence disks, but examiners remain responsible for validating dfdisk,
their write blockers, host systems and procedures against the standards and
rules of evidence that apply to them (for example ISO/IEC 17025, ISO/IEC 27037,
ASTM E3016) before using it on casework.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, INCLUDING
LOSS OF EVIDENCE OR DATA, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

### Trademarks

EnCase and the Expert Witness Format are trademarks of OpenText Corporation.
Linux is a registered trademark of Linus Torvalds. libewf is maintained by
Joachim Metz (libyal); GNU ddrescue is part of the GNU project. These names are
used only to describe compatibility; dfdisk is an independent project and is not
affiliated with or endorsed by any of their owners.
