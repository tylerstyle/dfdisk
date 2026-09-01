# dfdisk 🔍💾
> **Modern Forensic Disk Imaging, Damaged Media Rescue & Format Conversion CLI/TUI for Digital Forensics and Criminal Investigations.**

`dfdisk` is a high-performance terminal utility designed for DFIR examiners, law enforcement investigators, and forensic technicians. It combines rock-solid hardware discovery, safety guardrails, automated evidence naming, dual-hash integrity verification (MD5, SHA-1, SHA-256), and bi-directional conversion between **Expert Witness Format (`.E01`)** and **RAW (`.raw`/`.dd`)** images with a cyberpunk/forensic **Ratatui TUI** dashboard.

---

## ⚡ Key Features

- **Standard Forensic E01 Acquisition**: Powered by `libewf` (`ewfacquire`) for full EnCase 6/7 format compatibility, parallel multi-threaded Deflate compression, custom segment splitting (2GB, 4GB, unlimited), and bad sector zeroing.
- **Damaged Media Rescue Mode**: Integrated `ddrescue` multi-pass engine with non-destructive `.map` logfiles for failing hard drives and damaged flash media.
- **Automatic Evidence Naming Pipeline**: Automatically sanitizes and standardizes output filenames based on case inputs:
  $$\texttt{\{case\}\_\{location/ea\}\_\{evidence\}\_\{serial\}}\mathbf{.e01}$$
  *Example:* `VG12345/26` + `01` + `cf01` + `S4GFNX0T501075` $\rightarrow$ `vg12345_26_ea01_cf01_S4GFNX0T501075.e01`
- **Court-Ready `.info` Forensic Certificate**: Automatically writes sidecar audit documentation containing all hardware serials, bus topology, partition maps, SMART health status, timestamps, and matching pre/post cryptographic hashes.
- **Hardware Probing & Safety Guardrails**:
  - Deep inspection via `lsblk`, `udevadm`, `smartctl`, and `/sys/block`.
  - **System Disk Protection**: Automatically detects and prevents accidental acquisition/overwrite of OS root (`/`), `/boot`, `/nix`, or active swap disks with bright safety alerts.
  - **Mount Detection & Safe Unmounting**: Identifies mounted partitions and provides one-key safe unmount (`umount`) routines.
- **Bi-Directional Format Conversion**:
  - `RAW -> E01` (with full case headers, split sizes, and compression).
  - `E01 -> RAW` (with streaming hash verification).
- **SIMD Multi-Hasher & Verifier**: Fast parallel calculation and verification of MD5, SHA-1, and SHA-256 hashes.
- **Sleek Ratatui TUI**: Dark forensic cyber aesthetic with live speedometer, countdown ETA, bad sector counter, split segment monitor, and real-time engine telemetry.

---

## 🚀 Quick Start

### Nix Environment (Recommended)

To launch a shell with all required forensic dependencies (`libewf`, `smartmontools`, `ddrescue`, `rustc`, `cargo`):

```bash
nix-shell
```

### Build

```bash
cargo build --release
```

The resulting binary will be located at `./target/release/dfdisk`.

---

## 🖥️ Usage

### 1. Launch Interactive TUI (Default)

```bash
sudo dfdisk
```

#### TUI Keyboard Shortcuts:
- **Device Explorer Screen**:
  - `↑` / `↓` / `j` / `k`: Select device
  - `Enter` / `a` / `F5`: Setup acquisition for selected device
  - `u` / `F3`: Safely unmount active partitions on selected device
  - `r` / `F2`: Rescan / refresh storage media
  - `c` / `F7`: Switch to Image Converter mode (RAW $\leftrightarrow$ E01)
  - `q` / `Esc`: Quit
- **Case Setup Screen**:
  - `Tab` / `↓`: Next input field
  - `Shift+Tab` / `↑`: Previous input field
  - `Left` / `Right` / `Space`: Toggle options (Format, Split Size, Compression, Hashes, Engine)
  - `F5` / `Enter` on start button: Begin acquisition
  - `Esc`: Return to Device Explorer
- **Live Acquisition Monitor**:
  - `Ctrl+C` / `Esc`: Abort acquisition

---

### 2. CLI Automation & Scripting

#### List Connected Storage Media
```bash
dfdisk list
dfdisk list --json
```

#### Acquire Target Disk to E01
```bash
sudo dfdisk acquire /dev/sdb \
  --case "VG12345/26" \
  --ea "01" \
  --evidence "cf01" \
  --examiner "Det. J. Doe #4192" \
  --authority "Police CID / DFIR Unit" \
  --description "Suspect Kingston USB Drive" \
  --output-dir /mnt/evidence/cases/ \
  --format e01 \
  --split 2G \
  --compression fast \
  --auto-unmount
```

#### Recover Damaged Storage Media (ddrescue Mode)
```bash
sudo dfdisk acquire /dev/sdc \
  --case "VG12345/26" \
  --evidence "hd01" \
  --rescue \
  --output-dir /mnt/evidence/cases/
```

#### Convert Image Formats (RAW $\leftrightarrow$ E01)
```bash
# Convert RAW to E01
dfdisk convert evidence.raw --to e01 --case "VG12345/26" --evidence "cf01" -o /mnt/evidence/

# Convert E01 to RAW
dfdisk convert evidence.E01 --to raw -o /mnt/evidence/
```

#### Cryptographic Hash Verification
```bash
dfdisk verify evidence.E01 --md5 43a4195f3e626bdf70a5d6652e1a389a
```

---

## 📜 Forensic `.info` Report Sample

```text
================================================================================
                         DFDISK FORENSIC ACQUISITION REPORT
================================================================================

[CASE INFORMATION]
Case Number         : VG12345/26
Location / EA       : 01
Evidence Number     : cf01
Authority / Agency  : Criminal Investigation Department / DFIR Unit
Examiner            : Detective J. Doe (#4192)
Description         : Suspect Kingston USB Drive

[SOURCE HARDWARE SPECIFICATIONS]
Device Node         : /dev/sdb
Vendor / Model      : Kingston DataTraveler 3.0
Serial Number       : 0019E06B089DBB20B758064F
Bus Interface       : USB
Media Type          : Removable Flash/USB
Sector Size         : Logical: 512 bytes | Physical: 512 bytes
Total Sectors       : 62533632 sectors
Total Capacity      : 32017219584 bytes (32.02 GB (29.82 GiB))

[ACQUISITION CONFIGURATION]
Acquisition Tool    : dfdisk v0.1.0
Output Format       : Expert Witness Format (E01)
Compression         : Fast
Segment Split Size  : 2.0 GiB (2048 MB)
Error Handling      : Retries: 2 | Wipe bad sectors: Yes (Zero-fill)

[ACQUISITION TIMESTAMPS & PERFORMANCE]
Started             : 2026-09-01 07:15:00 UTC
Ended               : 2026-09-01 07:19:30 UTC
Elapsed Time        : 00:04:30
Average Speed       : 118.58 MB/s
Bad / Error Sectors : 0 sectors

[CRYPTOGRAPHIC INTEGRITY & VERIFICATION]
Source MD5          : a5ff1a52a6b027b00a1920ef7a4a55ce
Source SHA-256      : b630a52bcab287e6484bcc45124c3031513534db469d72f4a0574d6d009bb287

Image MD5           : a5ff1a52a6b027b00a1920ef7a4a55ce
Image SHA-256       : b630a52bcab287e6484bcc45124c3031513534db469d72f4a0574d6d009bb287

Verification Result : VERIFIED - ALL HASHES MATCH (Acquisition Integrity Confirmed)

[GENERATED EVIDENCE FILES]
 - /mnt/evidence/cases/vg12345_26_ea01_cf01_0019E06B089DBB20B758064F.E01
================================================================================
```

---

## ⚖️ License
GPLv3 or MIT (DFIR Open Source).
