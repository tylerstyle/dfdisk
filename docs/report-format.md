# dfdisk report format (schema 2)

Every acquisition that wrote anything to the destination ends with two reports
next to the image: `<base>.info` for people and its machine-readable twin
`<base>.info.json`. Both are written to a temporary name, fsynced and renamed into
place, and the directory is fsynced. The audit "acquisition_finished" record
carries the SHA-256 of both files. This holds for every verdict, including
INCOMPLETE and ABORTED.

## Base name

`<base>` is `{case}_{ea}_{evidence}_{serial}`:

- case, EA and evidence number: Unicode NFC, lower case; letters and digits are
  kept, a run of `/`, `-`, `_`, `.` or spaces becomes one `_`, other characters
  are dropped, and a token with nothing left reads `unknown`; an empty EA is `01`,
  and the EA token always starts with `ea` (`01` becomes `ea01`);
- serial: the serial of the device as it was selected, upper case, characters
  other than letters, digits, `-` and `_` become `_`; `NOSERIAL` when the device
  reports none.

Example: case `VG-2026/4192`, EA empty, evidence `SSD01`, serial `EXS970A0004192E`
gives `vg_2026_4192_ea01_ssd01_EXS970A0004192E`.

A base name that would make any output file name longer than 255 bytes (with the
longest suffix dfdisk writes) is refused as a usage error; names are never
truncated. Existing outputs of the same base name are refused, compared
case-insensitively (exFAT, NTFS and FAT destinations).

## Files

| File | Written by | Content |
|------|------------|---------|
| `<base>.E01`, `.E02`, … `.EAA` … | E01 engine (ewfacquire) | EWF image segments |
| `<base>.raw` | RAW engine, rescue engine | the image (one file; RAW is never split) |
| `<base>.info` | every acquisition | text report |
| `<base>.info.json` | every acquisition | JSON report, schema 2 |
| `<base>.ewfacquire.log` | E01 engine | ewfacquire's own log (`-l`) |
| `<base>.pieces.tsv` | RAW engine | piecewise SHA-256 of the source stream (see below) |
| `<base>.map` | rescue engine | GNU ddrescue mapfile |
| `<base>.identity.json` | rescue engine | identity of the source at the first start; a resume requires the same device |
| `<base>.info.session-N`, `<base>.info.session-N.json` | rescue engine | the reports of an earlier session, kept when a rescue is resumed |
| `<base>.smart-before.json` | acquisitions with `--smart basic` or `full` | raw `smartctl -j` output before the acquisition |
| `<base>.smart-after.json` | rescue | raw `smartctl -j` output after the rescue |
| `<base>.smart-before-N.json`, `<base>.smart-after-N.json` | resumed rescue | later SMART snapshots never overwrite earlier ones |
| `audit-<boot_id>.jsonl`, `audit-<boot_id>.head` | every acquisition whose audit log could be read and verified | copy of the audit log and its head hash (see [Audit records](#audit-records)) |
| `<image>.verify-<YYYYMMDDTHHMMSSZ>.txt` | `dfdisk verify` | verification addendum next to the image (`<image>` is the image file name without its extension) |
| `<base>.conversion.info`, `<base>.conversion.info.json`, `<base>.conversion.log` | `dfdisk convert`, `--rescue-to-e01` | conversion reports and the libewf tool log, next to the converted image (`<base>`: the source image name without its extensions) |
| `<base>.info.reserve` | every acquisition, temporarily | 1 MiB reservation created before anything else is written and deleted right before the reports are written, so a full destination still gets its report |

Image, auxiliary and SMART files are fsynced, together with the directory, and
dropped from the page cache (POSIX_FADV_DONTNEED) before verification, so the
verification reads them back from the destination rather than from memory (the
RAW engine re-reads with `O_DIRECT` where the filesystem allows it). An image
file that cannot be opened or fsynced (or a directory fsync that fails) means
the image may not be on the destination medium: the verification is FAILED
("the image could not be flushed durably to the destination", exit 4). An image
that cannot be dropped from the page cache keeps its verdict, but the
verification method says the re-read may have come from memory. The method
names the fsync and the eviction only when they succeeded. Problems with
auxiliary files are listed in the notes.

Auxiliary files (ewfacquire log, pieces file, ddrescue map, SMART JSON) are
listed in the report with their SHA-256.

A conversion (`dfdisk convert`, `--rescue-to-e01`) writes its own reports,
`<base>.conversion.info` and `<base>.conversion.info.json`, next to its output;
they name the report of the source image (path and SHA-256) and inherit its
read-error table. `--rescue-to-e01` writes the E01 next to the rescue image; a
later `--resume` of that rescue is refused while the E01 is there.

## Text report (`<base>.info`)

The text is deterministic: the same report always renders to the same bytes.
Every value is sanitised: control characters (including tab, newline, ESC and
bidirectional overrides) become a space. Missing case values read
`(not provided)`. Sections, in this order:

| Section | Content |
|---------|---------|
| VERDICT | outcome label and exit code, one-sentence explanation, key numbers ("Acquired X of Y bytes (P%, …)" with the percentage floored to tenths, so 100.0% only when every byte was acquired; substituted and unread sectors, stop reason, identity change, a known HPA/DCO hidden area, verification result, second source read), timestamp basis, schema version |
| CASE INFORMATION | case number, EA, evidence number, examiner, authority, description, seal number, seizure time and place, notes |
| SOURCE IDENTITY | device node, kind (whole disk, partition, device-mapper, decrypted dm-crypt plaintext, md, loop, regular file), kernel name with major:minor and diskseq, parent disk, partition start, vendor/model, firmware, serial with the source it came from and all candidates, a note when the serial may belong to a USB bridge, WWN, attachment, sector sizes, size, identity checks at start and end |
| WRITE PROTECTION | policy, read-only flags before, nodes dfdisk set read-only (BLKROSET), holders, exclusive open, dfnix registry, mounts before, mounts dfdisk unmounted |
| CAPACITY / HIDDEN AREAS | reported size, HPA/DCO (ATA) or namespace sizes (NVMe), the device the probe ran on (the parent disk of a partition), method, probe errors |
| SMART BEFORE / SMART AFTER | policy, exact command, overall health (PASSED, FAILED or UNKNOWN; inaccessible SMART is UNKNOWN, never FAILED), key attributes, raw JSON file |
| ACQUISITION SETTINGS (APPLIED) | only what the engine applied: engine, format, digests (E01 always includes MD5), compression and segments (E01 only), retries, read-error policy, error granularity, media type, piece size, second source read, SMART and write-protection policy |
| TIMESTAMPS & CLOCK | start and end (UTC, labelled "host system time, NOT synchronized" unless NTP synchronisation was confirmed), elapsed time from the monotonic clock, average speed, time zone and UTC offset, NTP state, RTC offset |
| READ ERRORS | summaries per kind, then the ranges (offset and length in bytes, sectors, status): the first 200 ranges, all of them in the JSON report; which tool the list comes from; sector size |
| HASHES | "Acquisition stream (computed while reading the source)" and "Image re-read (recomputed from the written image)" |
| VERIFICATION | result, method, second source read, piecewise SHA-256 file. "VERIFIED - ALL HASHES MATCH" appears only for verdict VERIFIED; otherwise the result is followed by "(overall verdict: …)" |
| FILES | image files; auxiliary files with SHA-256 |
| TOOL PROVENANCE | dfdisk and dfcore version and git revision, dfnix revision, kernel, host name, versions of the external tools used, every command run (argv, start, end, exit status) |
| AUDIT | whether the audit log was written (or why not), audit anchor, audit log copy, earlier sessions of a resumed rescue |
| NOTES | everything else worth knowing (warnings, fallbacks, decisions) |

Abridged beginning of a report (illustrative values):

```text
================================================================================
                       DFDISK FORENSIC ACQUISITION REPORT
================================================================================
VERDICT               : COMPLETED WITH READ ERRORS (exit code 7)
                        The full length of the source was written, but some sectors could not be read and were replaced by zeros in the image; the digests describe the image including those substituted sectors, not the original medium.
                        Acquired 16777216 of 16777216 bytes (100.0%, 16 MiB).
                        64 sectors (32 KiB) in 1 range were unreadable and replaced by zeros; the digests below describe the image including the substituted sectors, not the original medium.
                        Verification: matched (ewfverify -d md5).
Timestamps            : host system time, NOT synchronized
Report Schema         : 2 (machine-readable twin: case_2026_001_ea01_hdd01_SERIAL0001.info.json)
================================================================================
...
[READ ERRORS]
unreadable, zero-filled: 64 sectors (32 KiB) in 1 range
      #        offset (bytes)    length (bytes)       sectors  status
      1               1048576             32768            64  unreadable, zero-filled
Error List Source     : ewfinfo -e
Sector Size           : 512 bytes
```

## JSON report (`<base>.info.json`)

One pretty-printed JSON object. Check `schema_version` before reading it; this
document describes version 2. Empty optional case fields are `null` (the text
report prints "(not provided)").

| Field | Type | Meaning |
|-------|------|---------|
| `schema_version` | number | `2` |
| `tool_name`, `tool_version` | string | `"dfdisk"` and its version |
| `engine` | string | `"ewf"`, `"raw"` or `"rescue"` |
| `outcome` | string | `"verified"`, `"complete_unverified"`, `"completed_with_read_errors"`, `"incomplete"`, `"mismatch"`, `"verification_failed"`, `"aborted"` |
| `exit_code` | number | the process exit code of this verdict ([exit-codes.md](exit-codes.md)) |
| `outcome_reason` | string | why this verdict, one sentence |
| `case_metadata` | object | `case_number`, `location_ea`, `evidence_number`, `examiner` (strings); `authority`, `description`, `notes`, `seal_number`, `seizure_time`, `seizure_location` (string or null) |
| `source` | object | identity probed at the start: `path`, `canonical_path`, `kernel_name`, `maj_min`, `diskseq`, `kind` (`{"type": "disk"}`, `"partition"`, `"device_mapper"` with `crypt_plaintext`, `"md"`, `"loop"` with `backing_file`, `"regular_file"`, `"other"`), `size_bytes`, `logical_sector_size`, `physical_sector_size`, `model`, `vendor`, `firmware_rev`, `serial`, `serial_candidates` (`[{value, source}]`), `wwn`, `transport`, `removable`, `hotplug`, `rotational`, `read_only`, `parent_disks`, `partition_number`, `partition_start_sector`, `dm_uuid`, `dm_name`, `hardware_of`, `file_id`, `probe_notes` |
| `identity_at_end` | object or null | identity probed again after the acquisition |
| `identity_check` | object | `start_ok`, `end_ok` (null: not checked), `details` |
| `capacity` | object or null | `reported_bytes`, `probed_device`, `ata` (`native_max_sectors`, `current_max_sectors`, `hpa_present`, `dco_real_max_sectors`, `dco_present`, `sector_bytes`: the sector size of these counts), `nvme` (`nsze`, `ncap`, `nuse`, `lba_bytes`), `method`, `errors` |
| `write_protection` | object or null | `policy`, `sysfs_ro_before`, `parent_disks_ro_before`, `partitions_ro_before`, `set_by_dfdisk`, `method`, `nodes_set`, `ro_after`, `holders`, `exclusive_open`, `dfnix_registry` (`{"state": "present"}`, `"absent"`, or `"unreadable"` with `reason`), `mounts_before`, `unmounted_by_dfdisk`, `notes` |
| `smart_before`, `smart_after` | object or null | `policy`, `command`, `smartctl_version`, `exit_status`, `taken_at`, `summary` (parsed health and attributes), `json_file`, `json_sha256`, `note`, `device_serial` |
| `effective_config` | object | `engine`, `image_format`, `digests`, `verify_source`, `smart`, `write_protect`, `settings` (one of `{"ewf": {…}}`, `{"raw": {…}}`, `{"rescue": {…}}` with what that engine applied), `notes` |
| `output_dir`, `base_name` | string | where the files are |
| `started_at`, `ended_at` | string | RFC 3339, UTC, host system clock (see `clock`) |
| `elapsed_seconds` | number | from the monotonic clock |
| `average_speed_bytes_sec` | number | bytes acquired per second |
| `expected_bytes` | number | size of the source |
| `bytes_acquired` | number | bytes of the source in the image |
| `stop_reason` | string or null | why the run stopped early (source lost, destination full, read error with `--on-read-error stop`, …) |
| `aborted` | bool | stopped by the examiner or a signal |
| `read_errors` | object | `sector_size`, `ranges` (`[{offset, length, kind}]`), `source` (see below) |
| `acquisition_hashes` | object | `md5`, `sha1`, `sha256` (string or null), computed while reading the source |
| `image_hashes` | object | the same digests recomputed from the written image |
| `verification` | object | `result`, `method`, `source_reread` (see below) |
| `piecewise` | object or null | `piece_size`, `file`, `file_sha256`, `count` |
| `image_files` | array of string | the image file(s) |
| `auxiliary_files` | array | `[{path, sha256}]` |
| `provenance` | object | `dfdisk_version`, `dfdisk_git_rev`, `dfcore_version`, `dfcore_git_rev`, `dfnix_revision`, `kernel`, `hostname`, `tools` (name → version line), `commands` (`[{argv, started, ended, exit_code, signal, stop, error, stdout_tail, stderr_tail}]`) |
| `clock` | object | `start_utc`, `end_utc`, `timezone`, `utc_offset`, `ntp_synchronized` (null: unknown), `ntp_service`, `local_rtc`, `rtc_offset_seconds`, `monotonic_elapsed_secs`, `timestamp_basis` (`"UTC (NTP synchronized)"` or `"host system time, NOT synchronized"`), `note` |
| `audit` | object | `anchor` (hash of the "acquisition_started" record), `status` (`{"state": "written"}` or `{"state": "not_written", "reason": …}`), `export_file` |
| `resume_sessions` | array | earlier sessions of a resumed rescue: `[{session, report_file, report_sha256, started_at, ended_at, outcome}]` |
| `notes` | array of string | as in the text report |

### Read-error ranges

`read_errors.ranges` lists byte ranges of the source, measured from its first
byte, sorted, non-overlapping, with adjacent ranges of the same kind merged:

- `"substituted"`: unreadable; the image holds zeros there and has its full
  length. Any such range makes the verdict at best COMPLETED WITH READ ERRORS.
- `"unread"`: not read or not in the image (untried or unfinished ddrescue
  areas, the rest of the source after an early stop). Any such range makes the
  verdict INCOMPLETE.

`read_errors.source` names where the list comes from, for example `ewfinfo -e`
(the error list stored in the E01 itself), `ddrescue mapfile` or `raw engine`.
`sector_size` is the logical sector size the ranges were found with.

### Verification result

`verification.result` and `verification.source_reread` (the second read of the
source with `--verify-source`; null when there was none) are tagged objects:

```json
{"status": "matched", "method": "ewfverify -d md5"}
{"status": "mismatched", "method": "...", "details": "..."}
{"status": "not_possible", "reason": "..."}
{"status": "failed", "reason": "..."}
```

A second source read that differs makes the verdict MISMATCH, labelled by what
was compared: with acquisition digests (E01, RAW) "the source changed or reads
unstably: MD5 acquisition … but second read …"; without them (rescue, where the
second read is compared with the image) "the image differs from the source as
read a second time …: MD5 image … but second read …".

The one-sentence explanation under the verdict is chosen by what happened, not
only by the verdict: a rescue is INCOMPLETE "because the ddrescue map still
lists areas that were not tried or not finished" only when the map has such
areas and nothing else stopped the run (otherwise the explanation names the
stop or the identity change); a VERIFIED rescue says that its image digests
equal a second, independent read of the source; an ABORTED or INCOMPLETE run
says "its digests cover only what was acquired" only when digests exist.

## Piecewise hashes (`<base>.pieces.tsv`)

Written by the RAW engine while it reads the source: the SHA-256 of every piece
of `--piece-size` bytes (default 1 GiB; the last piece may be shorter).
Tab-separated text with this header line:

```text
index	offset	length	sha256
```

then one line per piece: piece number, offset and length in bytes, SHA-256 in
hex. The report's `piecewise` object names the file, its SHA-256, the piece size
and the number of pieces. `dfdisk verify --pieces <file>` recomputes every piece
from the image and names each piece that differs, which localises damage or
tampering to a piece instead of failing the image as a whole.

## Verification addendum (`dfdisk verify`)

`dfdisk verify` never changes an existing report. It writes a new file
`<image>.verify-<YYYYMMDDTHHMMSSZ>.txt` next to the image (never overwriting
one; `<image>` is the image file name without its extension) with the digests it
computed, what they were compared with, the verdict and its clock, and appends an
`image_verification` audit record.

## Audit records

dfdisk appends records to the dfnix audit log through dfcore: hash-chained JSON
lines, `/run/dfnix/audit.jsonl` by default; `DFNIX_AUDIT_LOG` overrides the path.

| Action | When |
|--------|------|
| `acquisition_started` | before anything is sent to the device: identity (with major:minor and diskseq), case fields, applied settings, destination, the path tools read the source through. Its hash is the report's **audit anchor**. |
| `acquisition_finished` | always after a "started" record, also after errors, aborts, signals and panics: outcome, exit code, read-error summary, every known digest, write protection, capacity and SMART summaries, SHA-256 of both reports, the files |
| `acquisition_refused` | a refusal after the device was selected and before "started" (identity, source safety, destination); nothing was written to the destination |
| `unmount` | `dfdisk unmount` and `--auto-unmount`: the mounts and what happened to them |
| `image_verification` | `dfdisk verify` |
| `conversion_started`, `conversion_finished` | `dfdisk convert` and `--rescue-to-e01`; a conversion refused before it started (usage, destination checks, existing outputs) writes no record |

Usage errors are not recorded (nothing was sent to the device). On dfnix
(protected-device registry present) an audit log that cannot be written refuses
the acquisition before the device is read. Elsewhere the report says
"Audit Log: NOT WRITTEN: …" and the run continues.

After each acquisition the log is copied into the output directory as
`audit-<boot_id>.jsonl`, with `audit-<boot_id>.head` holding the head hash and the
record count, so the case directory carries its own anchor. The live log under
/run starts afresh at every boot, so every boot gets its own file. An existing
copy is only ever replaced by a longer version of the same log; any other file of
that name is left alone and the copy goes to `audit-<boot_id>-<n>.jsonl`.
