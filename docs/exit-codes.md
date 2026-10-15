# dfdisk exit codes

dfdisk 0.2.0 exits with one documented code per result. Scripts can rely on these
codes; the text and JSON reports carry the same code (`exit_code` in
`<base>.info.json`, "VERDICT ... (exit code N)" in `<base>.info`).

| Code | Name | Meaning |
|-----:|------|---------|
| 0 | Verified | The whole source was acquired without read errors, and the digests recomputed from the written image match the digests computed while reading the source (for a rescue, where ddrescue computes none: the digests of a second, independent read of the source with `--verify-source`). |
| 1 | Internal error | A bug or an unexpected internal failure (including a panic, which is reported as "Error (INTERNAL ERROR): …" rather than with Rust's exit code 101). Please report it. |
| 2 | Usage error | Invalid arguments or inconsistent options. Nothing was written and nothing was sent to the device. |
| 3 | Refused | A safety or preflight rule refused the run (see below). Nothing was acquired. |
| 4 | Failed | The run could not be carried out (for example a required tool is missing: ewfacquire, ewfinfo and ewfverify for E01 and `--rescue-to-e01`, ddrescue for a rescue; this is found after the refusal checks and before anything is written, sent to the device or recorded as started), or the verification could not run or complete (outcome VERIFICATION FAILED). |
| 5 | Mismatch | A digest recomputed from the image, or from a second read of the source, differs from the digest computed during acquisition (for a rescue: the second read differs from the image). The report says which digests were compared. |
| 6 | Incomplete | Not all of the source was acquired: the run stopped early, areas were never read, the source was lost or changed, or the destination filled up. |
| 7 | Completed with read errors | The full length was written, but unreadable sectors were replaced by zeros. The digests describe the image including the substituted sectors, not the original medium. |
| 8 | Aborted | Stopped by the examiner or by a signal (SIGINT, SIGTERM). |
| 9 | Complete, not verified | The whole source was acquired without read errors, but no independent comparison was possible (for example a rescue without `--verify-source`). |

Codes 0 and 4 to 9 are verdicts of a run that wrote output; the report states the
verdict. Codes 2 and 3 (and 4 when a run could not start) come from runs that wrote
nothing except, for a refusal, possibly an audit record (see
[report-format.md](report-format.md#audit-records)).

## How a verdict is chosen

One function decides the verdict from the facts the run measured. The rules are
applied in this order; the first that matches wins:

1. the run was aborted → **8 Aborted**
2. the source changed or disappeared during the run → **6 Incomplete**
3. fewer bytes acquired than the source holds, ranges that were never read, or a
   stop reason (source lost, destination full, read error with
   `--on-read-error stop`) → **6 Incomplete**
4. a recomputed digest differs → **5 Mismatch**
5. the verification could not run or complete → **4 Failed**
6. sectors were replaced by zeros → **7 Completed with read errors**, even when the
   image digests match (they match the substituted stream, not the medium)
7. the image digests were recomputed and match → **0 Verified**
8. otherwise (nothing independent to compare) → **9 Complete, not verified**

"ALL HASHES MATCH" appears in a report only for verdict 0.

## Refusals (exit code 3)

dfdisk refuses, before anything is written to the destination or sent to the
source device, when for example:

- the device reports a size of 0 bytes (no medium present, or the size is
  unknown): there is nothing to acquire;
- the device no longer matches the one that was selected (kernel device number,
  diskseq, serial, WWN or size changed), or does not match `--expect-serial`,
  `--expect-wwn` or `--expect-size`;
- the device is protected by the dfnix protected-device registry, or the registry
  exists but cannot be read (fail closed);
- the device is a system disk, is mounted (in dfdisk's mount namespace), holds
  active swap, or has holders (device-mapper, LVM, md, LUKS): a holder claims the
  device, so it has to be closed first (there is no override);
- the device cannot be opened exclusively (`O_EXCL` returns EBUSY: it is in use,
  for example mounted in another mount namespace);
- the destination is on the source, on a dfnix evidence mount, on tmpfs/ramfs
  (without `--allow-tmpfs`), read-only, too small, on a FAT filesystem that
  cannot hold the image file, or already contains an output of the same name
  (compared case-insensitively);
- the space reservation for the report cannot be created;
- on dfnix: the audit log cannot be written;
- after the audit "started" record: the kernel read-only flag could not be set
  (`--write-protect auto`), or a hidden area (HPA/DCO) was found and
  `--refuse-hidden-areas` was given. Nothing has been read from the device at
  that point.

## Per subcommand

| Subcommand | Exit codes |
|------------|------------|
| `acquire` | The report's verdict (0, 4–9) once anything was written; 2, 3 or 4 when the run ended before the first write; 8 when aborted before the first write. With `--rescue-to-e01` the more severe of the rescue's and the conversion's code, from most to least severe 1, 2, 8, 5, 4, 3, 6, 7, 9, 0 (a conversion that is skipped because the rescue is not complete adds nothing; a conversion that could not start after the rescue wrote its image, because of a usage error or a refusal, counts as 4, never 2 or 3; a source that is not a whole number of 512-byte sectors is a usage error, 2, before the rescue starts). |
| `check` | 0 ready; otherwise the code of the first problem found: 2 usage, 3 refused, 4 a check could not run or a tool the engine runs is not installed; 8 interrupted. Writes nothing. |
| `verify` | 0 every digest compared matches (expected digests, the digests an E01 stores, every piece of `--pieces`); 5 a digest or a piece differs; 4 the verification could not run or a requested digest was not computed (never reported as a pass); 9 nothing to compare against (no expected digest given, none in the report, none stored in the image, no `--pieces`); 2 the image or pieces file does not exist, an expected digest is not exactly 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex digits (also in a `--report`), or arguments are invalid; 8 aborted. |
| `convert` | The conversion's verdict (0, 4–9; 7 when the source image holds zero-filled sectors of its acquisition); 2 for example a RAW size that is not a multiple of 512 bytes or missing case fields; 3 an output already exists or a destination check refused; 4 a tool could not run. |
| `unmount` | 0 everything was unmounted and nothing remains mounted (or nothing was mounted); 2 usage (for example a regular file); 3 refused (system mount, protected device, active swap, unidentifiable device); 4 an unmount failed or a mount remained. |
| `list` | 0, or 4 when the device scan failed. |
| `tui` (default) | 0 on a normal exit; the result's exit code when the TUI ends before the examiner acknowledged a result on screen (a run that finished after SIGHUP, or a quit by signal); 1 on a terminal failure; 4 when the signal handlers cannot be installed. |

Command-line parsing errors (unknown option, missing value, missing required
`--case`/`--evidence`/`--examiner`) exit 2. `--help` and `--version` exit 0.

## Signals

- SIGINT or SIGTERM: graceful abort. The running tool gets SIGINT (ewfacquire
  15 s, ddrescue 30 s grace), then SIGTERM, then SIGKILL; dfdisk keeps the partial
  output, writes the report with verdict ABORTED and exits **8**.
- A second SIGINT kills the running tool at once; the report is still written.
- SIGHUP (for example a dropped SSH session): dfdisk stops writing to the terminal,
  finishes the acquisition and writes the report; the exit code is the verdict.
