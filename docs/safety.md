# How dfdisk protects the source

dfdisk never writes to the source. It sends the device nothing but reads and
identify-class queries, and the report records every one of them. This page
states the exact rules; the README has the short version.
[exit-codes.md](exit-codes.md#refusals-exit-code-3) lists every refusal.

## Identity pinning

The device is identified by kernel device number, diskseq, serial, WWN and size
when it is selected, again right before the acquisition and again at the end. A
device that changed refuses the start; one that changes or disappears during the
run makes the verdict INCOMPLETE. External tools read through
`/dev/disk/by-diskseq/<N>` when that link points at the pinned device.

`--expect-serial`, `--expect-wwn` and `--expect-size` refuse a device that does
not have that serial, WWN or size in bytes.

## Refusals

dfdisk refuses (exit 3), before anything is written:

- an empty device (size 0: no medium, or the size is unknown);
- a device listed in the dfnix protected-device registry, and every device when
  the registry exists but cannot be read (fail closed);
- a system disk;
- a device with mounted filesystems (in dfdisk's mount namespace; a mount in
  another namespace makes the [exclusive open](#exclusive-open) fail) or with
  active swap;
- a device with holders: dm-crypt, LVM, md, or a loop device set up over the
  source or one of its partitions, or over its disk or another device below it
  with a byte range that includes the source. Mounts of such a loop device, and
  of its partitions that lie on the source, count as mounts of the source. A
  holder keeps the device open, so it has to be closed first; there is no
  override.

A device-mapper or md device stacked on such a loop device that covers more than
the source (kpartx over `losetup /dev/sdb` for a source `sdb2`) may or may not
map the source, as dfdisk does not read its mapping. Its mounts refuse the
acquisition as well, but they are not called mounts of the source.

## Unmounting

Unmounting is a separate, explicit, audited action: `dfdisk unmount`, U in the
TUI, or `--auto-unmount`. It unmounts every filesystem of the device and of
everything stacked on it (partitions, device-mapper and LUKS mappings, loop
devices set up over it), deepest first, and then checks that nothing stayed
mounted. It refuses system mounts, protected devices and the mounts of a device
that may or may not map the source ("cannot tell whether ... belongs to ...";
unmount those yourself). It never forces and never unmounts lazily. Open
LUKS, LVM and md holders are reported, not closed.

A signal (SIGINT, SIGTERM, SIGQUIT, SIGHUP) or a quit does not cut an unmount
short: dfdisk finishes it, checks whether anything stayed mounted and writes its
audit record before it exits. On dfnix an unmount that cannot be recorded in the
audit log is refused.

## Exclusive open

The source is opened with `O_EXCL` and held for the whole run, so the kernel
refuses to mount it or to assemble device-mapper, LVM or md devices on it
meanwhile. Setting up a loop device needs no exclusive claim and is not stopped
by it. EBUSY means the device is in use.

## Destination checks

Before anything is written, the destination must be:

- not on the source and not on a dfnix evidence mount;
- not tmpfs or ramfs (unless `--allow-tmpfs`);
- writable, with enough free space (an E01 destination with less free space than
  the source size needs `--allow-low-space`) and within the file size limits of
  FAT;
- free of an output of the same name (compared case-insensitively).

A 1 MiB reservation guarantees room for the report, even when the destination
fills up.

## Write protection

With `--write-protect auto` (the default) dfdisk sets the kernel read-only flag
(BLKROSET) on:

- the source node and its own partitions;
- every node it sits on down to the disk (the partition and intermediate dm/md
  devices under a LUKS, LVM or md source);
- the disk or disks it is stored on, together with every partition node of
  those disks.

Under a mapping of an image file (LUKS or kpartx over a loop device) the loop
device counts as the disk: the host disk that holds the file is never touched,
identified or queried.

A disk that has other mounted filesystems stays writable together with its
partitions outside the source's chain, as does a node of the chain that another
mounted device depends on. The report names exactly the nodes left writable.

dfdisk refuses if a flag cannot be set, leaves the flags set afterwards and
records every node. Each node keeps its own flag; `blockdev --setrw <node>`
clears one node. `--write-protect off` only records the state.

The kernel flag is not a hardware write blocker. Use one where your procedures
require it.

## Order of operations

Nothing is sent to the device (BLKROSET, hdparm, smartctl) before the audit
"acquisition_started" record is written. On dfnix an audit log that cannot be
written refuses the acquisition.

## Hidden areas

`hdparm -N` and `hdparm --dco-identify` (ATA) or `nvme id-ns` (NVMe) run on the
physical disk (there is none under a loop device), read-only, with a timeout. A
host protected area (HPA) or device configuration overlay (DCO) is a loud
warning and is recorded; `--refuse-hidden-areas` turns it into a refusal.
dfdisk never changes them, and an image covers what the device reports as its
size.

## SMART

`--smart basic` (the default) runs `smartctl -j -i -H -A -l error`; `full` adds
the extended logs without SCT commands; `off` sends nothing. Device scans never
run SMART; `dfdisk list --smart` asks for it explicitly and does not wake a disk
in standby. Inaccessible SMART is reported as UNKNOWN, never FAILED.

## Clock

Reports state whether the host clock was NTP-synchronised and give the RTC
offset. Without confirmed synchronisation, timestamps are labelled "host system
time, NOT synchronized". Durations come from the monotonic clock.

## Audit log

Acquisitions, refused acquisitions, unmounts, verifications, conversions and
refused conversions are recorded in the hash-chained dfnix audit log (dfcore).
Usage errors and runs that fail before they start (a missing tool, for example)
are not.

The log is `/run/dfnix/audit.jsonl`; `DFNIX_AUDIT_LOG` points it elsewhere, for
example at the case drive. On dfnix, where the protected-device registry exists,
an acquisition or unmount that cannot be recorded is refused. On other hosts the
run goes ahead and its report says that the audit log was not written, and why.

The "acquisition_finished" record is written on every path, including errors,
aborts and signals, and carries the SHA-256 of both reports. When the report
itself cannot be written, the record still carries the verdict, the digests,
the read errors and the files, and the error message printed by dfdisk names
the digests. Records of a MISMATCH, INCOMPLETE, ABORTED or VERIFICATION FAILED
run have the outcome `error`.

Every acquisition copies the log next to the image as `audit-<boot_id>.jsonl`
with its head hash in `audit-<boot_id>.head`: one copy per boot of the host,
never overwriting another boot's copy.

## Resuming a rescue

`--resume` continues a rescue only on the device it started on:

- The identity record `<base>.identity.json` (written at the first start, never
  changed) must have the SHA-256 the last report lists for it. A report that
  lists none is noted.
- The record must describe the source: kind, size, sector size, model, WWN and
  serial. A device with neither WWN nor serial is accepted only in the same
  attachment (not unplugged since).
- Behind a USB bridge without a WWN, the serial the bridge reports is not
  enough. Only the drive's own ATA IDENTIFY serial, recorded when SMART runs at
  the first start and at the resume, or the same attachment ties the drive.

A resume is also refused while the E01 of an earlier `--rescue-to-e01` lies
next to the rescue image. A refused resume leaves the image and the map
untouched, and the previous report stays as `<base>.info`.
