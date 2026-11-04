# Manual test — physical drive on Windows

This procedure is **not run in CI**. It is the only test that opens a real Windows physical
drive and therefore the only end-to-end proof that the Win32 read-only path behaves as designed.
Repeat it before a release on a machine with the same Windows build as the supported target.

> **Never attach the system disk, a disk containing the only copy of important data, or a disk
> you cannot re-image.** Use a disposable USB stick. Double-check the disk number, model and
> size before every command; `\\.\PhysicalDrive0` is usually the system disk.

## Prerequisites

- Windows 10/11 x64, an elevated terminal (Administrator).
- A disposable USB stick with a FAT32 or NTFS filesystem and some known files on it.
- A second local disk with enough free space for two full images of the stick.
- `dd` (Git for Windows is sufficient) or another raw-imaging tool, and PowerShell.
- A build of `openrecover` from the revision under test, with `profiles/` next to the executable
  or installed under `share/openrecover/profiles`.

## Identify the disk

1. Attach the USB stick and open an elevated PowerShell.
2. Record the disk number, friendly name, serial and size:

   ```
   Get-Disk | Format-Table Number, FriendlyName, SerialNumber, Size, OperationalStatus
   Get-Partition -DiskNumber <N> | Format-Table PartitionNumber, DriveLetter, Size
   ```

3. Confirm `<N>` is the USB stick, not the system disk. Record the evidence in the test notes.

## Before the run

1. Take the disk offline so Windows, antivirus and indexing cannot write to it:

   ```
   Set-Disk -Number <N> -IsOffline $true
   ```

2. Capture a full raw image of the stick and its SHA-256. Git Bash:

   ```
   dd if=//./PhysicalDrive<N> of=/d/evidence/before.img bs=1M status=progress
   sha256sum /d/evidence/before.img
   ```

   PowerShell equivalent for the hash:

   ```
   Get-FileHash D:\evidence\before.img -Algorithm SHA256
   ```

3. Save the output of `openrecover devices` for comparison with `Get-Disk`:

   ```
   openrecover devices --json > devices-before.json
   ```

4. Record the image hash somewhere outside the recovery output directory.

## Run

1. List partitions through the read-only device:

   ```
   openrecover partitions --source \\.\PhysicalDrive<N> --json
   ```

   The partition layout must match `Get-Partition`. A capacity error means the disk number is
   wrong — stop.

2. Scan deleted entries and carve unallocated space:

   ```
   openrecover scan --source \\.\PhysicalDrive<N> --json > scan.json
   openrecover recover --source \\.\PhysicalDrive<N> --mode both --out D:\evidence\recovered -vv
   ```

3. Verify every exported file against its recorded hash:

   ```
   openrecover verify --report D:\evidence\recovered\report.json
   ```

4. Inspect `report.json`:
   - `source.shared_write_fallback` must be `false` unless the fallback was explicitly allowed
     with `--allow-shared-write-sharing`.
   - `source.bad_sectors` lists unreadable sectors; a test stick should normally show none.
   - Every exported file has a `sha256`; carved entries show their confidence and absolute byte
     offsets.
   - The report contains the warnings emitted during the run, if any.

5. Run the whole scan a second time into a different output directory. The two `report.json`
   files must be identical except for `generated_at` and `exported_to` path-independent fields;
   manifests must be byte-identical.

## After the run

1. Bring the disk back online and take a second full image:

   ```
   Set-Disk -Number <N> -IsOffline $false
   # wait for the volume to settle, then offline again for the second image
   Set-Disk -Number <N> -IsOffline $true
   dd if=//./PhysicalDrive<N> of=/d/evidence/after.img bs=1M status=progress
   sha256sum /d/evidence/after.img
   ```

2. The before and after images must be byte-identical. If the stick was reconfigured by Windows
   between the images (for example an automatic chkdsk or mount-time metadata update), re-run
   the procedure with the disk offline for the whole test; a difference caused by Windows is
   still a failed read-only test because the disk must not have been writable by OpenRecover.

3. Compare the hashes of every exported file with a fresh `Get-FileHash`/`sha256sum` of the
   source files copied earlier (when known).

4. Confirm the verbose log contains no write, ioctl, format, repair or driver-install operation.
   The only Win32 device access must be `GENERIC_READ`, `FILE_SHARE_READ` and `OPEN_EXISTING`
   (the static check enforces this at build time; the manual run confirms the runtime path).

5. Keep `before.img`/`after.img` hashes with the test notes; delete the raw images only after
   the evidence has been archived.

## Checklist

- [ ] `<N>` confirmed as the disposable USB stick; system disk untouched.
- [ ] Disk taken offline before the first image and kept offline while OpenRecover ran.
- [ ] `before.img` SHA-256 recorded before running OpenRecover.
- [ ] `openrecover devices` lists the stick and matches `Get-Disk`.
- [ ] `openrecover partitions` matches `Get-Partition`; no write occurred.
- [ ] `scan`/`recover --mode both` produced a `report.json` and a `manifest.csv`.
- [ ] `verify` exit code is 0 and every file hash matches.
- [ ] `source.shared_write_fallback` is `false` (or the fallback was explicitly requested).
- [ ] Two runs produce deterministic reports and identical manifests.
- [ ] `after.img` SHA-256 equals `before.img` SHA-256 (or the difference is explained by
      Windows activity after the disk was brought online, not by OpenRecover).
- [ ] No `ReadOnlyViolation` appears in the logs or the report warnings.
