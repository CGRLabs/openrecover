# Manual test — Android bridge on a real device

This procedure is **not run in CI**. It validates the read-only Android bridge against a
physical phone and is the only test that exercises the real adb server, USB enumeration and
device-side permissions. It must be repeated on at least one device per supported Android
major version before a release.

Never use a device that holds the only copy of important data. Never run this procedure with a
device rooted by a third party or with a modified/unofficial build if that can be avoided.

## Prerequisites

- A physical Android phone with Developer options and USB debugging enabled.
- Android platform-tools (`adb`) available on `PATH` or passed with `--adb-path`.
- The phone must be unlocked; accept the USB debugging authorization prompt.
- The host must have a local output directory that is **not** an MTP/gvfs mount of the phone.
- Build `openrecover` from source at the revision under test.

## Before the run

1. Record the tool and device identity:

   ```
   adb devices -l
   adb shell getprop ro.product.model
   adb shell getprop ro.build.version.release
   adb shell getprop ro.build.version.sdk
   adb shell getprop ro.crypto.state
   ```

2. Snapshot the visible shared-storage metadata for the directories the default profile reads:

   ```
   adb shell "ls -l --time-style=full-iso /sdcard/DCIM /sdcard/DCIM/.thumbnails \
       /sdcard/Pictures /sdcard/Android/data 2>&1" > before.txt
   adb shell "find /sdcard -type f 2>/dev/null | sort" > before-files.txt
   ```

3. Take a second snapshot of any app-private paths if the profile is customized. Paths that
   return `Permission denied` are expected and must stay denied.

4. Save the output of `adb shell "sha256sum /sdcard/DCIM/* 2>/dev/null"` (or a representative
   subset) if hashes are available on the device.

## Run

1. Scan without pulling (must not create any file on the host or device):

   ```
   openrecover android scan --serial <SERIAL> --profile profiles/default.json
   ```

   Confirm the report lists the expected roots and `access_denied`/`absent` statuses, and that
   no output directory was created.

2. Pull with a local output directory:

   ```
   openrecover android pull --serial <SERIAL> --out D:\evidence\phone \
       --profile profiles/default.json
   ```

3. Confirm the report declares the mandatory limitations: inaccessible app-private data,
   encrypted `/data`, scoped storage when SDK >= 30, and the need for root/physical imaging for
   true undelete.

4. For each pulled file, compare the recorded SHA-256 with an independent hash of the local
   file (`certutil -hashfile <file> SHA256` on Windows, `sha256sum <file>` on Linux). They must
   match. Compare the local mtime with the device's `stat -c %Y <path>`.

5. Verify that pulling again into the same directory never overwrites: the second run must
   produce `name (1).ext`-style files and leave the first exports byte-identical.

## After the run

1. Repeat the snapshots exactly:

   ```
   adb shell "ls -l --time-style=full-iso /sdcard/DCIM /sdcard/DCIM/.thumbnails \
       /sdcard/Pictures /sdcard/Android/data 2>&1" > after.txt
   adb shell "find /sdcard -type f 2>/dev/null | sort" > after-files.txt
   ```

   `diff before-files.txt after-files.txt` must be empty. `diff before.txt after.txt` may only
   show access-time-independent changes; size and mtime columns must match.

2. Re-run the device-side hash command. The hashes must be unchanged.

3. Confirm the tool never requested root: the adb output must contain no `su`, `root`,
   `remount`, `push`, `install`, `uninstall`, `rm`, `mv`, `settings`, `pm` or `am` invocation.
   An easy check is to run the bridge with `-v` and inspect the reported command lines; every
   device command must be one of `getprop`, `find <dir> -type f`, `test -d <dir>`, or
   `stat -c %s|%Y|%n <files...>`, and every host-side adb invocation must be `start-server`,
   `devices -l`, `-s <serial> shell <allowlisted>`, or `-s <serial> pull <remote> <local>`.

4. Confirm the local output directory is not the MTP mount. On Windows, check the drive type
   (`GetDriveType` must not be `DRIVE_REMOTE`); on Linux, check that the output path is not
   below a `fuse.jmtpfs` or `fuse.gvfsd-fuse` mount.

5. Delete the local evidence copy only after the hashes and report have been archived.

## Checklist

- [ ] Device visible as `device` in `adb devices -l`; serial matches the command line.
- [ ] `openrecover android scan` produced a report and wrote nothing to disk.
- [ ] `openrecover android pull` exported files only through the local output directory.
- [ ] Every exported SHA-256 and mtime matches the device file.
- [ ] A second pull created `(1)` copies and did not overwrite the first exports.
- [ ] `before-files.txt` equals `after-files.txt`; device file hashes are unchanged.
- [ ] `before.txt`/`after.txt` size and mtime columns are unchanged.
- [ ] No device-side mutating command was issued (allowlist observed in verbose output).
- [ ] The report contains all mandatory limitations and any `access_denied` root.
- [ ] The output path is on a local fixed filesystem, not an MTP/gvfs mount.
