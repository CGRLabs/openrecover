# Read-Only Policy

This document reproduces the normative read-only rules from `docs/SPEC.md` section 3.1.
They override every other consideration in the project.

## Normative rules (spec section 3.1)

1. The public `BlockDevice` interface MUST NOT contain any method capable of mutation: no `write`,
   `flush`, `trim`, `resize`, `ioctl`-passthrough, or "raw handle" accessors.
2. The OS handle MUST be opened with read-only access **and** the code MUST verify post-open (where
   the OS permits) that the handle is read-only.
3. The only component allowed to create or write files is `OutputSink` (section 3.7), which
   operates exclusively on paths that pass the "not on source device" check.
4. Violation of rules 1–3 detected at runtime MUST throw `ReadOnlyViolation` (derived from
   `std::logic_error`). In release builds, `ReadOnlyViolation` thrown from inside `libopenrecover`
   MUST additionally be caught at the CLI top level, logged at `error`, and cause `std::abort()`
   (exit code 70). It MUST NOT be swallowed.
5. CI gate `tools/check_readonly.py` (section 3.6) MUST pass.

## How the rules are enforced

| Rule | Mechanism | Location |
|---|---|---|
| 1 | `BlockDevice` exposes only `info()`, `read()`, `bad_sectors()`; no copy, no mutating members. Compile-time negative checks fail the build if a mutating call becomes invocable. Tests (`test_readonly_guard.cpp`) apply the same checks to every device type. | `include/openrecover/io/block_device.hpp`, `tests/unit/test_readonly_guard.cpp` |
| 1 | `GuardedDevice` wraps every factory-produced device, counts reads and exposes `bytes_written()` (always 0) plus `assert_untouched()`. | `src/io/readonly_guard.cpp` |
| 2 | Windows: the only open path uses `GENERIC_READ` + `FILE_SHARE_READ` + `OPEN_EXISTING` exactly; `FakeWin32Api` records the arguments and the test asserts them (also that `GENERIC_WRITE`, `GENERIC_ALL`, `FILE_WRITE_DATA`, `FILE_APPEND_DATA` are clear). Linux: after `open(O_RDONLY|O_CLOEXEC|O_LARGEFILE)`, `F_GETFL` must report `O_RDONLY`, otherwise `ReadOnlyViolation`. | `src/io/win_physical_device.cpp`, `src/io/linux/linux_block_device.cpp`, `tests/unit/test_win32_flags.cpp` |
| 2 | Device-control requests pass through `safe_ioctl`, which throws `ReadOnlyViolation` for anything outside the four read-only geometry queries on Windows (`IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, `IOCTL_DISK_GET_LENGTH_INFO`, `IOCTL_STORAGE_QUERY_PROPERTY`, `IOCTL_STORAGE_GET_DEVICE_NUMBER`) or the three on Linux (`BLKGETSIZE64`, `BLKSSZGET`, `BLKPBSZGET`). | `include/openrecover/io/win32_api.hpp`, `src/io/linux/linux_block_device.cpp` |
| 3 | `OutputSink` is the only writer. It resolves the output root first, refuses if the root contains the source image or resides on the source disk, never overwrites (collision suffixes, temp file plus no-replace rename), sanitizes every path component and rejects traversal and symlink escape. | `src/io/output_sink.cpp` |
| 4 | `OR_FATAL_WRITE` throws `ReadOnlyViolation` with file/line context; the CLI top-level handler (M5) logs and aborts with exit code 70. | `include/openrecover/io/readonly_guard.hpp` |
| 5 | `tools/check_readonly.py` scans `libopenrecover/` and `cli/` for forbidden write, ioctl and driver-install tokens; `--selftest` proves the scanner detects planted violations. | `tools/check_readonly.py` |
| 5 | On Linux, `test_readonly_syscalls` runs the read path under `strace`, asserts the image is opened `O_RDONLY`, that no write-family syscall targets an image fd, and that the image SHA-256 and mode are unchanged. | `tests/unit/test_readonly_syscalls.cpp` |

Any code path that could write to a source device, source image or Android device is a
top-severity defect. Design decisions made while implementing these rules are recorded in
[DECISIONS.md](DECISIONS.md).
