# Security Policy

## Supported versions

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 1.4.0   | Yes       | Current release; fixes land here first. |
| ≤ 1.3.0 | No        | Frozen artifacts in `dist/`; not patched. |

## Reporting a vulnerability

Email the maintainer directly (see the repository profile) rather than opening a public issue.
Include: version, preset/OS, a minimal reproducer — a synthetic image or fuzz input is ideal —
and the observed impact.

Unfixed parsers are reachable from untrusted disk images, so malformed-input bugs (out-of-bounds
reads, integer issues in runlists/BATs/extent trees) count as vulnerabilities even if they only
crash a scan. Fuzz-target crashes with the reproducing input are the most useful report format.

## Why this project takes safety claims seriously

The library is read-only by construction: `BlockDevice` has no write path, `OutputSink` is the
only writer and refuses to write on or into the source, and both are enforced by a static scanner,
fault-injection tests and a Linux `strace` gate (see
[docs/READONLY_POLICY.md](docs/READONLY_POLICY.md)). All third-party parsing happens in-process
against ASan/UBSan-instrumented fuzz targets in CI.

## Scope notes

- Running `openrecover` against a physical drive typically requires administrator or `CAP_SYS_RAWIO`
  privileges; scan output (`report.json`, `manifest.csv`, exported files) inherits your umask.
- The Android bridge never escalates: `su`, `adb root`, `remount`, push/install and settings
  changes are rejected by policy in both transports.
- Recovery from a live, mounted volume can expose *other users'* deleted data if you have the
  privileges to read the raw device; that is a property of raw disk access, not a bypass of
  OpenRecover's guarantees.
