# Decision Log

Ambiguities found while implementing `docs/SPEC.md` (formerly `OPENRECOVER_SPEC.md`) are recorded
here, newest last, as required by section 0, rule 3. Dates are ISO-8601.

## 2026-10-20 — ByteView failure signalling

**Question:** Section 1.5 allows either a sticky-failure flag or a `ParseOverrun` exception.
**Choice:** the sticky-failure pattern; every reader returns 0 on failure and sets a flag observed
through `failed()`/`ok()`, and width/reach validation happens inside each reader. **Reason:**
parsers can read a whole structure and check once, no exception crosses a parser boundary, and I/O
and parse errors keep flowing through `Result` as section 1.4 requires.

## 2026-10-20 — Name of the device-control call in the Win32 shim

**Question:** Section 3.3.1 names the shim method `DeviceIoControl`, but section 3.6 forbids the
literal `DeviceIoControl` outside `win32_api_real.cpp`, and the shim header is not that file.
**Choice:** the portable interface method is `IWin32Api::IoControl`; only `RealWin32Api` maps it to
`::DeviceIoControl`, and device code reaches it exclusively through `safe_ioctl`. **Reason:** both
normative rules are satisfied, and the test fake implements `IoControl` without touching Win32.

## 2026-10-20 — Logging entry point name

**Question:** The static rule `\bwrite\s*\(` in section 3.6 matches any function named `write`.
**Choice:** the logger exposes `log::emit` plus level wrappers (`error`, `warn`, `info`, `debug`,
`trace`), never `log::write`. **Reason:** the scanner stays simple and has no exception for
logging; an allowlist entry for a logger would make the gate harder to audit.

## 2026-10-20 — OutputSink result type and atomic commit

**Question:** Section 3.7 specifies `Result<std::filesystem::path> write_file(...)` but also
requires SHA-256; callers need the hash, not only the path. **Choice:** `write_file(relative,
ByteSource&, optional<int64_t> mtime)` returns `WrittenFile{path, relative, sha256, size}`. Bytes
stream to a `.~N.part` temp file in the destination directory, then commit without replacement:
`MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` on Windows, `link()` + unlink on POSIX with a
check-then-rename fallback for filesystems without hard links. **Reason:** the temp-plus-rename
requirement and "never overwrite" are both preserved, and the hash is computed while streaming
rather than by a second read.

## 2026-10-20 — Collision suffix placement

**Question:** Section 3.7 says a collision appends ` (1)`, ` (2)` … but not where in the name.
**Choice:** insert before the extension (`report.json` → `report (1).json`); a name without an
extension gets the suffix at the end. Suffixing happens after `sanitize_component`, and the counter
stops at 100000 with `AlreadyExists`. **Reason:** the extension is preserved, so recovered files
still open with their associated program.

## 2026-10-20 — Output location when the backing disk is unknown (Windows)

**Question:** Section 3.7 requires refusing output on the source disk, but the disk backing the
output directory cannot always be determined (network shares, unusual volumes). **Choice:** refuse
with `OutputOnSourceDevice` instead of allowing. The disk number comes from a zero-access query
handle on the volume (`IWin32Api::DiskNumberForPath`, the only handle opened with neither read nor
write access). **Reason:** the read-only mandate overrides availability; if the relationship cannot
be proven safe, the sink must not create files.

## 2026-10-20 — Output location guard for image sources (Linux)

**Question:** Section 3.7's Linux bullet asks to compare `st_dev` and to refuse when the output
directory "contains the source image file". For a regular image file the source's `st_dev` is the
host filesystem, so a literal `st_dev` comparison would always refuse. **Choice:** for `ImageFile`
sources, refuse exactly when the resolved output directory is the same as or above the image
(`path_is_within(image, output_root)`), and run the check before creating any directory. For
`BlockNode` sources, resolve both the source disk (via `/sys/dev/block`, following dm/md slaves)
and the disk backing the output directory (via `/proc/self/mountinfo`), and refuse when they match
or either is unresolvable. **Reason:** the hazard is writing onto the source; refusing every output
for image sources would make the tool unusable, and containment is the protection the spec
describes.

## 2026-10-20 — `sanitize_component` operation order

**Question:** Section 1.5 lists sanitization rules without an order, and order changes the result
for long names ending in dots. **Choice:** (1) replace forbidden and control characters, (2) prefix
reserved Windows device names with `_`, (3) truncate to 200 bytes on a UTF-8 boundary, (4) strip
trailing dots and spaces, (5) map empty, `.` and `..` to `_`. **Reason:** prefixing before
truncation guarantees the final name is at most 200 bytes; stripping after truncation handles a
dot exposed by the cut; the emptiness check runs last.

## 2026-10-20 — Reserved Windows device names

**Question:** Section 1.5 does not mention names such as `CON` that Windows cannot create.
**Choice:** `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9` and `LPT1`–`LPT9` (case-insensitive, base
name before the first dot, trailing spaces ignored) get a `_` prefix, e.g. `_CON.txt`. **Reason:**
without this a recovered file with such a name cannot be written on Windows; a prefix keeps the
name recognizable and inside the 200-byte cap.

## 2026-10-20 — Extra configuration fields

**Question:** The fixed types in sections 1.4 and 3.2 do not include storage for the share-mode
fallback or the sector-size override. **Choice:** add `DeviceInfo.shared_write_fallback` (set by
the Windows opener and reported), `OpenOptions.allow_shared_write_sharing` (section 3.3.2) and
`OpenOptions.sector_size` (section 3.5; 0 means 512, validated as a power of two in
[512, 65536]). **Reason:** these values are required by the spec's own CLI and report clauses;
extending the existing structs avoids parallel configuration plumbing.

## 2026-10-20 — Decorator order and the guard's checksum

**Question:** Section 3.6 requires every factory result to be guarded and section 3.2 has a cache
decorator; the order determines whether cached reads pass through the guard. **Choice:**
`wrap_standard` wraps the raw device in `CachedDevice` when `cache_bytes > 0`, then always wraps
that in `GuardedDevice`; all factories use it. `GuardedDevice::assert_untouched()` hashes the
source through its inner device, which may be the cache. **Reason:** the guard must be outermost so
every public read is counted; hashing through the cache is safe because the cache only obtained
bytes by reading the source.

## 2026-10-20 — Windows post-open read-only verification

**Question:** Section 3.1, rule 2 requires verifying after open, where the OS permits, that the
handle is read-only. **Choice:** verification is structural: the only open path uses exactly
`GENERIC_READ`, `FILE_SHARE_READ` and `OPEN_EXISTING`, and `test_win32_flags` asserts those exact
arguments (including that forbidden bits are clear) through `FakeWin32Api`. **Reason:** Windows
offers no query for the access mask already granted on a device handle, and adding another IOCTL
would enlarge the surface the read-only policy must audit. The Linux path, where `F_GETFL` exists,
performs the real check.

## 2026-10-20 — Windows read path

**Question:** Section 3.3.4 allows a mutex or overlapped offsets, and mentions
`FILE_FLAG_NO_BUFFERING` only as future work. **Choice:** a per-handle `std::mutex` around
`SetFilePointerEx` plus `ReadFile`, a 1 MiB 4096-aligned bounce buffer, and no
`FILE_FLAG_NO_BUFFERING`; unaligned requests read whole sectors and copy the requested sub-range.
The bad-sector retry reads one sector at a time, zero-fills failures and records sector indices.
**Reason:** exactly the documented default; the bounce buffer removes the alignment hazard that
`NO_BUFFERING` would create for callers.

## 2026-10-20 — Container rejection by magic

**Question:** Section 3.5 requires containers to return `Unsupported` but does not specify
detection. **Choice:** `ImageDevice` rejects E01 (`EVF` signature), VMDK sparse (`KDMV`), VHD
(`conectix` at offset 0 or in the 512-byte footer) and VHDX (`vhdxfile`) with descriptive
`Unsupported` errors. **Reason:** a descriptive failure beats parsing container bytes as a raw
disk; detection is a fixed-size prefix or footer check and cannot misfire on a plausible raw image.
*Superseded for VHD on 2026-10-23: `conectix` now routes to `VhdDevice` instead of failing.*

## 2026-10-20 — Physical-drive path grammar

**Question:** Section 3.3.2 gives the regex `^\\\\\.\\PhysicalDrive[0-9]{1,3}$` and allows the
volume form. **Choice:** matching is case-sensitive and requires exactly that prefix; the volume
form accepts one ASCII letter followed by `:`. Drive numbers above 999 are invalid, and
`open_source` maps a valid drive path to `open_physical_drive` by parsing the digits.
**Reason:** literal implementation of the normative regex; accepting case variants or short forms
would widen the input grammar without benefit.

## 2026-10-20 — Additional static-check rules

**Question:** The section 3.6 table is a minimum; the read-only mandate encourages more.
**Choice:** `tools/check_readonly.py` additionally forbids `fopen`/`fstream` creation, Win32
creation dispositions, driver-install APIs (`DIF_*`, `SetupDi*`, `DiInstallDrv*`,
`UpdateDriverForPlugAndPlayDevices*`), `FSCTL_LOCK/DISMOUNT/SET_/DELETE`,
`IOCTL_DISK_SET/FORMAT/GROW/DELETE`, `IOCTL_STORAGE_EJECT`, and adb write verbs outside
`adb_command_policy.cpp`. The scanner covers only `libopenrecover/` and `cli/`, as specified, so
negative assertions inside `tests/` may name forbidden tokens. **Reason:** extra deny rules
tighten the gate at no maintenance cost, and the spec's scope keeps mocks and fixtures out of the
scan.

## 2026-10-20 — M0 dynamic read-only proof without a CLI

**Question:** Section 3.6's dynamic test spawns "the CLI", but the CLI is not scheduled until M5.
**Choice:** add `tests/support/readonly_probe.cpp` (built only on Linux). It opens a fixture image
through the production `open_source`, hashes it, performs unaligned reads, then creates an
`OutputSink` and writes one file. `test_readonly_syscalls` runs it under strace, checks that the
image is opened `O_RDONLY` and never written, and re-checks the SHA-256 and mode 0444.
**Reason:** the proof must exist at the M0 gate and must exercise the same production path the CLI
will use; the probe is test support, not a second implementation.

## 2026-10-20 — Syscall trace scope and skip behavior

**Question:** Section 3.6 lists a short strace filter, but the probe opens libraries and writes
output files that must not be confused with the image. **Choice:** trace
`open/openat/openat2/creat`, the write family (`write`, `writev`, `pwrite*`), `ftruncate`,
`truncate`, `fallocate`, `close` and `dup*`; track image fds across close and dup by parsing the
trace, and ignore writes to other fds. If `strace` is absent the test is SKIPPED (Catch2 skip,
`SKIP_RETURN_CODE 4`), not failed. **Reason:** fd tracking is required because numbers are reused;
skipping keeps developer containers usable while CI installs strace and enforces the test.

## 2026-10-20 — Symlink-escape test on unprivileged Windows

**Question:** Section 3.7 requires rejecting a symlink that escapes the output root, but creating
symlinks on Windows needs Developer Mode or elevation. **Choice:** the test creates the symlink
inside a `try` and reports SKIP if creation fails. Traversal is still covered unconditionally by a
separate test that asserts no written path component is `..` or `.` and that every path stays under
the root. **Reason:** the negative branch cannot be exercised without the privilege; skipping it is
honest and does not weaken the traversal checks that always run.

## 2026-10-20 — Cache capacity floor

**Question:** `OpenOptions.cache_bytes` is user-controlled, and a value below one 64 KiB block
would otherwise produce a zero-capacity cache. **Choice:** `CachedDevice` capacity is
`max(1, cache_bytes / 65536)` blocks. **Reason:** a zero-capacity cache cannot make progress while
evicting; one block is the minimum meaningful cache.

## 2026-10-20 — Test memory device ownership

**Question:** Section 9 says `MemoryDevice` is constructed from a `const` buffer; holding a
reference would leave it mutable through another handle. **Choice:** the constructor copies the
buffer into a private `const std::vector<uint8_t>`, and `contents()` returns a const reference.
**Reason:** copying makes the no-write property true at runtime as well as in the type system, at
negligible cost for test-sized buffers.

## 2026-10-20 — CLI handling of ReadOnlyViolation is deferred to M5

**Question:** Section 3.1, rule 4 requires the CLI top level to log a `ReadOnlyViolation` at
`error` and call `std::abort()` (exit 70); the CLI does not exist at M0. **Choice:** at M0 the
library always throws, and the tests assert this. The catch → error log → `std::abort()` handler
will be added with `cli/src/main.cpp` in M5 and covered by an M5 test. **Reason:** a stub CLI now
would violate the no-placeholder rule; recording the obligation keeps it from being missed.

## 2026-10-20 — Deleted LFN entries are accumulated, not restarted

**Question:** Section 4.2.4 says to start a new LFN stack when `Ord == 0xE5`, but deletion overwrites
the first byte of every LFN entry with `0xE5`, which would discard all but the last physical part of a
multi-part deleted long name. **Choice:** consecutive `0xE5` LFN entries are accumulated in physical
order and assembled by reverse physical order; sequence numbers are validated only when the short
entry is live. **Reason:** the stated intent is to recover deleted long names ("deleted LFN allowed");
restarting the stack on each entry would make multi-part deleted names unrecoverable and contradict
the M1 deleted-LFN tests.

## 2026-10-20 — FAT cluster bounds are clamped to the addressable FAT entries

**Question:** `max_valid_cluster = cluster_count + 1` can exceed the number of entries that fit in
`FATSz32`, and hostile FAT sizes can produce values that overlap the special markers. **Choice:**
clamp `max_valid_cluster` to `min(cluster_count + 1, FATSz32*BytsPerSec/4 - 1, 0x0FFFFFF6)` and reject
volumes whose FAT has fewer than three entries. **Reason:** every accepted cluster must have a full
4-byte entry, and clusters `0x0FFFFFF7` and above are markers, not data. The `-1` keeps
`FatReader::entry` in bounds.

## 2026-10-20 — Backup boot sector lookup uses the device sector size

**Question:** Section 4.2.1 locates the backup boot sector by `BkBootSec`, but the primary BPB may
carry a corrupt `BytsPerSec` — the very reason the fallback is needed. **Choice:** read the primary
and backup sectors using `max(512, device logical sector size)`, validate a 512-byte BPB within that
buffer, and require `1 <= BkBootSec < RsvdSecCnt` from the raw primary. **Reason:** the device's
logical sector size remains trustworthy when BPB fields do not, and a 512-byte BPB is always contained
in one device sector.

## 2026-10-20 — NTFS is detected but unsupported until M2

**Question:** Section 4.0 requires detection order NTFS then FAT32, but M1 does not include the NTFS
scanner. **Choice:** `detect_and_open` returns `ErrorCode::Unsupported` for `"NTFS    "` OEM IDs;
FAT32 validation failures also map to `Unsupported("unknown filesystem")`, while I/O failures
propagate unchanged. **Reason:** recognizing NTFS now avoids misclassifying it as FAT32, and
`Unsupported` matches the no-placeholder rule for features delivered in a later milestone.

## 2026-10-20 — Scan paths never start with a slash

**Question:** Section 4.2.5 defines `path = containing_directory + "/" + name`, while the
`RecoveredFile.path` comment requires paths to never start with `/`. **Choice:** root-level entries
use their bare name (`notes.txt`); directory children use `DOCS/report.txt`, and orphan paths use
`__orphans__/...`. **Reason:** the type contract and the section 4.2.6 orphan layout are explicit;
an empty parent contributes no separator.

## 2026-10-20 — Allocation map is conservative on errors

**Question:** `FatAllocationMap::is_cluster_allocated` can encounter an out-of-range cluster or a FAT
read error, but its interface returns only a boolean. **Choice:** report such clusters as allocated.
**Reason:** over-reporting allocation can only lower recovery confidence or exclude a cluster from
carving; under-reporting could let a later feature overwrite live data, which the read-only and
unallocated-only contracts forbid.

## 2026-10-20 — FAT32 fixtures use a deterministic Python builder

**Question:** The M1 fixture requirement names `mkfs.fat` and `mtools`, which are unavailable on the
development host (Windows, no WSL) and would not guarantee byte-identical images across machines even
where present. **Choice:** `tools/fixtures/make_fat32_fixtures.sh` invokes a deterministic Python
builder that writes the BPB, FATs, directory entries and cluster contents directly, with fixed volume
IDs and timestamps. The committed gzip images, not the generator, are authoritative for CI. **Reason:**
byte-level construction also lets the fixtures exercise spec-only cases (split LFNs, deleted
directories, terminator followed by stale entries) that mkfs/mtools cannot produce directly, while
keeping regeneration reproducible.

## 2026-10-20 — NTFS fixtures use a deterministic Python builder

**Question:** The M2 fixture requirement names `mkntfs -F -Q -s 512 -c 4096` and an `ntfs-3g` mount,
but neither is available on the Windows development host and their on-disk layout differs across
versions. **Choice:** `tools/fixtures/make_ntfs_fixtures.sh` invokes
`make_ntfs_fixtures.py`, which writes the boot sector, MFT records, fixups, attributes, runlists and
$Bitmap directly with fixed serial numbers and timestamps. The committed gzip images and goldens,
not the generator, are authoritative for CI. **Reason:** byte-level construction is reproducible
and can encode cases a real formatter will not produce on demand (torn records, 255-character names,
a deliberately stale parent sequence, a three-run $MFT), while keeping the M2 assertions unchanged.

## 2026-10-20 — NTFS fixture directories carry no index structures

**Question:** Real NTFS directories store their children in `$INDEX_ROOT`/`$INDEX_ALLOCATION`, but
the M2 scanner reconstructs paths exclusively from `$FILE_NAME` parent references. **Choice:** the
fixture directories are ordinary records with a directory flag and a `$FILE_NAME` attribute, and the
fixture `$Bitmap` is derived from the builder's allocated-cluster set rather than from index
metadata. **Reason:** the scanner never reads directory indexes, so index structures would add
thousands of bytes of unexercised layout without changing any recovery result; the fixture still
matches the committed golden byte-for-byte.

## 2026-10-20 — NTFS timestamps map $STANDARD_INFORMATION fields to ctime/mtime/atime

**Question:** `RecoveredFile` exposes three timestamps, while NTFS stores four (created, modified,
MFT-changed, accessed). **Choice:** created → `ctime_unix`, modified → `mtime_unix`, accessed →
`atime_unix`; the MFT-changed timestamp is not exposed. When `$STANDARD_INFORMATION` is absent, the
preferred `$FILE_NAME` timestamps are used instead. **Reason:** these are the closest semantic
equivalents in the common type and match the fields exposed for FAT32; mtime is the value users
expect for recovery ordering and deduplication.

## 2026-10-20 — Unsupported NTFS data streams are reported, not extracted

**Question:** Compressed and encrypted `$DATA` attributes cannot be decoded in M2 (compression is out
of scope; decryption requires keys), but silently omitting the file would hide recoverable metadata.
**Choice:** emit the record with `Confidence::Low`, `file_flags::Unsupported`, no extents, and the
note `ntfs_compressed|encrypted`; `read_file` returns `ErrorCode::Unsupported`. **Reason:** the file
name, path and timestamps remain useful to the user, while the unsupported-content marker and the
hard read error prevent exporting garbage bytes as recovered data.

## 2026-10-20 — Missing or unreadable $Bitmap lowers non-resident confidence to Medium

**Question:** The spec requires `$Bitmap`-based confidence, but a damaged volume may have no usable
`$Bitmap`; failing the whole scan would lose recoverable files. **Choice:** resident files stay
`High`, non-resident files become `Medium`, and the scanner logs a warning. I/O errors while reading
the allocation map still abort the scan, because they indicate a failing device rather than absent
metadata. **Reason:** Medium communicates that cluster reuse could not be checked without discarding
recoverable data; only genuine I/O failures are surfaced as errors.

## 2026-10-20 — NTFS metadata reads are bounded

**Question:** `$ATTRIBUTE_LIST` and `$MFT` sizes are attacker-controlled and could otherwise drive
unbounded allocation or recursion. **Choice:** reads of non-resident metadata attributes are capped
at 16 MiB, at most 64 extension records and 4096 attribute-list entries are followed, MFT record
sizes are restricted to powers of two in [512, 65536], index buffer sizes to powers of two in
[512, 1 GiB], and path depth to 255 components. The path cache is capped at 1,048,576 records.
**Reason:** these bounds exceed every realistic NTFS volume layout while keeping hostile images
within predictable memory and time budgets; exceeding them degrades to path uncertainty or a
`CorruptStructure` error, never to an out-of-bounds access.

## 2026-10-20 — Deleted hard links expose only the preferred $FILE_NAME

**Question:** A deleted file with multiple hard links has several names, and all of them may still
be recoverable from the record. **Choice:** choose one name by namespace preference (Win32/DOS →
POSIX → Win32-and-DOS → unknown) and emit one `RecoveredFile` per record at that name's path; other
links are not emitted as duplicates. Extension records referenced by `$ATTRIBUTE_LIST` are consumed
into their base record and skipped as standalone entries. **Reason:** one record is one data stream,
so emitting the same content under several paths would duplicate exports; the namespace preference
matches how Windows presents the canonical name.

## 2026-10-20 — Component names are capped at 200 bytes

**Question:** NTFS permits 255-character names, while paths must remain usable on recovery targets
and in the shared `RecoveredFile` model. **Choice:** reuse the M0 `sanitize_component` behavior:
strip path separators and control characters, replace invalid bytes, and truncate to 200 bytes.
The fixture golden records the truncated name. **Reason:** a single sanitization rule across
filesystems keeps exported paths safe and predictable; 200 bytes leaves room for the surrounding
path and extension on common target filesystems.

## 2026-10-20 — NTFS detection supersedes the M1 Unsupported stub

**Question:** The M1 decision returned `Unsupported` whenever the NTFS OEM ID was present;
M2 now supplies a real NTFS scanner, so that behavior and its test are obsolete. **Choice:**
`detect_and_open` delegates to `NtfsScanner::open` and propagates its result; the M1 detection
test now expects `CorruptStructure` for its deliberately malformed NTFS boot sector. **Reason:**
the milestone transition must not leave a permanent stub that rejects a filesystem the library
supports; the replacement assertion still verifies that NTFS magic never falls through to FAT32.

## 2026-10-20 — Carve fixtures share the deterministic Python media builders

**Question:** The M3 fixture requirement asks for a 16 MiB raw image with valid files, decoys,
a nested JPEG and random fill, but does not specify how the embedded media is produced; no media
toolchain is guaranteed on the host. **Choice:** `make_carve_fixtures.py` composes the image from
the JPEG/PNG/PDF/ZIP builders in `file_builders.py`, the same deterministic module the FAT32
fixture now uses for its deleted photo. All contents derive from fixed seeds and SHA-256-based
fill; accidental signature magics outside the intended offsets abort generation. The committed
gzip images and golden, not the generator, are authoritative for CI. **Reason:** byte-level
construction makes offsets, lengths and decoy behavior exact and reproducible, and sharing the
builders keeps the M1 dedup file and the M3 carve files structurally identical.

## 2026-10-20 — Nested carve fixture is sector-aligned inside its ZIP

**Question:** The default carve scan advances by the alignment (512 bytes without an allocation
map), while the fixture's nested JPEG is only reachable when `--nested` disables span skipping;
the spec requires `--nested` alone to toggle its discovery. **Choice:** the ZIP entry name is
482 bytes, which places the local-header payload at ZIP offset 512, so the nested JPEG starts on
a 512-byte boundary and is found by the aligned scan as soon as nesting is enabled. **Reason:**
`--nested` controls whether scanning continues inside a validated span, not the scan granularity;
forcing `--unaligned` as well would conflate the two options and make the toggle untestable.

## 2026-10-20 — Carve dedup matches the first non-sparse extent

**Question:** Section 5 says a carved hit is a duplicate when it equals the first extent of a
High-confidence filesystem-recovered file, but a sparse first extent has no bytes on disk.
**Choice:** skip sparse extents and compare `(offset,length)` against the first non-sparse extent;
only a High-confidence file with at least one non-sparse extent can mark a duplicate. **Reason:**
a sparse extent cannot produce the device bytes a carved hit represents, so equality against it
is meaningless and would suppress a genuine carve hit only by coincidence.

## 2026-10-20 — Carve allocation scoping treats pre-data bytes as allocated

**Question:** `IAllocationMap` exposes cluster-to-offset mapping but not the volume's cluster size
or the filesystem's metadata region; `UnallocatedOnly` must still avoid carving reserved bytes.
**Choice:** derive the cluster size from the offsets of clusters 1 and 2 and use cluster 2 as the
data anchor; any byte below that anchor (boot sector, FATs, root metadata) is treated as
allocated, as is any byte beyond `cluster_count()`. **Reason:** carving reserved metadata would
produce hits that can never be recovered files, and treating unknown out-of-range bytes as
allocated matches the M1 allocation-map rule that errors degrade conservatively.

## 2026-10-20 — PDF revisions may not link across an earlier %%EOF

**Question:** PDF incremental updates append a new xref after the previous revision's `%%EOF`,
but an unrelated PDF carved immediately afterwards has its own startxref/`%%EOF`. Following the
`startxref` chain naively let one candidate absorb the neighbouring document. **Choice:** a
revision is accepted only when its xref offset is greater than the previous accepted revision's
`%%EOF` position; otherwise chain walking stops at the last valid revision. **Reason:** legitimate
incremental updates always place the new xref after the prior EOF, so the rule rejects adjacent
documents without limiting valid multi-revision files; a regression test embeds two complete
classic PDFs back to back.

## 2026-10-20 — ReadOnlyViolation is defined in common/readonly.hpp

**Question:** `android/` must not include `io/` headers, but the command policy needs to throw
`ReadOnlyViolation`, which lived in `io/readonly_guard.hpp`. **Choice:** move the exception type
to `openrecover/common/readonly.hpp`; `io/readonly_guard.hpp` re-exports it with a using
declaration so all existing include sites keep working. **Reason:** the violation is a policy
concept, not an I/O implementation detail, and android must be able to signal it without pulling
the block-device interface into its dependency graph.

## 2026-10-20 — Remote paths allow apostrophes and spaces, reject other metacharacters

**Question:** Section 6.2.1 requires POSIX single-quote escaping but also says paths must not
contain shell metacharacters; apostrophes and spaces need escaping and are common in real
filenames. **Choice:** validate paths at the byte level: reject control characters (< 0x20, DEL),
backslash, and ``" $ ` ; & | < > ( ) { } [ ] * ? ! #``; allow spaces and apostrophes because
`'` → `'\''` quoting makes them inert, and the round-trip is exercised through a real POSIX
shell in `test_android_policy`. **Reason:** rejecting ordinary filenames such as `O'Brien.jpg`
would silently lose recoverable media, while every rejected character either cannot be quoted
safely or changes device-side parsing even inside quotes.

## 2026-10-20 — TestDir is encoded as a boolean string per backend

**Question:** the subprocess backend sees `test -d`'s exit status, but pure-python-adb's
`device.shell()` returns only stdout, so the sidecar cannot observe it. **Choice:** the
`IAdbTransport::shell_readonly` contract for `TestDir` is `"1"` (exists) or `"0"` (absent).
The subprocess transport maps exit code 0/1; the sidecar appends
`&& echo openrecover:yes || echo openrecover:no` to the same validated `test -d '<dir>'` command
and maps the marker. **Reason:** both backends must return the same result shape to the scan
pipeline; the wrapper executes only the already-allowlisted `test -d` plus `echo`, with the path
still quoted and validated.

## 2026-10-20 — Partial ListFiles/StatBatch output is returned with a warning

**Question:** `find` and `stat` can exit non-zero after printing valid lines (for example one
missing file in a stat batch, or an unreadable subtree), and the scan must still use the lines it
did receive. **Choice:** when stdout is non-empty for `ListFiles`/`StatBatch`, return it and log a
warning instead of failing the whole command; for every other allowlisted kind a non-zero exit is
an error. **Reason:** discarding partial listings loses recoverable evidence, while the pipeline
records `AccessDenied` roots separately and validates each stat line; an empty failed listing
still maps to an error.

## 2026-10-20 — The stat format argument is shell-quoted

**Question:** the spec shows `stat -c %s\|%Y\|%n`, but the format contains `|`, a shell
metacharacter, and `adb shell` re-parses the command string. **Choice:** the command sent to the
device is `stat -c '%s|%Y|%n' ...`; the C++ policy parses the quoted form back to the expected
`%s|%Y|%n` token. **Reason:** without quotes the device shell would interpret `|` as a pipeline
separator, changing the command entirely; quoting is invisible to stat and keeps the exact format
allowlisted.

## 2026-10-20 — Sidecar policy.json is a build artifact passed with --policy

**Question:** the Python sidecar must share the C++ policy, but writing generated files into the
source tree during a build is not acceptable. **Choice:** `adb_policy_dump` (built from the C++
constants) writes `policy.json` under the build directory; `test_android_sidecar` passes that path
to `sidecar.py --policy`, and `PySidecarAdbTransport::create` resolves an explicit path, then
`OPENRECOVER_SIDECAR_POLICY`, then `policy.json` next to `sidecar.py`. Packaging must install the
generated file beside the shipped sidecar. **Reason:** a single generated source keeps the two
allowlists identical, and an explicit `--policy` path avoids depending on the process working
directory or on a build-tree layout at runtime.

## 2026-10-20 — Child-process pipe writes are an explicit static-check exception

**Question:** `ChildSession::write_line` must write JSON Lines to the sidecar's stdin, but
`check_readonly.py` forbids `WriteFile`/`write(` outside `output_sink.cpp`. **Choice:** allow
those two tokens only in `src/android/child_process.cpp`, where every handle/fd is a pipe created
by `ChildSession::start`; no file or device is opened in that translation unit. **Reason:** a
sidecar protocol requires writing to a child process; the exception is narrow, inspectable, and
the checker still rejects the same calls in every other source file (verified by its selftest).

## 2026-10-20 — Sidecar list_devices returns serial and state only

**Question:** `AdbDevice` carries model/product/transport_id from `adb devices -l`, but ppadb's
host-device listing exposes only serial and state. **Choice:** the sidecar returns serial, state,
state_raw and empty model/product/transport_id; the readiness probe (`getprop`) fills the model
and manufacturer used by the report. **Reason:** fabricating fields would make the two backends
disagree; the authoritative identity is the serial, and USB metadata is already available from
`IUsbEnumerator` when present.

## 2026-10-20 — adb stdout newlines are normalized to LF

**Question:** `adb.exe` on Windows translates the device-side LF output to CRLF, while the parser
and the fake transport operate on LF. **Choice:** `SubprocessAdbTransport::shell_readonly`
normalizes CRLF to LF for successful stdout and partial listings; device-side output from the
Python sidecar is already LF. **Reason:** the output is line-oriented structured data, so removing
CR before LF cannot change any field, and it keeps the parsers identical across platforms.

## 2026-10-20 — USB enumeration reports every Windows device interface, without merging

**Question:** a composite Android device can expose more than one device interface, and
`UsbDeviceInfo` describes a device, not an interface. **Choice:** SetupAPI enumeration emits one
`UsbDeviceInfo` per interface path with a unique `instance_id`; duplicates are not merged. ADB
interface detection checks the node's own hardware/compatible IDs and, for composite devices,
any USB devnode with the same VID/PID whose IDs contain `Class_FF&SubClass_42&Prot_01`.
**Reason:** merging by VID/PID would collapse two physically distinct phones of the same model;
matching serials is the authoritative join (`adb devices -l`), so the bridge keeps the USB list as
a hint and leaves device-level merging to the caller.

## 2026-10-20 — Sysfs interface directories are tested via the probe helper on Windows

**Question:** the fake `/sys` tree test needs directories named `<dev>:<cfg>.<if>`, but Windows
forbids `:` in file names, so the full tree test cannot run there. **Choice:** the class-triplet
probe is exposed as `is_adb_interface_directory` and tested on every platform, while the complete
fake-tree test (prefix matching, sorting, attribute trimming) runs on POSIX. **Reason:** the
Windows CI gate still covers 152 assertions including all parsers and the SetupAPI enumerator
smoke test; skipping only the directory-name-dependent case avoids a test-only production seam.

## 2026-10-20 — Android pulls are staged in a private temp directory

**Question:** `adb pull` requires a local destination path and writes it itself, which conflicts
with "`OutputSink` is the only writer". **Choice:** `AndroidBridge::scan_and_pull` creates a
private, uniquely named directory under the system temp directory (or `AndroidBridgeOptions::
temp_dir`), pulls each file to `payload-N.bin` there, verifies its size, opens it read-only for
validation and streaming, and deletes it after `OutputSink::write_file` has produced the final
file. The temp directory is removed by RAII even on failure. **Reason:** the alternative is to
let adb write into the output tree, which would bypass collision handling, mtime preservation and
the source-mount guard. Staging is confined to a fresh directory that the bridge itself creates,
so no pre-existing path (including a symlink) is ever handed to adb.

## 2026-10-20 — max_depth counts file components; dir_regex matches the full remote directory

**Question:** the profile schema uses `max_depth: 6` and `dir_regex: "(^|/)cache(/|$)"`, but does
not define whether the file itself counts toward the depth or what `dir_regex` is applied to.
**Choice:** depth is the number of `/`-separated components of the file path relative to its scan
root (a file directly in the root has depth 1, so `max_depth` is the maximum relative component
count). `dir_regex` is applied with `regex_search` to the full remote directory path (the file's
remote path without its last component), not only to the portion below the root. **Reason:**
counting components keeps the rule simple and rejects nothing in the default profile's six-level
budget, while matching the full directory path still works when a profile root is itself a
`cache` directory (as in `vendor_examples.json`).

## 2026-10-20 — an empty type_filter means "no extension filter"

**Question:** the schema allows `type_filter` to be omitted or empty, but a filter semantics
for the empty list is not specified. **Choice:** an omitted, null or empty array accepts every
extension, including files without one; entries are lowercased and de-duplicated, and files whose
extension is not listed are refused before stat. **Reason:** the field is an optimization and
safety net, not a mandatory allowlist; treating `[]` as "allow nothing" would make an otherwise
valid minimal profile silently scan nothing.

## 2026-10-20 — Android confidence is finalized after structural validation

**Question:** the confidence table assigns `trash` High, `thumbnail` Medium and `cache` Low, but
section 6.4 step 5 also lets the structural validators override confidence for pulled media.
**Choice:** enumeration assigns the kind-based confidence and notes; after a successful pull the
jpg/jpeg, png, pdf and zip-like (zip/docx/xlsx/pptx) files are validated when
`AndroidBridgeOptions::validate_media` is true. `Valid` keeps the kind confidence except that a
cache file is raised to Medium; `ValidTruncated` forces Low and appends `truncated`; `Invalid`
forces Low and appends `corrupt`. Scan-only runs (which never pull) report the unvalidated
kind-based confidence. If validation cannot open or read the staged file, a warning is recorded
and the kind confidence is kept rather than calling the file corrupt. **Reason:** scan-only has
no bytes to validate, and a validator that cannot run is not evidence that the file is damaged.

## 2026-10-20 — MTP/gvfs output locations are refused before anything is created

**Question:** the spec forbids writing into the phone's own MTP-mounted storage, but
`OutputSink::open` only knows about block-device/image sources. **Choice:** `scan_and_pull` first
calls an Android-specific location check: on Windows it rejects drive types `DRIVE_REMOTE`,
`DRIVE_NO_ROOT_DIR` and `DRIVE_UNKNOWN`; on Linux it finds the longest `/proc/self/mountinfo`
mount point containing the output path and rejects `fuse.jmtpfs`, `fuse.gvfsd-fuse` and any
fstype/source/mount point containing `mtp` or `gvfs`, failing closed if the mount cannot be
identified. The check runs before `OutputSink::open`, so no directory is created on a rejected
target. **Reason:** an MTP mount is the source device's own storage; writing there would violate
the read-only mandate even though it is exposed as a local filesystem path.

## 2026-10-20 — Report paths are sink-relative when --out is given

**Question:** global `--report <path>` exists for every command, but `recover`, `carve` and
`android pull` already write into `--out`, and `scan`/`partitions` have no output directory at
all. **Choice:** with a non-empty `--out`, `--report` is interpreted as a `/`-separated path
relative to the output directory and may name a subdirectory (`reports/run.json`); without
`--report`, `recover`/`carve`/`android pull` write `report.json` at the output root, while
`scan`/`partitions` write no file and only print to stdout. Without `--out`, `--report` is a host
path whose parent becomes the sink root, so even scan-only reports still flow through
`OutputSink`. In every case `manifest.csv` is written next to the report, and an absolute or
`..`-containing relative path is rejected. **Reason:** `OutputSink` needs one root to enforce the
source-location and traversal guards; anchoring relative paths to `--out` makes that root
unambiguous, while the parent-directory rule gives scan-only commands a report location without
inventing a second writer. Defaulting scan to a file would also surprise scripts that expect
stdout-only output.

## 2026-10-20 — A volume that is not at offset 0 is selected only as a fallback

**Question:** when the source has an MBR/GPT and no `--partition`/`--offset` is given, the spec
does not say which volume `scan`/`recover` should use if offset 0 holds no filesystem.
**Choice:** first try offset 0; if no supported filesystem is found, try each non-superfloppy
partition in table order and use the first one that opens, recording a warning that names the
partition and its byte offset. Explicitly requested `--fs`/`--partition`/`--offset` combinations
never fall back and fail with their own error. **Reason:** a whole-disk image whose FAT32/NTFS
volume starts at 1 MiB is otherwise unusable without manual offsets, but silently choosing a
volume when the user asked for a specific one would be worse; the warning keeps the selection
visible in the report.

## 2026-10-20 — Report offsets are absolute within the source

**Question:** extent offsets and carved offsets could be relative to the selected partition or
`--offset` view, or absolute within the opened source. **Choice:** they are absolute byte
offsets in the source passed on the command line; the view offset is added with saturation at
`UINT64_MAX` to keep hostile values bounded. Partition summaries keep their own absolute
`start`/`length`. **Reason:** the report is evidence about the whole source, and `verify`,
`manifest.csv` and any later comparison against a full-disk image must not depend on which view
was selected during one run.

## 2026-10-20 — --types and --max-size filter exports, not report entries

**Question:** filters could either hide non-matching recovered files completely or only skip
their export. **Choice:** every entry found by metadata scanning or carving stays in
`report.json`/`manifest.csv`; `--types`/`--max-size` only decide which entries are written to
disk, leaving `exported_to` empty and `statistics.exported` lower. Type tokens are lowercased
and canonicalized (`jpg`→`jpeg`, `docx|xlsx|pptx|apk|jar|odt|ods|odp|epub`→`zip`), matching the
carve signatures. **Reason:** the report is the inventory of what was found and is also the
basis for `verify`; silently dropping evidence from it because the user filtered an export would
make later review impossible, while the counters still show what was actually exported.

## 2026-10-20 — Per-file export failures are warnings; sink failures abort

**Question:** a deleted file can fail to export because its clusters were overwritten or its
declared size is inconsistent, while other files are fine. **Choice:** metadata export records
`cannot export <path>: <error>` or `exported size differs ...` in `warnings`, leaves
`exported_to` empty and continues; an unsupported-content flag is skipped with a warning, and an
empty path is skipped. Failures from `OutputSink` itself (a collision, an escape or an I/O error
that invalidates the run) still abort, as does a carved-export hash mismatch. **Reason:** a
single corrupt directory entry must not prevent recovery of the remaining files, but a broken
sink would make the output tree untrustworthy, so it cannot be downgraded to a warning.

## 2026-10-20 — verify resolves exported paths against the report's directory

**Question:** `verify --report <file>` needs a base directory for the relative `exported_to`
values, and reports may contain scan-only entries or no entries at all. **Choice:** the base is
the report's parent directory (canonicalized); every `exported_to` must be a safe relative path
and must resolve inside that base. Metadata entries are checked for both SHA-256 and size,
carved entries for SHA-256 only; entries without `exported_to` are ignored. Any mismatch exits
`1`, and a report with zero exported files verifies successfully after checking zero files.
**Reason:** the report and its files are moved together as one evidence directory, so the
report's location is the only stable anchor; carved entries record the validated hit length,
which can legitimately differ from a truncated export, while metadata exports are expected to be
byte-exact. A scan-only report is not an error.

## 2026-10-20 — Android scan writes a report by default

**Question:** `android scan` is "scan without pulling", yet the command table requires `--out`,
and the global report rules default to `report.json`. **Choice:** `android scan --out DIR`
writes `DIR/report.json` (and `manifest.csv`) but no recovered files; `android pull` uses the
same destination rules. Both require the MTP/gvfs output-location guard before the output
directory is created. **Reason:** the report is the only artifact of a scan and must be
reviewable later; writing it under the same guarded sink keeps the read-only and no-MTP
guarantees identical for scan-only and pull runs.

## 2026-10-20 — Fuzz targets live in fuzz/ with per-target corpora

**Question:** section 8.3 names `tests/fuzz/` and `tests/fixtures/fuzz_corpus/`, while the
repository tree and the existing `fuzz_ntfs_record` target live in `fuzz/` and
`tests/fixtures/fuzz/`. **Choice:** keep the existing root `fuzz/` directory and the
`tests/fixtures/fuzz/<target>/` corpus layout, and extend it with `fuzz_fat32_boot`,
`fuzz_fat32_dir`, `fuzz_ntfs_runlist`, `fuzz_sig_{jpeg,png,pdf,zip}` and `fuzz_gpt`. All
targets reuse the test-only `MemoryDevice` from `tests/support` and are built only on Linux with
clang (`OPENRECOVER_BUILD_FUZZ=ON`); seed corpora are generated by
`tools/fixtures/make_fuzz_corpus.py` and CI runs each target for 60 seconds. **Reason:** the
tree is the structural authority and the existing target, CMake wiring and corpus are already
in this location; moving them would create churn without changing coverage. The Windows clang
libFuzzer runtime uses a static CRT and cannot link against this project's dynamic-CRT objects,
so a clear configure-time error replaces a confusing linker failure.

## 2026-10-20 — CLI parse errors map to exit code 2, help and version to 0

**Question:** CLI11 reports parse failures and help/version requests through the same exception
type, which would otherwise map both to a generic failure. **Choice:** `CLI::ParseError` is
inspected after `app.parse`; `CallForHelp`/`CallForVersion` exit `0`, every other parse error
exits `2`. `ReadOnlyViolation` maps to `70` and other command failures keep their `ErrorCode`
mapping (`3` permission, `4` busy, `5` unsupported, `6` output-on-source, `7` unauthorized).
**Reason:** the exit-code table distinguishes usage errors from runtime failures, and scripts
invoking `--help` must not treat it as an error.

## 2026-10-20 — GIF and BMP signatures are appended to the registry

**Question:** adding validators changes the deterministic signature order, which can reorder or
add carving hits. Where should the new signatures go? **Choice:** `GifSignature` and
`BmpSignature` are appended after the existing JPEG, PNG, PDF and ZIP entries in
`SignatureRegistry::builtins()`, and `--types` remains the way to restrict a scan. **Reason:**
registry order is observable through candidate scanning and reports; appending the new types
extends coverage without perturbing the established order or the existing fixture goldens.

## 2026-10-20 — GIF validation walks blocks and decodes LZW in deep mode

**Question:** GIF has no checksum, so which structural evidence should make a magic match
recoverable? **Choice:** require `GIF87a`/`GIF89a`, a nonzero canvas within a 2^28-pixel cap, a
coherent logical screen descriptor and global color table, and a complete block chain ending at
`0x3B`. Every image requires a global or local color table, a minimum code size of 2..8 and a
terminated sub-block chain; extensions are bounded and their fixed-size headers checked. Deep
validation decodes the LZW stream (initial clear code, clear/end handling, KwKwK sequences and
code-width growth) and requires exactly `width * height` pixels per image without materializing
dictionary strings. A missing trailer after at least one complete image is `ValidTruncated`
(Low, length = limit); reaching the limit anywhere else is `Invalid`. Subtypes are `gif87a` and
`gif89a`; the per-file cap is 128 MiB. **Reason:** the block chain alone is easy to forge, while
the pixel count is cheap to verify and accepts ordinary interlaced, animated and
extension-bearing files. Treating a pre-image cut as `Invalid` avoids reporting a header fragment
as recoverable data.

## 2026-10-20 — BMP validation is strict because the magic is two bytes

**Question:** `BM` is only two bytes and BMP has no checksum or self-describing terminator; how
strict should validation be? **Choice:** require zero reserved fields, a whitelisted DIB size
(12, 40, 52, 56, 64, 108 or 124), nonzero dimensions within a 2^28-pixel cap, `biPlanes == 1`, a
whitelisted bit-depth/compression pair, a coherent palette size and `bfOffBits`, and exact data
bounds from stride × height or from the RLE packets. RLE8/RLE4 streams must frame every run,
absolute packet, delta and end-of-line/bitmap marker within the bitmap bounds. Bitfield masks
must be nonzero, disjoint and fit the depth. Up to 64 MiB of trailing data inside `bfSize` is
accepted for ancillary profiles; the reported length is `bfSize`. Deep mode only raises
confidence because there is no additional structure to decode. A candidate whose header and
palette are complete but whose pixel data is cut by the limit is `ValidTruncated` (Low,
length = limit). **Reason:** a two-byte magic produces frequent chance matches in unallocated
space, so every redundant field is used to avoid exporting random bytes; the accepted structures
cover the common Windows, OS/2 and BITFIELDS writers, and rejecting an exotic but coherent header
is preferable to emitting garbage.

## 2026-10-20 — BMP embedded JPEG/PNG payloads are not decoded recursively

**Question:** BI_JPEG (4) and BI_PNG (5) bitmaps contain a complete JPEG or PNG image. Should the
validator parse that image? **Choice:** accept only the documented bit depths and require the
payload to start with a JPEG `FF D8 FF` sequence or the eight-byte PNG signature; report subtype
`jpeg`/`png`, add the note `embedded_image_unverified`, and keep confidence at Medium even in deep
mode. **Reason:** the embedded bytes are opaque from the BMP header's point of view, recursive
validation would duplicate the other validators and their resource limits, and the note makes the
unverified payload explicit in every report.

## 2026-10-20 — GIF/BMP fuzz targets and seeds

**Question:** the existing fuzz decision lists `fuzz_sig_{jpeg,png,pdf,zip}`; how should the new
validators be covered? **Choice:** add `fuzz_sig_gif` and `fuzz_sig_bmp` to `fuzz/CMakeLists.txt`
and the CI 60-second loop, with three deterministic seeds each under `tests/fixtures/fuzz/`
(valid multi-frame, valid single-frame/alternate dimensions, and truncated or malformed). The
seeds reuse the `file_builders.py` GIF/BMP builders. **Reason:** both validators make
attacker-controlled size and dictionary decisions, so they need the same ASan/UBSan coverage as
the existing parsers, and sharing the fixture builders keeps the seeds structurally meaningful.

## 2026-10-23 — exFAT deleted-entry interpretation

**Question:** exFAT clears the InUse bit on deletion and keeps the entry set in place, so how much
of the directory data can be trusted, and how is cluster reuse detected? **Choice:** treat any
entry set whose primary byte 0 is `0x05`/`0x85` (file) with a valid SetChecksum as a deleted file.
StreamExtension byte 1 bit 1 (`NoFatChain`) means the size is authoritative and the data is
contiguous from the first cluster; when the flag is absent follow the FAT chain and use the extents
it yields, so fragmented files come back exactly. If the chain is broken or loops, fall back to the
contiguous assumption, mark confidence `Low` and add the note `fat_chain_lost; contiguous_assumption`.
The allocation bitmap is the reuse oracle: any cluster of a deleted file that is currently allocated
sets `ClustersReallocated` and caps confidence at `Low`. Zero-length entries are reported at High with
no extents. The last extent is trimmed to the file size. Timestamps carry a UTC offset but not a
daylight rule, so they are recorded as parsed with the note `exfat_local_time_assumed_utc`.
**Reason:** the bitmap is the only on-volume evidence of reuse that survives a format-independent
undelete, `NoFatChain` is what Windows actually writes for small and contiguous files, and stating
the contiguous guess in the note keeps a recovered-but-wrong assumption visible in the report instead
of hidden in a confident-looking record.

## 2026-10-23 — VHD containers are read by their virtual geometry

**Question:** the 2026-10-20 decision rejects container formats by magic. VHD is the one container
whose mapping to virtual bytes is fully described by metadata inside the file, so should it be read?
**Choice:** yes for fixed and dynamic disks. `ImageDevice` classifies by the `conectix` cookie in the
first or last 512 bytes; `VhdDevice` validates the footer checksum and format version, takes the
virtual size from `CurrentSize`, and for a dynamic disk reads the `cxsparse` header at the footer's
`DataOffset`, the block size, and the big-endian block allocation table. Each data block is preceded
by a sector bitmap of `align_up(ceil(sectors_per_block / 8), 512)` bytes and bits are read
LSB-first; an unallocated BAT entry (`0xFFFFFFFF`) or a clear bit reads back as zeros. A truncated
bitmap or data block warns once and reads zeros rather than failing the whole open. Differencing
disks (`Type = 4`) return `Unsupported`. **Reason:** the footer and header are self-describing and
checksummed, so a misread is loud rather than silent; a recovery tool must present the same logical
disk the operating system saw, and mapping through the BAT is exactly that. Reading zeros for what
the container never allocated mirrors what a real sparse disk returns, and a partial copy of a dying
disk must still yield the sectors it does hold.

## 2026-10-23 — report.json records the container format

**Question:** with VHD support the bytes recovered are no longer the bytes of the file the operator
passed in, and `source.description` is deliberately the `--source` argument, not the device
description. How does a report show this? **Choice:** add `DeviceInfo.container` (set by the
container devices, propagated through the cache, guard and partition-view decorators) and mirror it
into `source.container` in the report, empty for a flat source. **Reason:** an auditor reading a
report must be able to tell whether an offset refers to the image file or to the disk inside it; a
dedicated field is machine-checkable, while appending to the free-form description is not.

## 2026-10-23 — the scan window is never part of a file's length

**Question:** `BoundedReader::limit()` is `min(signature max_file_size, bytes left in the scanned
region)`, so it says where the scan stopped, not where the file stopped. SQLite compared
`limit % page_size` and TIFF rejected a candidate whose trailing window exceeded 64 MiB of free
space. Both discard real files. **Choice:** a validator may only use the window to *bound* what it
claims, never to decide validity. The declared length (SQLite page count, RIFF size, TIFF's highest
referenced byte) drives the verdict; if it exceeds the window the hit is `ValidTruncated` with the
length rounded down to a boundary the validator can prove (whole pages for SQLite, the window itself
for WAV, whose chunk list is walked far enough to require a `fmt ` chunk before a truncated hit is
accepted). Engine-side checks stay as they are: a hit needs `0 < length_bytes <= reader.limit()`.
**Reason:** on a real image the window is tens or hundreds of megabytes wide and its size depends on
where the previous candidate ended, so any length arithmetic on it makes recovery a function of
unrelated scan geometry. Truncated is an honest answer; rejected is a lost file.

## 2026-10-23 — TIFF, WAV and SQLite get fuzz targets and replayable seeds

**Question:** the three newest validators have no libFuzzer target, and the corpora those targets
would use cannot be built or run on the Windows development host. How are the seeds kept honest?
**Choice:** add `fuzz_sig_tiff`, `fuzz_sig_wav` and `fuzz_sig_sqlite` to `fuzz/CMakeLists.txt` and
the CI 60-second loop, generate their seeds from new `file_builders.py` builders, name seeds that
must be rejected `invalid_*`, and have `test_sig_tiff`/`test_sig_wav`/`test_sig_sqlite` replay their
committed corpus through the real validator via `tests/support/fuzz_seeds.hpp`. **Reason:** the
replay test runs wherever the suite runs, so a builder that drifts away from the format fails on
Windows immediately instead of producing a corpus that only a Linux fuzzer would ever question; the
VHD fixture generators showed the same class of bug is caught far cheaper by a second consumer of
the builders than by hand-checking bytes.

## 2026-10-23 — VHD parsing is swept with the checksums repaired

**Question:** eight hand-written footer and block-table cases say the reader handles the shapes
someone thought of. Byte-flip fuzzing does not fix that: every field the format protects with a
checksum fails the checksum gate first, so a raw flip sweep refuses almost every mutant before it
reaches a value check, on Linux or Windows. **Choice:** run two sweeps in `test_vhd_device`. The
first flips bytes (every position with `0xFF`, sampled every eighth with the one-bit masks, since
each mutant costs about a millisecond through a fresh `CachedDevice`). The second rewrites a
footer or header field and then *recomputes the checksum that covers it*, so the parser has to
judge the value: disk type, current size, data offset, block size, table offset, entry count. Both
halves use one acceptance rule: a refusal carries `CorruptStructure`, `Unsupported` or
`InvalidArgument`, and anything else fails; a container that opens must keep its invariants
(virtual size inside the format cap, a fixed device never mapping the trailing footer, reads
completing to the requested length, overlapping reads agreeing about the same byte, no bytes
returned past the end of the disk, bad sectors only inside it). `fuzz_vhd` and a committed `vhd`
seed corpus carry the same shapes to Linux; the seeds are written by `make_vhd_fixtures.py`'s
container builders around a volume whose byte pattern the C++ test rebuilds on its own.
**Reason:** the repaired half reaches the value-validation branches a flip sweep cannot, and the
invariant list is what turns a sweep into a test rather than a crash oracle -- a device that opens
but answers the same offset twice differently, or maps past its own size, is exactly the recovery
bug a checker would report as a plausible file. Result: no reader defect across ~11 700 mutants;
the sweep found one out-of-range field offset in the test helper itself, which now asserts
`offset + width <= size` before it writes.

## 2026-10-23 — the package is audited by layout, not by a trial compile

**Context:** 1.1.0 started exporting `OpenRecover::core` for `find_package`, added the
`openrecover/openrecover.hpp` umbrella and `examples/recover_image.cpp`, and CPack now has to ship
headers, the vendored `tl/expected.hpp`, both static archives and the generated CMake files. A
consumer-only failure (a header the install rules forgot, an export set pointing at an archive that
was never installed, a `BUILD_INTERFACE` slip that leaves a `_deps/...` path in the installed
config) looks identical to a successful build from inside the tree.

**Decision:** `tests/e2e/install_layout.py` runs `cmake --install` into a prefix under the build
directory and audits the result without a compiler. It asserts the layout a consumer depends on
(umbrella header, `tl/expected.hpp`, config/version/targets files, two archives, the CLI, the
profiles directory the installed CLI resolves to, the sidecar payload); that every archive path the
export set imports exists and every installed archive is referenced; that no line of the generated
CMake files names an absolute build path unless it goes through `_IMPORT_PREFIX`; and that every
quoted include of every installed header resolves inside the package, walked transitively from the
umbrella. The umbrella must also keep naming all five subsystems and none of the internal scanners.

**Reason:** the header-closure walk is the cheap version of the trial-compile test, and it is the
check that actually catches the common regression -- one header missing from the install set. A
trial compile would additionally need a compiler in the test environment, which `ctest` run outside
the Visual Studio shell does not have, and it would fail for toolchain reasons rather than packaging
reasons. `--skip-install` lets the audit run against an existing prefix, which is how the negative
cases were verified: deleting `include/tl/expected.hpp` or `openrecover/common/error.hpp` from an
installed tree makes the test name the exact missing file, so the checks are not vacuous.

## 2026-10-23 — the pipeline lives in the library, the CLI keeps the strings

**Context:** `cli/src/commands.cpp` had grown the whole recovery procedure -- open the source, read
the partition table, pick a volume, force a filesystem, name each partition's filesystem, build
report entries, export metadata hits, choose a carve scope, export carve hits. A consumer that
wanted what `openrecover recover` does had to copy about four hundred lines of it, and the copy
drifted: the example in `examples/` already differed in volume selection and in which carve options
it set.

**Decision:** `openrecover/recover.hpp` owns the procedure. `open_volume` chooses the volume and
identifies the filesystem, `export_metadata` and `carve_and_export` write through the caller's
`OutputSink`, and `recover` chains both into a finalized `report::Report`. The CLI kept the parts
that are CLI-shaped: argument strings and their parsers, the progress printer, where the report goes
and what it is named, and the table it prints. `run_recover` is now twenty lines of adapters
(`make_source_request`, `make_filter`, `make_carve_request`) around three library calls, and the
example is ninety lines instead of two hundred. `commands.cpp` shrank from 1035 lines to 704.

**Reason:** the parity test is the migration. `cli_e2e` compares the CLI's reports against the
committed goldens and passed unchanged, and `test_recover_api` asserts the same numbers the goldens
carry (fat32_basic: nine deleted entries, nine exported, one carve hit that duplicates a metadata
file; carve_mixed: twelve hits, twelve exported), so the library path and the CLI path are the same
path by measurement, not by intent. Two deliberate deviations are recorded in the release notes:
five error messages were reworded because they no longer describe command-line flags, and
cancellation now surfaces from the phase that stopped ("scan cancelled", "carve cancelled").
Cancellation needed a decision of its own: `make_progress` used to return an empty callback when
`--json` or `--no-progress` suppressed output, which also silently disabled Ctrl-C, and the CLI
patched over that with a `g_cancelled` check after every scan. It now returns a callback that prints
nothing and only watches the flag, so the library is the one that stops.

**Consequence:** `recover()` takes an `OutputSink*` rather than an output path, because only the
caller knows where the report goes and the library must not decide. That is why the CLI calls the
three steps instead of `recover()` -- it opens the source *before* the destination, so a bad source
is reported as a source error rather than as "an output directory is required", and the ordering was
already user-visible behaviour. `recover()` is what a consumer calls, and what `test_recover_api`
and the example exercise.

## 2026-10-23 — Catch2 is compiled with exceptions so a failure fails

**Context:** a failing `REQUIRE` in a unit test did not end the test run. Catch2 printed
"Catch will terminate because it needed to throw an exception" and then hung until the ctest timeout
fired -- 300 seconds of nothing, with the binary holding its own output file open so the next build
could not relink it.

**Decision:** `cmake/OpenRecoverDeps.cmake` adds `/EHsc` to the fetched `Catch2` and `Catch2WithMain`
targets on MSVC. The project's own warning function is what gives `/EHsc`, and it is not applied to
third-party targets, so Catch2 detected a compiler without unwind support and built itself with
`CATCH_CONFIG_DISABLE_EXCEPTIONS`.

**Reason:** with exceptions off, `REQUIRE` cannot unwind out of a test case, so a genuine failure
turns into a hang and a hang turns into a timeout -- which reads like a slow machine rather than a
broken assertion, and hides the message. Test TUs are compiled with `/EHsc` by
`openrecover_set_warnings`, so the library and its consumers now agree on unwind support.

## 2026-10-23 — an LZNT1 group consumes its entry bytes, it is not padded to sixteen

**Context:** [MS-XCA] describes a compressed chunk as a sequence of groups, each a flag byte
followed by up to eight entries, an entry being one literal byte or a two-byte back-reference. It
does not say in one sentence how long a group is. Both readings are defensible: a fixed group of
`1 + 16` bytes, or entries packed consecutively so a group of eight literals takes 9 bytes and a
group of eight matches takes 17. The first decoder written here used the fixed reading.

**Decision:** entries are read consecutively. A group starts at a flag byte and ends after its
eighth entry, and whatever follows is the next flag byte. The same rule is what the fixture
encoder in `tools/fixtures/lznt1.py` writes, so a builder and a reader cannot drift apart.

**Reason:** the specification's own worked example settles it. Its 59-byte chunk decodes to the
142 documented characters with flag bytes at offsets 0x02, 0x0D, 0x19, 0x27 and 0x37, which is
where the text says the final flag byte sits; the fixed-16 reading misparses the same bytes and
reports a match reaching before the start of the chunk. libfwnt's `lznt1_decompress_subblock`
walks the same way, advancing by the entry size rather than by a group size. The offset/length
split is pinned by the same evidence: `shift = 12` and `mask = 0xFFF` while the chunk has produced
up to sixteen bytes, and one bit moves from the length to the displacement every time the produced
count doubles past 16, 32, 64 -- which `test_lznt1` checks with the tuple bytes themselves at the
sixteenth and seventeenth produced byte, so an off-by-one here fails a test rather than quietly
changing what a file looks like.

## 2026-10-23 — a compressed file is expanded at scan time and reported without extents

**Context:** spec 4.3 rule 10 says a compressed or encrypted unnamed `$DATA` is emitted with
`Unsupported`, no extents and `note="ntfs_compressed|encrypted"`, and the M2 fixture list requires
`ntfs_compressed.img`'s compressed file to come back `Unsupported`. That is the frozen v1.0.0
behaviour; 1.1.0's goal is the bytes, so this record supersedes both for *compressed* data only --
encrypted data keeps rule 10's outcome. The reading path is `RecoveredFile::extents` plus
`read_file`, which maps a file offset to a disk offset, and an LZNT1 file does not fit it: a
compressed unit is variable-length and its clusters sit next to the next unit's, so a read at an
arbitrary offset needs the whole unit decoded first.

**Decision:** a compressed `$DATA` is decoded during `scan_deleted` into
`RecoveredFile::resident_data`, the same channel a resident attribute already uses. `extents` is
left empty because there is no offset mapping to report, and the clusters the compressed form
occupies are kept privately so the reuse check still decides confidence: `High` while they are free,
`Low` with `ClustersReallocated` once they are not. The expansion is bounded -- 256 MiB per file
and 1 MiB per buffered unit -- and anything outside those bounds, an encrypted attribute, a unit
width that cannot be buffered, and a stream too damaged to decode are reported as `Low` with the
reason in `note`.

**Reason:** `read_file`, the export path, carving dedup and the report all already understand a
resident file, so the capability costs no interface change and stays read-only. The alternative --
a streaming decoder behind a new public hook -- would push unit buffering into every consumer for
the same bytes. The cost is memory for one file at a time, which is why the cap exists and why
exceeding it degrades to a note rather than an error. Chunk output is staged per chunk, so the last
partial unit of a file stops at the byte count it needs and never parses the padding that follows
the stream inside its cluster.

**Unit model, for the record:** the attribute's log2 field at 0x22 is the unit width in clusters
(Windows writes 4, so 16 clusters and 64 KiB with 4 KiB clusters); the runlist counts VCNs in the
*uncompressed* space, so a unit is followed by a hole for the clusters it did not need and adjacent
holes merge; a unit whose clusters are *all* allocated was stored verbatim, which is also how the
reader tells raw from compressed; and an all-zero unit is a single hole spanning it.

## 2026-10-23 — the $I record is read as documented, and a path is only claimed when it is safe

**Context:** a soft delete moves a file to `$Recycle.Bin\<SID>\$R<suffix>` and writes a sibling
`$I<suffix>` holding the original path, the deletion time and the size. The layout is not in
[MS-XCA] or any Microsoft document; it is reverse-engineered knowledge, and the field offsets
disagree between write-ups. Restoring the path is also the first feature in this library that puts
data from the *image* into the report's path field, which is the value an exporter turns into a
filename -- so a hostile or merely corrupt record becomes an injection question, not a cosmetic one.

**Decision:** take the layout from `libyal/dtformats`' Windows Recycle.Bin specification and confirm
it against an independent reader's validation data before writing a parser: little-endian, version
`u64` at 0, original size `u64` at 8, deletion FILETIME `u64` at 16, then version 1 putting the
UTF-16LE path at 24 inside a fixed 260-wchar field real Windows pads with NULs, and version 2
(Windows 10 and later) putting a `u32` character count at 24 -- counting the terminating NUL -- with
the path at 28. A version that is neither 1 nor 2 is `ErrorCode::Unsupported`; a record whose fields
or path are truncated is `CorruptStructure`. `$I` and `$R` are paired by their shared lowercase
suffix, because Windows picks that suffix at random and keeps the extension, so base names are not a
key. Recorded paths are refused when they start with `\\` (UNC and `\\?\` forms cannot be placed
under an output directory), and drive prefixes are stripped before each component goes through the
existing `sanitize_component`, so the only `:` left is one the sanitizer would have rewritten anyway;
a path containing `..` claims no path at all. A zero FILETIME means "not recorded" and leaves
`deleted_unix` unset rather than reporting a deletion in 1970. When the `$I` size differs from the
bytes actually recovered, the path is still restored -- it is metadata about the file, not about the
data -- and the file gains `PathUncertain` plus a note carrying both numbers. The `$I` records
themselves remain in the scan output as ordinary recovered files.

**Reason:** the restoration has to be self-describing or it is worse than the recycle-bin path it
replaces. `test_ntfs_recyclebin` therefore ends with a mutation sweep over a valid record and asserts
the invariant directly: whenever a path was restored it contains no backslash, no colon, no `..` and
is not the `$R` name it replaced, and whenever a flag or a deletion time is absent nothing was claimed
at all. The shape stays additive -- one new flag bit and a `deleted` key emitted only when a deletion
time is known -- so the 16 committed CLI goldens and every pre-existing NTFS golden are byte-identical
after this change, which the fixture rebuild re-checks rather than assumes. `flag_names` returns
flag-table order while the goldens store names alphabetically, so the test helper sorts before
comparing instead of freezing either order into the library.

**Cost, for the record:** the version 1 path field is a fixed 520 bytes that real Windows pads with
end-of-string characters, so decoding stops at the first UTF-16 NUL code unit rather than at the end
of the field, and the field itself is capped before it is decoded. Version 2 has the opposite
shape -- the count is trusted, so a record claiming more characters than the file holds is truncated
and refused, while one whose claimed span carries no terminator is read as the whole span. That is
why the claimed count is bounded to 1024 characters before any decoding happens.

## 2026-10-23 — a signature may anchor its magic past the start of the file

**Context:** every carved format so far begins with its magic, so the scan compared at the candidate
offset. An ISO media file does not: MP4, QuickTime, M4A, 3GPP and HEIF all open with a box whose
first four bytes are *that box's length*, and only then the fourcc. Matching four bytes at an offset
of four would either mean a special case in the engine or a signature that cannot be found.

**Decision:** `ISignature` gained `magic_offset()`, defaulting to zero, and the scan compares the
magic at `candidate + magic_offset()` while the hit keeps pointing at the candidate. The candidate
start stays the file start because the recovered bytes begin there -- the box header is part of the
file, not a prefix to skip.

**Reason:** the hook is one virtual with a default, so no existing signature, pack loader or fuzz
target changed, and the next format whose magic sits behind a length field gets it for free. The
alternative -- teaching the engine about box sizes -- would put format knowledge in the scanner,
which is where the read-only invariants live and which knows nothing about any one file type.

## 2026-10-23 — a media file is claimed by its boxes, and the boxes end where the vocabulary does

**Context:** an `ftyp` fourcc is eight bytes of luck in slack space; the family is the only container
format here whose length has to be *derived* by walking structure rather than read from one header
field. Two properties had to be chosen together: what makes a candidate a media file at all, and
where the file stops.

**Decision:** a candidate is a media file only if the brand list names a family the library knows --
the major brand first, then the compatible-brand list -- and the walk of top-level boxes has seen
both an `mdat` and a `moov` (a `meta` box counts for HEIF, which has no moov). The walk stops at the
first header whose fourcc is outside the top-level vocabulary of the format, and that point *is* the
end of the file: whatever follows was written by a different file or is slack. A box whose own bytes
run past the scan window, or one that declares size zero ("to the end of the file", which a scan
cannot see), makes the candidate a fragment: `ValidTruncated`, `Low`, length equal to the window. A
window that merely ends where the boxes ended is not a fragment, because every byte claimed then
belongs to a box that was read. The extension comes from the brand, so one signature exports `mp4`,
`mov`, `m4a`, `3gp` and `heic`.

**Reason:** the cluster after a deleted video is not free space, it is the next deleted file, so a
rule that keeps walking through unrecognised boxes would merge neighbours. Requiring both halves of
a playable file -- the descriptor and the media -- costs a real cut file (it comes back Low with the
missing half named in `note`) but refuses the header-only decoys that carving noise produces. The
mutation sweep in `test_sig_mp4` holds the invariants for every single-byte change of a valid file:
a refused result, or a result that claims only bytes inside the window, with the truncated verdict
always exactly window-sized and never above `Low`.

## 2026-10-23 — two families open with the same four bytes, so the form type decides

**Context:** RIFF is a container family, not a format: AVI, WAV and every other `LIST`-based
multimedia file start with the same four bytes and name themselves four bytes later. The library
already carved WAV with a `RIFF` magic and a `validate()` that checked `WAVE` at offset 8. Adding
AVI could have meant one signature reporting two subtypes, or a longer magic that the scan could
match directly.

**Decision:** two signatures, each with the four-byte `RIFF` magic, each checking its own form type
inside `validate()` -- `WavSignature` refuses `AVI ` and `AviSignature` refuses `WAVE`. The registry
lists WAV before AVI, and the scan takes the first signature that validates a candidate, so the
order only queues the two; it never picks between them. What an AVI hit may claim is judged by
structure: a `LIST hdrl` is what makes it a video, a `LIST movi` (or its `rec ` groups) is what
makes it a video with content, and a file that carries an `idx1` index but no movie list is
`ValidTruncated` at `Low` with the missing half named in `note`, because the index describes frames
that are not in the bytes being claimed.

**Reason:** a single signature for the RIFF family would have to report a subtype the exporter had
not been asked for, and a seven-byte magic (`RIFF` plus the form type at offset eight) is exactly
the special case `magic_offset()` was introduced to avoid: the hit must still start at the file, and
the form type is format knowledge that belongs in the validator. Keeping the two families apart in
`validate()` is also what makes the pair testable -- `test_carve_engine` places a wave and a video
in one freed region and requires one hit of each type, which a shared signature could not express.

## 2026-10-23 — a recording that stores no length is sized by the chain of its frames

**Context:** MPEG audio has no header that says how long the file is, and no trailer that has to be
present. Everything about a recording is in the frame headers: each says how many bytes that frame
occupies, and the next frame starts where it ends. In slack space that is both the whole problem and
the only evidence -- a two-byte sync word appears by chance, and a scan window can end in the middle
of a stream that continues.

**Decision:** a candidate is audio only if the frame headers chain: the decoder looks the bitrate and
sample rate up in the format's own tables, computes the frame length, and requires the next header at
exactly that offset with the same version, layer and sample rate. Three chained frames is the minimum
a hit needs, sixteen make it `High`, and anything shorter is refused or reported `Medium` with the
frame count in `note`. A frame that runs past the scan window, or frames that tile it exactly, is
`ValidTruncated` at `Low` -- a chain that reaches the window edge says nothing about where the file
ends. An ID3v2 tag is counted as part of the file when its size can be trusted: the declared size, the
padding after it and a version 2.4 footer held outside the size are all followed, while
unsynchronisation and an extended header are refused because they rewrite or relocate bytes the size
field no longer describes. An ID3v1 trailer is absorbed only when the frames stop exactly where the
`TAG` marker starts.

**Reason:** the chain is the only structure this format has, so it is also the only thing that
distinguishes a recording from noise that happens to open with `0xFF 0xE0`. Requiring parameters to
stay constant is what stops the walk running through the end of one deleted stream and into the
bytes of whatever was freed next to it -- the same neighbour-merging failure the media-file box
vocabulary guards against. The conservative verdicts cost a real cut file its `High` confidence but
keep every claim inside the bytes that were read, which is the invariant the single-byte mutation
sweep in `test_sig_mp3` enforces: never a byte outside the window, never `Truncated` below the
window edge, never a `Valid` verdict that says something is missing.

## 2026-10-23 — a container that stores no length is sized by the sectors it owns

**Context:** a compound file binary -- the container a legacy Word, Excel or PowerPoint document
lives in -- has no end-of-file field. Its 512-byte header names the sectors that hold the
allocation table, the table chains the directory and the streams, and nothing in the file says how
many sectors the last chain link is followed by. A validator that wanted a length had to either
guess one or read the table.

**Decision:** read the table and size the hit from it. The header's 109 map entries and the DIFAT
chain behind them name the allocation sectors; the hit ends at the highest table entry that is not
marked free, plus one sector. A window that cannot reach a table sector, a table longer than the
walk reads, or a table with no free entry at its end produces `Truncated` at `Low` instead of a
length. Inside the claimed bytes the directory has to terminate in a chain the table can follow,
name a root entry and at least one stream, keep every stream size inside the container, and give
every used entry one of the three object types and one of the two tree colours the format defines;
a chain that aims at a sector the table leaves free is refused. The extension comes from the
directory rather than from the container: `WordDocument` is `.doc`, `Workbook` or `Book` is `.xls`,
`PowerPoint Document` is `.ppt`, and none of them is `.cfb` at `Medium`.

**Reason:** the table is the only structure this format has, so it is both the only honest source of
a length and the strongest corruption signal available. Requiring a free tail is what keeps a
truncated container from being reported as a complete one: a table whose every entry is in use says
"the next sector might also belong to me", which is a boundary claim, not a fact. Checking chain
targets against the sectors the table itself claims to own catches the neighbour-merging failure --
a deleted document whose tail was reallocated picks up a chain that points at a sector the file
never owned, and the only way to know that is to read the table instead of trusting the header.
Naming the file from the directory stream rather than from the container is what the recovered bytes
actually are to the person asking for them back: a `.cfb` whose stream is `WordDocument` is a Word
document, and the alternative is telling the user to open an unknown binary and guess. A compound
file with no application stream still gets reported, one confidence step down, because it is a real
file that some other program wrote and refusing it would lose it. The single-byte mutation sweep in
`test_sig_cfb` holds the same three invariants the AVI, MP3 and media-file tests enforce: never a
byte outside the window, never `Truncated` below the window edge, never a `Valid` verdict that notes
something missing except for the one note that says the container is not an Office document.

## 2026-10-27 — 1.1.0 is the frozen baseline between cycles

**Question:** the documented goals of the 1.1.0 cycle are met and released, but the tree has to stay
usable as a starting point for the next cycle; should the version be bumped to a development number
now, or should the tree sit at the released number?

**Choice:** the tree sits at `1.1.0` -- the exact version packaged in `dist/` -- until the next cycle
starts. `AGENTS.md` names 1.1.0 as the frozen baseline and rule 3 became "released versions are
frozen" rather than naming one release; `OPENRECOVER_SPEC.md` gained an addendum so its v1 non-goal
list (exFAT, VHD, NTFS compressed extraction) cannot be read as a command to revert shipped code;
`RELEASE_NOTES.md` keeps the 1.1.0 section as a released record and holds the candidate scope under
`Planned`. A new cycle targets 1.2.0 and bumps the version with its first change, in the same step
as the golden refresh. **Reason:** the report goldens embed the tool version and `cli_e2e` masks only
`generated_at`, so bumping the version on an idle tree forces five golden regenerations and leaves
`--version` disagreeing with the artifact in `dist/` -- a baseline that claims to be the released one
but is not. The number should change when the behaviour does. **How to apply:** at cycle start, edit
`project(... VERSION)` in `CMakeLists.txt`, `OPENRECOVER_VERSION` in `cli/src/main.cpp`, the default
in `report::Report`, and `tests/unit/test_report.cpp`, then rerun the `cli_e2e` command of
`tests/CMakeLists.txt:190` with `--update-goldens` added and
`--work "${CMAKE_CURRENT_BINARY_DIR}/e2e-goldens"` so the committed goldens are rewritten from the
new binary, and keep the `find_package(OpenRecover 1.x)`
compatibility claim and `OpenRecoverConfigVersion.cmake` (`SameMajorVersion`) in step.

## 2026-10-28 — ext4 is read as written, and its checksums are trusted only where the format binds them

**Context:** ext4 is the filesystem breadth item of 1.2.0. It differs from the Windows formats in
three ways that shape the parser: the superblock sits at byte 1024 rather than in a boot sector, so
there is no first-sector signature and the partition scanner sees "nothing" on a bare volume; deleted
inodes keep their block map but lose their name, which only survives in directory slack; and a
`metadata_csum` volume carries per-inode checksums whose seed and coverage depend on the creator OS.

**Decision:** read ext4 through the same `IFileSystemScanner` seam as every other format. Detection
tries the ext4 magic at 1024 before FAT32, and a volume that carries the magic but fails validation
is reported as an ext4 error instead of being handed to the FAT32 parser. The partition scanner
recognises a bare ext4 volume as a `superfloppy` using the same signature-level test it already used
for FAT32, exFAT and NTFS, so `partitions`, `--partition 0` and `report.partitions` agree across the
four whole-device formats. Inode checksums are verified only when the volume is `metadata_csum` and
`creator_os` is Linux, matching the kernel, so a volume formatted by another OS is not reported as
corrupt for a checksum it never wrote the same way. A deleted inode is named from a directory entry
whose inode field was cleared, paired by its timestamp; when no entry survives the file is reported
with `PathUncertain` rather than dropped. The block bitmap decides reuse: a deleted file whose blocks
are marked allocated is `Low` with `ClustersReallocated`, because the bytes belong to whoever the
filesystem gave them to next; `flex_bg` only relocates where the allocator stores the per-group
bitmaps, so the map follows each group's own descriptor instead of assuming one bitmap per cluster.
Inline data is decoded in place; encrypted and compressed inodes are reported `Unsupported` with an
explicit note instead of exporting ciphertext as if it were content. Volume
features that move metadata or change block accounting (`meta_bg`, bigalloc, quota snapshots) are
refused at the superblock: this reader follows the linear descriptor table, so decoding a `meta_bg`
volume would treat arbitrary blocks as group descriptors and report files that never existed.

**Reason:** every one of these choices is about not claiming more than the disk says. The 1024-byte
superblock is why detection has to look past sector 0; skipping that would make `--fs auto` silently
fail on every ext4 image. Verifying foreign-OS checksums would produce a corruption verdict on a
perfectly healthy volume, and a recovery tool that cries wolf is worse than one that reports lower
confidence. The bitmap already exists to answer "is this still mine?", and using it is the only way
to avoid handing back another file's bytes under the deleted file's name. Reporting encrypted bytes
as recovered content would violate the one promise the tool makes: what it returns is the file.

**How to apply:** the Python builder in `tools/fixtures/make_ext4_fixtures.py` writes both images and
their goldens; CI never runs `mke2fs`, for the same reproducibility reason the NTFS fixtures are
built in Python. `test_ext4_recover` asserts the goldens, `test_ext4_mutation` sweeps single-byte
corruptions of the committed image, and the three ext4 fuzz targets replay their seed corpora. A
change to the inode pairing, reuse or checksum rules must keep those three layers green and add a
golden field when the user-visible report changes.

## 2026-10-28 — a VHDX is judged by its structures, and its absent blocks are zeros

**Context:** VHDX is the container-breadth item of 1.3.0. Unlike VHD's single 512-byte footer, its
geometry is spread over two headers, two region tables, a metadata region and a BAT, and every
header and table carries its own CRC32C. The format also defines block states VHD has no equivalent
for -- `NOT_PRESENT`, `UNDEFINED` and `ZERO` -- and a differencing disk is only meaningful with the
parent chain a read-only recovery tool cannot assume.

**Decision:** a VHDX is detected by the `vhdxfile` identifier, never by its extension, and is read
into a virtual `BlockDevice` of the size the metadata names, so the filesystem layer sees exactly
what it would see in a flat image. Header and region-table copies are used as a pair: when one copy
fails its checksum or bounds check, the other is tried, and a file with no usable pair is refused.
`NOT_PRESENT`, `UNDEFINED` and `ZERO` blocks read as zeros; a partially-present block is read
through the 1 MiB sector bitmap that precedes it; a payload that runs past the end of the container
zero-fills its tail with one warning, matching the VHD contract. A differencing disk, a metadata
table that carries a parent locator, an unknown required region and an unknown required metadata item
are `Unsupported`; bad checksums, out-of-range geometry, an unknown block state and a BAT entry with
no file offset are `CorruptStructure`. Bitmaps are only consulted when the chunk ratio allows them,
and the virtual size is bounded at 64 TiB, so a mutated header cannot make the device describe a
larger disk than the format permits.

**Reason:** the two-header/two-table layout exists so a torn write leaves one side intact; refusing a
container because one copy is stale would lose a recoverable image. Treating every non-present state
as zeros is what the format specifies and what a filesystem parser needs: a hole is data the volume
never wrote, not a read error. Parent chains are refused rather than approximated because guessing a
parent would attribute another disk's blocks to this one -- the same reasoning that keeps
differencing VHD out. Detecting by content keeps a renamed `.vhd`/`.img` working and keeps a flat
image whose bytes happen to start with the identifier from being misread as a container.

**How to apply:** the Python builder in `tools/fixtures/make_vhdx_fixtures.py` writes the full and
sparse images and their goldens; `test_vhdx_recover` hashes the virtual volume and compares FAT32
recovery against the flat golden, `test_vhdx_device` sweeps single-byte mutations and checksum-
repaired field patches, and `fuzz_vhdx` replays the committed seeds. A change to validation,
block-state handling or zero-fill behaviour must keep those layers green and update the `vhdx`
section of `tools/fixtures/README.md`.

## 2026-10-29 — a JPEG is rejoined only when its tail proves itself

**Context:** `OPENRECOVER_SPEC.md` §5.2 and §10 declare contiguous-only carving and name
fragment-aware (bifragment / SmartCarving) reassembly a v1 non-goal. That rule was written for a
carver that would have to guess where a file resumes, and guessing is what turns recovery into
fabrication: a wrong join hands back bytes from a stranger's file under the deleted file's name.
But a deleted photo on a volume that kept being written is the common case, and a carver that
stops at the first discontinuity reports half a file as if that were all of it. JPEG is the one
signature here whose bytes carry their own terminator and a self-synchronising pattern, so a tail
can be tested rather than assumed.

**Decision:** a JPEG whose marker walk fails *after* at least one scan and one frame header now
returns `ValidTruncated` at the exact offset where parsing stopped (a new `discontinuity` note;
before this it could report the end of the scan window). The engine, with
`CarveOptions::reassemble` enabled, aligns past that cut to the next allocation-unit boundary and
asks the signature for a `Continuation`: `JpegSignature::find_continuation` walks the bytes there
with the same rules the header walk uses -- `FF 00` stuffing, `FF D0..D7` restart markers and
`FF FF` fill are data -- and refuses at the first marker a scan cannot contain. A tail that
reaches `EOI` at least 16 bytes in is accepted; anything else is `std::nullopt` and the head
stays a truncated hit. A joined hit is two `CarveFragment` ranges: `length` is the sum, the
SHA-256 and the exported bytes are the logical file (head then tail), the flags are the
validator's `Truncated` plus `Fragmented`, the confidence stays the validator's `Low`, and
`report.json` gains `"fragments": 2` for that entry only. The option defaults to `false` in the
library and is set by the CLI, with `--no-reassemble` to turn it off; the search is bounded by
`max_reassembly_gap` (8 MiB).

**Reason:** the validator, not the engine, decides what its own tail looks like, which keeps the
format knowledge in one place and makes the join proof-shaped: random data after the cut is
rejected within a few bytes, because an illegal `FFxx` is almost immediate, while a real entropy
stream is accepted only across its whole length to `EOI`. Not lowering the head's confidence
further and not hiding the flag keeps the report honest -- a joined file is an inference about the
disk, and the note plus flags say so. Leaving reassembly off by default in the library means an
existing consumer's hits do not change shape under it, and the gap bytes are never exported: the
tool reports the extents it has, not the bytes it skipped.

**Limits, stated where a reader will hit them:** only JPEG reassembles; a progressive JPEG split
inside a scan is indistinguishable from a scan's end; a zero-filled gap carries no marker so it
reads as entropy, and a tail that begins inside a zero run is joined with those zeros included,
inflating its length and hash (still `Low`, still `Fragmented`); a tail that starts beyond the
8 MiB gap bound is not searched. *(The single-hop rule below is superseded by the chain entry of
the same date: the engine now walks from cut to cut and keeps the result only when it reaches
`EOI`.)*

**How to apply:** `tools/fixtures/make_carve_fixtures.py` writes `carve_fragmented.img.gz` (a 1 MiB
image with a JPEG cut at 2000 bytes whose tail resumes on the next 512-byte boundary, and a second
cut JPEG with no tail) and its golden; `test_carve_fixtures` asserts the joined hash, both extents,
the flags, the exported bytes and that the orphan stays truncated, `test_carve_engine` covers the
join over a synthetic device and the `reassemble = false` path, and `test_sig_jpeg` pins the cut
offset and the continuation rules. A change to the discontinuity offset, the tail rules or the
fragment plumbing must keep those green and keep `cli_carve_fragmented` matching its golden.
Separately, do not regenerate `carve_mixed*` from the current builder: the committed image and
golden are the 1.2.0 artifacts restored from `dist/openrecover-1.2.0-source.tar.gz`, and the
builder as it stands produces a different palette PNG inside them, so its "byte-for-byte" claim
does not hold for that fixture. New fixtures get their own images, as this one did.

## 2026-10-29 — a chain of JPEG pieces is kept only when it reaches the terminator

**Question:** 1.3.0 joins a JPEG head to one tail, and refuses the join when the bytes after the
first cut are not a scan in their own right. A deleted photo on a volume that kept being written is
often split more than once, and a progressive image puts several scans in one file, so a carver that
joins once still hands back a prefix plus one piece — or, for a progressive image cut at a scan
boundary, nothing at all. What should the engine do with the pieces after the first tail?

**Context:** the join is only as good as the signature's ability to say "these bytes are still my
scan". `find_continuation` already walks a run of entropy-coded bytes and knows when it stops: at
`EOI`, or at any other marker. That second case was the end of the search in 1.3.0; it is also
exactly the shape of the next piece when an image is split twice.

**Decision:** `Continuation` gained `bool complete`. `JpegSignature::find_continuation` now returns
`{0, at, false}` when the run stops at a marker at offset `at > 0` (any marker except `SOI`), and
`{0, end, true}` when it reaches `EOI` at least 16 bytes in; `nullopt` means no run was found at all
(the bytes open on a marker, or no marker appears inside the window). The engine walks the chain:
starting at the first allocation-unit boundary after the head, each attempt reads a window of at
most `max_reassembly_gap` bytes bounded by the scan and by `max_file_size`, asks for a continuation,
records the piece when it is at least one allocation unit long, and resumes at the next boundary
after the cut. The walk stops at the first attempt that returns nothing, when it has persisted for
`kMaxReassemblyAttempts` (256) or `kMaxReassemblyPieces` (8, head included) pieces, or when the next
boundary has drifted more than `max_reassembly_gap` past the last attributed byte. Only an
`EOI`-terminated chain is accepted; an accepted chain replaces the head-only hit, and an unaccepted
one is discarded whole, leaving the head as the truncated hit it was. An accepted hit carries only
the `Fragmented` flag: `Truncated` described the head alone, and the assembled file ends at its own
terminator. `SOI` ends the search outright:
a scan tail can never contain another start-of-image, so the bytes beyond belong to a different
file.

**Reason:** a chain is a stronger claim than a single tail, so the acceptance test is stricter, not
looser: the file is only stitched when its own terminator is found at the end. Discarding an
unfinished chain rather than keeping its pieces keeps the failure mode from 1.3.0 -- a truncated
head is a truthful answer, a half-stitched file is not. The `SOI` refusal is the cheapest available
answer to "does this continuation belong to my file or to the one after it": a neighbouring JPEG's
header can never be mistaken for scan data, while a progressive image's segment markers still stop
the run without ending the chain. Skipping runs shorter than an allocation unit stops a marker-rich
header from contributing zero-length extents. `max_reassembly_gap` keeps its 8 MiB value but now
means two things: how far the walk may resume past the last attributed byte, and the most one
resumed run may contribute.

**Limits, stated where a reader will hit them:** at the time of this entry only JPEG reassembled; PNG
gained the same chain walk later the same day (next entry), and nothing else does. A gap of pure
fill carries no marker, so it is absorbed as scan data and inflates the joined file (still `Low`,
still `Fragmented`). A foreign file's *entropy* data after a gap is indistinguishable from the
missing piece, so a chain that runs from one image's scan into another's and finds an `EOI` can
splice them; `SOI` only stops the case where the neighbouring header is reached first. A run longer
than `max_reassembly_gap` cannot be joined because the window ends before its marker.

**How to apply:** `carve_fragmented.img` now carries a JPEG split twice into three pieces with the
piece extents in its golden; `test_carve_fixtures` asserts the stitched hash, all three extents and
the exported bytes, `test_carve_engine` covers a four-extent chain and a chain that never reaches
`EOI`, `test_sig_jpeg` pins the cut/complete rules and the `SOI` refusal, `cli_carve_fragmented`
reports `"fragments": 3` plus an `"extents"` array mapping each piece on the device,
`test_report` pins that a contiguous hit carries neither key, and the signature fuzz harness replays
a chain from the cut (seed `chained.jpg`). A change to the walk must keep all of those green.

## 2026-10-29 — a PNG tail is rejoined only where CRC-valid chunks reach IEND

**Question:** the chain walk is format-agnostic, but a PNG has no scan and no marker stream: its
structure is chunks that each carry their own CRC. A PNG cut inside an IDAT chunk is not
distinguishable from a corrupt PNG by chunk validity alone — both fail a CRC. How does a PNG head
prove it was cut, and how does the tail prove it belongs to the head?

**Context:** `png_with_bad_idat_crc` is a committed decoy: a complete RGBA PNG whose first IDAT CRC
is flipped. The validator must keep rejecting it, and `carve_mixed`'s golden depends on that. A PNG
cut by later writes looks different: the cut chunk is the last one whose header is still the file's
own, its declared length runs past the surviving bytes, and the bytes where it says it ends are
whatever overwrote the file — not a chunk boundary.

**Decision:** the validator keeps its verdict for semantic violations and for a stream that simply
runs out of bytes, and adds one discriminator for the three structural failures (length past the
limit, non-letter type, CRC mismatch): if the bytes at the failing chunk's *declared* end parse as a
whole valid chunk (length, type letters and CRC), the file's structure survived and the candidate is
rejected whole as before; otherwise the chunk is where the file's bytes stopped, and the result is
`ValidTruncated` with `length_bytes` at that chunk's start and a `discontinuity` note.
`PngSignature::find_continuation` scans forward for a candidate whose own CRC verifies and whose
successor also starts a plausible header (sane length, letter type), then walks chunk by chunk: it
returns `complete` at `IEND` with length zero, and otherwise returns the run up to the first chunk
that fails, so the engine resumes past that cut exactly as it does for JPEG. It never starts on
`IEND` alone, and it gives up on the whole search the moment it meets another PNG signature before
the candidate. The engine is unchanged: `reassemble`, the eight-piece cap, the alignment skip, the
gap limit and the drop-if-incomplete rule all apply to PNG through the same path.

**Reason:** the declared-end test is what keeps the decoy decoy. Treating every post-IHDR CRC
failure as a cut would have turned `corrupted_crc` into a hit and changed a frozen mixed-image
golden for no gain; the intact boundary is positive evidence that the chunk, not the file, is
broken. The successor-header test is the PNG analogue of "a marker is where a scan stops": a CRC can
match by chance once, but a boundary that both verifies and opens a plausible header is ~2^-32 of
one. Refusing the search after another signature is the same reasoning as JPEG's `SOI` refusal —
chunks after a neighbouring image's signature belong to that image. Returning the incomplete run
rather than `nullopt` keeps the chain walk honest: the incomplete length is how the engine learns
where the next cut is without the validator seeing the tail.

**Limits, stated where a reader will hit them:** a cut that lands exactly on a chunk boundary has no
broken chunk to show, so the validator reads whatever overwrote the gap as the next header. Zero or
otherwise unparseable bytes fail its type, which is an ordinary cut at the boundary and joins; bytes
that parse as a plausible length and letter type make the head a truncation claiming everything to
the end of the source, with no tail. A tail must be found within
`max_reassembly_gap` of the head and the walk spends a byte budget of one and a half windows so a
crafted run cannot make every offset look like a header, capped at 4096 candidates. A PNG signature
inside a real image's IDAT data (legal by the format, since IDAT is compressed bytes) would make a
tail refusing to cross it; none of the builders produce one. Reassembly is still `Low` confidence
even when the joined bytes are the complete original.

**How to apply:** `carve_fragmented_png.img` holds a PNG cut once, a PNG cut twice into three
pieces and an orphan head placed before a second image, with the extents and original hashes in
`carve_fragmented_png.golden.json`; `test_sig_png` pins the cut, the resync, the stop at the first
failing chunk, the boundary cut under zero and letter fill and the refusals, `test_carve_engine`
covers a stitched PNG in memory and one cut exactly on a chunk boundary,
`test_carve_fixtures` and `cli_carve_fragmented_png` prove the join end to end (including
`--no-reassemble`), and seeds `split_idat.png` / `orphan_idat.png` drive the fuzz replay. Changing
`cut_or_invalid` or the order of the header checks requires re-checking the `corrupted_crc` and
header-only PNG decoys in `carve_mixed` first: checking the type before the length fits the window
turns the header-only decoy into a 33-byte "cut".

## 2026-10-29 — a gap piece is only the file's if its clusters are free

**Question:** the chain walk starts at an allocation boundary as the format's alignment, but it
never asked the allocation map whether the bytes it found there were in use. Under
`Scope::UnallocatedOnly` a piece whose clusters belong to a live file would be stitched into a
deleted one, and the scan's promise that it only reads free space would be broken by its own
reassembly.

**Context:** the head is still filtered by `geometry.is_allocated` before it is validated, so a
reassembled hit could consist of free head bytes followed by pieces taken from allocated clusters —
bytes the scan was told not to claim.

**Decision:** `AllocationGeometry::overlaps_allocated(map, begin, end)` reports whether any
allocation unit the piece touches is marked in use, and the walk stops (breaking the chain, so the
head stays a truncated hit) when `restrict_allocation` is on and a candidate piece overlaps one.
Bytes past the map's last cluster count as allocated, matching `is_allocated`.

**Reason:** the allocation map is the only statement the engine has about what is free; a piece that
crosses a cluster in use is either a live file's data or a buffer that was rewritten, and in both
cases it does not belong to the deleted file. Stopping rather than skipping keeps the rule the same
as every other failure in the walk: an unfinished chain is discarded and the head is reported alone.

**Limits, stated where a reader will hit them:** the head itself is still checked only at its start
byte, so a head that runs into allocated clusters is reported as before. `Scope::All` and a scan with
no map place no such restriction, and a stale map that marks a genuinely free cluster allocated
costs the join.

**How to apply:** `test_carve_engine`'s "refuses a gap piece that sits in an allocated cluster" pins
the refusal with the PNG resync layout; a change to the walk must keep it and the free-cluster join
beside it green.

## 2026-10-29 — a GIF tail is proven by its own arithmetic

**Question:** the chain walk needs a tail that proves itself, but GIF has no checksums anywhere --
no CRC per chunk like PNG, no marker legality rules tight enough to distinguish a scan from noise.
What makes a GIF head a cut rather than a corrupt file, and what makes a tail the head's?

**Context:** a bare GIF sub-block chain parses from roughly one offset in 85 of junk: a size byte
in 1..255 followed by arbitrary data terminates at the first 0x00, so structure alone proves
nothing about a candidate. The only arithmetic the format carries is the LZW stream each frame
must decode, which is why `validate` under deep validation decodes every frame and `find_continuation`
forces deep validation for its candidates.

**Decision:** the validator keeps `Invalid` for a broken header, a frame whose stream fails the
deep decode, or a structural failure before any frame has completed, and reports `ValidTruncated`
with a `discontinuity` note only when a block fails to parse *after* at least one frame completed --
the failed block is dropped whole and the cut sits at its introducer. The asymmetry is the
precedents: a decode failure is PNG's failed inflate (proof the bytes are not the file), while a
structural failure of a block is indistinguishable from that block having been overwritten, once
the bytes before it have proven themselves by decoding. `GifSignature::find_continuation` scans
forward for a candidate that is a fully validated block under *forced* deep decode, walks it and its
successors to the trailer, and refuses the whole search the moment it meets `GIF87a`/`GIF89a`; it
claims only extensions whose label the format assigns a meaning to (graphic control, application,
plain text), because a comment's chain is free-form and parses anywhere.

**Reason:** forced deep decode is the only usable filter -- without it every junk offset that
parses as a sub-block chain is a candidate, and the engine's skip-short-runs rule would still make
the result depend on where noise fell. Restricting extension labels costs nothing (GIF comment
extensions are vanishingly rare in practice) and removes the largest false-positive class. Refusing
after another signature is JPEG's `SOI` and PNG's rule unchanged: bytes past a neighbouring GIF's
header belong to that GIF.

**Limits, stated where a reader will hit them:** a tail that resumes in the middle of an
interrupted frame's sub-block chain joins at the *next* frame's introducer -- the interrupted
frame's remaining sub-blocks sit in the gap and are unprovable, so the recovered copy of that frame
decodes short and the hit stays `Fragmented`/`Low`. A tail that cuts a frame inside its own data
proves nothing and is never claimed. The byte budget is one and a half windows over 4096 candidates.
Because a cut in the middle of a sub-block chain is terminated by whatever fill follows, the
committed fixture cuts on frame boundaries instead: with the image's 0x5A fill a mid-chain head
marches through the fill in 90-byte blocks (sub-block size 90 from the fill bytes), which no golden
could pin. A boundary cut leaves the head an intact block run that the fill fails to continue, so
the assembled bytes are the original file byte for byte and both the once-cut and twice-cut hits
hash identically.

**How to apply:** `carve_fragmented_gif.img` holds a GIF cut once, cut twice into three pieces and
an orphan head before the next GIF, with extents and the shared original hash in
`carve_fragmented_gif.golden.json`; `test_sig_gif` pins the cut-after-a-frame rule, the
decode-failure split between shallow and deep, the join-at-next-introducer behaviour and the weak
candidate refusals, `test_carve_engine` covers a stitched GIF and a mid-stream cut joined at the
next frame, `test_carve_fixtures` and `cli_carve_fragmented_gif` prove the join end to end
(including `--no-reassemble`), and seeds `cut_frame.gif` / `split_frames.gif` drive the fuzz replay.
Any change to the block walk must keep `test_sig_gif`'s "bytes that fail the deep decode are
corruption" case green beside the cut cases: making a decode failure a cut would turn truncated
LZW streams into joins.
