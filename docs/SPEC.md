# OpenRecover — Implementation Specification

**Spec version:** 1.0  
**Audience:** Autonomous coding agent (OpenCode). Follow this document literally.  
**Targets:** Windows x64 (primary), Linux x86_64 (image/container testing).  
**Out of scope (MUST NOT be implemented):** iOS, macOS/APFS/HFS+, any cloud recovery, any write/repair/format functionality, root/privilege-escalation on Android, ext4/exFAT/ReFS (listed as future work only).

**Addendum (2026-10-27, OpenRecover 1.1.0):** three items this spec lists as v1 non-goals are now
implemented, tested and shipped -- **exFAT** metadata and recovery, **VHD** containers (fixed and
dynamic; differencing disks stay `Unsupported`), and **NTFS compressed-file extraction** (LZNT1).
Sections 10 and the header line above describe v1.0.0 and do not forbid that work any more; read
`openrecover/RELEASE_NOTES.md` for the 1.1.0 behaviour. Everything else listed there remains a
non-goal.

**Addendum (2026-10-28, OpenRecover 1.2.0):** **ext4** is now implemented, tested and
part of the filesystem set: superblock and group descriptors, inodes with extents, `inline_data` and
indirect blocks, deleted-inode recovery, and block-bitmap reuse detection. The ext4 entry in the
header line above and in section 10 records the v1.0.0 scope and does not forbid that work any more.
ReFS and the macOS filesystems stay non-goals.

**Addendum (2026-10-28, OpenRecover 1.3.0 in development):** **VHDX** containers are now in scope.
A VHDX is read through its virtual geometry -- the `vhdxfile` identifier, both headers with their
checksums, both region tables, the metadata region (virtual disk size, block and sector sizes) and
the block allocation table with its sector bitmaps -- and unallocated blocks and sectors read back
as zeros, the same contract the VHD reader already keeps. Differencing disks and a parent chain stay
`Unsupported`. The container entries in the header line above and in section 10 record the v1.0.0
scope and do not forbid that work any more. E01 remains a non-goal for this cycle.

---

## 0. Rules for the Implementing Agent

1. Keywords **MUST**, **MUST NOT**, **SHOULD**, **MAY** are normative.
2. Implement milestones strictly in order (M0 → M5, section 9). Do not start milestone N+1 until `ctest -L Mn` passes for milestone N. Never delete or weaken a test to make a gate pass.
3. If anything is ambiguous, choose the documented default, then append a one-paragraph entry to `docs/DECISIONS.md` (date, question, choice, reason). Do not ask for clarification mid-milestone.
4. No placeholder implementations (`TODO`, `unimplemented`, stubs returning success). An unsupported feature MUST return `Error::Unsupported` with a descriptive message.
5. **The read-only mandate overrides everything.** Any code path that could write to a source device, source image, or Android device is a defect of the highest severity.
6. All integer parsing of on-disk data MUST be bounds-checked. All on-disk data is hostile input (fuzz targets are required, see section 9).

---

## 1. Architecture Overview & Directory Layout

### 1.1 Language & Toolchain (fixed decisions)

| Item | Decision |
|---|---|
| Language | C++20 (core library, CLI). Rust is NOT used in v1. |
| Build | CMake ≥ 3.24, Ninja. Presets: `win-msvc-release`, `win-msvc-debug`, `linux-clang-debug`, `linux-gcc-release`. |
| Compilers | MSVC 19.38+ (VS 2022), Clang ≥ 16, GCC ≥ 12. Warnings as errors (`/W4 /WX`, `-Wall -Wextra -Wpedantic -Werror`). |
| Dependencies (vendored via CMake `FetchContent`, pinned by tag/hash) | `miniz` (inflate/CRC32/Adler32 for PNG/ZIP deep validation), `Catch2` v3 (tests), `nlohmann/json` (reports, Android profiles, sidecar protocol), `CLI11` (CLI parsing), `tl::expected` (Result type), a single-header SHA-256 (public domain implementation, placed in `third_party/`). |
| Optional Android sidecar | Python ≥ 3.10 + `pure-python-adb` (`ppadb`). Not required for build or core tests. |
| Endianness | All on-disk formats parsed with explicit little/big-endian readers. Never `reinterpret_cast` a buffer to a packed struct. |

### 1.2 Directory Tree

```
openrecover/
├── CMakeLists.txt
├── CMakePresets.json
├── README.md
├── docs/
│   ├── DECISIONS.md
│   └── READONLY_POLICY.md              # copy of section 3.1 rules
├── third_party/                        # vendored/pinned deps (sha256.h, etc.)
├── cmake/
│   └── OpenRecoverWarnings.cmake
├── libopenrecover/                     # STATIC library target: openrecover_core
│   ├── CMakeLists.txt
│   ├── include/openrecover/
│   │   ├── common/
│   │   │   ├── bytes.hpp               # LE/BE readers, bounds-checked ByteView
│   │   │   ├── result.hpp              # Result<T> = tl::expected<T, Error>
│   │   │   ├── error.hpp               # Error, ErrorCode
│   │   │   ├── crc32.hpp  hash.hpp     # CRC32 (miniz), SHA-256
│   │   │   ├── log.hpp
│   │   │   └── types.hpp               # RecoveredFile, Confidence, etc.
│   │   ├── io/
│   │   │   ├── block_device.hpp        # BlockDevice interface
│   │   │   ├── readonly_guard.hpp      # ReadOnlyViolation + OR_FATAL_WRITE macro
│   │   │   ├── image_device.hpp        # flat .dd/.img
│   │   │   ├── partition_view.hpp      # offset/length window over a BlockDevice
│   │   │   ├── cached_device.hpp       # LRU read cache decorator
│   │   │   ├── win32_api.hpp           # injectable Win32 shim interface
│   │   │   ├── win_physical_device.hpp
│   │   │   ├── linux_block_device.hpp
│   │   │   └── output_sink.hpp         # the ONLY writer in the project
│   │   ├── partition/
│   │   │   ├── mbr.hpp  gpt.hpp  partition_scanner.hpp
│   │   ├── fs/
│   │   │   ├── filesystem.hpp          # IFileSystemScanner interface
│   │   │   ├── fat32.hpp
│   │   │   ├── ntfs.hpp
│   │   │   ├── ntfs_attributes.hpp  ntfs_runlist.hpp
│   │   │   └── allocation_map.hpp      # IAllocationMap (free/used clusters)
│   │   ├── carve/
│   │   │   ├── carve_engine.hpp
│   │   │   ├── signature.hpp           # ISignature, SignatureRegistry
│   │   │   ├── sig_jpeg.hpp  sig_png.hpp  sig_pdf.hpp  sig_zip.hpp
│   │   │   └── bounded_reader.hpp
│   │   ├── android/
│   │   │   ├── android_bridge.hpp
│   │   │   ├── usb_enumerator.hpp      # IUsbEnumerator (Win/Linux impls)
│   │   │   ├── adb_transport.hpp       # IAdbTransport (+ Subprocess, PySidecar, Fake)
│   │   │   ├── adb_command_policy.hpp  # allowlist + quoting
│   │   │   └── scan_profile.hpp
│   │   └── report/
│   │       └── report.hpp              # JSON + CSV manifest writer
│   ├── src/                            # mirrors include/ (one .cpp per header)
│   │   ├── io/win/win32_api_real.cpp   # ONLY file allowed to include <windows.h> I/O calls
│   │   ├── io/linux/...
│   │   └── ...
│   └── platform/
│       ├── windows/usb_enumerator_win.cpp   # SetupAPI
│       └── linux/usb_enumerator_linux.cpp   # sysfs
├── cli/
│   ├── CMakeLists.txt                  # target: openrecover (executable)
│   └── src/main.cpp  cmd_scan.cpp  cmd_recover.cpp  cmd_carve.cpp
│       cmd_devices.cpp  cmd_android.cpp
├── tools/
│   ├── check_readonly.py               # static forbidden-symbol scanner (CI gate)
│   ├── adb_sidecar/
│   │   ├── sidecar.py                  # JSON-lines server over stdio (ppadb)
│   │   └── requirements.txt
│   └── fixtures/
│       ├── make_fat32_fixtures.sh      # mtools-based generator
│       ├── make_ntfs_fixtures.sh       # ntfs-3g based generator
│       ├── make_carve_fixtures.py      # builds raw images with embedded files
│       └── README.md
├── tests/
│   ├── CMakeLists.txt
│   ├── unit/
│   │   ├── test_bytes.cpp  test_block_device.cpp  test_readonly_guard.cpp
│   │   ├── test_win32_flags.cpp  test_mbr_gpt.cpp
│   │   ├── test_fat32_parse.cpp  test_fat32_recover.cpp
│   │   ├── test_ntfs_parse.cpp  test_ntfs_runlist.cpp  test_ntfs_recover.cpp
│   │   ├── test_sig_jpeg.cpp  test_sig_png.cpp  test_sig_pdf.cpp  test_sig_zip.cpp
│   │   ├── test_carve_engine.cpp
│   │   └── test_android_*.cpp
│   ├── fuzz/                           # libFuzzer targets (Linux clang only)
│   ├── fixtures/
│   │   ├── images/                     # committed small images + *.golden.json
│   │   ├── samples/                    # valid & corrupt jpg/png/pdf/zip samples
│   │   └── android/fake_sdcard/        # directory tree for FakeAdbTransport
│   └── manual/                         # real-hardware procedures (not in CI)
└── .github/workflows/ci.yml            # win + linux matrix
```

### 1.3 Layering Rules (enforced by CMake target dependencies)

```
cli ──► openrecover_core
            report ─► (all below)
            android ─► common            (NO dependency on io/BlockDevice)
            carve  ─► io, fs(AllocationMap only), common
            fs     ─► io, partition, common
            partition ─► io, common
            io     ─► common
```

`io/` MUST NOT depend on anything except `common/`. `android/` MUST NOT include `io/` headers (it operates on files via ADB, not block devices).

### 1.4 Shared Types (`common/types.hpp`) — define exactly

```cpp
enum class Confidence { High, Medium, Low };        // see section 8.4 for rules
enum class FileOrigin { FilesystemMetadata, Carved, AndroidPull };

struct Extent { uint64_t offset_bytes; uint64_t length_bytes; bool sparse; };

struct RecoveredFile {
    std::string          path;          // UTF-8, '/' separators, never starts with '/'
    std::string          name;
    uint64_t             size_bytes;    // logical size as best known
    std::vector<Extent>  extents;       // byte offsets relative to the BlockDevice passed to scanner
    std::optional<std::vector<uint8_t>> resident_data; // NTFS resident $DATA
    std::optional<int64_t> mtime_unix, ctime_unix, atime_unix;
    FileOrigin           origin;
    Confidence           confidence;
    uint32_t             flags;         // bitmask: PathUncertain=1, Truncated=2, ClustersReallocated=4,
                                        //          NameFirstCharGuessed=8, Fragmented=16, Unsupported=32
    std::string          note;
    std::string          type_hint;     // "jpeg","png","pdf","zip","docx",... may be empty
};
```

`Result<T>` is `tl::expected<T, Error>`; `Error{ErrorCode code; std::string message; uint64_t offset;}`. Exceptions are reserved for **programmer errors and read-only violations** (`ReadOnlyViolation`); I/O and parse failures use `Result`.

### 1.5 Byte Utilities (`common/bytes.hpp`)

- `class ByteView { const uint8_t* p; size_t n; }` — every accessor `u8/u16le/u32le/u64le/u16be/u32be(off)` MUST bounds-check and return `Result<>`-free via a `bool ok()` sticky-failure pattern **or** throw `ParseOverrun` caught at parser entry points and converted to `Error{CorruptStructure}`. Choose the sticky-failure pattern (`reader.failed()`), document in `DECISIONS.md`.
- `utf16le_to_utf8(span)` handles surrogate pairs; unpaired surrogates → U+FFFD.
- Path sanitizer `sanitize_component(std::string)`: replace `/ \ : * ? " < > |` and control chars (<0x20) with `_`; strip trailing dots/spaces; empty → `_`; truncate to 200 bytes on UTF-8 boundary; reject `.`/`..` (replace with `_`). Applied to every name before writing to disk.

---

## 2. Global Behavioral Requirements

- **Determinism:** same input → byte-identical report (sorted by `(origin, offset, path)`), no timestamps in reports other than file metadata and an explicit `generated_at` field that tests mask.
- **Memory:** streaming only. Peak RSS for scanning a 1 TiB device MUST stay < 512 MiB. Never read an entire device or MFT into memory (MFT is processed record by record via a cached reader).
- **Progress & cancel:** long operations accept `std::function<bool(uint64_t done, uint64_t total)> progress` (return `false` = cancel) and `std::stop_token`.
- **Logging:** levels `error|warn|info|debug|trace`; never log file contents.
- **Locale:** all paths internal UTF-8; Windows output paths converted with `MultiByteToWideChar(CP_UTF8)` and `\\?\` long-path prefix.

---

## 3. Module 1 — Read-Only I/O Abstraction (`BlockDevice`)

### 3.1 Read-Only Policy (normative)

1. The public `BlockDevice` interface MUST NOT contain any method capable of mutation: no `write`, `flush`, `trim`, `resize`, `ioctl`-passthrough, or "raw handle" accessors.
2. The OS handle MUST be opened with read-only access **and** the code MUST verify post-open (where the OS permits) that the handle is read-only.
3. The only component allowed to create or write files is `OutputSink` (section 3.7), which operates exclusively on paths that pass the "not on source device" check.
4. Violation of rules 1–3 detected at runtime MUST throw `ReadOnlyViolation` (derived from `std::logic_error`). In release builds, `ReadOnlyViolation` thrown from inside `libopenrecover` MUST additionally be caught at the CLI top level, logged at `error`, and cause `std::abort()` (exit code 70). It MUST NOT be swallowed.
5. CI gate `tools/check_readonly.py` (section 3.6) MUST pass.

### 3.2 Interface

```cpp
namespace openrecover::io {

struct DeviceInfo {
    std::string  description;     // "\\\\.\\PhysicalDrive2" or "/path/disk.img"
    uint64_t     size_bytes;
    uint32_t     logical_sector_size;   // 512 or 4096
    uint32_t     physical_sector_size;  // >= logical
    bool         is_image;
};

struct ReadResult {
    size_t bytes_read;                    // may be < requested only at EOF
    bool   had_bad_sectors;               // true if any sector was zero-filled
};

class BlockDevice {
public:
    virtual ~BlockDevice() = default;
    virtual const DeviceInfo& info() const noexcept = 0;
    // Reads exactly `len` bytes at absolute byte `offset` unless EOF is reached.
    // Arbitrary (unaligned) offset/len MUST be supported by every implementation.
    // Thread-safe: MUST be callable concurrently.
    virtual Result<ReadResult> read(uint64_t offset, uint8_t* dst, size_t len) = 0;
    // Bad-sector bookkeeping (sector index relative to this device).
    virtual std::vector<uint64_t> bad_sectors() const = 0;

    BlockDevice(const BlockDevice&) = delete;
    BlockDevice& operator=(const BlockDevice&) = delete;
    // INTENTIONALLY ABSENT: write/flush/trim/ioctl
};

// Factory — only entry points
Result<std::unique_ptr<BlockDevice>> open_physical_drive(uint32_t drive_number, const OpenOptions&);  // Windows
Result<std::unique_ptr<BlockDevice>> open_block_node(const std::string& path, const OpenOptions&);    // Linux /dev/sdX
Result<std::unique_ptr<BlockDevice>> open_image(const std::filesystem::path&, const OpenOptions&);    // both OS

struct OpenOptions {
    bool allow_shared_write_sharing = false; // see 3.3.2 — DEFAULT FALSE
    uint64_t cache_bytes = 64ull << 20;      // LRU cache size
};
}
```

Decorators (`PartitionView`, `CachedDevice`) take `std::shared_ptr<BlockDevice>` and implement `BlockDevice`; they add no write capability.

### 3.3 Windows Implementation (`win_physical_device.cpp`)

#### 3.3.1 Win32 Shim (mandatory for testability)

All Win32 calls go through `struct IWin32Api` (virtual: `CreateFileW`, `ReadFile`, `SetFilePointerEx`, `DeviceIoControl`, `CloseHandle`, `GetLastError`, `GetFileSizeEx`, `GetFileType`). `win32_api_real.cpp` is the only translation unit allowed to call the real functions. Tests inject `FakeWin32Api` that records every argument.

#### 3.3.2 Opening the Device — exact call

```cpp
// Path validation (MUST precede open): regex ^\\\\\.\\PhysicalDrive[0-9]{1,3}$
// Optional volume form (\\.\C:) MAY be accepted with regex ^\\\\\.\\[A-Za-z]:$ using identical flags.
HANDLE h = api.CreateFileW(
    path.c_str(),
    GENERIC_READ,                         // dwDesiredAccess: EXACTLY GENERIC_READ. No other bits.
    FILE_SHARE_READ,                      // dwShareMode: EXACTLY FILE_SHARE_READ (default)
    nullptr,                              // lpSecurityAttributes
    OPEN_EXISTING,                        // dwCreationDisposition: never CREATE_*, never TRUNCATE_*
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
    nullptr);
```

Rules:
- `dwDesiredAccess` MUST equal `GENERIC_READ` exactly. Unit test `test_win32_flags.cpp` asserts `access == GENERIC_READ`, `(access & (GENERIC_WRITE|GENERIC_ALL|FILE_WRITE_DATA|FILE_APPEND_DATA|DELETE|WRITE_DAC|WRITE_OWNER)) == 0`, `share == FILE_SHARE_READ`, `disposition == OPEN_EXISTING`.
- **Known OS caveat (document in README):** when another process (e.g. the OS or AV) holds the drive open with write access, `FILE_SHARE_READ`-only opens fail with `ERROR_SHARING_VIOLATION` (32). Default behavior: return `Error{DeviceBusy}` with a message instructing the user to take the disk offline (Disk Management → *Offline*) or attach it via a write-blocker. Only if the user passes `--allow-shared-write-sharing` (CLI) / `OpenOptions.allow_shared_write_sharing = true`, retry once with `FILE_SHARE_READ | FILE_SHARE_WRITE`. Access remains `GENERIC_READ` in all cases (this flag only permits *others* to write; we never do). Log a `warn` when this fallback is used and record it in the report (`"shared_write_fallback": true`).
- `FILE_FLAG_NO_BUFFERING` is NOT used by default (avoids buffer-alignment hazards); our own `CachedDevice` provides caching. Sector alignment is still performed internally (3.3.4) so an opt-in `NO_BUFFERING` can be added later.
- Error mapping: `ERROR_ACCESS_DENIED`(5) → `PermissionDenied` ("Run as Administrator"); `ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND` → `NotFound`; `ERROR_SHARING_VIOLATION`(32) → `DeviceBusy`; anything else → `IoError` including numeric code and `FormatMessageW` text.

#### 3.3.3 Geometry (the ONLY allowed `DeviceIoControl` codes)

```cpp
constexpr DWORD kAllowedIoctls[] = {
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,   // logical sector size, media type
    IOCTL_DISK_GET_LENGTH_INFO,         // exact byte length
    IOCTL_STORAGE_QUERY_PROPERTY,       // StorageAccessAlignmentProperty -> physical sector size
    IOCTL_STORAGE_GET_DEVICE_NUMBER,    // sanity: confirm drive number
};
```

All calls pass through `safe_ioctl(code, ...)` which throws `ReadOnlyViolation` if `code` is not in `kAllowedIoctls`. `FSCTL_LOCK_VOLUME`, `FSCTL_DISMOUNT_VOLUME`, `IOCTL_DISK_SET_*`, `IOCTL_DISK_FORMAT_*`, `IOCTL_STORAGE_EJECT_*` MUST NOT appear anywhere. If `IOCTL_DISK_GET_LENGTH_INFO` fails, fall back to `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` DiskSize; if both fail → `IoError`.

#### 3.3.4 Read Algorithm

```
read(offset, dst, len):
    if len == 0 → return {0,false}
    if offset >= size → return {0,false}; clamp len to size - offset
    S = logical_sector_size
    a_start = offset / S * S;  a_end = ceil((offset+len)/S) * S    (clamp a_end to size rounded up to S)
    process in chunks of at most 1 MiB:
        buf = aligned bounce buffer (_aligned_malloc(chunk, 4096))
        SetFilePointerEx(h, a_start_chunk, nullptr, FILE_BEGIN)   // or OVERLAPPED with Offset/OffsetHigh
        ReadFile(h, buf, chunk, &got, nullptr)
        if ReadFile fails with ERROR_CRC(23) | ERROR_SECTOR_NOT_FOUND(27) | ERROR_IO_DEVICE(1117) | ERROR_READ_FAULT(30):
            retry the chunk sector-by-sector (S bytes each);
            for each failing sector: zero-fill, record sector index in bad_sectors set, set had_bad_sectors
        copy relevant sub-range to dst
```

- `SetFilePointerEx`+`ReadFile` pair MUST be guarded by a mutex **or** use overlapped offsets; choose a per-device `std::mutex` for the handle (simple, correct) with `CachedDevice` reducing contention.
- Any `ReadFile` failure other than the bad-sector codes → `IoError` (no zero-fill).
- Dynamic disks, BitLocker-encrypted or Storage Spaces volumes: detected by failing FS signature checks → scanners return `Unsupported`/`NoFilesystem`; the I/O layer does nothing special.

### 3.4 Linux Implementation

- `open(path, O_RDONLY | O_CLOEXEC | O_LARGEFILE)`; read via `pread` (thread-safe, no seek state). `O_DIRECT` not used.
- Geometry for block nodes: `ioctl(fd, BLKGETSIZE64)`, `BLKSSZGET`, `BLKPBSZGET`. These are the only ioctls permitted (`safe_ioctl` allowlist). For regular files use `fstat`.
- Error mapping: `EACCES/EPERM` → `PermissionDenied`; `ENOENT` → `NotFound`; `EIO` on a sector → sector-by-sector retry exactly as in 3.3.4.
- After open, `fcntl(fd, F_GETFL)` MUST show `(flags & O_ACCMODE) == O_RDONLY`; otherwise throw `ReadOnlyViolation`.

### 3.5 Flat Disk Image Support (`ImageDevice`)

- Accepts `.dd`, `.img`, `.raw`, `.bin` (extension is NOT enforced; any regular file). Opened read-only with `CreateFileW(GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING)` on Windows (through `IWin32Api`) and `open(O_RDONLY)` on Linux.
- Sector size default 512; override via `OpenOptions.sector_size` / `--sector-size 4096`.
- File size not multiple of sector size: last partial sector is readable; `size_bytes` is the exact file size.
- `PartitionView(device, offset, length)` presents a partition inside an image/disk as its own `BlockDevice` (offset 0). Reads beyond `length` return short reads (EOF semantics). Also exposed on CLI as `--offset <bytes|sectors:N>` for images that are a bare partition at non-zero offset.
- Sparse image files are read as-is (holes read as zeros by the OS).
- Containers (E01, VMDK, VHD) are NOT supported in v1 → `Unsupported`.

### 3.6 Runtime Guard & Static Enforcement

**Runtime guard components**

1. `readonly_guard.hpp`:
   ```cpp
   struct ReadOnlyViolation : std::logic_error { using std::logic_error::logic_error; };
   [[noreturn]] void fatal_write_attempt(const char* what, const char* file, int line);
   #define OR_FATAL_WRITE(what) ::openrecover::io::fatal_write_attempt(what, __FILE__, __LINE__)
   ```
   `fatal_write_attempt` logs, throws `ReadOnlyViolation`.
2. `safe_ioctl` allowlist (3.3.3 / 3.4).
3. Handle verification after open (3.3.2 test hook, 3.4 `F_GETFL`).
4. `OutputSink` path guard (3.7).
5. A `GuardedDevice` decorator wraps every device returned by factories in non-release **and** release builds. It counts `read` calls and provides a `bytes_written() == 0` invariant used by tests (always 0 by construction); it additionally exposes `assert_untouched()` for tests that compare an image hash before/after.

**Static enforcement — `tools/check_readonly.py`** (runs in CI and as CTest `readonly_static_check`, label `M0`)

Scans all files under `libopenrecover/` and `cli/` and fails (exit 1) if any of the following tokens appear outside the allowlisted file(s):

| Forbidden token (regex) | Allowed only in |
|---|---|
| `\bWriteFile(Ex)?\b`, `\bSetEndOfFile\b`, `\bSetFileInformationByHandle\b`, `\bDeleteFile`, `\bMoveFile`, `\bFlushFileBuffers\b` | `src/io/output_sink.cpp` (Win branch) |
| `\bpwrite(64)?\b`, `\bwrite\s*\(`, `\bftruncate\b`, `\bfsync\b`, `\bfwrite\b`, `std::ofstream`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` | `src/io/output_sink.cpp` |
| `FSCTL_(LOCK|DISMOUNT|SET_|DELETE)`, `IOCTL_DISK_(SET|FORMAT|GROW|DELETE)`, `IOCTL_STORAGE_EJECT` | nowhere |
| `GENERIC_WRITE`, `GENERIC_ALL`, `FILE_WRITE_DATA`, `FILE_APPEND_DATA` | nowhere (except inside the string-literal in `test_win32_flags.cpp` negative assertions) |
| `\bDeviceIoControl\b` | `src/io/win/win32_api_real.cpp` |
| `\bioctl\s*\(` | `src/io/linux/*.cpp` |
| `"push"`, `"install"`, `"uninstall"`, `"rm"`, `"su"`, `"root"`, `"remount"`, `"reboot"` as adb verbs | `src/android/adb_command_policy.cpp` (in the deny-list literal only) |

**Dynamic test (Linux, label `M0`):** `tests/unit/test_readonly_syscalls.cpp` spawns the CLI against a fixture image under `strace -f -e trace=openat,write,pwrite64,ftruncate -o trace.txt`; asserts (a) the image file is opened only with `O_RDONLY`, and (b) no `write`/`pwrite64` syscall targets that fd. Also: `sha256(image)` before == after, and the image is `chmod 0444` during the test.

### 3.7 `OutputSink` (the only writer)

- Constructed with an output directory. At construction it MUST resolve the output directory to its real path and verify it is **not located on the source device**:
  - Windows: compare the volume serial/`GetVolumePathNameW`+`IOCTL_STORAGE_GET_DEVICE_NUMBER` of the output directory's volume against the source `\\.\PhysicalDriveN` number → refuse (`Error{OutputOnSourceDevice}`) if equal.
  - Linux: compare `st_dev` of the output directory with the source device node/image's `st_dev` / containing mount; refuse if the output directory resides on a filesystem backed by the source block device or contains the source image file.
  - Override flag does NOT exist.
- API: `Result<std::filesystem::path> write_file(relative_path, ByteSource&)` — creates parent directories, never overwrites (collision → append ` (1)`, ` (2)` …), writes via a temp name then atomic rename, sets mtime if provided, returns the final path. Computes SHA-256 while writing.
- All relative paths pass through `sanitize_component` per component and are verified to remain inside the output root after canonicalization (zip-slip/path-traversal guard).

---

## 4. Module 2 — Partition Tables & Filesystem Metadata Parsers

All scanners implement:

```cpp
class IFileSystemScanner {
public:
    virtual ~IFileSystemScanner() = default;
    virtual FsKind kind() const = 0;                        // Fat32, Ntfs
    virtual const FsGeometry& geometry() const = 0;         // bytes/sector, bytes/cluster, total clusters
    virtual Result<std::vector<RecoveredFile>> scan_deleted(const ScanOptions&, ProgressFn) = 0;
    virtual Result<std::unique_ptr<IAllocationMap>> allocation_map() = 0;   // for CarveEngine scoping
    virtual Result<size_t> read_file(const RecoveredFile&, uint64_t file_offset,
                                     uint8_t* dst, size_t len) = 0;         // reads via extents/resident data
};
Result<std::unique_ptr<IFileSystemScanner>> detect_and_open(std::shared_ptr<BlockDevice>); // by signature, not by partition type byte
class IAllocationMap { virtual bool is_cluster_allocated(uint64_t cluster) const = 0;
                       virtual uint64_t cluster_to_byte_offset(uint64_t) const = 0; virtual uint64_t cluster_count() const = 0; };
```

Detection order: NTFS (`OEM ID == "NTFS    "` at offset 3) → FAT32 (section 4.2.1 validation) → `Error::Unsupported("unknown filesystem")`.

### 4.1 Partition Scanner (`partition/`)

1. Read LBA 0. Require bytes 510–511 == `55 AA`.
2. If MBR partition entry type `0xEE` at index 0 → parse GPT. Else parse 4 MBR entries at offset `0x1BE` (16 bytes each: status@0, type@4, LBA start@8 (u32le), sector count@12 (u32le)); skip type `0x00`; for extended types `0x05/0x0F/0x85` follow EBR chain (max depth 128, cycle detection by visited LBA set; EBR LBA = extended_base + relative).
3. GPT: header at LBA 1: signature `"EFI PART"`, header size@12, header CRC32@16 (validate by zeroing field 16–19 and computing CRC32 over `header_size` bytes), `PartitionEntryLBA`@72 (u64), `NumPartitionEntries`@80 (u32), `SizeOfPartitionEntry`@84 (u32, ≥128), entries-array CRC32@88. Validate both CRCs; if primary invalid, try backup header at last LBA; if both invalid → fall back to MBR protective entry and `warn`. Each entry: type GUID@0 (16, all-zero = unused), first LBA@32, last LBA@40 (u64 inclusive), name@56 (UTF-16LE, 72 bytes). Only entries with first ≤ last ≤ device_last_lba are accepted.
4. Output `std::vector<PartitionInfo>{index, start_byte, length_byte, type_desc, scheme}`. For each partition, `detect_and_open(PartitionView)` is attempted; failures are reported, not fatal.
5. If LBA 0 itself contains a valid FAT32/NTFS boot sector (superfloppy/partition image), treat the whole device as a single volume.

### 4.2 FAT32

#### 4.2.1 Boot Sector (BPB) Parsing and Validation

Read the first 512 bytes of the volume (use `max(512, logical_sector_size)`). Offsets (little-endian):

| Offset | Size | Field | Validation |
|---|---|---|---|
| 0x00 | 3 | JumpBoot | `EB xx 90` or `E9 xx xx` |
| 0x0B | 2 | BytsPerSec | ∈ {512, 1024, 2048, 4096} |
| 0x0D | 1 | SecPerClus | power of 2, 1..128 |
| 0x0E | 2 | RsvdSecCnt | ≥ 1 (typ. 32) |
| 0x10 | 1 | NumFATs | 1 or 2 (typ. 2) |
| 0x11 | 2 | RootEntCnt | MUST be 0 for FAT32 |
| 0x13 | 2 | TotSec16 | MUST be 0 for FAT32 |
| 0x16 | 2 | FATSz16 | MUST be 0 for FAT32 |
| 0x20 | 4 | TotSec32 | > 0 and × BytsPerSec ≤ volume length |
| 0x24 | 4 | FATSz32 | > 0 |
| 0x28 | 2 | ExtFlags | bit7: 1 = only one FAT active (active = bits 0–3) |
| 0x2C | 4 | RootClus | ≥ 2 |
| 0x30 | 2 | FSInfo | sector number (informational) |
| 0x32 | 2 | BkBootSec | backup boot sector (typ. 6) |
| 0x1FE | 2 | Signature | `55 AA` |

Derived values (use `uint64_t`):
```
bytes_per_cluster = BytsPerSec * SecPerClus
fat_start_sector  = RsvdSecCnt
data_start_sector = RsvdSecCnt + NumFATs * FATSz32
data_sectors      = TotSec32 - data_start_sector
cluster_count     = data_sectors / SecPerClus            // must be >= 65525 to be FAT32; if < 65525 → warn, proceed
cluster_to_byte(N)= (data_start_sector + (N - 2) * SecPerClus) * BytsPerSec    // N >= 2
max_valid_cluster = cluster_count + 1
fat_entries_possible = FATSz32 * BytsPerSec / 4         // clamp max_valid_cluster to this
```
If the primary BPB fails validation, try the backup boot sector at `BkBootSec` (if 1..RsvdSecCnt-1) before failing.

#### 4.2.2 FAT Table Access

- Entry for cluster N at byte `fat_start_sector*BytsPerSec + N*4` in the **active** FAT (ExtFlags rule above; otherwise FAT #0). Value = `u32le & 0x0FFFFFFF`.
- Semantics: `0` free; `0x0FFFFFF7` bad; `>= 0x0FFFFFF8` end-of-chain; `2..max_valid_cluster` next cluster; anything else → corrupt.
- Provide `FatReader::entry(N)` with a 64 KiB sector-window cache. `FatAllocationMap::is_cluster_allocated(N)` = `entry(N) != 0`.

#### 4.2.3 Directory Entry Decoding (32 bytes each)

Short entry layout:

| Off | Size | Field |
|---|---|---|
| 0 | 11 | Name (8) + Ext (3), space padded, OEM codepage |
| 11 | 1 | Attr (0x01 RO, 0x02 Hidden, 0x04 System, 0x08 VolumeID, 0x10 Directory, 0x20 Archive, 0x0F = LFN) |
| 12 | 1 | NTRes (bit3 = name lowercase, bit4 = ext lowercase) |
| 13 | 1 | CrtTimeTenth (0–199, 10 ms units) |
| 14 | 2 | CrtTime |
| 16 | 2 | CrtDate |
| 18 | 2 | LstAccDate |
| 20 | 2 | FstClusHI |
| 22 | 2 | WrtTime |
| 24 | 2 | WrtDate |
| 26 | 2 | FstClusLO |
| 28 | 4 | FileSize |

- `first_cluster = (FstClusHI << 16) | FstClusLO` (mask HI to 12 bits → effective 28 bits).
- Date: bits 15–9 year-1980, 8–5 month (1–12), 4–0 day (1–31). Time: bits 15–11 hour, 10–5 minute, 4–0 seconds/2. Invalid fields → timestamp omitted. Timestamps are local time; convert to Unix epoch **assuming UTC** and set note `"fat_local_time_assumed_utc"`.
- **End of directory:** `Name[0] == 0x00`. For *live* directory walking, stop there. For **deleted-entry harvesting, DO NOT stop** at `0x00`; continue to the end of the cluster chain (stale entries can follow in the same cluster), but ignore all-zero 32-byte entries.
- **Deleted marker:** `Name[0] == 0xE5`. (`Name[0] == 0x05` in a *live* entry means the real first byte is `0xE5`.)
- LFN entries (`Attr == 0x0F`): `Ord`@0 (bit 6 = 0x40 marks the last/first-in-disk logical entry; low 5 bits = sequence 1..20), `Name1`@1 (5×UTF-16LE), `Attr`@11, `Type`@12 (=0), `Chksum`@13, `Name2`@14 (6×UTF-16LE), `FstClusLO`@26 (=0), `Name3`@28 (2×UTF-16LE). A deleted LFN entry has `Ord` byte = `0xE5`.

**Short-name checksum (for LFN association):**
```cpp
uint8_t sum = 0;
for (int i = 0; i < 11; ++i) sum = (uint8_t)(((sum & 1) ? 0x80 : 0) + (sum >> 1) + name11[i]);
```

#### 4.2.4 Directory Traversal Algorithm

```
scan_deleted():
  1. dir_queue = [(RootClus, path="")]
  2. visited_dir_clusters = {}
  3. while queue not empty:
       (cluster, path) = pop
       if cluster in visited: continue; add
       chain = follow_chain(cluster)          // live FAT chain; stop at EOC/free/bad/cycle; max 2^24 clusters
       entries = read all 32-byte entries of chain
       lfn_stack = []
       for each entry e:
          if e is all zero: lfn_stack.clear(); continue
          if e.Attr == 0x0F:
              ord = e.Name[0]
              if ord == 0xE5 or (ord & 0x40): start new lfn_stack (deleted LFN allowed)
              push e; continue
          // short entry
          if e.Attr & 0x08 (volume label) and Attr != 0x0F: lfn_stack.clear(); continue
          if name is "." or "..": lfn_stack.clear(); continue
          deleted = (e.Name[0] == 0xE5)
          long_name = assemble_lfn(lfn_stack, checksum(e.Name))   // requires matching Chksum for all stack entries, sequence descending; else none
          lfn_stack.clear()
          is_dir = Attr & 0x10
          if !deleted:
              if is_dir and first_cluster>=2: queue.push(first_cluster, path/name)   // recurse live dirs
              continue
          // ---- deleted entry
          build RecoveredFile (see 4.2.5); if is_dir → also queue the dir for harvesting (4.2.6) but do NOT emit it as a file
```

- `assemble_lfn`: collect UTF-16 code units from each LFN entry in order of **descending** sequence from the stack (the on-disk order is last-part first), stop at `0x0000`, ignore `0xFFFF` padding. All entries' `Chksum` MUST equal the short-entry checksum computed from the **original** short name. For a deleted short entry whose first byte was overwritten with `0xE5`, compute the checksum trying each candidate first byte: if an LFN is present, take the first character from the LFN's short-name-derived value is unavailable, so instead **brute-force `c` ∈ 0x21..0xFF** for `Name[0]` and accept the first value for which the checksum matches the LFN stack's `Chksum`; set flag `NameFirstCharGuessed` only if no LFN is present (then the first char is replaced with `_`).
- Case: apply `NTRes` lowercase bits to the 8.3 name when no LFN exists.
- Path of a deleted file = `path_of_containing_directory + "/" + name`. Containing-directory path comes from the traversal queue (live dir) or from 4.2.6 (deleted dir).

#### 4.2.5 Deleted File → `RecoveredFile`

FAT zeroes the file's FAT chain on deletion, so the chain is lost. Recovery assumes **contiguous allocation**:

```
if first_cluster < 2 or first_cluster > max_valid_cluster: skip (size-0 files: emit with empty extents if FileSize == 0 and name valid)
n = ceil(FileSize / bytes_per_cluster)            // if FileSize == 0 → emit zero-length file
if first_cluster + n - 1 > max_valid_cluster: skip (note "extent beyond volume")
extent = { cluster_to_byte(first_cluster), FileSize }  (contiguous run)
confidence:
   all n clusters have FAT entry == 0 (still unallocated)       → High
   some clusters now allocated (reused)                        → Low, flag ClustersReallocated
   FileSize > 4 GiB - 1 impossible (u32)                       → n/a
mark flag Fragmented NEVER (cannot be known); note "contiguous_assumption"
```
Additionally: if the **first** cluster's FAT entry is nonzero (overwritten by a new file) → `Low`, `ClustersReallocated`; the carve engine remains the fallback.

#### 4.2.6 Deleted Directories & Path Reconstruction

A deleted directory entry (`Attr & 0x10`, `Name[0]==0xE5`) with plausible `first_cluster` is harvested only if the cluster at `first_cluster` begins with entries `.` (`2E 20×10`) and `..` (`2E 2E 20×9`), both with `Attr & 0x10`. Then:
- The `.` entry's cluster field MUST equal `first_cluster`; the `..` entry's cluster is the parent (0 = root).
- Push `(first_cluster, path/deletedname)` on the queue (it is walked with the "do not stop at 0x00" rule).
- Maintain `dir_path_by_cluster: map<uint32,string>` populated from live and deleted directories. For a directory found only through `..` references with unknown name: path component `_DIR_<cluster>`.
- Entries whose parent chain cannot be resolved go under `__orphans__/` with flag `PathUncertain`.

#### 4.2.7 FAT32 Test-Critical Edge Cases (MUST be covered)

LFN spanning two sectors/clusters; deleted LFN with mismatched checksum (→ fall back to short name); `0x05` first byte; directory entries after a `0x00` terminator; zero-length file; file at the last cluster; `FatSz32` with `ExtFlags` mirroring disabled; corrupt BPB with valid backup BPB; cyclic FAT chain in a live directory.

### 4.3 NTFS

#### 4.3.1 Boot Sector Parsing

| Off | Size | Field | Rule |
|---|---|---|---|
| 0x03 | 8 | OEM ID | `"NTFS    "` |
| 0x0B | 2 | BytesPerSector | 512/1024/2048/4096 |
| 0x0D | 1 | SectorsPerCluster | if `value <= 0x80`: value (power of 2); else `2^(256 - value)` (as signed negative exponent: `1 << (256 - value)`) |
| 0x28 | 8 | TotalSectors | |
| 0x30 | 8 | MFT start LCN | `mft_byte = LCN * bytes_per_cluster` |
| 0x38 | 8 | MFTMirr start LCN | fallback source for record 0..3 |
| 0x40 | 1 (signed) | ClustersPerMFTRecord | if `> 0`: `n * bytes_per_cluster`; if `< 0`: `1 << (-n)` bytes (typ. `0xF6` = −10 → 1024) |
| 0x44 | 1 (signed) | ClustersPerIndexBuffer | same rule |
| 0x48 | 8 | Volume serial | |
| 0x1FE | 2 | Signature | `55 AA` |

`bytes_per_cluster = BytesPerSector * SectorsPerCluster`. `mft_record_size` MUST be a power of 2 in [512, 65536]. If boot sector invalid, try the backup boot sector at the last sector of the volume (`TotalSectors * BytesPerSector`).

#### 4.3.2 MFT Record Parsing

1. Read `mft_record_size` bytes. Magic `"FILE"` at 0 (`"BAAD"` → corrupt, skip; all-zero → unused slot, skip).
2. **Apply the update-sequence fixup** (MANDATORY before reading any other field):
   - `usa_offset = u16@0x04`, `usa_count = u16@0x06` (count includes the USN itself; `usa_count - 1` stripes). `usn = u16@usa_offset`.
   - For `i in 1..usa_count-1`: stripe end at `i*512 - 2`; require `u16@(i*512-2) == usn` else record is torn → skip; then overwrite those 2 bytes with the array value `u16@(usa_offset + 2*i)`.
   - Validate `usa_offset + 2*usa_count <= record_size`, and stripes: `usa_count - 1 == record_size / 512`.
3. Header (after fixup): `LogSeqNo`@0x08 (u64), `SequenceNumber`@0x10 (u16), `HardLinkCount`@0x12, `FirstAttrOffset`@0x14 (u16), `Flags`@0x16 (u16: **bit0 = IN_USE**, **bit1 = IS_DIRECTORY**), `BytesInUse`@0x18 (u32), `BytesAllocated`@0x1C (u32), `BaseRecordRef`@0x20 (u64; nonzero → this is an extension record belonging to base `ref & 0x0000FFFFFFFFFFFF`), `NextAttrId`@0x28, `RecordNumber`@0x2C (u32, if `FirstAttrOffset >= 0x30`; otherwise derive from position).
4. **Deleted file:** `(Flags & 0x01) == 0`, `BaseRecordRef == 0`, magic `FILE`, record number ≥ 24 (skip reserved system records 0–23 except when `--include-system`).
5. **Attribute iteration** from `FirstAttrOffset`: each attribute header: `Type`@0 (u32), `Length`@4 (u32, must be ≥ 16, multiple of 8, within `BytesInUse`), `NonResident`@8 (u8), `NameLength`@9 (chars), `NameOffset`@0x0A, `Flags`@0x0C (u16: 0x0001 compressed, 0x4000 encrypted, 0x8000 sparse), `AttrId`@0x0E. Terminate at `Type == 0xFFFFFFFF`. Cap at 256 attributes/record.
   - Resident: `ContentLength`@0x10 (u32), `ContentOffset`@0x14 (u16); content must lie within the attribute.
   - Non-resident: `StartVCN`@0x10, `EndVCN`@0x18 (u64), `RunlistOffset`@0x20 (u16), `CompressionUnitSize`@0x22 (u16), `AllocatedSize`@0x28, `RealSize`@0x30, `InitializedSize`@0x38 (u64).
6. Attribute types of interest: `0x10` $STANDARD_INFORMATION, `0x20` $ATTRIBUTE_LIST, `0x30` $FILE_NAME, `0x80` $DATA, `0x90` $INDEX_ROOT, `0xA0` $INDEX_ALLOCATION, `0xB0` $BITMAP.
7. **$STANDARD_INFORMATION** (resident): Created@0, Modified@8, MFTChanged@0x10, Accessed@0x18 — FILETIME (100 ns ticks since 1601-01-01 UTC) → `unix = ticks/10_000_000 - 11644473600`.
8. **$FILE_NAME** (resident): ParentRef@0 (u64: low 48 bits = MFT index, high 16 = sequence), times@8..0x27, AllocSize@0x28, RealSize@0x30, Flags@0x38, NameLength@0x40 (u8 chars), Namespace@0x41 (0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS), Name@0x42 (UTF-16LE). A record may have several; **choose preference: Win32 (1) or Win32+DOS (3) > POSIX (0) > DOS (2)**. The chosen record supplies name and parent.
9. **$DATA:** use the **unnamed** `$DATA` (NameLength == 0) as the file content. Named streams (ADS) ignored in v1 (counted in report as `ads_ignored`). If `$ATTRIBUTE_LIST` (0x20) exists, parse its entries (type u32@0, entry length u16@4, name length u8@6, name offset u8@7, starting VCN u64@8, MFT ref u64@0x10, attr id u16@0x18) and load referenced extension records (apply fixup; verify their `BaseRecordRef` matches) to find `$FILE_NAME` / `$DATA` extents; limit 64 extension records.
10. If the unnamed `$DATA` is **compressed (0x0001) or encrypted (0x4000)** → emit entry with flag `Unsupported`, `note="ntfs_compressed|encrypted"`, no extents. Sparse (0x8000) is supported (sparse extents).

#### 4.3.3 Locating the MFT (including fragmented MFT)

1. Read record 0 at `mft_byte` (fixup applied). Its unnamed `$DATA` is the `$MFT` itself: decode its runlist → `mft_extents` (list of `{lcn, length_clusters}`). Total MFT size = `RealSize`.
2. Number of records = `RealSize / mft_record_size`. Record N byte offset: walk `mft_extents` accumulating `extent_bytes` until the extent containing `N*mft_record_size`.
3. If record 0 is corrupt, use `$MFTMirr` (LCN from boot sector; contains records 0–3 only) just to recover the `$MFT` runlist; if that also fails → `Error{CorruptStructure}`.
4. Iterate N = 24 … count-1 sequentially (sequential read, 1 MiB read-ahead window). Memory: O(1).

#### 4.3.4 Data Run Decoding

Runlist bytes at `attr + RunlistOffset`, terminated by header byte `0x00` or end of attribute:

```
pos = 0; prev_lcn = 0; vcn = StartVCN
loop:
   header = b[pos++]; if header == 0 → stop
   len_size = header & 0x0F;  off_size = header >> 4
   if len_size == 0 or len_size > 8 or off_size > 8 → Corrupt
   length = unsigned LE of next len_size bytes           // clusters; must be > 0
   if off_size == 0: run = SPARSE(length)
   else: delta = SIGNED LE of next off_size bytes (sign-extend from the top bit of the last byte)
         lcn = prev_lcn + delta; prev_lcn = lcn
         validate 0 <= lcn and (lcn + length) <= total_clusters else Corrupt
   emit run {vcn, lcn|sparse, length}; vcn += length
total of lengths MUST be >= ceil(RealSize / bytes_per_cluster) - StartVCN (else flag Truncated)
```
Convert to `Extent{lcn*bytes_per_cluster, length*bytes_per_cluster, sparse}`; trim the last extent so total logical bytes == `RealSize` (`InitializedSize` bytes beyond are zero — treat as zero-fill when reading). Overflow-check every multiplication/addition (`__builtin_*_overflow` / `_mul128` helpers).

#### 4.3.5 Allocation Check (Confidence)

- Load `$Bitmap` (MFT record 6, unnamed `$DATA`; one bit per cluster, bit `c & 7` of byte `c >> 3`). `NtfsAllocationMap::is_cluster_allocated`.
- For each extent of a deleted file: if **all** clusters are unallocated → `High`; if any allocated → `Low` + `ClustersReallocated`; also `Low` if `SequenceNumber` evidence of reuse isn't available (n/a). Resident data (no extents) → `High` (resident bytes live inside the MFT record).
- Additional High-confidence gate: for deleted files with a recognized `type_hint` (by extension), the first 16 bytes of data are validated against the section-5 signature table; mismatch → downgrade one level.

#### 4.3.6 Path Reconstruction

```
resolve_path(record_no):
   parts = []; cur = record_no; depth = 0; uncertain = false
   while cur != 5 (root):
       depth++ > 255 → uncertain=true; break (cycle)
       rec = load_record(cur); if invalid/unused: uncertain=true; parts.push("_MFT"+cur); break
       fn = best_file_name(rec)
       parts.push(sanitize(fn.name))
       parent_idx = fn.ParentRef & 0xFFFFFFFFFFFF; parent_seq = fn.ParentRef >> 48
       parent = load_record(parent_idx)
       if parent invalid, or not a directory, or (parent.in_use and parent.SequenceNumber != parent_seq)
            or (!parent.in_use and parent.SequenceNumber != parent_seq and parent.SequenceNumber != parent_seq+1):
           uncertain = true; if parent invalid → parts.push("__orphans__"); break
       cur = parent_idx
   return reverse(parts).join("/"), uncertain
```
A deleted directory's sequence number is incremented on deallocation, hence the `+1` tolerance. Memoize `path_cache: unordered_map<uint64_t, {string,bool}>` with an LRU bound of 1M entries. Uncertain → flag `PathUncertain`.

#### 4.3.7 NTFS Reading File Content

`read_file` maps `file_offset` through `extents` (binary search by cumulative logical offset), zero-fills sparse extents and the `[InitializedSize, RealSize)` tail, and returns resident bytes for resident files.

#### 4.3.8 NTFS Test-Critical Edge Cases

Torn record (USN mismatch); `ClustersPerMFTRecord = 0xF6`; negative run offsets; sparse runs; 2-record `$ATTRIBUTE_LIST` file; DOS+Win32 dual `$FILE_NAME`; deleted directory parent (sequence+1); resident-data deleted file (<~700 bytes); fragmented `$MFT`; 4096-byte-sector volume; files with run lengths needing 3-byte length fields.

---

## 5. Module 3 — Structure-Aware Carving Engine (`CarveEngine`)

### 5.1 Interfaces

```cpp
struct ValidationResult {
    enum class Verdict { Valid, ValidTruncated, Invalid } verdict;
    uint64_t length_bytes;        // exact determined file length (Valid) / bytes validated (Truncated)
    std::string subtype;          // e.g. "docx","apk","jfif","exif","pdf-1.7"
    Confidence confidence;
    std::vector<std::string> notes;
};

class ISignature {
public:
    virtual ~ISignature() = default;
    virtual std::string_view name() const = 0;             // "jpeg"
    virtual std::span<const std::span<const uint8_t>> magics() const = 0;  // all start patterns, all at offset 0
    virtual size_t   min_header_bytes() const = 0;         // quick prefilter length
    virtual uint64_t max_file_size() const = 0;            // hard cap per hit (configurable)
    virtual std::string_view default_extension() const = 0;
    virtual ValidationResult validate(BoundedReader& r) const = 0;   // r is positioned at candidate start (offset 0)
};

class BoundedReader {       // reads from BlockDevice with hard upper bound; offsets are relative to candidate start
public:
    Result<size_t> read_at(uint64_t rel, uint8_t* dst, size_t len);   // short at bound
    uint64_t       limit() const;      // = min(max_file_size, device_end - start, region_end - start)
};

struct CarveOptions {
    enum class Scope { UnallocatedOnly, All } scope = Scope::UnallocatedOnly;  // UnallocatedOnly requires an IAllocationMap, else falls back to All with warn
    bool unaligned = false;             // false: only test candidates at sector boundaries (default)
    uint32_t alignment = 0;             // 0 → use cluster size if known, else logical sector size
    bool nested = false;                // false: skip scanning inside an already validated span
    bool deep_validate = false;         // CRC/inflate verification (slower)
    std::set<std::string> types;        // empty = all registered
    uint64_t start_byte = 0, end_byte = UINT64_MAX;
    size_t   min_confidence = Low;
};

struct CarveHit { uint64_t offset; uint64_t length; std::string type, subtype; Confidence confidence; uint32_t flags; std::string sha256; };
Result<std::vector<CarveHit>> CarveEngine::run(BlockDevice&, const IAllocationMap*, const CarveOptions&, ProgressFn);
```

### 5.2 Scanning Algorithm

```
window = 4 MiB buffer, overlap = 64 KiB
cursor = start_byte aligned up to `alignment`
while cursor < end:
    read window [cursor, cursor+window+overlap)
    for each aligned offset p in window (step = alignment):
        if scope == UnallocatedOnly and map: skip p if cluster(p) is allocated
        b0 = buf[p]; fast switch on first byte  (0xFF→jpeg, 0x89→png, 0x25→pdf, 0x50→zip)
        if memcmp(buf+p, magic, magic_len) != 0 continue
        r = BoundedReader(device, p, limit)
        v = sig.validate(r)
        if v.verdict != Invalid:
            emit CarveHit{p, v.length_bytes, ...}; 
            if !nested: p = align_up(p + v.length_bytes)   // skip over recovered span
    cursor += window   (the overlap guarantees magic straddling is seen, and validators read directly from the device, not the window)
```
- Aligned scan is the default because filesystems allocate on cluster boundaries. `--unaligned` tests every byte offset using `memchr` on the first-byte of each magic.
- Validators read from the device through `BoundedReader` (with a small read cache) — they are NOT limited to the window.
- Hits sorted by offset; hits fully contained in another hit (when `nested=false`) are dropped; **overlap resolution**: if two validated hits overlap partially, keep higher confidence, then longer.
- Dedup against filesystem-recovered files: a carved hit whose `[offset, offset+length)` equals (±0) the first extent of an FS-recovered file with High confidence is marked `duplicate_of` in the report and not exported twice.
- v1 supports **contiguous files only**; fragmented files will typically yield `ValidTruncated` or `Invalid`. *(Superseded for JPEG as of 1.3.0 and for PNG and GIF as of 1.4.0 — a head may be joined to validated runs across a gap; see the §10 addendum.)*

### 5.3 Signature Database (exact magics)

| Type | Magic (hex, offset 0) | Aligned-scan prefix test | Default max size | Ext |
|---|---|---|---|---|
| JPEG | `FF D8 FF` (followed by marker byte ∈ {E0,E1,E2,E8,DB,C0,C2,EE,FE}) | 4 bytes | 64 MiB | `.jpg` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 8 bytes | 128 MiB | `.png` |
| PDF | `25 50 44 46 2D` (`%PDF-`) followed by `31 2E 30..37` (`1.0`–`1.7`) or `32 2E 30` (`2.0`) | 8 bytes | 1 GiB | `.pdf` |
| ZIP | `50 4B 03 04` (local file header); also `50 4B 05 06` is NOT a start magic (empty archive: ignored) | 4 bytes | 2 GiB | `.zip` |

Max sizes are defaults overridable via `--max-size <type>=<bytes>`.

### 5.4 JPEG Validator (`sig_jpeg`)

Parse as a sequence of marker segments, tracking state:

```
pos = 0; require bytes[0..1] = FF D8 (SOI); pos = 2
saw_sof = saw_dqt = saw_dht = false; scans = 0; width=height=0; ncomp=0
loop:
    skip fill bytes: while b[pos]==0xFF and b[pos+1]==0xFF: pos++
    require b[pos]==0xFF; m = b[pos+1]; pos += 2
    if m == 0x00 → Invalid (stray stuffed byte outside scan)
    standalone markers: 0x01 (TEM), 0xD0–0xD7 (RSTn, outside scan: Invalid), 0xD8 (SOI again: Invalid), 0xD9 (EOI) → handle below
    if m == 0xD9: if scans >= 1 and saw_sof → END (length = pos); else Invalid
    else: seg_len = u16be@pos; require seg_len >= 2 and pos+seg_len <= limit; payload = pos+2 .. pos+seg_len
      switch m:
        0xDB (DQT): parse tables: each: Pq/Tq byte (Pq 0|1, Tq 0..3), 64 or 128 bytes; total must equal seg_len-2 → saw_dqt
        0xC4 (DHT): each: Tc/Th byte, 16 counts, sum(counts) <= 256 symbols; total matches → saw_dht
        0xC0,0xC1,0xC2 (SOF0/1/2) [also accept 0xC3,0xC5–0xC7,0xC9–0xCB,0xCD–0xCF as valid-but-rare; set subtype]:
              precision ∈ {8,12} (12 only with SOF1/2); height = u16be@+1, width = u16be@+3;
              require width>0 and height>0 (height==0 requires DNL: treat as Invalid); ncomp = b@+5 ∈ {1,3,4};
              seg_len == 8 + 3*ncomp; each component: id, (H<<4|V) with H,V in 1..4, Tq 0..3
              only ONE SOF allowed → second SOF is Invalid; saw_sof = true
        0xDA (SOS): require saw_sof; Ns = b@+0 in 1..4 and Ns <= ncomp; seg_len == 6 + 2*Ns; Ss/Se/Ah/Al sane
              baseline (SOF0/1): require saw_dqt and saw_dht ; progressive: same
              pos += seg_len; scans++
              ---- entropy-coded segment scan ----
              loop: find next 0xFF in data: 
                 next = b[i+1]
                 if next == 0x00 → stuffed byte, continue
                 if next in D0..D7 → restart marker, continue
                 if next == 0xFF → fill, continue
                 else → end of scan; pos = i; break (marker handled by main loop)
              if limit reached → ValidTruncated (length = limit validated bytes), confidence Low
        0xDD (DRI): seg_len==4 ; 0xE0..0xEF (APPn), 0xFE (COM): skip payload; 
              APP0 "JFIF\0" / APP1 "Exif\0\0" → subtype "jfif"/"exif"; APP1 Exif: also verify TIFF header (II*\0 | MM\0*) within first 16 payload bytes else note
        0xDC (DNL), 0xC8,0xF0–0xFD (reserved JPGn): skip payload
        any other: Invalid
      pos += seg_len
```
- Output: `length_bytes = pos after EOI`. Valid → confidence `High` if EOI found, SOF dims `<= 65535` and Exif/JFIF structure ok; `Medium` if no APP0/APP1 present (plain JPEG); `ValidTruncated` if data ran out before EOI → `Low`, flag `Truncated`.
- Embedded thumbnails: when an APP1/Exif segment contains an inner JPEG (`FF D8`), the segment-length skip naturally bypasses it (inner SOI/EOI are inside the payload) — **test required**.
- Trailing data after EOI is not part of the file (MPF/“MPO” multi-picture files: APP2 `MPF\0` → note `mpo_may_contain_additional_images`; keep length at first EOI).
- `deep_validate`: additionally decode Huffman bitstream structurally? NOT required. Instead verify there is ≥ 1 MCU worth of entropy data (≥ 2 bytes between SOS header and next marker).

### 5.5 PNG Validator (`sig_png`)

```
require 8-byte signature
pos = 8; seen = {}; idat_started = false; idat_ended = false; idat_total = 0
loop (chunk):
    require pos + 12 <= limit               // length(4) + type(4) + CRC(4)
    len = u32be@pos            // MUST be <= 0x7FFFFFFF and pos+12+len <= limit
    type = 4 bytes @pos+4      // each byte must be ASCII letter (A-Z/a-z); else Invalid
    data = pos+8 .. pos+8+len
    crc_stored = u32be@pos+8+len
    crc_calc   = CRC32(type || data)        // zlib/ISO-HDLC polynomial 0xEDB88320, init 0xFFFFFFFF, final xor 0xFFFFFFFF
    if crc_stored != crc_calc → Invalid   (this validation is ALWAYS performed, deep or not)
    first chunk MUST be IHDR → else Invalid
    IHDR: len == 13; width=u32be@0, height=u32be@4, both in 1..0x7FFFFFFF; bit_depth@8, color_type@9, compression@10 (==0), filter@11 (==0), interlace@12 (0|1)
          valid (color_type, bit_depth): (0:1,2,4,8,16) (2:8,16) (3:1,2,4,8) (4:8,16) (6:8,16)
          sanity: width*height <= 2^31 pixels (configurable) 
    PLTE: len % 3 == 0 and 3 <= len <= 768; allowed only for color types 2,3,6(optional); REQUIRED for type 3; must precede first IDAT; at most once; for type 3, entries <= 2^bit_depth
    IDAT: must follow IHDR (and PLTE if present); IDAT chunks must be CONSECUTIVE (any other chunk between two IDATs → Invalid); idat_total += len
    IEND: len == 0; (CRC bytes must be AE 42 60 82, implied by CRC check) → END at pos+12 
    ancillary chunk ordering: tRNS before IDAT (after PLTE); gAMA/cHRM/sRGB/iCCP before PLTE; 
        (ordering violations → note + downgrade to Medium, NOT Invalid, except IDAT/IHDR/PLTE/IEND rules above)
    duplicates: IHDR, PLTE, IEND, and the singletons (gAMA, cHRM, sRGB, iCCP, sBIT, bKGD, hIST, tRNS, pHYs, tIME) at most once → violation → Invalid for IHDR/PLTE/IEND, Medium otherwise
    unknown chunk with critical bit (first letter uppercase) not in {IHDR,PLTE,IDAT,IEND} → Invalid
    if hit limit before IEND → ValidTruncated (only if IHDR+≥1 IDAT validated), flag Truncated, Low
require idat_total > 0 before IEND else Invalid
```
**Deep validation (`deep_validate=true`, default ON for `High` assignment of PNG):** concatenate IDAT payloads (stream through miniz `tinfl` in streaming mode, no full buffer): 
- zlib header: `CMF`: `CM = CMF & 0x0F == 8`, `CINFO <= 7`; `(CMF*256 + FLG) % 31 == 0`; `FDICT` bit must be 0. 
- Inflate to completion; verify Adler-32 trailer; verify decompressed size == expected: non-interlaced: `height * (1 + ceil(width * channels * bit_depth / 8))`; interlaced (Adam7): sum over the 7 passes of `h_p * (1 + ceil(w_p * bpp_bits / 8))` for non-empty passes (w_p,h_p computed with the Adam7 start/step tables). Mismatch → Invalid.
- Result: shallow-valid only (CRCs ok, structure ok) → `Medium`; deep-valid → `High`.

### 5.6 PDF Validator (`sig_pdf`)

Offsets below are relative to the candidate start `H` (position of `%PDF-`).

1. **Header:** `%PDF-1.[0-7]` or `%PDF-2.0`, followed by `\r`, `\n`, or `\r\n`/space. A binary-comment line (`%` + ≥4 bytes ≥0x80) following is typical → note only.
2. **Candidate trailer search:** scan forward (bounded by `max_file_size`) for the 5-byte token `%%EOF`. For each occurrence `E` (in ascending order), the candidate end is `E+5` plus an optional EOL (`\r\n`, `\r`, or `\n`; also tolerate one extra whitespace byte if followed by zero/garbage padding).
3. **Candidate validation** (for each `E`):
   - Search backwards from `E` (up to 1024 bytes) for the last `startxref` keyword; after it (whitespace, then decimal integer `X`, whitespace) immediately precedes `%%EOF`. Reject if the token order is wrong.
   - Resolve `X` against the file: try `H + X` first, then `X` as absolute-from-start only if `H == 0`. At that position:
     a. **Classic xref:** token `xref`, EOL, then one or more subsection headers `<first> <count>` followed by exactly `count` 20-byte entries `nnnnnnnnnn ggggg n|f` + 2-byte EOL (accept `\r\n`, ` \n`, ` \r`); then keyword `trailer` and a dictionary `<<…>>` containing `/Size <int>` and `/Root <int> <int> R` (`/Root` may be absent only in a hybrid/XRefStm case—then require `/XRefStm`). Entry 0 SHOULD be `0000000000 65535 f`.
     b. **XRef stream:** `<int> <int> obj` followed within 1024 bytes by a dictionary containing `/Type /XRef`, `/Size`, `/W [a b c]` (3 ints), and `stream` keyword; `/Root` present.
   - If `/Prev <int>` exists: follow the chain (max depth 64) applying the same rules; every `/Prev` target must lie within `[H, E]`.
   - If `/Size` > 0 and (classic) the sum of subsection counts ≥ 1: spot-check up to 16 in-use entries (`n`): the offset must point at `<objnum> <gen> obj` (objnum equals the entry's index) — at least 90% of the sampled entries must match (some generators write wrong offsets; <90% → downgrade to `Low`, ≥ 1 match required to be Valid at all).
   - Valid candidate ⇒ record `valid_end = E_end`.
4. **Incremental updates:** the first valid candidate is the base. Subsequent `%%EOF` candidates that validate **and whose `/Prev` chain leads to the previous valid candidate's xref** extend the file (`valid_end` advances). Stop at the first valid candidate that does not link, at `max_file_size`, or at the next top-level `%PDF-` header located at a sector boundary after the current `valid_end` with no `%%EOF` before it. (Embedded PDFs inside streams are skipped because they are never `/Prev`-linked.)
5. **Linearized files:** if the first object after the header has `/Linearized` and `/L <length>` — require `length == valid_end - H` for `High`; mismatch → note `linearized_length_mismatch`, `Medium`.
6. **No valid candidate found but header + ≥1 `obj`/`endobj` pairs and no EOF within limit** → `ValidTruncated`, `Low` (length = last `endobj` + 6).
7. **Confidence:** High = xref validated + ≥90% spot-check + `/Root` object resolvable (object `R` found at its offset and contains `/Type /Catalog`); Medium = xref valid but Root not verified; Low = truncated/spot-check failures.
8. **Encrypted PDFs** (`/Encrypt` in trailer): valid; subtype notes `encrypted`.

### 5.7 ZIP Validator (`sig_zip`)

Candidate start `L` has `50 4B 03 04`.

1. **Local header check at L:** version needed@4 (u16), flags@6, method@8 ∈ {0,8,9,12,14,93,95,99}; name length@26 (u16), extra length@28 (u16); `30 + n + m <= limit`; name chars must not contain control chars < 0x20 (UTF-8 if flag bit 11; else CP437 accepted).
2. **Locate End of Central Directory:** scan forward from `L` for `50 4B 05 06` occurrences (bounded by `max_file_size`); for each occurrence `Q`:
   - Read EOCD (22 bytes): disk#@4, cd-disk@6, entries-on-disk@8, total-entries@10, cd-size@12 (u32), cd-offset@16 (u32), comment-len@20 (u16). Require `Q + 22 + comment_len <= limit` (comment must not contain `50 4B 05 06` followed by a plausible EOCD — otherwise prefer the **last** EOCD whose `comment_len` exactly spans to the next candidate or end).
   - **ZIP64:** if `total-entries == 0xFFFF` or `cd-size == 0xFFFFFFFF` or `cd-offset == 0xFFFFFFFF`: locator `50 4B 06 07` must be at `Q-20` (disk@4, eocd64-offset@8 u64, total-disks@16), and the ZIP64 EOCD `50 4B 06 06` at `L + eocd64_offset`: size-of-record@4 (u64), version made@12, needed@14, disk#@16, cd-disk@20, entries-on-disk@24 (u64), total-entries@32 (u64), cd-size@40 (u64), cd-offset@48 (u64). Use these values.
   - Require `disk# == 0 && cd-disk == 0` (multi-volume → Unsupported).
   - Offsets are relative to `L` (carving a self-contained archive): require `cd_offset + cd_size == Q` (or `== eocd64_pos` for ZIP64). If prepended data (SFX stub) exists we can't see it because L is the *first local header*; tolerate `cd_offset + cd_size == Q` only.
3. **Central directory walk:** from `L + cd_offset`, parse exactly `total_entries` entries: signature `50 4B 01 02`, fixed 46 bytes: method@10, CRC32@16, comp-size@20, uncomp-size@24, name-len@28, extra-len@30, comment-len@32, local-header-offset@42 (u32; ZIP64 extra field id `0x0001` supplies 64-bit values for fields set to `0xFFFFFFFF`, in order uncomp, comp, local-offset, disk). For each entry:
   - `lho < cd_offset`; at `L + lho` the bytes are `50 4B 03 04`; the local header's name equals the central name (byte-equal); `L + lho + 30 + n + m + comp_size <= cd_offset` (when flag bit 3 data-descriptor is set the local header sizes may be 0 — use central sizes).
   - Entries' local-header regions must not overlap (sort by `lho`; each `lho_next >= lho + 30 + n + m + comp_size [+ descriptor 12/16/24]`).
   - The total number of entries parsed equals `total_entries` and the walk ends exactly at `cd_offset + cd_size` (± ZIP64 EOCD/locator/digital-signature `50 4B 05 05`).
   - **Deep (`deep_validate`):** for each entry with method 0 or 8 and `uncomp_size <= 256 MiB`: stream (inflate via miniz) and compare CRC32 and sizes. Any mismatch → `Medium` (not Invalid: damaged-entry archives are still useful) and note `entry_crc_mismatch:<name>`.
4. **First valid EOCD wins:** length = `Q + 22 + comment_len - L` (ZIP64 included).
5. **Subtype classification** (from central directory names; first match wins):

| Condition | subtype / ext |
|---|---|
| `[Content_Types].xml` and `word/` | `docx` |
| `[Content_Types].xml` and `xl/` | `xlsx` |
| `[Content_Types].xml` and `ppt/` | `pptx` |
| first entry `mimetype` (stored, uncompressed) = `application/vnd.oasis.opendocument.*` | `odt/ods/odp` by mime |
| `AndroidManifest.xml` and `classes.dex` | `apk` |
| `META-INF/MANIFEST.MF` | `jar` (apk checked first) |
| `mimetype` = `application/epub+zip` | `epub` |
| otherwise | `zip` |

6. **Truncated:** no valid EOCD within limit but ≥ 1 local header chain validates sequentially (header → data via sizes in header when no data-descriptor flag) → `ValidTruncated`, `Low`, flag `Truncated`, length = end of last fully-validated entry.
7. **Confidence:** High = full CD walk consistent + (deep CRCs OK or deep not requested and all structural checks pass); Medium = CRC mismatches; Low = truncated.

### 5.8 Output of Carving

Each hit exported via `OutputSink` to `carved/<type>/<offset_hex16>_<len>.<ext>` (`ext` from subtype when known). The file bytes are streamed from the device in 1 MiB chunks. SHA-256 recorded. Zero bytes of the source are modified.

### 5.9 Adding Signatures

New signature = new `ISignature` subclass + registry line + fixtures + unit tests; no engine changes. The registry returns signatures in deterministic order.

---

## 6. Module 4 — Android USB Bridge (`AndroidBridge`)

### 6.0 Honest Scope (normative)

Without root, ADB provides access only to the **shared storage and app-accessible areas** exposed to the `shell` user. Deleted-file recovery here means *recovering items that still exist as files in accessible locations* (thumbnails, caches, trash/recycle folders). The bridge MUST NOT:
- run `su`, `adb root`, `adb remount`, `adb disable-verity`, exploit anything, or attempt privilege escalation;
- modify the device (`push`, `install`, `uninstall`, `rm`, `mv`, `cp` to device, `settings put`, `pm`, `am`, `reboot`, etc.);
- read the raw block device (`/dev/block/*`) or `/data` of other apps. Paths denied by the OS are reported as `AccessDenied`.
It MUST state limitations in the report (`"limitations": [...]`): inaccessible app-private data, encrypted `/data`, scoped-storage restrictions on Android 11+, and that true low-level undelete requires root/physical imaging (out of scope).

### 6.1 Device Detection

#### 6.1.1 `IUsbEnumerator`

```cpp
struct UsbDeviceInfo {
    uint16_t vid, pid;
    std::string serial_usb;           // USB iSerialNumber if available
    std::string manufacturer, product;
    std::string instance_id;          // Windows device instance id / Linux sysfs path
    bool has_adb_interface;           // class 0xFF, subclass 0x42, protocol 0x01
    bool known_android_vid;           // matched against table 6.1.3 (hint only)
};
class IUsbEnumerator { virtual Result<std::vector<UsbDeviceInfo>> enumerate() = 0; };
```

#### 6.1.2 Windows — SetupAPI (`usb_enumerator_win.cpp`)

```
GUID_DEVINTERFACE_USB_DEVICE = {A5DCBF10-6530-11D2-901F-00C04FB951ED}
hDevInfo = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_USB_DEVICE, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
for i = 0; SetupDiEnumDeviceInterfaces(hDevInfo, nullptr, &guid, i, &ifData); ++i:
    SetupDiGetDeviceInterfaceDetailW (two-call size pattern) → DevicePath, e.g.
        \\?\usb#vid_18d1&pid_4ee7#<serial>#{a5dcbf10-...}
    parse regex (case-insens.): vid_([0-9a-f]{4})&pid_([0-9a-f]{4})   → vid, pid
    parse serial = third '#'-delimited segment (if it does not contain '&' it is a real iSerial; else synthetic → leave empty)
    SetupDiGetDeviceRegistryPropertyW: SPDRP_HARDWAREID (MULTI_SZ; contains USB\VID_xxxx&PID_xxxx&MI_xx for composite), SPDRP_FRIENDLYNAME/DEVICEDESC, SPDRP_MFG
    has_adb_interface: enumerate hardware IDs / CompatibleIDs (SPDRP_COMPATIBLEIDS) for "USB\Class_FF&SubClass_42&Prot_01"
        and, for composite devices, enumerate child interfaces (SetupDiEnumDeviceInfo with DIGCF_ALLCLASSES on enumerator "USB", match "MI_xx" siblings with the same VID/PID)
SetupDiDestroyDeviceInfoList(hDevInfo)   // RAII wrapper required
```
Link `setupapi.lib`. No driver installation, no `SetupDiCallClassInstaller`, no `DIF_*` calls (add to the forbidden-token list).

#### 6.1.3 Known Android VID Table (hint only; non-exhaustive; stored in `android/vid_table.inc`)

| Vendor | VID | Vendor | VID |
|---|---|---|---|
| Google | 0x18D1 | Samsung | 0x04E8 |
| HTC | 0x0BB4 | Huawei | 0x12D1 |
| Motorola | 0x22B8 | LG | 0x1004 |
| Sony | 0x0FCE | ASUS | 0x0B05 |
| Xiaomi | 0x2717 | OnePlus | 0x2A70 |
| Oppo | 0x22D9 | Lenovo | 0x17EF |

Matching rules: a device is a **candidate** if `has_adb_interface` OR `known_android_vid`. A VID match alone is never treated as authoritative; the authoritative state is `adb devices -l` (6.2.4). Devices in MTP/PTP-only mode (no ADB interface) are listed with `adb_state = "no_adb_interface"` and a hint: *Enable Developer options → USB debugging, set USB mode to File Transfer.*

#### 6.1.4 Linux

Enumerate `/sys/bus/usb/devices/*`; read `idVendor`, `idProduct`, `serial`, `manufacturer`, `product`; for each `<dev>:<cfg>.<if>` child read `bInterfaceClass/SubClass/Protocol` = `ff/42/01` for ADB. No libusb requirement.

### 6.2 ADB Transport Layer

```cpp
class IAdbTransport {
public:
    virtual Result<std::vector<AdbDevice>> list_devices() = 0;                 // serial, state, model, product, transport_id
    virtual Result<std::string> shell_readonly(const std::string& serial, const AdbShellCmd&) = 0;   // allowlisted structured command
    virtual Result<void> pull(const std::string& serial, const std::string& remote, const std::filesystem::path& local_tmp) = 0;
    virtual ~IAdbTransport() = default;
};
// Implementations: SubprocessAdbTransport (default), PySidecarAdbTransport (optional), FakeAdbTransport (tests)
```

#### 6.2.1 Command Policy (`adb_command_policy.cpp`) — allowlist, not blocklist

`AdbShellCmd` is a **closed enum + validated arguments**, never a free string:

| Kind | Device-side command executed | Arg validation |
|---|---|---|
| `GetProp(key)` | `getprop <key>` | key matches `^[A-Za-z0-9._-]{1,64}$` |
| `ListFiles(dir)` | `find <dir> -type f` | dir passes remote-path validation |
| `StatBatch(files[])` | `stat -c %s\|%Y\|%n <f1> <f2> …` (≤ 64 files per call) | each file passes validation |
| `TestDir(dir)` | `test -d <dir>` | dir validated |

Top-level adb verbs allowed (argv arrays): `start-server`, `devices -l`, `-s <serial> shell <allowlisted>`, `-s <serial> pull <remote> <local>`. Everything else → `Error{PolicyViolation}` (and `ReadOnlyViolation` thrown if the verb is in the deny-list: `push install uninstall root unroot remount reboot sideload disable-verity shell-with-su ...`).

**Remote-path validation:** UTF-8; must start with `/sdcard/`, `/storage/emulated/0/`, or `/storage/<XXXX-XXXX>/` (SD cards); no `..` components; no NUL/newline; max 4096 bytes. **Quoting for `adb shell`** (adb concatenates args and the device shell re-parses them): every dynamic arg is wrapped in single quotes with `'` replaced by `'\''`. Subprocess execution uses an argv array (`CreateProcessW` with a constructed command line using proper Win32 quoting rules / `posix_spawnp`), **never** a shell string with `system()`/`popen()`.

#### 6.2.2 `SubprocessAdbTransport` (default)

- Locates `adb` in order: `--adb-path`, `OPENRECOVER_ADB` env var, `<exe_dir>/platform-tools/adb(.exe)`, `PATH`. Not found → `Error{AdbNotFound}` with download hint (no auto-download).
- Runs `adb start-server` once; every call has a timeout (default 30 s for shell, 15 min for pulls, configurable), kills the child on timeout, captures stdout/stderr (stderr bounded to 1 MiB).
- `adb devices -l` output parser: lines after header `List of devices attached`; format `<serial>\s+<state>\s+(key:value\s*)*`; states: `device` (ready), `unauthorized` (user must accept the RSA prompt on the phone → `Error{DeviceUnauthorized}` with instructions), `offline`, `no permissions` (Linux udev hint), `recovery`, `sideload` (ignored).
- Map USB device ↔ adb device: match `UsbDeviceInfo.serial_usb == adb serial` when available; otherwise report both lists separately.

#### 6.2.3 `PySidecarAdbTransport` (optional, uses `pure-python-adb`)

- Launched as a child process: `python tools/adb_sidecar/sidecar.py` (interpreter from `--python` / `OPENRECOVER_PYTHON`). Dependency: `pure-python-adb` (import `from ppadb.client import Client as AdbClient`), connecting to the ADB server at `127.0.0.1:5037` (the server is still started with `adb start-server`).
- **Protocol: JSON Lines over stdin/stdout** (UTF-8, one object per line, no pretty printing, stderr = logs):
  - Request: `{"id":<int>,"op":"list_devices"|"shell"|"pull","serial":"...","cmd":{"kind":"ListFiles","dir":"/sdcard/DCIM/.thumbnails"},"remote":"...","local":"..."}`
  - Response: `{"id":<int>,"ok":true,"data":...}` or `{"id":<int>,"ok":false,"error":{"code":"...","message":"..."}}`
- The sidecar MUST re-implement the **same allowlist** (shared constants file `tools/adb_sidecar/policy.json` generated from C++ at build time and verified by a unit test that both implementations reject the same 20 malicious inputs). The sidecar uses only `device.shell(<constructed string>)` for allowlisted kinds and `device.pull(remote, local)`. It exposes no `push`, `install`, `shell` passthrough.
- C++ side supervises: handshake `{"op":"hello"}` → `{"ok":true,"data":{"proto":1,"ppadb":"x.y.z"}}`; process killed on destructor; any malformed line → `Error{ProtocolError}`.
- Selection: `--adb-backend subprocess|python` (default `subprocess`).

#### 6.2.4 Readiness Probe (on connect)

`getprop ro.product.model`, `ro.product.manufacturer`, `ro.build.version.release`, `ro.build.version.sdk` (SDK int, used for scoped-storage notes: ≥ 30 → note `scoped_storage_restricts_android_data`), `ro.crypto.state` (informational). Record in the report. Verify `test -d /sdcard` (else `Error{StorageUnavailable}`).

### 6.3 Scan Profiles — Where "deleted" Items May Still Exist

Profiles are JSON (`profiles/default.json`, user-extendable via `--profile <file>`); schema:

```json
{
  "schema": 1,
  "name": "default",
  "roots": [
    {"id":"thumbnails",      "path":"/sdcard/DCIM/.thumbnails",       "kind":"thumbnail", "recursive":true},
    {"id":"thumbnails_pics", "path":"/sdcard/Pictures/.thumbnails",   "kind":"thumbnail", "recursive":true},
    {"id":"trashed_media",   "path":"/sdcard",                        "kind":"trash",     "recursive":true,
        "name_regex":"^\\.trashed-[0-9]+-.+", "max_depth":6},
    {"id":"app_media_cache", "path":"/sdcard/Android/data",           "kind":"cache",     "recursive":true,
        "dir_regex":"(^|/)cache(/|$)", "max_depth":6, "optional":true}
  ],
  "type_filter": ["jpg","jpeg","png","webp","gif","mp4","pdf","zip","docx","xlsx","pptx","txt"],
  "max_file_size": 2147483648
}
```
- `trash` kind: Android 11+ MediaStore marks "trashed" items by renaming them `.trashed-<expiry_epoch>-<original name>` in their original directory (files remain until expiry, ~30 days). Parsing: `expiry = <digits>`, `original_name = remainder`. Report `trashed_expires_at`.
- `.thumbnails` directories hold cached image thumbnails of possibly deleted originals (resolution is low; mark `kind=thumbnail`, `note="low-resolution derivative"`).
- `cache`: app cache directories may contain media derived from deleted content; `optional:true` roots that return `AccessDenied` are recorded (`"access_denied": true`) and skipped silently (no error exit).
- **Vendor trash folders** (gallery "Recently deleted" etc.) differ between manufacturers/OS versions and are NOT hard-coded as authoritative; ship `profiles/vendor_examples.json` as an *unverified, user-editable template* clearly marked as such in its `"comment"` field.

### 6.4 Scan & Pull Algorithm

```
scan(serial, profile, out_dir, options):
  1. probe device (6.2.4); abort on unauthorized/offline
  2. for each root:
       r = TestDir(root.path); if not dir: record "absent", continue
       r = ListFiles(root.path) → newline-separated paths
            (paths containing '\n' are impossible to represent: detected when a line doesn't start with a root prefix → skip + warn)
            if the command exits non-zero with "Permission denied"/"Operation not permitted" → record AccessDenied for that root (partial output still used)
       apply name_regex / dir_regex / max_depth / type_filter (case-insensitive extension), exclude zero-length
  3. StatBatch in groups of ≤ 64 → size, mtime
       skip files > max_file_size
  4. for each file (deterministic order: root id, path):
        local = out_dir/android/<serial_sanitized>/<root.id>/<relative path sanitized per component>
        pull into temp name; verify local size == stat size; compute SHA-256; atomic rename (via OutputSink)
        set local mtime = remote mtime
        RecoveredFile{origin=AndroidPull, path, size, mtime, confidence per kind}
  5. Run structural validators (section 5 signatures) on pulled jpg/png/pdf/zip files:
        Valid → keep confidence; ValidTruncated → Low; Invalid → Low + note "corrupt"
  6. report
```
Confidence mapping: `trash` → High; `thumbnail` → Medium (note low-res); `cache` → Low unless validator says Valid (then Medium).

`adb pull` never modifies the device (it reads). `OutputSink` is the only local writer. Output directory MUST NOT be inside the phone's own mount (MTP-mounted folders) — the guard rejects paths whose root is a shell namespace/MTP volume (Windows: drive type `DRIVE_REMOTE`/non-fixed shell namespace; Linux: `fuse.jmtpfs`/`gvfs` mount).

### 6.5 Fake Transport for Tests

`FakeAdbTransport(root_dir)` maps device paths under `/sdcard/...` to `tests/fixtures/android/fake_sdcard/...`, implements `list_devices` (returns one fake `device`), `ListFiles` (recursive directory walk, newline-joined), `StatBatch` (real `stat`), `pull` (file copy), and can inject faults: `unauthorized`, `offline`, `AccessDenied` on a given path, truncated output, timeouts. All Android unit tests and the whole `scan` algorithm run against it in CI (no device required). Real-device procedure lives in `tests/manual/android_real_device.md`.

---

## 7. CLI & Reporting

### 7.1 Commands (`openrecover <command> [options]`)

| Command | Purpose |
|---|---|
| `devices` | List physical drives (Win: enumerate `\\.\PhysicalDrive0..31` by attempting read-only open + geometry; Linux: `/sys/block`) and Android candidates (6.1). |
| `partitions --source <S>` | Show MBR/GPT partitions and detected filesystems. |
| `scan --source <S> [--partition N \| --offset X] [--fs auto\|fat32\|ntfs]` | List deleted files from metadata (no export). |
| `recover --source <S> --out <DIR> [--mode metadata\|carve\|both] [--min-confidence low\|medium\|high] [--types jpeg,png,pdf,zip] [--scope unallocated\|all] [--unaligned] [--deep] [--max-size type=bytes] [--sector-size N] [--allow-shared-write-sharing]` | Export files. |
| `carve --source <S> --out <DIR> [...]` | Carving only. |
| `android scan\|pull --serial <SER> --out <DIR> [--profile <file>] [--adb-backend ...] [--adb-path <p>]` | Section 6. |
| `verify --report <file>` | Re-hash exported files against a report. |

`<S>` forms: `\\.\PhysicalDriveN` (Windows), `/dev/sdX` (Linux), or a path to an image file. Global flags: `--json`, `-v/-vv`, `--no-progress`, `--report <path>`.

### 7.2 Exit Codes

`0` success · `1` generic error · `2` usage error · `3` permission denied · `4` device busy · `5` unsupported filesystem · `6` output-on-source refused · `7` device/ADB unauthorized · `70` read-only violation (abort).

### 7.3 Report (JSON, `report.json`; CSV `manifest.csv` mirrors the file table)

```json
{
  "tool": "openrecover", "version": "1.0.0", "generated_at": "...",
  "source": {"description":"...","size_bytes":0,"sector_size":512,"shared_write_fallback":false,"bad_sectors":[]},
  "partitions":[{"index":0,"scheme":"gpt","start":1048576,"length":0,"fs":"ntfs"}],
  "files":[{
    "id":1,"origin":"filesystem_metadata","path":"Users/a/pic.jpg","size":12345,
    "confidence":"high","flags":["ClustersReallocated"],"mtime":1700000000,
    "extents":[{"offset":1052672,"length":12345,"sparse":false}],
    "sha256":"...","exported_to":"files/Users/a/pic.jpg","type":"jpeg","note":""}],
  "carved":[{"offset":0,"length":0,"type":"png","subtype":"","confidence":"high","sha256":"...","exported_to":"carved/png/..."}],
  "android":{"device":{"serial":"...","model":"...","sdk":34},"roots":[{"id":"thumbnails","status":"ok|absent|access_denied","files":0}],"limitations":["..."]},
  "statistics":{"deleted_entries_found":0,"exported":0,"carve_hits":0,"duplicates_skipped":0,"ads_ignored":0},
  "warnings":[]
}
```
A carved entry that the engine joined from more than one extent (1.3.0 single-tail joins, 1.4.0 chains; JPEG, PNG and GIF as of 1.4.0) also carries `"fragments": N` and an `"extents"` array mapping each piece in file order (`offset`, `length`); every other entry is unchanged and carries neither key.

Report files are written by `OutputSink` in the output directory only.

---

## 8. Cross-Cutting Details

### 8.1 `CachedDevice`
LRU of 1 MiB aligned blocks, `std::shared_mutex`; read-ahead of one block when sequential access is detected (3 consecutive adjacent reads). Cache capacity from `OpenOptions.cache_bytes`.

### 8.2 Threading
v1: scanning pipelines are single-threaded per device; `BlockDevice::read` is thread-safe so carve validation of multiple candidate hits MAY be parallelized with a bounded thread pool (default `min(4, hw_threads)`), results re-sorted for determinism.

### 8.3 Fuzzing
`tests/fuzz/` (libFuzzer, clang, Linux): `fuzz_fat32_boot`, `fuzz_fat32_dir`, `fuzz_ntfs_record`, `fuzz_ntfs_runlist`, `fuzz_sig_jpeg/png/pdf/zip`, `fuzz_gpt`. Each feeds bytes through an in-memory `MemoryDevice` (test-only `BlockDevice`) with ASan+UBSan. CI runs each for 60 s on PR; seed corpora in `tests/fixtures/fuzz_corpus/`.

### 8.4 Confidence Rules (summary)
- **High:** structure fully validated (and, for FS-recovered files, all clusters unallocated or resident data).
- **Medium:** validated with minor anomalies (missing optional structures, CRC mismatch in non-critical entries, thumbnails).
- **Low:** truncated, clusters reallocated, validator rejected content of an FS-recovered file, or cache-derived unverified.

---

## 9. Development Milestones & Testing Strategy

**Gate rule:** each milestone has a CTest label (`M0`…`M5`). A milestone is complete only when `ctest -L "M[0-n]" --output-on-failure` passes on **both** Linux and Windows CI, `tools/check_readonly.py` passes, and the milestone's fixture + golden files are committed. Unit tests MUST NOT require Administrator rights or real devices.

### Test Infrastructure (build first, within M0)

- `MemoryDevice : BlockDevice` (test-only, in `tests/support/`) — wraps a `std::vector<uint8_t>`; supports fault injection (`fail_at(offset)`, `bad_sector(n)`), a **read-counter**, and **asserts it has no write interface** by being constructed from a `const` buffer.
- `ImageBuilder` helpers (C++) to assemble FAT32/NTFS structures from byte-level builders for *unit-level mock byte arrays* (e.g., `make_fat32_bpb({...})`, `make_ntfs_record({...})`, `make_png({...})`).
- Golden-file comparer for `report.json` (masks `generated_at`).
- Fixture generation scripts are documented and deterministic (fixed seeds, fixed volume IDs); **generated images ≤ 16 MiB each**, committed gzip-compressed, decompressed by CMake into the build dir.

### M0 — Foundations & Read-Only Core (`ctest -L M0`)

**Deliver:** CMake presets, `common/*`, `BlockDevice`, `ImageDevice`, `PartitionView`, `CachedDevice`, `readonly_guard`, `IWin32Api` + `WinPhysicalDevice` (compiled on Windows; Win32 logic tested via fake on all OSes where the fake compiles), `LinuxBlockDevice`, `OutputSink`, `tools/check_readonly.py`, CI workflow.  
**Tests (all required):**
1. `test_bytes`: LE/BE readers, overrun → failure flag, UTF-16 surrogates, `sanitize_component` (`CON`, `..`, trailing dot, 300-byte names).
2. `test_block_device`: `ImageDevice` on a 1 MiB patterned file — unaligned reads (offset 513, len 1000), read across EOF (short), read at exactly EOF (0 bytes), 4096-sector override, `PartitionView` clamping, `CachedDevice` equals uncached byte-for-byte on 10 000 random reads (seeded).
3. `test_win32_flags`: with `FakeWin32Api`, assert the exact `CreateFileW` arguments (`GENERIC_READ`, `FILE_SHARE_READ`, `OPEN_EXISTING`, forbidden bits clear); path regex rejects `\\.\PhysicalDrive`, `\\.\PhysicalDrive1x`, `C:\foo`, `\\.\PHYSICALDRIVE0\..\`; `ERROR_SHARING_VIOLATION` → `DeviceBusy` and **no retry** by default; with `allow_shared_write_sharing` exactly one retry with `FILE_SHARE_READ|FILE_SHARE_WRITE` and still `GENERIC_READ`; `safe_ioctl` throws `ReadOnlyViolation` for `IOCTL_DISK_SET_DRIVE_LAYOUT_EX` and `FSCTL_LOCK_VOLUME`; bad-sector retry path zero-fills and records sector via `FakeWin32Api` returning `ERROR_CRC`.
4. `test_readonly_guard`: no mutating symbol is reachable (compile-time `static_assert(!std::is_invocable_v<decltype(&BlockDevice::read)...>`-style negative checks via `requires`-expression tests that `dev.write(...)`, `dev.flush()` are ill-formed); `fatal_write_attempt` throws; `OutputSink` rejects an output dir containing the source image, rejects `../` traversal, never overwrites.
5. `readonly_static_check` (python) passes; and a **negative self-test** (`tools/check_readonly.py --selftest`) proves it detects a planted `WriteFile(` in a temp file.
6. (Linux) `test_readonly_syscalls` — strace test from 3.6; image sha256 unchanged.

### M1 — Partition Tables & FAT32 (`ctest -L M1`)

**Deliver:** `mbr`, `gpt`, `partition_scanner`, `fat32`, `FatAllocationMap`, `detect_and_open`.  
**Mock byte-array unit tests:** hand-built BPB variants (valid, FATSz16≠0, RootEntCnt≠0, bad signature, 4096-byte sectors); FAT chain walker (EOC, bad cluster `0x0FFFFFF7`, cycle, out-of-range); directory-entry decoder (date/time boundaries, `0x05` rule, NTRes case bits); **LFN assembler** (3-part name, checksum mismatch, deleted LFN, brute-forced first char); MBR with extended chain and loop; GPT with bad primary CRC + valid backup.  
**Disk-image fixtures** (`tests/fixtures/images/fat32_*.img`, generated by `tools/fixtures/make_fat32_fixtures.sh` using `mkfs.fat -F 32 -S 512 -s 4` + `mtools` (`mmd`, `mcopy`, `mdel`, `mrd`), 8 MiB):
 - `fat32_basic.img`: dirs `/DOCS`, `/PICS/2024`; files with long names, unicode names; **then deleted**: 6 files, 1 directory with 2 files, 1 zero-length file.
 - `fat32_reused.img`: delete a file, then create a new one that reuses its clusters.
 - `fat32_in_mbr.img` and `fat32_in_gpt.img`: same volume inside partition tables.  
**Assertions:** `scan_deleted()` output equals `fat32_basic.golden.json` exactly (paths, sizes, extents, confidence); recovered bytes (via `read_file`) hash-match the original files for High-confidence entries; reused-cluster file reported `Low` + `ClustersReallocated`; image SHA-256 unchanged.

### M2 — NTFS (`ctest -L M2`)

**Deliver:** `ntfs`, `ntfs_attributes`, `ntfs_runlist`, `NtfsAllocationMap`, path resolver, attribute-list support.  
**Mock byte-array unit tests:** boot sector (cluster-size encodings `0x08`, `0xF6`/`0xF4`, `0x80+` shifts); MFT record builder with fixup (valid, torn stripe, wrong `usa_count`); attribute iterator (truncated attribute, `Length=0` infinite-loop guard); **runlist decoder vectors** (`21 18 34 56 00`, negative delta `11 08 F0 ...`, sparse `01 10 00`, 3-byte lengths, overflow, `off_size > 8`); `$FILE_NAME` namespace preference; FILETIME conversion (epoch edge: 1601, 1970, 2106); path resolver (cycle, missing parent, sequence mismatch, `+1` deleted-parent tolerance, depth > 255).  
**Disk-image fixtures** (`ntfs_*.img`, generated by `tools/fixtures/make_ntfs_fixtures.sh` with `mkntfs -F -Q -s 512 -c 4096` + populate/delete through an `ntfs-3g` mount (needs root/FUSE; the committed compressed images are authoritative so CI doesn't need it), 16 MiB):
 - `ntfs_basic.img`: nested dirs; files: resident (<600 B), non-resident contiguous, fragmented (3 runs), sparse, large-name (255 chars), hard-linked; then deleted: files, one directory tree.
 - `ntfs_fragmented_mft.img`: > 1 MFT extent (crafted by creating thousands of small files).
 - `ntfs_compressed.img`: a compressed file, deleted → must be `Unsupported`.
 - `ntfs_4k_sector.img`: 4096-byte sector emulation.  
**Assertions:** golden JSON match; resident deleted file bytes equal original; fragmented file's extents reassemble to the original SHA-256 when clusters unallocated; deleted-directory paths reconstructed with `PathUncertain` only where expected; `$Bitmap`-based confidence matches the golden; no crash on `fuzz_ntfs_record` seed corpus.

### M3 — Carving Engine (`ctest -L M3`)

**Deliver:** `BoundedReader`, `CarveEngine`, four signatures, allocation-scoping, dedup, `OutputSink` export of hits.  
**Mock byte-array unit tests (per signature, built with the C++ builders):**
 - **JPEG:** minimal valid baseline (SOI, DQT, SOF0, DHT, SOS+data, EOI); progressive (2 scans); with Exif containing an **embedded thumbnail JPEG**; fill bytes `FF FF`; RST markers inside scan; missing EOI (truncated); `seg_len` overflow; two SOFs; SOS before SOF; zero width.
 - **PNG:** valid 1×1 RGBA & palette image; corrupted IHDR CRC; corrupted IDAT CRC; non-consecutive IDATs; missing IEND (truncated); invalid color/bit-depth pair (`2/4`); PLTE missing for type 3; zlib header invalid; Adler mismatch; inflated-size mismatch; Adam7 image.
 - **PDF:** classic xref; xref stream; incremental update (2 `%%EOF`); linearized (length mismatch); wrong `startxref` offset; PDF with junk before `%PDF-`; embedded PDF inside a stream (must not terminate early); truncated.
 - **ZIP:** empty-ish single file; DOCX-like, APK-like, ODT-like (classification); ZIP with comment containing `PK\x05\x06`; ZIP64 (fabricated); data-descriptor entries; CD offset/size inconsistent; local-name ≠ central-name; CRC mismatch (deep) → Medium; truncated (no EOCD).  
**Disk-image fixture** `tests/fixtures/images/carve_mixed.img` (16 MiB, built by `make_carve_fixtures.py`): raw (no filesystem) image with 12 valid files (3 per type) at known sector-aligned offsets, 6 decoys (magic only, garbage following; truncated; corrupted CRC), 1 JPEG nested inside a ZIP, random fill. **Golden:** exact `{offset,length,type,confidence}` list; zero false positives for decoys; `--nested` toggles the nested JPEG; unaligned variant (files at offset+17) found only with `--unaligned`; `UnallocatedOnly` scope with a synthetic `IAllocationMap` excludes files in "allocated" clusters.  
Also: carve hit vs. FS-recovered dedup test using `fat32_basic.img` after additionally running `carve`.

### M4 — Android Bridge (`ctest -L M4`)

**Deliver:** `IUsbEnumerator` (Win SetupAPI + Linux sysfs), `adb_command_policy`, `SubprocessAdbTransport`, `PySidecarAdbTransport` + `sidecar.py`, `FakeAdbTransport`, profile loader, scan/pull pipeline.  
**Tests:**
1. **Policy:** table-driven — 40 accepted/rejected inputs: `..` traversal, `'; rm -rf /sdcard #`, `$(id)`, backticks, newlines, `/data/data/...`, empty, 5000-byte paths, serial with spaces/`;`, verbs `push/install/root/remount`. Quoting function round-trips paths containing `'` through a reference POSIX shell (`sh -c 'printf %s <quoted>'`) on Linux.
2. **Parsers:** `adb devices -l` samples (device, unauthorized, offline, `no permissions`, multiple devices, daemon-start noise lines `* daemon started successfully`); `find`/`stat` output including spaces and unicode; SetupAPI device-path parser on 15 captured path strings (composite `&mi_00`, synthetic serials with `&`); VID/PID table lookup; sysfs enumerator against a fake `/sys` tree in a temp dir.
3. **Pipeline on `FakeAdbTransport`:** fixture `fake_sdcard` tree: `.thumbnails` (valid JPEG + 1 corrupt), `.trashed-1735689600-IMG_1.jpg`, `Android/data/com.x/cache/a.png`, a denied directory; assert pulled files, SHA-256, mtime preservation, confidence mapping, `access_denied` roots recorded without failing, `unauthorized` fault → exit code 7, timeout fault → child killed (subprocess transport tested against a `fake_adb` script).
4. **Sidecar:** protocol round-trip tests with a Python stub (skipped with `ctest -L M4` message if Python/ppadb unavailable → test marked SKIPPED, not failed); allowlist parity test (same 20 malicious inputs rejected by C++ and Python).
5. **Static:** `check_readonly.py` additionally verifies no `adb` verb outside the allowlist appears in source and no `DIF_*`/driver-install APIs are used.
6. **Manual (not CI):** `tests/manual/android_real_device.md` — procedure with a physical test device; checklist includes confirming (via `adb shell ls -l --time-style=full-iso` before/after) that no device file changed.

### M5 — Integration, CLI, Hardening (`ctest -L M5`)

**Deliver:** all CLI commands, `report`, `verify`, exit codes, orchestrated `recover --mode both` (metadata first, then carve scoped to unallocated space, dedup), docs, packaging (`cpack` ZIP for Windows, tarball for Linux), fuzz targets wired in CI.  
**Tests:**
1. **CLI end-to-end** on `fat32_basic.img`, `ntfs_basic.img`, `carve_mixed.img`: run the binary, compare `report.json` to goldens, verify exported file hashes via `openrecover verify`.
2. Exit codes: missing source (1), bad flags (2), unreadable file (3), `--out` inside the source image's directory tree (6), unsupported filesystem image (5).
3. **Read-only proof, end-to-end:** for every image fixture, run `recover` and assert `sha256(image)` unchanged and (Linux) strace shows no write syscalls on the source fd.
4. **Large/sparse stress:** a 64 GiB *sparse* image (created with `truncate -s 64G`, a few valid structures near the beginning/end) completes carve with `--scope all` within 120 s... (acceptance: memory < 512 MiB measured via `getrusage`/`GetProcessMemoryInfo`; test uses a reduced 2 GiB variant in CI and the 64 GiB variant under label `M5-nightly`).
5. **Determinism:** run twice → byte-identical `report.json` (masked timestamp).
6. **Fuzz smoke:** each fuzz target runs 60 s with no findings (Linux CI job).
7. **Windows manual checklist** `tests/manual/windows_physical_drive.md`: attach a USB stick (not the system disk), take it offline in Disk Management, run elevated `openrecover devices`, `scan --source \\.\PhysicalDrive<N>`, confirm with a write-blocker or by comparing a before/after `Get-FileHash` of a full dd image of the stick.

**Definition of Done (v1.0):** M0–M5 gates green on both OSes; zero `ReadOnlyViolation` in any test; fuzz targets clean; `README.md` documents the Windows share-mode caveat, the Android scope limits (6.0), and the contiguous-only carving limitation.

---

## 10. Explicit Non-Goals / Future Work (do NOT implement in v1)

exFAT, ext4, ReFS, APFS/HFS+ (out of scope entirely), BitLocker/VeraCrypt decryption, E01/VMDK/VHD containers, fragment-aware (bifragment / SmartCarving) reassembly, NTFS ADS and compressed-file extraction, USN-journal/`$LogFile` mining, Android root/physical imaging, any GUI, any network/cloud functionality.

*As of 1.1.0, exFAT, fixed/dynamic VHD containers and NTFS compressed-file (LZNT1) extraction are
implemented and shipped. As of 1.3.0, ext4, VHDX containers and JPEG fragment reassembly are
implemented as well. As of 1.4.0, JPEG chains, PNG reassembly and GIF reassembly are implemented
too. Every other item above remains a non-goal.*

*The reassembly exception is narrower than the non-goal it replaces: a JPEG head is joined only to
runs of scan data that the signature recognises across the gap, a PNG head only to chunks whose CRCs
verify, and a GIF head only to blocks whose image data decodes -- a GIF carries no checksums, so
its frames' LZW streams are the proof. Any join is kept only when the chain ends at the format's
terminator (`EOI`, `IEND`, the GIF trailer). An unallocated-only scan refuses any piece that touches
a cluster the allocation map marks in use, and an accepted chain is reported `Fragmented` without
`Truncated`. Nothing is written, repaired or format-restored. See `docs/DECISIONS.md`, "2026-10-29 —
a JPEG is rejoined only when its tail proves itself", "2026-10-29 — a chain of JPEG pieces is kept
only when it reaches the terminator", "2026-10-29 — a PNG tail is rejoined only where CRC-valid
chunks reach IEND", "2026-10-29 — a gap piece is only the file's if its clusters are free" and
"2026-10-29 — a GIF tail is proven by its own arithmetic".*
