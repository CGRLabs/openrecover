# OpenRecover 1.4.0

Released 2026-10-29. This cycle is about carving completeness. 1.3.0 taught the carver to recognise the
tail of a split JPEG; this cycle asks the harder question, because a deleted photo on a busy volume
is often split more than once and the middle pieces have to be found too. The work targets chains of
fragments: every piece after the head is still joined only when its bytes prove on their own terms
that they belong to the file, and the chain is accepted only when it ends at the format's
terminator. JPEG proves itself with markers, PNG with chunk checksums, and GIF with its own
arithmetic: a GIF carries no checksums, so its frames must decode.

## New in this cycle

- **A JPEG split more than once is stitched back together.** A continuation no longer has to reach
  `EOI` on its own. `find_continuation` reports the cut where the bytes stop being a scan (a new
  `Continuation::complete` flag says whether the run ended at the terminator or at another marker),
  and the engine walks from that cut to the next, one allocation-unit boundary at a time. A run
  shorter than the alignment is skipped instead of exported, the search may resume no further than
  `max_reassembly_gap` past the last attributed byte, a chain is capped at eight extents, and the
  whole chain is dropped unless it ends at the format's terminator -- the head then stands alone as
  a truncated hit, exactly as it did before. The report's `fragments` count and the exported bytes
  follow the whole chain, and a joined entry now lists where each extent lives: `"extents"` holds
  the device `offset` and `length` of every piece in file order, next to the count. A contiguous
  hit still carries neither key.
- **A walk stops at another image.** A scan tail can never contain `SOI`; when the bytes after a gap
  open a new JPEG, the continuation is refused instead of absorbing the neighbouring file's frames.
- **A PNG cut inside its image data is rejoined on its surviving chunk run.** The validator now
  tells a cut from a corrupt file: a chunk that fails its length, type or CRC is reported as a
  truncation at that chunk only when the bytes where the chunk says it ends are not themselves a
  valid chunk boundary; an intact boundary there keeps the candidate rejected whole, as before.
  `PngSignature::find_continuation` searches for a chunk whose CRC verifies and whose successor
  header is plausible, walks the run chunk by chunk to `IEND`, refuses a lone `IEND` and refuses
  once it meets another PNG's signature, and returns the incomplete run at the first chunk that
  fails so the same chain walk resumes past it. Extents, confidence, the eight-piece cap, the gap
  limit and the drop-if-unterminated rule are the JPEG rules unchanged. A cut that lands exactly on
  a chunk boundary still resyncs when the fill in the gap cannot open a chunk; fill that parses as a
  plausible header leaves the head a truncation to the end of the source, with no tail.
- **A GIF cut on a frame boundary is rejoined on its surviving frames.** GIF has no checksums
  anywhere, so the validator proves a cut differently: a block whose bytes fail to parse is
  reported as a truncation at that block only once at least one frame has completed -- before any
  frame the candidate is rejected whole, as before. The proof of the tail is the decode:
  `GifSignature::find_continuation` searches for a block that not only parses but whose image data
  passes a forced deep LZW decode (a bare sub-block chain parses at hundreds of junk offsets, so
  structure alone proves nothing), walks the run block by block to the trailer, claims only
  extensions whose label is one the format assigns a meaning to (a comment's free-form chain parses
  anywhere), and refuses once it meets another GIF's header. A tail resuming mid-stream joins at
  the next frame's introducer -- the interrupted frame's remaining sub-blocks sit in the gap and
  are unprovable -- so the recovered copy of that frame decodes short. Bytes that fail the deep
  decode are corruption rather than a cut and keep the head rejected, as PNG treats a failed
  inflate. Extents, confidence, the eight-piece cap, the gap limit and the drop-if-unterminated
  rule are the JPEG rules unchanged.
- **A chain never borrows a cluster in use.** An unallocated-only scan now checks every piece of the
  chain against the allocation map, not just the head: a run whose bytes touch an allocated cluster
  belongs to whatever file owns that cluster now, so the walk stops and the head stays a truncated
  hit. `Scope::All` and map-less scans are unchanged.
- **A finished chain is not `Truncated`.** The `Truncated` flag describes the head's verdict; once
  the chain reaches `EOI`/`IEND` the assembled file is complete, so a joined hit carries only
  `Fragmented`, while a dropped chain leaves the head flagged `Truncated` and alone.
- **Fixtures and fuzzing.** `carve_fragmented.img` now also holds a JPEG split twice into three
  pieces, with the piece extents and the original hash in its golden; `test_sig_jpeg` pins the cut
  and `complete` rules and the `SOI` refusal, `test_carve_engine` covers a four-extent chain, a
  chain that never reaches its terminator and the refusal of a piece in an allocated cluster,
  `test_carve_fixtures` and `cli_carve_fragmented` prove
  the join end to end, and the signature fuzz harness now replays a chain from the cut rather than a
  single continuation, with a two-cut seed. A committed `carve_fragmented_png.img` holds a PNG cut
  once, a PNG cut twice into three pieces and an orphan head placed before a second image, with the
  matching golden, `test_sig_png` cases for the cut, the resync and the exact-boundary cut, and two
  PNG seeds for the fuzz harness. A committed `carve_fragmented_gif.img` holds the same three-piece
  shape for GIF -- cuts on frame boundaries and an orphan head before the next GIF, with the
  byte-identical hash of both the once-cut and the twice-cut file in its golden, `test_sig_gif`
  cases for the cut, the decode-failure split and the continuation rules, and two GIF seeds for the
  fuzz harness.

---

# OpenRecover 1.3.0

Released 2026-10-29. This cycle is about the images a recovery tool can open and the files it can
put back together. 1.1.0 read fixed and dynamic VHD; 1.3.0 adds VHDX, the format Hyper-V has written by
default since Windows Server 2012, through the same read-only container seam so the CLI, the
`recover()` API and the report treat it exactly like a flat image. It also joins the two halves of a
JPEG that later writes split, instead of handing back a truncated prefix.

## New in this cycle

- **VHDX containers.** The reader validates the `vhdxfile` identifier, both 4 KiB headers and their
  CRC32C checksums (using the other copy when one is torn), both region tables, and the metadata
  region that names the virtual disk size, block size and logical/physical sector sizes. The block
  allocation table is decoded into fully-present, partially-present, zero, undefined and
  not-present blocks; partially-present blocks are read through their 1 MiB sector bitmap, and
  everything that is not present reads back as zeros. A truncated payload zero-fills its tail with
  a warning, the same contract as VHD.
- **Container reporting.** A VHDX is detected from its content, not its extension, and
  `DeviceInfo`/`report.json` report `source.container` as `"vhdx"`. The CLI, `recover()` and the
  report therefore see the same 8 MiB virtual volume a Hyper-V image presents, at the same paths,
  with the same hashes as the flat image it carries.
- **Refusals that name the format.** A differencing VHDX, or one whose metadata carries a parent
  locator, is `Unsupported`; so is an unknown required region or metadata item. Malformed
  geometry, checksums, block-table states and out-of-range virtual sizes are `CorruptStructure`.
  A disk whose log is marked pending is read with a warning that the log is not replayed, mirroring
  ext4's clean-unmount warning.
- **CRC32C is shared.** The ext4 checksum layer and the VHDX reader now use one
  `common/crc32c` implementation instead of a table per format.
- **Fixtures and fuzzing.** Committed full and sparse VHDX images built by the project's Python
  builder (the sparse one leaves zero blocks unallocated), with SHA-256 goldens and FAT32 recovery
  tests that compare byte for byte against the flat image. `test_vhdx_device` sweeps every
  single-byte mutation of a valid container and every header, region-table, metadata and BAT field
  with the covering checksum repaired, and `fuzz_vhdx` ships five committed seeds covering the
  zero, undefined and not-present states, a parent locator and a truncated file.
- **A split JPEG is rejoined.** A deleted photo on a volume that kept being written survives as a
  head in unallocated space, someone else's data across the middle, and a tail that resumes after
  it. When the JPEG validator's marker walk fails after at least one scan and a frame header, it
  now reports truncation at the exact byte where parsing stopped, so the carved prefix is the part
  that really is the file instead of the rest of the scanned window. With reassembly on, the engine
  then reads from the next allocation-unit boundary and asks the signature whether those bytes are
  its own continuation: the tail walk treats byte stuffing, `RSTn` and fill bytes as data and
  refuses everything else at the first marker a scan cannot contain, so unrelated data is rejected
  almost immediately. A tail that reaches `EOI` at least 16 bytes in is joined.
- **The join is recorded, not hidden.** A joined hit carries `Fragmented` alongside the head's
  `Truncated` flag, stays `Low` confidence, has a `length` that is the sum of its extents, and its
  SHA-256 and exported bytes are the logical file (head, then tail). `report.json` adds
  `"fragments": 2` to a joined carved entry; a contiguous hit's entry is unchanged and has no such
  key.
- **Reassembly is a library option.** `carve::CarveOptions::reassemble` defaults to `false`, so a
  library consumer keeps contiguous hits unless it opts in; the CLI opts in, and `--no-reassemble`
  turns it off. The head-to-tail search is bounded by `max_reassembly_gap` (8 MiB by default), and
  bytes between the cut and the next boundary are treated as someone else's and never exported.
- **What is not joined.** Only JPEG reassembles. A split inside a progressive scan looks exactly
  like the end of that scan, so it is not joined. A zero-filled gap contains no marker and therefore
  reads as entropy, so a tail whose real start sits inside a zero run is joined with those zeros
  included -- the report still flags the hit as `Fragmented` and `Low`.
- **Fragment fixture.** A committed 1 MiB image holds a JPEG cut at 2000 bytes whose tail resumes on
  the next 512-byte boundary, plus a second cut JPEG with no tail anywhere, both built by
  `make_carve_fixtures.py`. `test_carve_fixtures` checks the golden hash, the two extents, the flags
  and that the exported file equals the image's fragments concatenated, and that the orphan stays a
  truncated hit; `test_carve_engine` covers the join over a synthetic device and the
  `reassemble = false` path, and `test_sig_jpeg` pins the cut offset and the continuation rules.

---

# OpenRecover 1.2.0

Released 2026-10-28. This cycle is about breadth: the filesystem set a recovery tool is judged by.
1.1.0 covered what a Windows user deletes; 1.2.0 covers what a Linux user deletes, and closes the
gap by the same route as every previous capability -- a read-only parser behind the existing
`IFileSystemScanner`, so the CLI, the high-level `recover()` API and any library consumer get it
through one seam.

## New in this cycle

- ext4: superblock, block groups and group-descriptor checksums, for every block size the format
  allows; group geometry counts from `s_first_data_block`, so a 2 KiB or 4 KiB volume does not
  invent a group past its last data block.
- ext4: inode table reads, extent-tree and `inline_data` decoding, indirect-block fallback.
- ext4: deleted-inode recovery with directory-entry `file_type`, extent-based export, and
  block-bitmap reuse detection like exFAT's cluster check. A volume that was not cleanly
  unmounted is still read, with a warning that its journal is not replayed and the metadata may
  lag the last commit.
- `--fs` accepts `ext4`; detection reads past the first sector, because the ext4 superblock lives at
  byte 1024 of the volume and its magic is `0xEF53`.
- `partitions` lists a bare ext4 volume as a `superfloppy`, the same as FAT32 and exFAT, so `--partition
  0` and `report.partitions` describe it instead of reporting that no filesystem was found.
- ext4 features that change what a file's bytes are or where the metadata lives -- volume-level
  encryption, compression, casefold, bigalloc and `meta_bg` -- make the volume `Unsupported`; a
  per-inode encrypted file on an otherwise readable volume is reported with the `Unsupported` flag
  and not exported.
- A committed ext4 fixture image written by the project's own Python builder, with SHA-256 goldens
  for two volumes, a single-byte mutation sweep over the committed image, and libFuzzer targets over
  the superblock, directory blocks and inodes with committed seed corpora -- the same treatment the
  other parsers in this library already had.

---

# OpenRecover 1.1.0

Released 2026-10-27. The library was the focus of the previous cycle: each addition is a read-only
capability that the CLI and any library consumer get through the same `BlockDevice` and scanner
interfaces.

## What 1.1.0 added

- **exFAT recovery.** Boot, FAT, allocation-bitmap and directory-set parsing; deleted entries are
  recognised by the cleared InUse bit and validated against their SetChecksum. Recovery honours
  the `NoFatChain` flag, follows surviving FAT chains (including fragmented ones), traverses
  deleted directories, and uses the allocation bitmap to decide whether a deleted file's clusters
  were reused — a reused file is reported as `Low` confidence with the `ClustersReallocated` flag,
  and a lost chain falls back to a contiguous assumption that is labelled in the report note.
- **VHD containers.** Fixed and dynamic Virtual Hard Disks are read through their *virtual*
  geometry: the footer and `cxsparse` header are validated, the block allocation table and the
  per-block sector bitmaps are followed, and unallocated blocks and sectors read back as zeros.
  A dynamic disk therefore recovers the same files as the flat image it carries. Differencing
  disks stay `Unsupported` because they need their parent chain.
- **Container reporting.** `DeviceInfo` and `report.json` gained a `container` field, so a report
  states explicitly when the recovered bytes came from inside a VHD rather than from raw sectors.
- **Three more carved formats.** TIFF, WAV and SQLite are registered built-in signatures, so
  `--types` and the library registry covered nine families; the media-file, AVI, MP3 and compound-file
  signatures below make thirteen. A TIFF hit ends at the highest byte
  its IFD entries reference, a WAV hit is confirmed by walking the RIFF chunk list, and a SQLite
  hit is sized from the header page count and page size.
- **Carving judged by the file, not by the scan.** The SQLite and TIFF validators no longer consult
  how much room the scan happened to leave after the candidate: a page count that is not a whole
  number of scan windows, or free space that trails an image, used to discard valid hits. A
  candidate that genuinely runs past the end of the scanned region is now reported as truncated
  (`Truncated` flag, `Low` confidence) instead of being rejected or silently claimed in full.
- **Byte-range helpers.** `ByteView` gained a big-endian 64-bit reader, which the VHD metadata
  (all big-endian, 64-bit sizes) needs.
- **Container parsing swept, not spot-checked.** `test_vhd_device` mutates roughly 11 700
  versions of a valid fixed and dynamic disk — every single byte, then every footer and header
  field with the checksum that covers it repaired so the parser has to judge the value itself,
  then every block-table entry and sector-bitmap byte. Each mutant either is refused with
  `CorruptStructure`, `Unsupported` or `InvalidArgument`, or opens as a device that keeps its
  read invariants. A `fuzz_vhd` libFuzzer target and a committed `vhd` seed corpus carry the same
  shapes to Linux; the seeds are built by the same Python that writes the release fixtures and
  replayed on Windows, so a builder and a reader cannot drift apart unnoticed.
- **A recovery is one call.** `openrecover/recover.hpp` is the high-level API the CLI itself now
  uses: `recover(request)` opens the source, chooses the volume, exports what the filesystem
  metadata still names, carves what it lost, and returns a finalized `report::Report`. Its steps are
  public separately — `open_volume`, `export_metadata`, `carve_and_export` — for a tool that wants
  to interleave them with its own work, and `ExportFilter` applies one confidence floor, type list
  and per-type size cap to both phases. `test_recover_api` pins that surface on the real fixtures:
  volume selection by partition pin, byte offset and forced filesystem, cancellation through the
  progress callback, and the same numbers the CLI goldens report.
- **NTFS compressed files are recovered, not skipped.** A deleted file whose `$DATA` carries the
  `Compressed` flag is expanded while its record is read. `openrecover/fs/lznt1.hpp` decodes the
  LZNT1 chunk stream [MS-XCA]: each chunk's 2-byte header gives its own length, so the walk reads
  chunk by chunk; a chunk is a run of flag bytes with up to eight entries each, an entry is a
  literal byte or a two-byte back-reference, and the entries consume the chunk consecutively rather
  than being padded to a fixed sixteen data bytes. The attribute's log2 field says how wide a
  compression unit is (Windows writes 16 clusters), the runlist counts VCNs in the *uncompressed*
  space so every unit is followed by a hole for the clusters it did not need, a unit that needed
  all of its clusters was stored verbatim, and an all-zero unit is one hole. A compressed file is
  therefore reported with its expanded bytes, `High` confidence while its clusters stay free, and
  `ClustersReallocated` when they do not. Encrypted files, a unit width that cannot be buffered, a
  stream larger than 256 MiB, and a runlist too damaged to decode are all reported as `Low` with
  the reason in `note` instead of being guessed at. `tools/fixtures/lznt1.py` writes real LZNT1
  streams for the fixture image, and the fixture's own reference decoder, the C++ decoder and the
  committed SHA-256 goldens have to agree — the writer and the reader are separate
  implementations, so neither can drift unnoticed. A `fuzz_lznt1` target with a committed `lznt1`
  seed corpus walks the decoder under ASan and UBSan, including a destination shorter than one
  chunk and a stream cut inside its own header.
- **Soft deletes keep their original path.** A file deleted by Explorer does not lose its name —
  Windows moves it into `$Recycle.Bin\<SID>\$R<suffix>` and leaves a sibling `$I<suffix>` record
  holding where it came from, when it was deleted and how big it was. `openrecover/fs/ntfs_recyclebin.hpp`
  reads that record: both the Vista-era version 1 layout (a fixed 260-wchar path field) and the
  Windows 10+ version 2 layout (a 32-bit character count before the path) decode, and a version the
  format does not define is refused rather than guessed at. The scan pairs `$I` and `$R` by the
  shared suffix Windows picked, and reattaches the recorded path in place of the recycle-bin path
  the file would otherwise be reported under. Restoring is deliberately conservative: a recorded
  path that is UNC or that escapes with `..` sets no path claim, a `$I` size that disagrees with
  what was recovered adds `PathUncertain` and says both numbers in the note, and a zero deletion
  FILETIME is treated as "not recorded" instead of a deletion in 1970. The `$I` files themselves
  stay in the output — they are recoverable data too. `tools/fixtures/make_ntfs_fixtures.py` writes
  both versions, the padding, the orphan and the deliberately-truncated record, and
  `test_ntfs_recyclebin` sweeps a mutated record to prove that whatever path comes out is one the
  exporter can use. A `fuzz_recycle_info` target with a committed `recycle_info` seed corpus carries
  the same shapes to Linux.
- **Video, audio and phone pictures.** The registry gained an ISO media-file signature. MP4,
  QuickTime, M4A, 3GPP and HEIF all open with an `ftyp` box, so one signature covers the family and
  the brand list decides which file a hit is: `subtype` and the exported extension become `mp4`,
  `mov`, `m4a`, `3gp` or `heic`. That needed a general capability rather than a special case, because
  a format whose first four bytes are a length field cannot be found by a magic at offset zero:
  `ISignature` now reports a `magic_offset()` and the scan anchors there while the hit keeps pointing
  at the file start. Validation is by structure. The brand list has to name a family this library
  knows, the top-level boxes are then walked, and the file ends at the first header outside the
  format's box vocabulary -- the cluster after a deleted video holds a different deleted file, so a
  walk that kept going would merge them. A candidate is only claimed once both an `mdat` and the
  `moov` (or, for HEIF, a `meta` box) that describes it are inside the scan window; a box that runs
  past the window, or one that declares its length as "to the end of the file", yields `Truncated`,
  `Low` and a note naming the half that is missing. `fuzz_sig_mp4` and a committed `sig_mp4` corpus
  carry ten seeds -- camera ordering, a 64-bit `mdat`, a cut media box, three refusal shapes -- and
  `test_sig_mp4` sweeps every single-byte mutation of a valid file, requiring each result to be
  either refused or to claim only bytes inside the window.
- **Camera video and recordings in the shapes they were saved in.** Two more signatures, `avi` and
  `mp3` and `cfb`, so `--types jpeg,png,pdf,zip,gif,bmp,tiff,wav,sqlite,mp4,avi,mp3,cfb` is the
  built-in list.
  An AVI opens with the same `RIFF` magic a WAV does, so the two families are told apart by the form
  type at byte 8 inside each validator rather than by a longer magic: `test_carve_engine` puts a
  wave and a video in the same freed region and requires one hit of each type. An AVI hit is walked
  as a chunk list -- `LIST hdrl` says the file is a video, `LIST movi` (or its `rec ` groups) says
  the frames came with it, and an `idx1` index that lists frames the movie list does not contain is
  reported as `Truncated` with a note instead of as a video. Chunk sizes have to tile the declared
  file, word alignment included; a declared file bigger than the signature allows, a chunk that
  overruns it, and a chunk list that never ends are all refused. MPEG audio stores no length
  anywhere, so a hit is sized by its frames: each four-byte header's bitrate and sample-rate
  indices are looked up in the format's own tables to work out how many bytes that frame is, and the
  walk continues only while the next header lands exactly where the previous frame said it would and
  agrees on version, layer and sample rate. Three chained frames is the shortest thing the library
  will call a recording; sixteen earn `High`. An ID3v2 tag belongs to the file, so its declared
  size, the padding that follows it and a version 2.4 footer held outside that size are all
  counted, while an unsynchronised or extended-header tag is refused because its bytes no longer
  match the frames it wraps; an ID3v1 trailer is absorbed only when the frames end exactly where
  the tag starts. `fuzz_sig_avi` and `fuzz_sig_mp3` carry nine and eight committed seeds -- a wave
  inside the AVI corpus, a tag whose size is not synchsafe, a sample-rate change mid-stream -- and
  both unit tests sweep every single-byte mutation of a valid file against the same three
  invariants: never claim a byte outside the window, never report `Truncated` at less than the
  window, and never let a `Valid` verdict note that something is missing.
- **Legacy Office documents come back with their own extension.** A compound file binary stores no
  length anywhere: the allocation table is the only thing in the container that says which sectors
  belong to the file. The `cfb` signature reads that table -- the header's 109 map entries and the
  DIFAT chain behind them, then every sector the table occupies -- and ends the hit at the highest
  entry that is not marked free, so a document whose last sector is a partial one is still carved at
  the right size. A table the window cannot reach, or one with no free sector at the end, is reported
  `Truncated` at `Low` rather than guessed at. The version-3 and version-4 sector sizes are both
  honoured, and a header whose byte-order mark, sector shift, reserved bytes, mini-table count or map
  count contradicts the format is refused. Inside the claimed bytes the directory has to terminate in
  a chain the table can follow, list a root entry and at least one stream, keep every stream inside
  the container, and give every entry one of the three object types the format defines. What that
  stream is called then names the file: `WordDocument` becomes `.doc`, `Workbook` or `Book` becomes
  `.xls`, `PowerPoint Document` becomes `.ppt`, and a container holding none of them is reported as
  `.cfb` at `Medium`, because a compound file that is not somebody's document is still a real file.
  `fuzz_sig_cfb` carries fourteen committed seeds -- a four-kibibyte-sector version-4 container, a
  table long enough to need a DIFAT chain, a directory that chains to itself, a stream larger than
  the file that holds it -- and `test_sig_cfb` sweeps every single-byte mutation of a valid container
  against the same invariants the AVI and MP3 tests use.
- **The library is consumable.** `openrecover/openrecover.hpp` is a single umbrella header for the
  stable surface, and `OpenRecover::core` is now an exported CMake target: `find_package(OpenRecover
  1.1 REQUIRED)` after `cmake --install` gives a consumer the library, its headers, the vendored
  `tl/expected.hpp` it needs, and the miniz archive it links against. `examples/recover_image.cpp`
  is a ~90-line program built entirely on the high-level API, and the `install_layout` test audits
  the package on every run — export set against installed files, no build-tree path leakage, and
  every quoted include in every installed header resolving inside the package.

## Report schema changes

`files[].flags` gained the `OriginalPathRestored` value, set when the path came from `$Recycle.Bin`
metadata rather than the directory tree. Flag names are a stable, additive list; consumers should
ignore values they do not know.

`files[].deleted` is a new optional seconds-since-epoch field, the deletion time recorded out-of-band
by the recycle bin. It is emitted only for the files that have one, so a report of a volume with no
recycle-bin metadata is byte-identical to the same report before this release. Consumers should treat
an absent key as "deletion time unknown".

`source.container` is a new string field, empty for a flat source and otherwise the container
format in use (currently `"vhd fixed"` or `"vhd dynamic"`). The committed CLI goldens were
regenerated with it; consumers should treat an absent key as an empty string.

The `note` of an NTFS file that cannot be read is now a specific reason instead of one combined
string: `"ntfs_encrypted"`, `"ntfs_compressed_corrupt: …"`, `"ntfs_compressed_unsupported: …"` or
`"ntfs_compressed_too_large"`. A compressed file that *can* be read no longer carries a note at
all. Consumers should treat `note` as diagnostic text, not as a field to match on.

## Message wording

The argument and phase errors now come from the library, so five CLI messages changed. They are
diagnostics, not schema: the exit codes are the same and no report field moved.

| Before | Now |
| --- | --- |
| `--partition and --offset are mutually exclusive` | `a pinned partition and a pinned offset are mutually exclusive` |
| `--offset is beyond the end of the source` | `the pinned offset is beyond the end of the source` |
| `--scope unallocated requires a supported FAT32 or NTFS volume` | `carving unallocated space requires a supported FAT32, exFAT or NTFS volume` |
| `N carved hit(s) exceeded --max-size and were not exported` | `N carved hit(s) exceeded the size limit and were not exported` |
| `cancelled` | `scan cancelled` or `carve cancelled`, from the phase that stopped |

## Planned

Nothing in this release is half-done; the list below was candidate scope for the next cycle, and
ext4 was taken up in 1.2.0. Remaining: VHDX and E01 containers, the recycle bin of the non-NTFS
filesystems (FAT keeps deleted paths in a hidden `INFO2` file, exFAT has no equivalent), and further
carving signatures.

A new cycle bumps this file's header to `OpenRecover 1.3.0 — In development` and changes the version
in the same first step, because the report goldens embed the tool version: see
`docs/DECISIONS.md`, "1.1.0 is the frozen baseline between cycles".

---

# OpenRecover 1.0.0

Released 2026-10-20.

OpenRecover is a read-only deleted-file recovery tool for disks, disk images and Android shared
storage. Version 1.0.0 is the first complete release: the M0–M5 milestones are implemented and
the full gate passes on Windows x64.

## Highlights

- **Read-only by construction.** `BlockDevice` exposes only `read()`; the single `OutputSink` is
  the only component that writes recovered files, and it writes only to the chosen output
  directory. Windows physical drives are opened with `GENERIC_READ` and filesystem writes are
  checked by a static scanner plus fault-injection and syscall tests.
- **Filesystem recovery.** MBR and GPT partition tables, FAT32 and NTFS metadata recovery,
  including LFN names, runlists, sparse and fragmented extents, hard links and deleted directory
  chains. Files recovered from metadata are written with their original size and modification
  time; SHA-256 is recorded for every export.
- **Structure-aware carving.** JPEG, PNG, PDF and ZIP signatures validated against their internal
  structure (marker chains, chunk CRCs, xref tables, ZIP central directories), scoped to
  unallocated space with `--mode both` deduplication against metadata exports.
- **Android bridge without root.** Enumerates USB devices over ADB and collects accessible
  remnants (thumbnails, caches, trash). The command policy allows only read-only `shell` verbs;
  `su`, `root`, `remount`, `push`, `install`, `rm`, `settings`, `pm`, `am`, `reboot` and
  `/dev/block` access are rejected in both the C++ and Python sidecars.
- **Deterministic reports.** `report.json` plus `manifest.csv` with stable IDs and ordering;
  `generated_at` is the only field that changes between runs. `openrecover verify` re-hashes the
  exported files against the report.
- **Windows physical drives.** Long-path-safe output, offline-disk guidance and an explicit,
  logged `--allow-shared-write-sharing` fallback that still opens the device read-only.

## Supported inputs

- Windows physical drives (`\\.\PhysicalDriveN`) and volumes, Linux block devices.
- Flat images (`.img`, `.raw`, `.dd`, `.bin`) on Windows and Linux.
- MBR and GPT partition tables; FAT32 and NTFS filesystems.
- Carving of JPEG, PNG, PDF and ZIP on raw or unallocated regions.

Unsupported by design and reported as `ErrorCode::Unsupported`: any write, repair or format
operation, exFAT/ext4/ReFS/APFS/HFS+, E01/VMDK/VHD/VHDX containers, NTFS alternate data streams,
compressed NTFS file extraction, iOS, Android root or physical imaging, a GUI, and networking.

## Command line

```text
openrecover devices [--json]
openrecover partitions --source <img|device> [--sector-size N] [--json]
openrecover scan      --source <img|device> [--fs auto|fat32|ntfs] [--partition N | --offset N]
openrecover recover   --source <img|device> --out <dir> [--mode metadata|carve|both]
openrecover carve     --source <img|device> --out <dir> [carve options]
openrecover verify    --report <dir>/report.json
openrecover android scan --serial <S> --out <dir> [--profile <json>] [--adb-backend subprocess|python]
openrecover android pull --serial <S> --out <dir> [--profile <json>] [--adb-backend subprocess|python]
```

Exit codes: `0` success, `1` generic error, `2` usage error, `3` permission denied, `4` device
busy, `5` unsupported filesystem, `6` output on the source, `7` Android device unauthorized,
`70` read-only violation. See `README.md` for carving options and report layout.

## Quality gates

Verified for this release on Windows x64 with MSVC 19.51:

- Full `ctest -L "M[0-5]"` suite: **30/30 passed** in both Debug and Release builds (parsing,
  recovery fixtures, carving, Android transports and policy, reports, CLI end-to-end, golden
  comparison with `generated_at` masked, determinism, tamper detection and read-only checks).
- Read-only static scanner: **OK**, 91 source files scanned; the scanner's negative self-test
  passes in the same run.
- Sparse-image stress: 2 GiB variant passes within the standard suite; the 64 GiB variant is
  opt-in with `-DOPENRECOVER_NIGHTLY_TESTS=ON` and label `M5-nightly`.
- Fuzzing infrastructure: nine libFuzzer targets with ASan/UBSan over the FAT32, NTFS, partition
  and carving parsers, plus committed seed corpora. The Linux CI job runs each target for 60
  seconds; libFuzzer is not built on Windows (its runtime uses a static CRT).

Linux builds are supported from source; the CI workflow builds them and runs the `strace` proof
that source descriptors are never written. This release package was produced and gated on
Windows.

## Installation

Windows x64: unzip `openrecover-1.0.0-windows-x64.zip` anywhere and run
`bin\openrecover.exe`. The binary uses the dynamic MSVC runtime; install the **Microsoft Visual
C++ 2015–2022 Redistributable (x64)** if it is not already present. The Android `python` backend
additionally requires Python 3 and the `adb` command on `PATH`; the default `subprocess` backend
requires only `adb`.

Verify the download before use:

```sh
sha256sum -c SHA256SUMS.txt          # Git Bash / Linux
Get-FileHash -Algorithm SHA256 <file>  # PowerShell
```

## Known limitations

- **Windows share mode.** While another process holds the drive open for writing, OpenRecover
  returns `DeviceBusy`. Take the disk offline in Disk Management or use a hardware write-blocker.
  `--allow-shared-write-sharing` permits *other* processes to keep write access; OpenRecover
  itself never writes, but recovery results may be less complete.
- **Android scope.** Without root, only files visible to the `shell` user can be collected;
  app-private data cannot be undeleted. Reports state these limits.
- **Contiguous-only carving.** Fragmented files are truncated or rejected; metadata-based
  recovery is unaffected because extents are known.
- **NTFS compressed files** are reported as unsupported with no extents; alternate data streams
  are not exported.
- **No installer or code signing.** The ZIP is a portable layout, not a signed installer.

## Artifacts

| File | Contents |
|---|---|
| `openrecover-1.0.0-windows-x64.zip` | Windows x64 CLI, Android profiles and sidecar, documentation |
| `openrecover-1.0.0-source.tar.gz` | Full source tree, spec, tests, fixtures and fuzz corpora |
| `RELEASE_NOTES.md` | This document |
| `SHA256SUMS.txt` | SHA-256 of every artifact in this directory |

## Building from source

Requirements: CMake 3.24+, Ninja, C++20 compiler (MSVC 19.38+, Clang 16+, GCC 12+) and Python 3
for the static read-only check. Dependencies are pinned by URL and SHA-256 and fetched by CMake.

```sh
cmake --preset win-msvc-release
cmake --build --preset win-msvc-release
ctest --preset win-msvc-release -L "M[0-5]" --output-on-failure
cmake --build --preset win-msvc-release --target package
```

On Linux use `linux-clang-debug` or `linux-gcc-release` instead. For fuzzing with clang/libFuzzer,
configure with `-DOPENRECOVER_BUILD_FUZZ=ON` on Linux.
