# Changelog

All notable changes to OpenRecover are documented here. Released versions are frozen in `dist/`;
full release narratives are in [RELEASE_NOTES.md](RELEASE_NOTES.md).

## [1.4.0] — 2026-10-29

Carving completeness: chained fragment reassembly beyond JPEG.

- A PNG cut inside its image data is joined, chunk by chunk, to the run whose CRCs verify
  through `IEND`.
- A GIF cut on a block boundary is joined, block by block, to the frame run that decodes
  through the trailer.
- Reassembled hits keep every extent in `report.json` (`extents`, `fragments`), are exported as
  the concatenated logical file, and are reported `Low` confidence with the `Fragmented` flag.
- Chains are capped at eight extents and bounded by `CarveOptions::max_reassembly_gap`; a chain
  that never reaches its terminator drops back to a truncated head.

## [1.3.0] — 2026-10-29

Container breadth and the first reassembly format.

- VHDX containers: file identifier, both headers, region tables with CRC32C, metadata region and
  block allocation table with sector bitmaps; absent blocks read as zeros.
- JPEG fragment reassembly: a head that stops at a discontinuity is joined to the runs where its
  entropy stream resumes, validated to `EOI`.
- `--no-reassemble` (CLI) and `carve::CarveOptions::reassemble` (library, default `false`).

## [1.2.0] — 2026-10-28

- ext4: superblock features and checksum seed, block-group descriptors with CRC32c, inode tables,
  extent trees, inline data, pre-extents indirect fallback; deletion-timestamp pairing and block
  bitmap reuse judgement; feature-mutating volumes refused as `Unsupported`.

## [1.1.0] — 2026-10-27

First frozen, library-first baseline.

- exFAT recovery (allocation bitmap, FAT chains, `NoFatChain`, deleted directory traversal).
- Fixed and dynamic VHD readers with virtual geometry.
- Thirteen carved formats (adds GIF, BMP, TIFF, WAV, SQLite, MP4/QuickTime/M4A/3GPP/HEIF,
  RIFF AVI, MPEG audio, legacy Office CFB).
- `find_package(OpenRecover)` export set; the package itself is audited by `install_layout`.

## [1.0.0] — 2026-10-20

First complete release (milestones M0–M5).

- Read-only `BlockDevice` core with static, fault-injection and syscall enforcement.
- MBR/GPT, FAT32 and NTFS metadata recovery — LFNs, runlists, sparse and fragmented extents,
  hard links, deleted directory chains.
- Structure-aware carving of JPEG, PNG, PDF and ZIP.
- Android ADB bridge without root, allowlisted command policy in C++ and Python sidecars.
- Deterministic `report.json` + `manifest.csv`, `openrecover verify`, Windows physical-drive
  support with the logged `--allow-shared-write-sharing` fallback.
