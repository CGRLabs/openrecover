# Disk-image fixtures

The gzip images under `tests/fixtures/images/` and the JSON documents under
`tests/fixtures/golden/` are committed and authoritative. CI decompresses the images
into the build tree at configure time and never runs the generators.

`file_builders.py` holds the deterministic JPEG, PNG, PDF, ZIP, GIF and BMP builders
shared by the FAT32, Android and carve generators. All media is produced from fixed
seeds, so rebuilding any fixture on another host yields identical bytes.

## FAT32 (M1)

`make_fat32_fixtures.py` builds the BPB, both FATs, directory entries and cluster
contents directly so the images are reproducible byte-for-byte on every host. The
M1 spec lists `mkfs.fat` + `mtools`; those are unavailable on the Windows
development host and would not guarantee identical images, so the Python builder
is used instead (see `docs/DECISIONS.md`, 2026-10-20).

```sh
python tools/fixtures/make_fat32_fixtures.py
```

Outputs:

| File | Contents |
|---|---|
| `fat32_basic.img.gz` | 8 MiB FAT32 volume with live and deleted files, a deleted directory, and a zero-length file |
| `fat32_reused.img.gz` | 8 MiB FAT32 volume where a live file reuses a deleted file's clusters |
| `fat32_in_mbr.img.gz` | 9 MiB MBR container with the basic volume at 1 MiB |
| `fat32_in_gpt.img.gz` | 9 MiB GPT container with the basic volume at 1 MiB |
| `fat32_basic.golden.json` | Expected recovered-file records plus original-content hashes |
| `fat32_reused.golden.json` | Expected records for the reuse case |

## exFAT (M1)

`make_exfat_fixtures.py` writes the exFAT boot sector, FAT, allocation bitmap,
upcase table and directory entry sets directly so the images are reproducible
byte-for-byte. Entry sets carry valid SetChecksum values and deleted entries are
marked by clearing the InUse bit, matching the on-disk deletion behaviour.

```sh
python tools/fixtures/make_exfat_fixtures.py
```

Outputs (8 MiB):

| File | Contents |
|---|---|
| `exfat_basic.img.gz` | Live files and directories, deleted files recovered through NoFatChain, a surviving FAT chain, a fragmented chain and the lost-chain contiguous fallback, plus a deleted directory with two children |
| `exfat_reused.img.gz` | A deleted file whose clusters the bitmap marks as reallocated, next to a recoverable deleted file |
| `exfat_basic.golden.json` | Expected recovered-file records plus original-content hashes |
| `exfat_reused.golden.json` | Expected records for the reuse case |

## VHD containers (M0/M1)

`make_vhd_fixtures.py` reuses `make_fat32_fixtures.build_basic()` and wraps that exact
8 MiB volume in the two container types the reader supports. Every integer is
big-endian, footers and the dynamic header carry the one-complement checksum the
format requires, and the dynamic disk leaves each all-zero 1 MiB block unallocated in
the block allocation table — so the container is a quarter of the volume's size while
still presenting the same bytes. The goldens therefore match the flat FAT32 golden
apart from the container hash.

```sh
python tools/fixtures/make_vhd_fixtures.py
```

Outputs:

| File | Contents |
|---|---|
| `fat32_vhd_fixed.img.gz` | The FAT32 volume plus a 512-byte fixed footer |
| `fat32_vhd_dynamic.img.gz` | The same volume in a dynamic disk: leading and trailing footers, `cxsparse` header, one allocated block with its sector bitmap, seven unallocated BAT entries |
| `fat32_vhd_fixed.golden.json` | Container hash plus the FAT32 recovered-file records |
| `fat32_vhd_dynamic.golden.json` | The same records for the dynamic container |

## VHDX containers (M0/M1)

`make_vhdx_fixtures.py` wraps the same 8 MiB FAT32 volume in a VHDX. Every integer is
little-endian and every header and table carries its CRC32C. The file identifier, both
4 KiB headers, both region tables, the metadata region (virtual size, 1 MiB block size,
512-byte logical sectors) and the BAT all follow the Microsoft layout. The full container
allocates every block; the sparse one leaves each all-zero 1 MiB block in the `ZERO`
state, so it is half the volume's size while presenting identical bytes. Each block is
written fully present; the unit tests build partially-present blocks with their sector
bitmaps by hand.

```sh
python tools/fixtures/make_vhdx_fixtures.py
```

Outputs:

| File | Contents |
|---|---|
| `fat32_vhdx_full.img.gz` | The FAT32 volume with every block fully present |
| `fat32_vhdx_sparse.img.gz` | The same volume with all-zero blocks in the `ZERO` state |
| `fat32_vhdx_full.golden.json` | Container hash plus the FAT32 recovered-file records |
| `fat32_vhdx_sparse.golden.json` | The same records for the sparse container |

`build_fuzz_seeds()` in the same module writes the five `vhdx` corpus seeds: one block in
the zero, undefined and not-present states, a disk with a parent locator, and a file
truncated inside the second region table. Each is a few kilobytes because the builder
uses a 4 KiB region size and a 4 KiB block.

## NTFS (M2)

`make_ntfs_fixtures.py` builds the boot sector, $MFT records, fixups, attributes,
runlists and $Bitmap directly so the images are reproducible byte-for-byte. The M2
spec lists `mkntfs` + `ntfs-3g`; those are unavailable on the Windows development
host and their output is not stable across versions, so the Python builder is used
instead (see `docs/DECISIONS.md`, 2026-10-20).

```sh
python tools/fixtures/make_ntfs_fixtures.py
```

Outputs (all 16 MiB):

| File | Contents |
|---|---|
| `ntfs_basic.img.gz` | 512-byte sectors / 4 KiB clusters; live and deleted resident/nonresident files, a deleted directory chain, hard links, sparse data, a 255-character name, orphan/stale parents and a reallocated cluster |
| `ntfs_fragmented_mft.img.gz` | 4096 MFT records stored in three non-contiguous runs, with contiguous, resident and fragmented deleted probes |
| `ntfs_compressed.img.gz` | LZNT1 `$DATA` streams: a mixed-unit file (repetitive, incompressible, sparse and verbatim units, plus a short tail unit), an all-hole file, a torn stream, an encrypted file and a plain resident file |
| `ntfs_4k_sector.img.gz` | 4096-byte sectors with 4096-byte MFT records |
| `ntfs_recyclebin.img.gz` | A `$Recycle.Bin` directory holding emptied soft deletes: `$I`/`$R` pairs in format versions 1 and 2, a record that disagrees about the size, an unreadable record, an orphan `$R`, a record without a deletion time and a relative recorded path |
| `ntfs_basic.golden.json` | Expected recovered-file records plus original-content hashes |
| `ntfs_fragmented_mft.golden.json` | Expected records for the fragmented-MFT case |
| `ntfs_compressed.golden.json` | Expected records for the compressed case |
| `ntfs_4k_sector.golden.json` | Expected records for the 4K-sector case |
| `ntfs_recyclebin.golden.json` | Expected records for the recycle-bin case, including the restored paths and deletion times |

The fixture $Bitmap is computed from the builder's allocated-cluster set rather than
from real index structures; directories are encoded as records with $FILE_NAME
attributes only (see `docs/DECISIONS.md`, 2026-10-20).

`tests/fixtures/fuzz/ntfs_record/` holds real MFT records extracted from these images
for the `fuzz_ntfs_record` target and the M2 seed-corpus test.

## ext4 (M1)

`make_ext4_fixtures.py` writes the superblock, group descriptors, block/inode bitmaps,
inode table, directory blocks and extents directly, then computes the CRC32c checksums
the reader verifies: the superblock checksum, every group descriptor, and the inodes of
a volume whose creator OS is Linux. Build with a real `mke2fs` is not used for the same
reason as NTFS -- the output is not stable across versions and the host has no Linux
tooling -- so both fixtures are reproducible byte-for-byte.

```sh
python tools/fixtures/make_ext4_fixtures.py
```

Outputs (all 256 KiB, 1 KiB blocks, two block groups):

| File | Contents |
|---|---|
| `ext4_basic.img.gz` | Live and deleted files, a deleted subdirectory, a file whose blocks were reallocated, inline data, sparse extents, indirect blocks, a deliberately bad inode checksum, an encrypted inode and an unwritten extent |
| `ext4_reused.img.gz` | The same layout after blocks have moved on: deleted inodes whose data now belongs to live files, so the reader has to demote them by bitmap reuse |
| `ext4_basic.golden.json` | Geometry, image SHA-256, expected recovered records (paths, sizes, confidence, flags, note substrings, times), absent paths and live-file content hashes |
| `ext4_reused.golden.json` | The same records for the reused-blocks volume |

`test_ext4_recover` asserts the golden records against the committed images, and
`test_ext4_mutation` applies 600 deterministic single-byte corruptions to
`ext4_basic.img.gz` and checks that every one still opens, scans, and returns either a
report or a typed refusal without ever reading outside the volume.

`tests/fixtures/fuzz/ext4_super/`, `ext4_dir/` and `ext4_inode/` hold superblocks,
directory blocks and inode records taken from these images (plus hand-built broken
variants) for the `fuzz_ext4_super`, `fuzz_ext4_dir` and `fuzz_ext4_inode` targets and
the seed-corpus test.

## Structure-aware carving (M3)

`make_carve_fixtures.py` builds a 16 MiB raw image (no filesystem) with three valid
files per type (JPEG, PNG, PDF, ZIP), six decoys, and one JPEG nested inside a ZIP.
The 12 valid files start on 64 KiB boundaries, the nested JPEG starts on a 512-byte
boundary inside its ZIP entry, and the rest is seeded random fill. The generator
aborts if any signature magic appears outside the intended starts, so a decoy or a
fill collision can never be mistaken for a valid file in a golden.

The unaligned variant is the same image with 17 zero bytes prepended, shifting every
file off the alignment grid. The golden records both images' SHA-256 values, the
expected hits, the nested hit, the decoy offsets, the synthetic allocation geometry
(64 KiB clusters, six clusters marked allocated) and the expected unaligned hits.

```sh
python tools/fixtures/make_carve_fixtures.py
```

Outputs:

| File | Contents |
|---|---|
| `carve_mixed.img.gz` | 16 MiB mixed-media image at sector-aligned offsets |
| `carve_mixed_unaligned.img.gz` | The same media shifted by 17 bytes |
| `carve_mixed.golden.json` | Image hashes, expected hits, nested JPEG, decoys, allocation scope and unaligned hits |
| `carve_fragmented.img.gz` | 1 MiB image: one JPEG cut at 2000 bytes whose tail resumes on the next sector boundary, one JPEG split twice into three pieces, one cut JPEG with no tail |
| `carve_fragmented.golden.json` | The joined hit's two extents and original SHA-256, the chained hit's three extents, and the orphan head that must stay truncated |
| `carve_fragmented_png.img.gz` | 1 MiB image: one PNG cut inside an IDAT chunk, one PNG split twice into three pieces, one cut PNG head followed by a second image |
| `carve_fragmented_png.golden.json` | The joined and chained PNG extents with the SHA-256 of the original chunks, and the orphan head that must stop at its first broken chunk |
| `carve_fragmented_gif.img.gz` | 1 MiB image: one GIF cut on a frame boundary, one GIF cut twice into three pieces, one cut GIF head followed by a second GIF |
| `carve_fragmented_gif.golden.json` | The joined and chained GIF extents with the SHA-256 both share (the cuts sit on block boundaries, so the assembled bytes are the original), and the orphan head that must stay truncated |

`tests/fixtures/images/` intentionally stores these images gzipped (~16.8 MB for
the mixed pair); the build tree holds the expanded images. `carve_mixed*` are the
1.2.0 artifacts: the builder reproduces the layout but not the palette PNG's
compressed bytes on every zlib build, so they are not regenerated (see
`docs/DECISIONS.md`, 2026-10-29).

`tools/fixtures/decompress_gz.py SRC DST` expands every `*.img.gz` and is invoked by
`tests/CMakeLists.txt` during configuration.

## Fuzz corpora (M5)

`make_fuzz_corpus.py` writes the seed corpora under `tests/fixtures/fuzz/<target>/`
for the libFuzzer targets. The signature seeds reuse `file_builders.py`; the FAT32,
runlist and GPT seeds are built in the script so they stay small and deterministic.
The `ntfs_record` corpus is extracted from the NTFS fixtures by the M2 generator, and
the `ext4_super`, `ext4_dir` and `ext4_inode` corpora are cut from volumes built by
`make_ext4_fixtures.py`'s own builder.

Seeds that the validator is expected to reject are named `invalid_*`. The TIFF, WAV, media-file,
AVI, MP3, compound-file and SQLite corpora follow that convention, and `test_sig_tiff`, `test_sig_wav`,
`test_sig_mp4`, `test_sig_avi`, `test_sig_mp3`, `test_sig_cfb` and `test_sig_sqlite` each replay their
corpus through the real validator
(`fuzz_seeds.hpp`), so a builder that drifts away from the format fails on Windows and Linux alike. A family signature
whose subtype comes from the format rather than from its own name -- `sig_mp4` reports `mp4`, `mov`,
`m4a`, `3gp` or `heic` depending on the brand -- passes the accepted subtype set to that replay.

The `sig_avi` corpus opens with a `wave` seed on purpose: both families start at `RIFF`, so the AVI
seeds carry the one input the AVI validator must refuse for the wrong reason, and the MP3 seeds carry
a single-frame stream and a mid-stream sample-rate change for the same reason. The MP3 corpus sizes each
seed from the frame tables rather than from a stored length, so a builder whose frame arithmetic drifts
produces a chain the validator stops short of.

The `sig_cfb` seeds are assembled from a sector table rather than from a length field: `build_cfb`
lays out the allocation sectors, the directory and one chain per stream, then writes the table from
the same arithmetic, so a builder that drifts produces a container whose last sector does not match
the entry that describes it. The corpus carries the two sector sizes (version 3 at 512 bytes, version
4 at 4 KiB), a table long enough to need a DIFAT chain behind the 109 entries in the header, a
container with no application stream, and a header-only file with no table at all.

The `vhd` corpus reuses `make_vhd_fixtures.py`'s container builders with a small block size, so
the Python that writes the 8 MiB FAT32-in-VHD images also writes these seeds. Every valid seed
holds one 4 KiB volume whose byte pattern `test_vhd_device` rebuilds independently and reads
back, which catches a container builder that no longer produces what the format describes.

The `vhdx` corpus comes from `make_vhdx_fixtures.build_fuzz_seeds()`. Its valid seeds carry the
same volume with the block in the zero, undefined and not-present states; `invalid_parent.vhdx`
adds a parent locator and `invalid_truncated.vhdx` is cut inside the second region table, so the
replay in `test_vhdx_device` exercises both the fallback to the first copy and the refusal path.

```sh
python tools/fixtures/make_fuzz_corpus.py
```
