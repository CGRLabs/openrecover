#!/usr/bin/env python3
"""Wrap the FAT32 test volume in VHDX containers.

A VHDX exposes the same 8 MiB volume as `fat32_basic.img`, so the recovered file set must
be byte-identical to the flat image golden. Three layouts are written:

* `fat32_vhdx_full.img` -- every block fully present (the closest thing VHDX has to a
  fixed disk);
* `fat32_vhdx_sparse.img` -- all-zero blocks stored in the ZERO state and the last block
  that has data stored as PARTIALLY_PRESENT, so the sector-bitmap read path is exercised;
* two small invalid seeds for the fuzz corpus, built by the same code.

The layout follows MS-VHDX: a 64 KiB file identifier, two 4 KiB headers with CRC32c
checksums, two 64 KiB region tables, a BAT of 64-bit entries and a metadata table of
16-byte GUIDs. It is written by hand rather than by Hyper-V so the output is deterministic
and needs no host tooling.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import make_fat32_fixtures as fat32

KIB = 1024
MIB = 1 << 20
HEADER_1 = 64 * KIB
HEADER_2 = 128 * KIB
REGION_1 = 192 * KIB
REGION_2 = 256 * KIB
REGION_BYTES = 64 * KIB
BLOCK_SIZE = 1 * MIB

BAT_REGION_ID = bytes.fromhex("6677c22d23f60042" "9d64115e9bfd4a08")
METADATA_REGION_ID = bytes.fromhex("06a27c8b90479a4b" "b8fe575f050f886e")
FILE_PARAMETERS_ID = bytes.fromhex("3767a1ca36fa434d" "b3b633f0aa44e76b")
VIRTUAL_DISK_SIZE_ID = bytes.fromhex("2442a52f1bcd7648" "b2115dbed83bf4b8")
LOGICAL_SECTOR_ID = bytes.fromhex("1dbf41816fa90947" "ba47f233a8faab5f")
PHYSICAL_SECTOR_ID = bytes.fromhex("c748a3cd5d447144" "9cc9e9885251c556")
PARENT_LOCATOR_ID = bytes.fromhex("2d5fd3a80bb34d45" "abf7d3d84834ab0c")

FULLY_PRESENT = 4
PARTIALLY_PRESENT = 5
ZERO = 2
UNDEFINED = 1
NOT_PRESENT = 0

_PARAMS_AT = 0x100
_SIZE_AT = 0x108
_LOGICAL_AT = 0x110
_PHYSICAL_AT = 0x114


def _make_table() -> tuple[int, ...]:
    poly = 0x82F63B78
    table = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _make_table()


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _put_crc32c(block: bytearray, field: int) -> None:
    struct.pack_into("<I", block, field, 0)
    struct.pack_into("<I", block, field, crc32c(bytes(block)))


def header(sequence: int) -> bytearray:
    out = bytearray(4 * KIB)
    out[0:4] = b"head"
    struct.pack_into("<Q", out, 8, sequence)
    struct.pack_into("<H", out, 64, 0)  # log version
    struct.pack_into("<H", out, 66, 1)  # format version
    _put_crc32c(out, 4)
    return out


def region_table(bat_offset: int, bat_bytes: int, meta_offset: int, meta_bytes: int) -> bytearray:
    out = bytearray(REGION_BYTES)
    out[0:4] = b"regi"
    struct.pack_into("<I", out, 8, 2)
    entries = ((BAT_REGION_ID, bat_offset, bat_bytes), (METADATA_REGION_ID, meta_offset, meta_bytes))
    for index, (guid, offset, length) in enumerate(entries):
        at = 16 + index * 32
        out[at : at + 16] = guid
        struct.pack_into("<Q", out, at + 16, offset)
        struct.pack_into("<I", out, at + 24, length)
        struct.pack_into("<I", out, at + 28, 1)  # required
    _put_crc32c(out, 4)
    return out


def metadata_region(size: int, block_size: int, virtual_bytes: int, logical: int, physical: int,
                    parent: bool = False) -> bytearray:
    out = bytearray(size)
    out[0:8] = b"metadata"
    items = [
        (FILE_PARAMETERS_ID, _PARAMS_AT, 8),
        (VIRTUAL_DISK_SIZE_ID, _SIZE_AT, 8),
        (LOGICAL_SECTOR_ID, _LOGICAL_AT, 4),
        (PHYSICAL_SECTOR_ID, _PHYSICAL_AT, 4),
    ]
    if parent:
        items.append((PARENT_LOCATOR_ID, 0x118, 8))
    struct.pack_into("<H", out, 10, len(items))
    for index, (guid, offset, length) in enumerate(items):
        at = 32 + index * 40
        out[at : at + 16] = guid
        struct.pack_into("<I", out, at + 16, offset)
        struct.pack_into("<I", out, at + 20, length)
        struct.pack_into("<I", out, at + 28, 1)  # virtual disk metadata
        struct.pack_into("<I", out, at + 32, 1)  # required
    struct.pack_into("<I", out, _PARAMS_AT, block_size)
    struct.pack_into("<I", out, _PARAMS_AT + 4, 2 if parent else 0)
    struct.pack_into("<Q", out, _SIZE_AT, virtual_bytes)
    struct.pack_into("<I", out, _LOGICAL_AT, logical)
    struct.pack_into("<I", out, _PHYSICAL_AT, physical)
    return out


def _sector_used(volume: bytes, start: int, end: int) -> bool:
    return any(volume[start:end])


def build_vhdx(volume: bytes, *, block_size: int = BLOCK_SIZE, region_bytes: int = MIB,
               partial_blocks: tuple[int, ...] = (), tight: bool = False,
               parent: bool = False, all_present: bool = False,
               modes: tuple[str, ...] | None = None) -> bytes:
    """Wrap `volume` in a VHDX container.

    Blocks are stored fully present unless they are all zero (then ZERO), or named in
    `partial_blocks` (then PARTIALLY_PRESENT with a bitmap of the sectors that carry data).
    `tight` packs the BAT and metadata regions just past the region tables, which keeps
    the fuzz seeds small; the committed fixture uses the 1 MiB alignment Hyper-V writes.
    """
    sectors = block_size // 512
    blocks = (len(volume) + block_size - 1) // block_size
    if tight:
        bat_offset = REGION_2 + REGION_BYTES
        meta_offset = bat_offset + region_bytes
        payload_start = (meta_offset + region_bytes + MIB - 1) // MIB * MIB
    else:
        bat_offset = MIB
        meta_offset = bat_offset + region_bytes
        payload_start = meta_offset + region_bytes

    chosen: list[str] = []
    for index in range(blocks):
        start = index * block_size
        chunk = volume[start : start + block_size]
        if modes is not None and index < len(modes):
            chosen.append(modes[index])
        elif all_present:
            chosen.append("partial" if index in partial_blocks else "full")
        elif all(byte == 0 for byte in chunk):
            chosen.append("zero")
        elif index in partial_blocks:
            chosen.append("partial")
        else:
            chosen.append("full")

    layout: list[tuple[str, int, int]] = []  # (mode, payload offset, bitmap offset)
    cursor = payload_start
    for mode in chosen:
        if mode == "full":
            layout.append((mode, cursor, 0))
            cursor += block_size
        elif mode == "partial":
            layout.append((mode, cursor + MIB, cursor))
            cursor += MIB + block_size
        else:
            layout.append((mode, 0, 0))

    container = bytearray(cursor)
    container[0:8] = b"vhdxfile"
    container[HEADER_1 : HEADER_1 + 4 * KIB] = header(1)
    container[HEADER_2 : HEADER_2 + 4 * KIB] = header(2)
    table = region_table(bat_offset, region_bytes, meta_offset, region_bytes)
    container[REGION_1 : REGION_1 + REGION_BYTES] = table
    container[REGION_2 : REGION_2 + REGION_BYTES] = table
    container[bat_offset : bat_offset + region_bytes] = bytes(region_bytes)
    container[meta_offset : meta_offset + region_bytes] = metadata_region(
        region_bytes, block_size, len(volume), 512, 512, parent)

    for index, (mode, payload, bitmap) in enumerate(layout):
        start = index * block_size
        chunk = volume[start : start + block_size]
        if mode in ("full", "partial"):
            container[payload : payload + len(chunk)] = chunk
        if mode == "partial":
            bits = 0
            for sector in range(sectors):
                sector_start = start + sector * 512
                if sector_start >= len(volume):
                    break
                sector_end = min(sector_start + 512, len(volume))
                if _sector_used(volume, sector_start, sector_end):
                    bits |= 1 << sector
            container[bitmap : bitmap + (sectors + 7) // 8] = bits.to_bytes((sectors + 7) // 8, "little")
            entry = (payload // MIB) << 20 | PARTIALLY_PRESENT
        elif mode == "full":
            entry = (payload // MIB) << 20 | FULLY_PRESENT
        elif mode == "zero":
            entry = ZERO
        elif mode == "undefined":
            entry = UNDEFINED
        else:
            entry = NOT_PRESENT
        struct.pack_into("<Q", container, bat_offset + index * 8, entry)
    return bytes(container)


def _choose_partial_block(volume: bytes, block_size: int) -> int:
    """The last block with data and at least one empty sector, else the last block with data."""
    sectors = block_size // 512
    best = -1
    for index in range((len(volume) + block_size - 1) // block_size):
        start = index * block_size
        chunk = volume[start : start + block_size]
        used = sum(1 for sector in range(sectors)
                   if _sector_used(chunk, sector * 512, min((sector + 1) * 512, len(chunk))))
        if used == 0:
            continue
        best = index
        if used < sectors:
            return index
    return best


def build_fixtures() -> dict[str, bytes]:
    volume, _files, _hashes = fat32.build_basic()
    partial = _choose_partial_block(volume, BLOCK_SIZE)
    return {
        "fat32_vhdx_full.img": build_vhdx(volume, all_present=True),
        "fat32_vhdx_sparse.img": build_vhdx(volume, partial_blocks=(partial,) if partial >= 0 else ()),
    }


def build_fuzz_seeds() -> dict[str, bytes]:
    """Small containers: a ZERO block needs no payload, so each seed is header-sized."""
    volume = sweep_volume(4096)
    small = dict(region_bytes=4 * KIB, tight=True)

    def seed(modes: tuple[str, ...], **kwargs) -> bytes:
        return build_vhdx(volume, modes=modes, **small, **kwargs)

    zero = build_vhdx(bytes(4096), modes=("zero",), **small)
    return {
        "zero_block.vhdx": zero,
        "undefined_block.vhdx": seed(("undefined",)),
        "not_present_block.vhdx": seed(("notpresent",)),
        "invalid_parent.vhdx": seed(("notpresent",), parent=True),
        "invalid_truncated.vhdx": zero[: REGION_2 + 1024],
    }


def sweep_volume(size: int) -> bytes:
    """A 13-valued alphabet with a run of zeros, matching the C++ sweep seed volume."""
    out = bytearray((index * 31 + 7) % 13 + 1 for index in range(size))
    out[1024:2048] = bytes(1024)
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parents[2]
    parser.add_argument("--images", type=Path, default=repo / "tests/fixtures/images")
    parser.add_argument("--golden", type=Path, default=repo / "tests/fixtures/golden")
    args = parser.parse_args()

    volume, files, hashes = fat32.build_basic()
    fixtures = build_fixtures()
    for name, image in fixtures.items():
        fat32.write_gzip(args.images / (name + ".gz"), image)
        fat32.write_json(
            args.golden / (name[: -len(".img")] + ".golden.json"),
            fat32.golden_document(name, image, files, hashes),
        )
        print(f"  {name}: {len(image)} bytes, sha256 {hashlib.sha256(image).hexdigest()[:16]}")
    print(f"wrote {len(fixtures)} images to {args.images}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
