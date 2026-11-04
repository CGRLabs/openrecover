#!/usr/bin/env python3
"""Wrap the FAT32 test volume in fixed and dynamic VHD containers.

Both containers present the exact same 8 MiB volume as `fat32_basic.img`, so the
recovered file set must be byte-identical to the flat image golden. The dynamic
container additionally leaves every all-zero 1 MiB block unallocated in the block
allocation table, which is what exercises the sparse read path.

Layout follows the Microsoft VHD image format with every integer big-endian:
a footer in the last 512 bytes (plus a leading copy for the dynamic disk), a
`cxsparse` dynamic header, data blocks each preceded by a sector bitmap, and the
block allocation table just before the trailing footer.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import make_fat32_fixtures as fat32

SECTOR = 512
FOOTER_BYTES = 512
HEADER_BYTES = 1024
BLOCK_SIZE = 1 << 20  # 1 MiB, the size Hyper-V and disk2vhd use
FORMAT_VERSION = 0x00010000
TYPE_FIXED = 2
TYPE_DYNAMIC = 3
TYPE_DIFFERENCING = 4
UNALLOCATED = 0xFFFFFFFF
TIMESTAMP = 0x65229A00  # 2023-10-09, fixed so the output is deterministic
UUID = bytes.fromhex("4f524356484400010203040506070809")


def checksum(block: bytearray, checksum_at: int) -> int:
    total = 0
    for index, value in enumerate(block):
        if checksum_at <= index < checksum_at + 4:
            continue
        total += value
    return (~total) & 0xFFFFFFFF


def footer(disk_type: int, current_size: int, data_offset: int) -> bytearray:
    out = bytearray(FOOTER_BYTES)
    out[0:8] = b"conectix"
    struct.pack_into(">I", out, 8, 0)  # features: none
    struct.pack_into(">I", out, 12, FORMAT_VERSION)
    struct.pack_into(">Q", out, 16, data_offset)
    struct.pack_into(">I", out, 24, TIMESTAMP)
    out[28:32] = b"rvry"
    struct.pack_into(">I", out, 32, 0x00010000)
    out[36:40] = b"Wi2k"
    struct.pack_into(">Q", out, 40, current_size)
    struct.pack_into(">Q", out, 48, current_size)
    sectors = current_size // SECTOR
    struct.pack_into(">H", out, 56, min(sectors // (16 * 255), 0xFFFF))
    out[58] = 16
    out[59] = 255
    struct.pack_into(">I", out, 60, disk_type)
    out[68:84] = UUID
    out[84] = 0
    # The checksum covers the finished block, so it has to be written last.
    struct.pack_into(">I", out, 64, checksum(out, 64))
    return out


def dynamic_header(table_offset: int, max_entries: int, block_size: int) -> bytearray:
    out = bytearray(HEADER_BYTES)
    out[0:8] = b"cxsparse"
    struct.pack_into(">Q", out, 8, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">Q", out, 16, table_offset)
    struct.pack_into(">I", out, 24, FORMAT_VERSION)
    struct.pack_into(">I", out, 28, max_entries)
    struct.pack_into(">I", out, 32, block_size)
    out[40:56] = UUID
    struct.pack_into(">I", out, 36, checksum(out, 36))
    return out


def build_fixed(volume: bytes) -> bytes:
    return volume + bytes(footer(TYPE_FIXED, len(volume), 0xFFFFFFFFFFFFFFFF))


def sector_used(volume: bytes, sector: int) -> bool:
    start = sector * SECTOR
    return any(volume[start : start + SECTOR])


def build_dynamic(volume: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Wrap `volume` in a dynamic container, leaving all-zero blocks unallocated.

    `block_size` defaults to the 1 MiB Hyper-V and disk2vhd use; the fuzz seeds pass a
    small one so a whole sparse disk fits in a few kilobytes.
    """
    size = len(volume)
    sectors_per_block = block_size // SECTOR
    bitmap_bytes = ((sectors_per_block + 7) // 8 + SECTOR - 1) // SECTOR * SECTOR
    blocks = (size + block_size - 1) // block_size

    layout = []  # (block index, file offset or None, bitmap bytearray)
    cursor = SECTOR + HEADER_BYTES  # leading footer copy, then the dynamic header
    for index in range(blocks):
        base = index * sectors_per_block
        bits = bytearray(bitmap_bytes)
        used = 0
        for offset in range(sectors_per_block):
            if base + offset >= size // SECTOR:
                break
            if not sector_used(volume, base + offset):
                continue
            bits[offset // 8] |= 1 << (offset % 8)
            used += 1
        if used == 0:
            layout.append((index, None, None))
            continue
        layout.append((index, cursor, bits))
        cursor += bitmap_bytes + block_size

    table_offset = (cursor + SECTOR - 1) // SECTOR * SECTOR
    container = bytearray(table_offset + 4 * blocks + SECTOR + FOOTER_BYTES)
    entries = []
    for index, offset, bits in layout:
        if offset is None:
            entries.append(UNALLOCATED)
            continue
        container[offset : offset + bitmap_bytes] = bits
        start = index * block_size
        container[offset + bitmap_bytes : offset + bitmap_bytes + block_size] = volume[start : start + block_size]
        entries.append(offset)
    for index, value in enumerate(entries):
        struct.pack_into(">I", container, table_offset + 4 * index, value)

    head = dynamic_header(table_offset, blocks, block_size)
    container[SECTOR : SECTOR + HEADER_BYTES] = head
    foot = footer(TYPE_DYNAMIC, size, SECTOR)
    container[0:FOOTER_BYTES] = foot
    tail = len(container) - FOOTER_BYTES
    container[tail : tail + FOOTER_BYTES] = foot
    return bytes(container)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parents[2]
    parser.add_argument("--images", type=Path, default=repo / "tests/fixtures/images")
    parser.add_argument("--golden", type=Path, default=repo / "tests/fixtures/golden")
    args = parser.parse_args()

    volume, files, hashes = fat32.build_basic()
    images = {
        "fat32_vhd_fixed.img": build_fixed(volume),
        "fat32_vhd_dynamic.img": build_dynamic(volume),
    }
    for name, image in images.items():
        fat32.write_gzip(args.images / (name + ".gz"), image)
        fat32.write_json(
            args.golden / (name[: -len(".img")] + ".golden.json"),
            fat32.golden_document(name, image, files, hashes),
        )
        print(f"  {name}: {len(image)} bytes, sha256 {hashlib.sha256(image).hexdigest()[:16]}")

    print(f"wrote {len(images)} images to {args.images}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
