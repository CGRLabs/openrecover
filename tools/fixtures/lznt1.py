#!/usr/bin/env python3
"""A small, deliberate LZNT1 encoder for the NTFS test fixtures.

Windows compresses a non-resident $DATA one compression unit at a time. A unit is
``unit_clusters`` clusters wide and holds ``unit_bytes`` logical bytes; inside a unit the
logical stream is cut into sub-blocks of 4096 bytes, and each sub-block becomes one chunk
that is either a back-reference stream or, when it does not shrink, its bytes verbatim.

A unit whose compressed form is not smaller than the unit is stored raw, and a unit of
nothing but zero bytes is not stored at all; the caller records which of the three cases
each unit is so it can build the runlist Windows builds.

The byte layout follows [MS-XCA] and is pinned by the decoder's own tests: a chunk's
entries are read one flag byte at a time, eight entries per group, each entry a literal
byte or a two-byte back-reference, and the entries run consecutively rather than being
padded to a fixed sixteen data bytes.
"""

from __future__ import annotations

SUB_BLOCK_BYTES = 4096
MAX_CHUNK_COUNT = 0x0FFF
COMPRESSED_FLAG = 0x8000
SIGNATURE = 3
MIN_MATCH = 3
MAX_CANDIDATES = 32


def tuple_split(produced: int) -> tuple[int, int]:
    """Return (offset_shift, length_mask) for a tuple written after `produced` bytes."""
    shift = 12
    mask = 0x0FFF
    probe = produced - 1 if produced else 0
    while probe >= 16:
        shift -= 1
        mask >>= 1
        probe >>= 1
    return shift, mask


def _find_match(data: bytes, index: int, positions: dict, produced: int) -> tuple[int, int] | None:
    """Longest back-reference usable at `index`, as (displacement, length)."""
    shift, mask = tuple_split(produced)
    max_length = mask + MIN_MATCH
    max_displacement = min(produced, 1 << (16 - shift))
    if max_displacement < 1:
        return None

    key = data[index : index + MIN_MATCH]
    if len(key) < MIN_MATCH:
        return None
    best = (0, 0)
    for start in reversed(positions.get(key, ())[-MAX_CANDIDATES:]):
        displacement = index - start
        if displacement > max_displacement:
            continue
        length = MIN_MATCH
        while length < max_length and index + length < len(data) and data[start + length] == data[
            index + length
        ]:
            length += 1
        # A match may read past its own write position, which the decoder replays byte by byte.
        if length > best[1]:
            best = (displacement, length)
        if length == max_length:
            break
    return best if best[1] >= MIN_MATCH else None


def _encode_entries(data: bytes) -> list[tuple]:
    entries: list[tuple] = []
    positions: dict[bytes, list[int]] = {}
    index = 0
    produced = 0
    while index < len(data):
        match = _find_match(data, index, positions, produced)
        if match:
            displacement, length = match
            for start in range(index, index + length - MIN_MATCH + 1):
                key = data[start : start + MIN_MATCH]
                if len(key) == MIN_MATCH:
                    positions.setdefault(key, []).append(start)
            entries.append(("match", displacement, length))
            index += length
            produced += length
        else:
            key = data[index : index + MIN_MATCH]
            if len(key) == MIN_MATCH:
                positions.setdefault(key, []).append(index)
            entries.append(("literal", data[index]))
            index += 1
            produced += 1
    return entries


def _group_bytes(entries: list[tuple]) -> bytes:
    """Pack entries into flag byte plus entry bytes, eight entries per group.

    The produced count the offset/length split depends on is the count within the chunk, so it
    carries across groups instead of restarting at each flag byte.
    """
    out = bytearray()
    produced = 0
    for group_start in range(0, len(entries), 8):
        group = entries[group_start : group_start + 8]
        flags = 0
        body = bytearray()
        for bit, entry in enumerate(group):
            if entry[0] == "match":
                flags |= 1 << bit
                shift, mask = tuple_split(produced)
                displacement, length = entry[1], entry[2]
                assert 1 <= displacement <= (1 << (16 - shift))
                assert MIN_MATCH <= length <= mask + MIN_MATCH
                tuple_value = ((displacement - 1) << shift) | (length - MIN_MATCH)
                body += tuple_value.to_bytes(2, "little")
                produced += length
            else:
                body.append(entry[1])
                produced += 1
        out.append(flags)
        out += body
    return bytes(out)


def _chunk_header(body_bytes: int, compressed: bool) -> bytes:
    count = body_bytes - 1
    assert 0 <= count <= MAX_CHUNK_COUNT
    header = count | (SIGNATURE << 12) | (COMPRESSED_FLAG if compressed else 0)
    return header.to_bytes(2, "little")


def compress_sub_block(data: bytes) -> bytes:
    """One 4096-byte sub-block as a chunk: compressed when it shrinks, verbatim otherwise."""
    body = _group_bytes(_encode_entries(data))
    if len(body) < len(data):
        return _chunk_header(len(body), True) + body
    return _chunk_header(len(data), False) + data


def compress_unit(unit: bytes, unit_bytes: int) -> bytes | None:
    """The compressed form of one full unit, or None if it is not smaller than the unit."""
    if len(unit) != unit_bytes:
        raise ValueError("a compression unit must be a whole unit wide")
    out = bytearray()
    for start in range(0, unit_bytes, SUB_BLOCK_BYTES):
        out += compress_sub_block(unit[start : start + SUB_BLOCK_BYTES])
        if len(out) >= unit_bytes:
            return None
    return bytes(out)


def classify_units(data: bytes, *, cluster_size: int, unit_clusters: int) -> list[tuple[str, bytes]]:
    """Split `data` into compression units and say how each one is stored.

    Returns ("sparse", b"") for an all-zero unit, ("raw", bytes) for a unit stored verbatim
    because compression did not help, and ("compressed", bytes) for a unit that shrank.
    """
    unit_bytes = cluster_size * unit_clusters
    units: list[tuple[str, bytes]] = []
    for start in range(0, max(len(data), 1), unit_bytes):
        unit = data[start : start + unit_bytes].ljust(unit_bytes, b"\x00")
        if not any(unit):
            units.append(("sparse", b""))
            continue
        compressed = compress_unit(unit, unit_bytes)
        used = 0 if compressed is None else (len(compressed) + cluster_size - 1) // cluster_size
        # Needing every cluster is how a reader tells a verbatim unit from a compressed one, so a
        # unit that saves less than a whole cluster is stored uncompressed.
        if compressed is None or used >= unit_clusters:
            units.append(("raw", unit))
        else:
            units.append(("compressed", compressed))
    return units


def decompress_unit(stored: bytes, unit_bytes: int) -> bytes:
    """Reference decoder, used by the builder to prove what it wrote can be read back."""
    out = bytearray()
    position = 0
    while position + 2 <= len(stored) and len(out) < unit_bytes:
        header = int.from_bytes(stored[position : position + 2], "little")
        count = header & MAX_CHUNK_COUNT
        if count == 0:
            break
        chunk_bytes = count + 3
        body = stored[position + 2 : position + chunk_bytes]
        position += chunk_bytes
        if not header & COMPRESSED_FLAG:
            out += body[: count + 1]
            continue
        produced = 0
        index = 0
        while index < len(body):
            flags = body[index]
            index += 1
            for bit in range(8):
                if index >= len(body):
                    break
                if flags & (1 << bit):
                    tuple_value = int.from_bytes(body[index : index + 2], "little")
                    index += 2
                    shift, mask = tuple_split(produced)
                    length = (tuple_value & mask) + MIN_MATCH
                    displacement = (tuple_value >> shift) + 1
                    if displacement > produced:
                        raise ValueError("match reaches before the chunk start")
                    for _ in range(length):
                        out.append(out[len(out) - displacement])
                        produced += 1
                else:
                    out.append(body[index])
                    index += 1
                    produced += 1
    return bytes(out[:unit_bytes])
