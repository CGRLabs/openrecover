#!/usr/bin/env python3
"""Build the deterministic M3 carve fixtures.

`carve_mixed.img` is a raw 16 MiB image with no filesystem: twelve valid files
(three each of JPEG, PNG, PDF and ZIP), six rejected decoys, one JPEG nested in
a ZIP, and deterministic pseudo-random fill. `carve_mixed_unaligned.img` contains
the same bytes shifted by 17 so only an unaligned scan finds the media.

`carve_fragmented.img` is a separate 1 MiB image holding one JPEG split by a gap
(the head stops at a discontinuity, the tail resumes on the next sector boundary
and ends with EOI), one JPEG split twice into three pieces, and one cut JPEG with
no tail, so the engine's reassembly is tested without perturbing the mixed image.

`carve_fragmented_png.img` is a third 1 MiB image with the same idea for PNG: the
cuts fall inside an IDAT chunk's compressed data, so the head stops at the chunk
that failed its checksum, the tail is found again by a chunk whose CRC proves it,
and a neighbouring PNG's signature stops an orphan head from claiming it.

`carve_fragmented_gif.img` is a fourth 1 MiB image, for GIF: the cuts fall on block
boundaries -- right before a frame's graphic control extension -- so each head is an
intact block run the 0x5A background stops, each tail proves itself on a graphic
control extension plus a frame whose LZW stream decodes to its exact pixel count,
and an orphan head's search runs into the chained GIF's signature and refuses it.

The committed gzip images are authoritative for CI. This builder regenerates the
layout, but `carve_mixed*` is not byte-for-byte reproducible across every zlib
build (the palette PNG's compressed bytes differ), so those two images are the
1.2.0 artifacts and should not be regenerated casually; new fixtures get their
own images.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

import file_builders as media

IMAGE_BYTES = 16 * 1024 * 1024
SLOT_BYTES = 64 * 1024
UNALIGNED_SHIFT = 17
CLUSTER_BYTES = SLOT_BYTES
ANCHOR_OFFSET = SLOT_BYTES
CLUSTER_COUNT = 257  # cluster 2 starts at ANCHOR_OFFSET and reaches the image end

# Every valid media file starts at a 64 KiB boundary so the synthetic allocation
# map below can classify clusters without partial overlaps.
FILE_OFFSETS = [0x010000 + index * SLOT_BYTES for index in range(12)]
DECOY_OFFSETS = [0x0D0000 + index * SLOT_BYTES for index in range(6)]

# Files whose first cluster the synthetic map marks as allocated. One of each type.
SCOPE_ALLOCATED_FILE_INDICES = [1, 4, 7, 10]


def random_fill(length: int, seed: str) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{seed}:{counter}".encode("ascii")).digest()
        counter += 1
    return bytes(out[:length])


# 30-byte local header plus this 482-byte name puts the nested JPEG payload on
# a 512-byte boundary, so the default aligned scan can reach it with --nested.
NESTED_ENTRY_NAME = "nested-directory/" + "n" * (482 - len("nested-directory/") - 4) + ".jpg"
assert len(NESTED_ENTRY_NAME) == 482


def build_media() -> list[dict]:
    nested_jpeg = media.build_jpeg(entropy_size=420)
    return [
        {"name": "jpeg_baseline", "type": "jpeg", "confidence": "high",
         "bytes": media.build_jpeg(entropy_size=300)},
        {"name": "png_rgba", "type": "png", "confidence": "medium",
         "bytes": media.build_png("rgba")},
        {"name": "pdf_classic", "type": "pdf", "confidence": "high",
         "bytes": media.build_pdf_classic()},
        {"name": "zip_with_nested_jpeg", "type": "zip", "confidence": "high",
         "bytes": media.build_zip([(NESTED_ENTRY_NAME, nested_jpeg)])},
        {"name": "jpeg_exif", "type": "jpeg", "confidence": "high",
         "bytes": media.build_jpeg(exif=True, entropy_size=320)},
        {"name": "png_palette", "type": "png", "confidence": "medium",
         "bytes": media.build_png("palette")},
        {"name": "pdf_xref_stream", "type": "pdf", "confidence": "medium",
         "bytes": media.build_pdf_xref_stream()},
        {"name": "zip_stored_text", "type": "zip", "confidence": "high",
         "bytes": media.build_zip([("readme.txt", b"openrecover carve fixture\n" * 12)])},
        {"name": "jpeg_progressive", "type": "jpeg", "confidence": "high",
         "bytes": media.build_jpeg(progressive=True, entropy_size=340)},
        {"name": "png_gray", "type": "png", "confidence": "medium",
         "bytes": media.build_png("gray")},
        {"name": "pdf_incremental", "type": "pdf", "confidence": "high",
         "bytes": media.build_pdf_incremental()},
        {"name": "zip_stored_binary", "type": "zip", "confidence": "high",
         "bytes": media.build_zip([("payload.bin", bytes((i * 29 + 7) & 0xFF for i in range(900)))])},
    ]


def build_decoys() -> list[dict]:
    baseline = media.build_jpeg(entropy_size=300)
    return [
        {"kind": "magic_only_garbage", "type": "jpeg", "offset": DECOY_OFFSETS[0],
         "bytes": b"\xFF\xD8\xFF\xE0\x00\x01" + b"garbage after the magic bytes\n" * 3},
        {"kind": "corrupted_crc", "type": "png", "offset": DECOY_OFFSETS[1],
         "bytes": media.png_with_bad_idat_crc()},
        {"kind": "magic_only_garbage", "type": "pdf", "offset": DECOY_OFFSETS[2],
         "bytes": b"%PDF-1.7\n" + b"garbage that is not a document\n" * 12},
        {"kind": "magic_only_garbage", "type": "zip", "offset": DECOY_OFFSETS[3],
         "bytes": b"PK\x03\x04" + b"\x00" * 4 + b"\x07\x00" + b"\x00" * 20 + b"x"},
        {"kind": "truncated", "type": "jpeg", "offset": DECOY_OFFSETS[4],
         "bytes": baseline[: media.jpeg_scan_start(baseline)]},
        {"kind": "truncated", "type": "png", "offset": DECOY_OFFSETS[5],
         "bytes": media.png_truncated_after_header()},
    ]


def magic_collisions(image: bytes, allowed: set[int]) -> list[str]:
    checks = {
        "jpeg": media.JPEG_MARKER_PREFIX,
        "png": media.PNG_MAGIC,
        "pdf": media.PDF_MAGIC,
        "zip": media.ZIP_LOCAL_MAGIC,
    }
    problems = []
    for kind, magic in checks.items():
        for offset in media.find_magic_offsets(image, magic):
            if offset not in allowed:
                problems.append(f"{kind} magic at {offset:#x}")
    return problems


# ---- fragmented-carve fixture ----
#
# `carve_fragmented.img` is a raw 1 MiB image holding one JPEG whose bytes are split in
# two: the head sits at a sector-aligned offset, junk follows, and the tail resumes at the
# next sector boundary and ends with EOI. A second JPEG is split three ways, so the engine
# has to walk from one cut to the next rather than stopping at the first tail. A third JPEG
# head has no tail at all, so it must stay a truncated hit. The background is a constant
# byte so the fixture says exactly one thing: which runs the engine joins and which it
# leaves alone.

FRAGMENTED_IMAGE_BYTES = 1024 * 1024
FRAGMENTED_HEAD_OFFSET = 0x010000
FRAGMENTED_CUT = 2000
FRAGMENTED_TAIL_OFFSET = (FRAGMENTED_HEAD_OFFSET + FRAGMENTED_CUT + 511) // 512 * 512
CHAINED_HEAD_OFFSET = 0x030000
CHAINED_CUTS = (3000, 6000)
FRAGMENTED_ORPHAN_OFFSET = 0x060000
FRAGMENTED_ORPHAN_CUT = 1500
FRAGMENTED_BACKGROUND = 0x5A


def place_pieces(image: bytearray, data: bytes, cuts: tuple[int, ...], head: int) -> list[dict]:
    """Write `data` split at `cuts`, each piece on a 512-byte boundary, cut-marked."""
    pieces = []
    source = 0
    at = head
    for cut in cuts:
        piece = data[source:cut]
        assert len(piece) > 0
        image[at:at + len(piece)] = piece
        pieces.append({"offset": at, "length": len(piece)})
        # The bytes after a piece are not entropy-coded, which is what marks the cut.
        image[at + len(piece):at + len(piece) + 2] = b"\xFF\x02"
        at = (at + len(piece) + 2 + 511) // 512 * 512
        source = cut
    piece = data[source:]
    assert len(piece) > 0
    image[at:at + len(piece)] = piece
    pieces.append({"offset": at, "length": len(piece)})
    return pieces


def build_fragmented_image(seed: str) -> tuple[bytes, dict]:
    image = bytearray([FRAGMENTED_BACKGROUND] * FRAGMENTED_IMAGE_BYTES)

    jpeg = media.build_jpeg(entropy_size=6000)
    assert FRAGMENTED_CUT < len(jpeg) - 2
    head, tail = jpeg[:FRAGMENTED_CUT], jpeg[FRAGMENTED_CUT:]
    assert FRAGMENTED_TAIL_OFFSET >= FRAGMENTED_HEAD_OFFSET + FRAGMENTED_CUT
    image[FRAGMENTED_HEAD_OFFSET:FRAGMENTED_HEAD_OFFSET + len(head)] = head
    image[FRAGMENTED_HEAD_OFFSET + FRAGMENTED_CUT:FRAGMENTED_HEAD_OFFSET + FRAGMENTED_CUT + 2] = b"\xFF\x02"
    image[FRAGMENTED_TAIL_OFFSET:FRAGMENTED_TAIL_OFFSET + len(tail)] = tail

    chained = media.build_jpeg(entropy_size=9000)
    assert CHAINED_CUTS[-1] < len(chained) - 2
    chain_pieces = place_pieces(image, chained, CHAINED_CUTS, CHAINED_HEAD_OFFSET)
    assert chain_pieces[-1]["offset"] + chain_pieces[-1]["length"] < FRAGMENTED_ORPHAN_OFFSET

    orphan = media.build_jpeg(entropy_size=4000)
    image[FRAGMENTED_ORPHAN_OFFSET:FRAGMENTED_ORPHAN_OFFSET + FRAGMENTED_ORPHAN_CUT] = \
        orphan[:FRAGMENTED_ORPHAN_CUT]
    image[FRAGMENTED_ORPHAN_OFFSET + FRAGMENTED_ORPHAN_CUT:
          FRAGMENTED_ORPHAN_OFFSET + FRAGMENTED_ORPHAN_CUT + 2] = b"\xFF\x02"

    image = bytes(image)
    problems = magic_collisions(
        image, {FRAGMENTED_HEAD_OFFSET, CHAINED_HEAD_OFFSET, FRAGMENTED_ORPHAN_OFFSET}
    )
    if problems:
        raise RuntimeError(f"fragmented fixture magic collisions with seed {seed}: {problems}")

    golden = {
        "image": "carve_fragmented.img",
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "size_bytes": len(image),
        "seed": seed,
        "fragmented": {
            "offset": FRAGMENTED_HEAD_OFFSET,
            "prefix_length": len(head),
            "tail_offset": FRAGMENTED_TAIL_OFFSET,
            "tail_length": len(tail),
            "length": len(jpeg),
            "type": "jpeg",
            "confidence": "low",
            "fragments": 2,
            "sha256": hashlib.sha256(jpeg).hexdigest(),
        },
        "chained": {
            "offset": CHAINED_HEAD_OFFSET,
            "pieces": chain_pieces,
            "length": len(chained),
            "type": "jpeg",
            "confidence": "low",
            "fragments": len(chain_pieces),
            "sha256": hashlib.sha256(chained).hexdigest(),
        },
        "orphan": {
            "offset": FRAGMENTED_ORPHAN_OFFSET,
            "length": FRAGMENTED_ORPHAN_CUT,
            "type": "jpeg",
            "confidence": "low",
            "fragments": 0,
        },
    }
    return image, golden


# ---- fragmented-PNG fixture ----
#
# The cuts fall inside an IDAT chunk's compressed data. The head therefore stops at the first
# chunk whose CRC no longer matches, and the tail is reached by what proves it: a chunk whose
# type, length and CRC all check out, followed by chunks that reach IEND. The orphan head has
# no tail of its own and sits before the chained PNG, so its search runs into that image's
# signature and must refuse it rather than absorb the neighbouring file's chunks.

FRAGMENTED_PNG_IMAGE_BYTES = 1024 * 1024
FRAGMENTED_PNG_JOINED_OFFSET = 0x010000
FRAGMENTED_PNG_ORPHAN_OFFSET = 0x030000
FRAGMENTED_PNG_CHAINED_OFFSET = 0x050000
FRAGMENTED_PNG_BACKGROUND = 0x5A


def align_sector(value: int) -> int:
    return (value + 511) // 512 * 512


def place_png_pieces(image: bytearray, data: bytes, cuts: tuple[int, ...], head: int,
                     chunks: list[dict]) -> list[dict]:
    """Write `data` split at offsets inside chunk data, each piece on a 512-byte boundary.

    The two-byte gap before the next piece breaks the stream so no piece reads as continuous
    with the following one. The head is placed so that the position where its cut chunk says
    it ends stays background: the validator must see a cut, not a boundary it can walk past.
    """
    pieces = []
    source = 0
    at = head
    for cut in cuts:
        piece = data[source:cut]
        assert len(piece) > 0
        image[at:at + len(piece)] = piece
        pieces.append({"offset": at, "length": len(piece)})
        next_at = align_sector(at + len(piece) + 2)
        if len(pieces) == 1:
            following = next(c["offset"] for c in chunks if c["offset"] > cut)
            declared_end = at + (following - source)
            if declared_end >= next_at:
                next_at = align_sector(declared_end + 1)
        at = next_at
        source = cut
    piece = data[source:]
    assert len(piece) > 0
    image[at:at + len(piece)] = piece
    pieces.append({"offset": at, "length": len(piece)})
    return pieces


def build_fragmented_png_image(seed: str) -> tuple[bytes, dict]:
    image = bytearray([FRAGMENTED_PNG_BACKGROUND] * FRAGMENTED_PNG_IMAGE_BYTES)
    png = media.build_png_rgb()
    chunks = media.png_chunks(png)
    idats = [chunk for chunk in chunks if chunk["type"] == "IDAT"]
    assert len(idats) >= 7, "the PNG needs enough IDAT chunks for two cuts"

    def cut_at(chunk: dict) -> int:
        return chunk["data_offset"] + chunk["data_length"] // 2

    # One cut in IDAT #3: the joined image.
    joined_cut = cut_at(idats[3])
    joined_pieces = place_png_pieces(image, png, (joined_cut,), FRAGMENTED_PNG_JOINED_OFFSET,
                                     chunks)
    joined_head, joined_tail_piece = joined_pieces[0], joined_pieces[1]
    joined_tail_start = joined_tail_piece["offset"] + (idats[4]["offset"] - joined_cut)
    joined = {
        "offset": FRAGMENTED_PNG_JOINED_OFFSET,
        "prefix_length": idats[3]["offset"],
        "tail_offset": joined_tail_start,
        "tail_length": len(png) - idats[4]["offset"],
        "length": idats[3]["offset"] + len(png) - idats[4]["offset"],
        "type": "png",
        "confidence": "low",
        "fragments": 2,
        "sha256": hashlib.sha256(png[:idats[3]["offset"]] + png[idats[4]["offset"]:]).hexdigest(),
    }
    assert joined_head["length"] == joined_cut
    assert joined["tail_offset"] < FRAGMENTED_PNG_ORPHAN_OFFSET

    # An orphan cut in IDAT #2, with no tail: it must stay a truncated hit.
    orphan_cut = cut_at(idats[2])
    image[FRAGMENTED_PNG_ORPHAN_OFFSET:FRAGMENTED_PNG_ORPHAN_OFFSET + orphan_cut] = \
        png[:orphan_cut]
    orphan = {
        "offset": FRAGMENTED_PNG_ORPHAN_OFFSET,
        "length": idats[2]["offset"],
        "type": "png",
        "confidence": "low",
        "fragments": 0,
    }

    # Two cuts, in IDAT #1 and IDAT #5: the chained image.
    cut_one, cut_two = cut_at(idats[1]), cut_at(idats[5])
    chained_pieces = place_png_pieces(image, png, (cut_one, cut_two),
                                      FRAGMENTED_PNG_CHAINED_OFFSET, chunks)
    first_tail = chained_pieces[1]["offset"] + (idats[2]["offset"] - cut_one)
    second_tail = chained_pieces[2]["offset"] + (idats[6]["offset"] - cut_two)
    pieces = [
        {"offset": FRAGMENTED_PNG_CHAINED_OFFSET, "length": idats[1]["offset"]},
        {"offset": first_tail, "length": idats[5]["offset"] - idats[2]["offset"]},
        {"offset": second_tail, "length": len(png) - idats[6]["offset"]},
    ]
    chained = {
        "offset": FRAGMENTED_PNG_CHAINED_OFFSET,
        "pieces": pieces,
        "length": sum(piece["length"] for piece in pieces),
        "type": "png",
        "confidence": "low",
        "fragments": len(pieces),
        "sha256": hashlib.sha256(png[:idats[1]["offset"]] + png[idats[2]["offset"]:
                                                                 idats[5]["offset"]] +
                                 png[idats[6]["offset"]:]).hexdigest(),
    }
    assert pieces[1]["offset"] < pieces[2]["offset"]
    assert pieces[2]["offset"] + pieces[2]["length"] <= FRAGMENTED_PNG_IMAGE_BYTES

    image = bytes(image)
    problems = magic_collisions(
        image,
        {FRAGMENTED_PNG_JOINED_OFFSET, FRAGMENTED_PNG_ORPHAN_OFFSET,
         FRAGMENTED_PNG_CHAINED_OFFSET},
    )
    if problems:
        raise RuntimeError(f"fragmented PNG fixture magic collisions with seed {seed}: {problems}")

    golden = {
        "image": "carve_fragmented_png.img",
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "size_bytes": len(image),
        "seed": seed,
        "joined": joined,
        "chained": chained,
        "orphan": orphan,
    }
    return image, golden


# ---- fragmented-GIF fixture ----
#
# GIF carries no checksums, so a tail proves itself only by structure: the cuts fall on
# block boundaries -- right before a frame's graphic control extension -- so each head is
# an intact block run that the 0x5A background's introducer stops, and each tail opens on
# a graphic control extension followed by a frame whose LZW stream decodes to its exact
# pixel count. The orphan head sits before the chained GIF, so its continuation search
# runs into that image's signature and must refuse it rather than absorb its frames.

FRAGMENTED_GIF_IMAGE_BYTES = 1024 * 1024
FRAGMENTED_GIF_JOINED_OFFSET = 0x010000
FRAGMENTED_GIF_ORPHAN_OFFSET = 0x030000
FRAGMENTED_GIF_CHAINED_OFFSET = 0x050000
FRAGMENTED_GIF_BACKGROUND = 0x5A


def place_gif_pieces(image: bytearray, data: bytes, cuts: tuple[int, ...],
                     head: int) -> list[dict]:
    """Write `data` split at block-boundary cuts, each piece on a 512-byte boundary."""
    pieces = []
    source = 0
    at = head
    for cut in cuts:
        piece = data[source:cut]
        assert len(piece) > 0
        image[at:at + len(piece)] = piece
        pieces.append({"offset": at, "length": len(piece)})
        at = align_sector(at + len(piece) + 2)
        source = cut
    piece = data[source:]
    assert len(piece) > 0
    image[at:at + len(piece)] = piece
    pieces.append({"offset": at, "length": len(piece)})
    return pieces


def build_fragmented_gif_image(seed: str) -> tuple[bytes, dict]:
    image = bytearray([FRAGMENTED_GIF_BACKGROUND] * FRAGMENTED_GIF_IMAGE_BYTES)
    gif = media.build_gif(frames=3, width=64, height=64, noise=True)
    blocks = media.gif_blocks(gif)
    assert len(blocks) == 7, "the GIF needs three graphic-control-plus-image pairs"
    gce1 = blocks[2]["offset"]
    gce2 = blocks[4]["offset"]
    # The chained walk pushes the middle piece only when it clears the alignment floor.
    assert gce2 - gce1 >= 512, "the middle frame must span more than one sector"

    # One cut before the second frame: the joined image, byte-identical when assembled.
    joined_pieces = place_gif_pieces(image, gif, (gce1,), FRAGMENTED_GIF_JOINED_OFFSET)
    joined = {
        "offset": FRAGMENTED_GIF_JOINED_OFFSET,
        "prefix_length": gce1,
        "tail_offset": joined_pieces[1]["offset"],
        "tail_length": joined_pieces[1]["length"],
        "length": len(gif),
        "type": "gif",
        "confidence": "low",
        "fragments": 2,
        "sha256": hashlib.sha256(gif).hexdigest(),
    }
    assert joined_pieces[1]["offset"] + joined_pieces[1]["length"] < FRAGMENTED_GIF_ORPHAN_OFFSET

    # An orphan cut before the second frame, with no tail: it must stay a truncated hit.
    image[FRAGMENTED_GIF_ORPHAN_OFFSET:FRAGMENTED_GIF_ORPHAN_OFFSET + gce1] = gif[:gce1]
    orphan = {
        "offset": FRAGMENTED_GIF_ORPHAN_OFFSET,
        "length": gce1,
        "type": "gif",
        "confidence": "low",
        "fragments": 0,
    }

    # Two cuts, before the second and third frames: the chained image.
    chained_pieces = place_gif_pieces(image, gif, (gce1, gce2),
                                      FRAGMENTED_GIF_CHAINED_OFFSET)
    chained = {
        "offset": FRAGMENTED_GIF_CHAINED_OFFSET,
        "pieces": chained_pieces,
        "length": len(gif),
        "type": "gif",
        "confidence": "low",
        "fragments": len(chained_pieces),
        "sha256": hashlib.sha256(gif).hexdigest(),
    }
    assert chained_pieces[-1]["offset"] + chained_pieces[-1]["length"] <= FRAGMENTED_GIF_IMAGE_BYTES

    image = bytes(image)
    problems = magic_collisions(
        image,
        {FRAGMENTED_GIF_JOINED_OFFSET, FRAGMENTED_GIF_ORPHAN_OFFSET,
         FRAGMENTED_GIF_CHAINED_OFFSET},
    )
    if problems:
        raise RuntimeError(f"fragmented GIF fixture magic collisions with seed {seed}: {problems}")

    golden = {
        "image": "carve_fragmented_gif.img",
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "size_bytes": len(image),
        "seed": seed,
        "joined": joined,
        "chained": chained,
        "orphan": orphan,
    }
    return image, golden


def build_image(seed: str) -> tuple[bytes, list[dict], dict, dict]:
    files = build_media()
    decoys = build_decoys()
    placements = []
    for offset, entry in zip(FILE_OFFSETS, files):
        placements.append({**entry, "offset": offset})
    nested = None
    for offset, decoy in zip(DECOY_OFFSETS, decoys):
        placements.append({**decoy, "offset": offset})

    nested_jpeg_offset = FILE_OFFSETS[3] + media.zip_payload_offset(placements[3]["bytes"])
    assert nested_jpeg_offset % 512 == 0
    nested_jpeg = placements[3]["bytes"][
        nested_jpeg_offset - FILE_OFFSETS[3] :
        nested_jpeg_offset - FILE_OFFSETS[3] + len(media.build_jpeg(entropy_size=420))
    ]

    for salt in range(16):
        image = bytearray(random_fill(IMAGE_BYTES, f"{seed}:{salt}"))
        for replacement in placements:
            start = replacement["offset"]
            data = replacement["bytes"]
            assert start + len(data) <= start + SLOT_BYTES
            image[start : start + len(data)] = data
        allowed = {replacement["offset"] for replacement in placements}
        allowed.add(nested_jpeg_offset)
        if not magic_collisions(bytes(image), allowed):
            break
    else:
        raise RuntimeError("random fill kept colliding with signature magics")

    image = bytes(image)
    hits = []
    for replacement in placements[: len(files)]:
        hits.append(
            {
                "offset": replacement["offset"],
                "length": len(replacement["bytes"]),
                "type": replacement["type"],
                "confidence": replacement["confidence"],
            }
        )
    hits.sort(key=lambda hit: hit["offset"])
    nested = {
        "container_offset": FILE_OFFSETS[3],
        "offset": nested_jpeg_offset,
        "length": len(nested_jpeg),
        "type": "jpeg",
        "confidence": "high",
    }
    decoy_records = [
        {
            "offset": decoy["offset"],
            "length": len(decoy["bytes"]),
            "kind": decoy["kind"],
            "type": decoy["type"],
        }
        for decoy in placements[len(files) :]
    ]
    return image, hits, nested, decoy_records


def unaligned_image(image: bytes) -> bytes:
    shifted = bytearray(len(image) + UNALIGNED_SHIFT)
    shifted[UNALIGNED_SHIFT:] = image
    return bytes(shifted)


def write_gzip(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            gz.write(data)


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parents[2]
    parser.add_argument("--images", type=Path, default=repo / "tests/fixtures/images")
    parser.add_argument("--golden", type=Path, default=repo / "tests/fixtures/golden")
    parser.add_argument("--seed", default="openrecover-carve-mixed-v1")
    parser.add_argument(
        "--force",
        action="store_true",
        help="rewrite the committed carve_mixed* images (not byte-for-byte reproducible)",
    )
    args = parser.parse_args()

    image, hits, nested, decoys = build_image(args.seed)
    shifted = unaligned_image(image)
    assert len(image) == IMAGE_BYTES

    excluded_offsets = [FILE_OFFSETS[index] for index in SCOPE_ALLOCATED_FILE_INDICES]
    allocated_clusters = [2 + index for index in SCOPE_ALLOCATED_FILE_INDICES]

    unaligned_hits = [
        {**hit, "offset": hit["offset"] + UNALIGNED_SHIFT} for hit in hits
    ]

    golden = {
        "image": "carve_mixed.img",
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "size_bytes": len(image),
        "seed": args.seed,
        "hits": hits,
        "nested": nested,
        "decoys": decoys,
        "scope": {
            "cluster_size": CLUSTER_BYTES,
            "anchor_offset": ANCHOR_OFFSET,
            "cluster_count": CLUSTER_COUNT,
            "allocated_clusters": allocated_clusters,
            "excluded_offsets": excluded_offsets,
        },
        "unaligned_image": "carve_mixed_unaligned.img",
        "unaligned_image_sha256": hashlib.sha256(shifted).hexdigest(),
        "unaligned_shift": UNALIGNED_SHIFT,
        "unaligned_hits": unaligned_hits,
    }

    if args.force or not (args.images / "carve_mixed.img.gz").exists():
        write_gzip(args.images / "carve_mixed.img.gz", image)
        write_gzip(args.images / "carve_mixed_unaligned.img.gz", shifted)
        write_json(args.golden / "carve_mixed.golden.json", golden)
        print(f"wrote carve_mixed.img ({len(image)} bytes) and its unaligned variant")
        print(f"valid hits: {len(hits)}, decoys: {len(decoys)}, nested JPEG at {nested['offset']}")
    else:
        print("kept the committed carve_mixed* images: this builder is not byte-for-byte "
              "reproducible across zlib builds (docs/DECISIONS.md, 2026-10-29); pass --force "
              "to rewrite them")

    fragmented, fragmented_golden = build_fragmented_image(f"{args.seed}:fragmented")
    write_gzip(args.images / "carve_fragmented.img.gz", fragmented)
    write_json(args.golden / "carve_fragmented.golden.json", fragmented_golden)
    print(f"wrote carve_fragmented.img ({len(fragmented)} bytes) and its golden")

    fragmented_png, fragmented_png_golden = build_fragmented_png_image(
        f"{args.seed}:fragmented-png")
    write_gzip(args.images / "carve_fragmented_png.img.gz", fragmented_png)
    write_json(args.golden / "carve_fragmented_png.golden.json", fragmented_png_golden)
    print(f"wrote carve_fragmented_png.img ({len(fragmented_png)} bytes) and its golden")

    fragmented_gif, fragmented_gif_golden = build_fragmented_gif_image(
        f"{args.seed}:fragmented-gif")
    write_gzip(args.images / "carve_fragmented_gif.img.gz", fragmented_gif)
    write_json(args.golden / "carve_fragmented_gif.golden.json", fragmented_gif_golden)
    print(f"wrote carve_fragmented_gif.img ({len(fragmented_gif)} bytes) and its golden")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
