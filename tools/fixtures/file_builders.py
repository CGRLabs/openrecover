#!/usr/bin/env python3
"""Deterministic builders for the small media files embedded in fixtures.

The bytes are intentionally simple but structurally valid for the validators in
libopenrecover/src/carve. All offsets and lengths derive from the builders so
goldens can be computed without running the C++ code.
"""

from __future__ import annotations

import struct
import zlib

JPEG_MARKER_PREFIX = b"\xFF\xD8\xFF"
PNG_MAGIC = b"\x89PNG\r\n\x1A\n"
PDF_MAGIC = b"%PDF-"
ZIP_LOCAL_MAGIC = b"PK\x03\x04"
GIF_MAGIC = b"GIF89a"
BMP_MAGIC = b"BM"


def _jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xFF" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def build_jpeg(*, exif: bool = False, progressive: bool = False, entropy_size: int = 300) -> bytes:
    """Baseline or progressive JPEG with a single scan."""
    out = bytearray(b"\xFF\xD8")
    if exif:
        # Minimal TIFF header after the Exif identifier; the validator only checks the header.
        out += _jpeg_segment(0xE1, b"Exif\x00\x00II*\x00" + b"\x00" * 8)
    else:
        out += _jpeg_segment(
            0xE0, b"JFIF\x00" + bytes([1, 1, 0, 0, 1, 0, 1, 0, 0])
        )

    out += _jpeg_segment(0xDB, b"\x00" + bytes([1] * 64))

    sof_payload = bytearray()
    sof_payload += bytes([8]) + struct.pack(">HH", 240, 320) + bytes([3])
    for component in range(3):
        sof_payload += bytes([component + 1, 0x11, 0])
    out += _jpeg_segment(0xC2 if progressive else 0xC0, bytes(sof_payload))

    dht_payload = bytearray([0x00]) + bytes([1] + [0] * 15) + bytes([0x00])
    out += _jpeg_segment(0xC4, bytes(dht_payload))

    if progressive:
        out += b"\xFF\xFF"  # fill bytes before the scan marker

    sos_payload = bytes([3])
    for component in range(3):
        sos_payload += bytes([component + 1, 0x00])
    sos_payload += bytes([0, 63, 0])
    out += _jpeg_segment(0xDA, sos_payload)

    entropy = bytearray()
    for index in range(entropy_size):
        entropy.append((index * 37 + 11) & 0x7F)
    if progressive:
        # Escaped entropy byte and restart markers must be skipped, not treated as markers.
        entropy[100:100] = b"\xFF\x00\xFF\xD0"
    out += entropy
    out += b"\xFF\xD9"
    return bytes(out)


def jpeg_scan_start(data: bytes) -> int:
    """Offset of the SOS marker in a JPEG produced by build_jpeg."""
    return data.index(b"\xFF\xDA")


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def _zlib_stored(raw: bytes) -> bytes:
    """A zlib stream of uncompressed (stored) blocks, identical on every zlib build."""
    out = bytearray(b"\x78\x01")
    pos = 0
    while True:
        block = raw[pos:pos + 65535]
        final = pos + len(block) == len(raw)
        out.append(0x01 if final else 0x00)
        out += struct.pack("<HH", len(block), (~len(block)) & 0xFFFF)
        out += block
        pos += len(block)
        if final:
            break
    out += struct.pack(">I", zlib.adler32(raw) & 0xFFFFFFFF)
    return bytes(out)


def build_png(kind: str = "rgba") -> bytes:
    """A small PNG: 1x1 RGBA, 2x2 palette, or 4x1 grayscale."""
    out = bytearray(PNG_MAGIC)
    if kind == "rgba":
        out += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        out += _png_chunk(b"IDAT", zlib.compress(b"\x00\x10\x20\x30\x40", 9))
    elif kind == "palette":
        out += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 3, 0, 0, 0))
        out += _png_chunk(b"PLTE", b"\xFF\x00\x00\x00\xFF\x00")
        out += _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x01\x00\x01\x00", 9))
    elif kind == "gray":
        out += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 1, 8, 0, 0, 0, 0))
        out += _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x40\x80\xFF", 9))
    else:
        raise ValueError(f"unknown PNG kind: {kind}")
    out += _png_chunk(b"IEND", b"")
    return bytes(out)


def png_truncated_after_header() -> bytes:
    """Signature and IHDR only; no image data, so it is not a recoverable file."""
    out = bytearray(PNG_MAGIC)
    out += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 6, 0, 0, 0))
    return bytes(out)


def build_png_rgb(*, width: int = 64, height: int = 40, idat_bytes: int = 1024) -> bytes:
    """An RGB PNG whose image data is stored deflate split across several IDAT chunks.

    Stored blocks keep the bytes identical across zlib builds, and the fixed chunk size gives
    a cut inside one IDAT real chunk boundaries to resync onto on either side.
    """
    assert width > 0 and height > 0 and idat_bytes > 0
    raw = bytearray()
    value = 0
    for _ in range(height):
        raw.append(0)
        for _ in range(width * 3):
            raw.append(value & 0xFF)
            value += 1
    out = bytearray(PNG_MAGIC)
    out += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    stream = _zlib_stored(bytes(raw))
    for start in range(0, len(stream), idat_bytes):
        out += _png_chunk(b"IDAT", stream[start:start + idat_bytes])
    out += _png_chunk(b"IEND", b"")
    return bytes(out)


def png_chunks(data: bytes) -> list[dict]:
    """The chunks of a PNG built by this module, in file order."""
    chunks = []
    pos = len(PNG_MAGIC)
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        chunks.append({
            "type": data[pos + 4:pos + 8].decode("ascii"),
            "offset": pos,
            "data_offset": pos + 8,
            "data_length": length,
            "total_length": 12 + length,
        })
        pos += 12 + length
    return chunks


def png_with_bad_idat_crc() -> bytes:
    data = bytearray(build_png("rgba"))
    pos = 8
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = bytes(data[pos + 4 : pos + 8])
        if chunk_type == b"IDAT":
            crc_pos = pos + 8 + length
            data[crc_pos] ^= 0xFF
            return bytes(data)
        pos += 12 + length
    raise AssertionError("PNG builder produced no IDAT chunk")


def _gif_lzw(pixels: list[int], min_code_size: int) -> bytes:
    """GIF LZW with the code width giflib uses (grow after emitting a code)."""
    clear = 1 << min_code_size
    end = clear + 1
    next_code = clear + 2
    code_size = min_code_size + 1
    bit_buffer = 0
    bit_count = 0
    out = bytearray()

    def put(code: int) -> None:
        nonlocal bit_buffer, bit_count, code_size
        bit_buffer |= code << bit_count
        bit_count += code_size
        while bit_count >= 8:
            out.append(bit_buffer & 0xFF)
            bit_buffer >>= 8
            bit_count -= 8
        if next_code >= (1 << code_size) and code_size < 12:
            code_size += 1

    dictionary: dict[tuple[int, int], int] = {}
    put(clear)
    prefix = pixels[0] if pixels else 0
    for suffix in pixels[1:]:
        key = (prefix, suffix)
        if key in dictionary:
            prefix = dictionary[key]
            continue
        put(prefix)
        if next_code < 4096:
            dictionary[key] = next_code
            next_code += 1
        else:
            put(clear)
            dictionary.clear()
            next_code = clear + 2
            code_size = min_code_size + 1
        prefix = suffix
    put(prefix)
    put(end)
    if bit_count:
        out.append(bit_buffer & 0xFF)
    return bytes(out)


def _gif_subblocks(data: bytes) -> bytes:
    out = bytearray()
    for pos in range(0, len(data), 255):
        chunk = data[pos : pos + 255]
        out.append(len(chunk))
        out += chunk
    out.append(0)
    return bytes(out)


def build_gif(*, frames: int = 2, width: int = 4, height: int = 4,
              noise: bool = False) -> bytes:
    """A GIF89a with a two-color global table and one or more LZW images.

    With noise=True the frames carry deterministic pseudo-random four-color pixels,
    whose LZW streams are far larger than a checkerboard's at the same canvas size.
    """
    assert 1 <= frames <= 4
    assert width > 0 and height > 0
    out = bytearray(GIF_MAGIC)
    out += struct.pack("<HH", width, height)
    out += bytes([0x80, 0, 0])  # global color table, two entries
    out += b"\x00\x00\x00\xFF\xFF\xFF"
    for frame in range(frames):
        out += b"\x21\xF9\x04\x00\x00\x00\x00\x00"
        out += b"\x2C" + struct.pack("<HHHH", 0, 0, width, height) + b"\x00"
        if noise:
            state = 0x1234567 * (frame + 1)
            pixels = []
            for _ in range(width * height):
                state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
                pixels.append((state >> 16) & 3)
        else:
            pixels = [(x + y + frame) % 2 for y in range(height) for x in range(width)]
        out += b"\x02" + _gif_subblocks(_gif_lzw(pixels, 2))
    out += b"\x3B"
    return bytes(out)


def gif_blocks(data: bytes) -> list[dict]:
    """Offsets of a GIF's top-level blocks: the introducers the validator walks."""
    blocks = []
    pos = 13
    if data[10] & 0x80:
        pos += 3 * (2 << (data[10] & 7))
    while pos < len(data):
        kind = {0x2C: "image", 0x21: "extension", 0x3B: "trailer"}[data[pos]]
        blocks.append({"offset": pos, "kind": kind})
        introducer = data[pos]
        pos += 1
        if introducer == 0x3B:
            break
        if introducer == 0x2C:
            packed = data[pos + 8]
            pos += 9
            if packed & 0x80:
                pos += 3 * (2 << (packed & 7))
            pos += 1  # minimum code size
            while data[pos]:
                pos += 1 + data[pos]
            pos += 1
        else:
            pos += 1  # label
            while data[pos]:
                pos += 1 + data[pos]
            pos += 1
    return blocks


def gif_without_trailer() -> bytes:
    """A complete first frame without the trailer, a recoverable truncation."""
    return build_gif(frames=1)[:-1]


def build_bmp(*, width: int = 4, height: int = 4) -> bytes:
    """A bottom-up 24-bit BI_RGB bitmap with a BITMAPINFOHEADER."""
    assert width > 0 and height > 0
    stride = ((width * 24 + 31) // 32) * 4
    pixels = bytearray(stride * height)
    for y in range(height):
        for x in range(width):
            pos = y * stride + x * 3
            pixels[pos : pos + 3] = bytes([(x * 40) & 0xFF, (y * 40) & 0xFF, 0x80])
    dib = struct.pack(
        "<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0
    )
    assert len(dib) == 40
    file_size = 14 + len(dib) + len(pixels)
    return b"BM" + struct.pack("<IHHI", file_size, 0, 0, 14 + len(dib)) + dib + bytes(pixels)


def bmp_with_bad_header() -> bytes:
    """A bitmap whose DIB header size is not one of the defined structures."""
    data = bytearray(build_bmp())
    struct.pack_into("<I", data, 14, 41)
    return bytes(data)


SQLITE_MAGIC = b"SQLite format 3\x00"
PAGE_SIZES = tuple(512 << shift for shift in range(8))  # 512 .. 65536


def build_sqlite(*, page_size: int = 4096, pages: int = 2, change_counter: int = 7,
                 version_valid_for: int = 7) -> bytes:
    """A SQLite database of `pages` pages with a complete 100-byte header."""
    assert page_size in PAGE_SIZES, f"unsupported page size {page_size}"
    header = bytearray(100)
    header[0:16] = SQLITE_MAGIC
    # 64 KiB pages are encoded as the value 1.
    struct.pack_into(">H", header, 16, 1 if page_size == 65536 else page_size)
    header[18:24] = bytes([1, 1, 0, 64, 32, 32])
    struct.pack_into(">II", header, 24, change_counter, pages)
    struct.pack_into(">II", header, 32, 0, 0)  # freelist trunk page, freelist count
    struct.pack_into(">II", header, 40, 1, 4)  # schema cookie, schema format number
    struct.pack_into(">I", header, 48, 2000)  # default page cache size
    struct.pack_into(">I", header, 52, 1)  # largest root b-tree page
    struct.pack_into(">III", header, 56, 1, 0, 0)  # encoding, user version, incremental vacuum
    struct.pack_into(">I", header, 68, 0)  # application id
    struct.pack_into(">I", header, 92, version_valid_for)
    struct.pack_into(">I", header, 96, 3040000)  # SQLITE_VERSION_NUMBER

    body = bytearray(page_size * pages)
    body[0:100] = header
    for page in range(1, pages):
        start = page * page_size
        body[start] = 0x0D  # leaf b-tree page
        for offset in range(start + 1, start + page_size):
            body[offset] = (offset * 31 + 7) & 0xFF
    return bytes(body)


def sqlite_with_stale_page_count() -> bytes:
    """The change counter moved past the version-valid-for number, so the page count is stale."""
    return build_sqlite(change_counter=9, version_valid_for=7)


def sqlite_short_header() -> bytes:
    """A candidate too short for the page-count and version-valid-for fields at 28 and 92."""
    return build_sqlite(page_size=512, pages=1)[:96]


def _riff_chunk(cid: bytes, payload: bytes) -> bytes:
    out = bytearray(cid + struct.pack("<I", len(payload)) + payload)
    if len(payload) % 2:
        out.append(0)  # chunks are word aligned
    return bytes(out)


def build_wav(*, samples: int = 64, info_chunk: bool = False,
              declared_riff_size: int | None = None) -> bytes:
    """An 8-bit mono PCM wave; the format chunk can be preceded by an INFO list."""
    out = bytearray(b"RIFF\x00\x00\x00\x00WAVE")
    if info_chunk:
        out += _riff_chunk(b"LIST", b"INFO" + b"OpenRecover")
    out += _riff_chunk(b"fmt ", struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8))
    out += _riff_chunk(b"data", bytes((index * 7) & 0xFF for index in range(samples)))
    size = declared_riff_size if declared_riff_size is not None else len(out) - 8
    struct.pack_into("<I", out, 4, size)
    return bytes(out)


def wav_without_data() -> bytes:
    """A format chunk only; there is no sample payload to recover."""
    out = bytearray(b"RIFF\x00\x00\x00\x00WAVE")
    out += _riff_chunk(b"fmt ", struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8))
    struct.pack_into("<I", out, 4, len(out) - 8)
    return bytes(out)


def build_tiff(*, little: bool = True, slack: int = 0) -> bytes:
    """A baseline TIFF with two inline SHORT entries and an out-of-line description."""
    description = b"OpenRecover seed\x00"
    entries_at = 8 + 2 + 3 * 12
    description_at = entries_at + 4
    if little:
        head = b"II*\x00" + struct.pack("<I", 8)
        order = "<"
        width_value = 8
    else:
        head = b"MM\x00*" + struct.pack(">I", 8)
        order = ">"
        width_value = 8 << 16  # an inline SHORT is left justified in big-endian TIFF

    out = bytearray(head)
    out += struct.pack(order + "H", 3)
    out += struct.pack(order + "HHII", 0x0100, 3, 1, width_value)  # ImageWidth
    out += struct.pack(order + "HHII", 0x011A, 3, 1, width_value)  # RowsPerStrip
    out += struct.pack(order + "HHII", 0x011E, 2, len(description), description_at)
    out += struct.pack(order + "I", 0)  # end of the IFD chain
    assert len(out) == description_at, "IFD layout drifted from the offsets"
    out += description
    out += bytes(slack)
    return bytes(out)


def tiff_with_bad_entry_type() -> bytes:
    """An IFD entry whose field type is not one of the defined ones."""
    data = bytearray(build_tiff())
    struct.pack_into("<H", data, 10 + 2, 99)
    return bytes(data)


def _mp4_box(kind: bytes, payload: bytes) -> bytes:
    assert len(kind) == 4
    return struct.pack(">I", len(payload) + 8) + kind + payload


def _mp4_box64(kind: bytes, payload: bytes) -> bytes:
    """The same box with a 64-bit size, which is how an mdat past 4 GiB is written."""
    assert len(kind) == 4
    return (struct.pack(">I", 1) + kind + struct.pack(">Q", len(payload) + 16) + payload)


def _mp4_ftyp(major: bytes, compatible: tuple[bytes, ...]) -> bytes:
    return _mp4_box(b"ftyp", major + struct.pack(">I", 0x200000) + b"".join(compatible))


def build_mp4(*, major: bytes = b"isom", compatible: tuple[bytes, ...] = (b"isom", b"mp42"),
              moov_bytes: int = 120, mdat_bytes: int = 4096, moov_last: bool = False,
              free_bytes: int = 0, mdat_builder=_mp4_box, trailing: bytes = b"") -> bytes:
    """An ftyp/moov/mdat file whose top-level boxes tile it exactly.

    `moov_last` mirrors what a camera writes: the media data is muxed first and the metadata
    only after it, so the moov sits at the end of the file.
    """
    moov = _mp4_box(b"moov", bytes((index * 11) & 0xFF for index in range(moov_bytes)))
    mdat = mdat_builder(b"mdat", bytes((index * 7) & 0xFF for index in range(mdat_bytes)))
    out = bytearray(_mp4_ftyp(major, compatible))
    if free_bytes:
        out += _mp4_box(b"free", bytes(free_bytes))
    out += mdat if moov_last else moov
    out += moov if moov_last else mdat
    out += trailing
    return bytes(out)


def build_mov() -> bytes:
    return build_mp4(major=b"qt  ", compatible=(), moov_last=True, free_bytes=8)


def build_m4a() -> bytes:
    return build_mp4(major=b"M4A ", compatible=(b"M4A ", b"mp42"), moov_bytes=64, mdat_bytes=1024)


def build_3gp() -> bytes:
    return build_mp4(major=b"3gp5", compatible=(b"3gp4", b"isom"), mdat_builder=_mp4_box64)


def build_heic(*, meta_bytes: int = 96, mdat_bytes: int = 2048) -> bytes:
    """A HEIF image: a meta box describes the items, an mdat holds them."""
    out = bytearray(_mp4_ftyp(b"mif1", (b"mif1", b"heic")))
    out += _mp4_box(b"meta", b"\x00\x00\x00\x00" + bytes((i * 3) & 0xFF for i in range(meta_bytes)))
    out += _mp4_box(b"mdat", bytes((i * 5) & 0xFF for i in range(mdat_bytes)))
    return bytes(out)


def mp4_without_media() -> bytes:
    """A brand header followed by padding; there is no media to recover."""
    out = bytearray(_mp4_ftyp(b"isom", (b"isom", b"mp42")))
    out += _mp4_box(b"free", bytes(24))
    return bytes(out)


def mp4_unknown_brand() -> bytes:
    """A well-formed ftyp whose brands belong to no family this library names."""
    return build_mp4(major=b"WXYZ", compatible=(b"ABCD", b"EFGH"))


def mp4_truncated_mdat(*, declared_mdat: int = 1 << 20) -> bytes:
    """The mdat header claims more media than the bytes the scan can reach."""
    body = bytearray(build_mp4(mdat_bytes=64))
    mdat_at = len(body) - 64 - 8
    struct.pack_into(">I", body, mdat_at, declared_mdat)
    return bytes(body)


def mp4_ftyp_overrun(*, total_bytes: int = 40) -> bytes:
    """A brand header that claims to be longer than the file it opens."""
    body = bytearray(build_mp4(moov_bytes=8, mdat_bytes=8))
    struct.pack_into(">I", body, 0, 512)
    return bytes(body[:total_bytes])


def _avi_list(form: bytes, inner: bytes) -> bytes:
    return _riff_chunk(b"LIST", form + inner)


def _avi_frame_payload(index: int, frame_bytes: int) -> bytes:
    return bytes(((index * 17 + position * 7) & 0xFF for position in range(frame_bytes)))


def build_avi(*, width: int = 64, height: int = 48, frames: int = 4, frame_bytes: int = 96,
              include_frames: bool = True, with_index: bool = True, rec_lists: bool = False,
              declared_riff_size: int | None = None) -> bytes:
    """An AVI with one video stream: an hdrl list, a movi list of frames and an idx1 index.

    `rec_lists` groups the frames into `LIST rec ` chunks, which is what a capture tool writes
    when it records in passes; the frames are the same bytes either way.
    """
    avih = struct.pack("<15I", 33333, 0, 4, 0x10, frames, 0, 0, 1, frame_bytes, width, height,
                       0, 0, 0, 0)
    strf = struct.pack("<IiiHHIIiiII", 40, width, -height, 1, 24, 0, width * height * 3, 0, 0, 0, 0)
    strl = _avi_list(b"strl", _riff_chunk(b"strh", b"vids" + bytes(44)) +
                     _riff_chunk(b"strf", strf))
    hdrl = _avi_list(b"hdrl", _riff_chunk(b"avih", avih) + strl)

    out = bytearray(b"RIFF\x00\x00\x00\x00AVI ")
    out += hdrl
    if include_frames:
        movie = bytearray()
        if rec_lists:
            for start in range(0, frames, 2):
                inner = b"".join(_riff_chunk(b"00dc", _avi_frame_payload(i, frame_bytes))
                                 for i in range(start, min(start + 2, frames)))
                movie += _avi_list(b"rec ", inner)
        else:
            for index in range(frames):
                movie += _riff_chunk(b"00dc", _avi_frame_payload(index, frame_bytes))
        out += _avi_list(b"movi", bytes(movie))
    if with_index:
        out += _riff_chunk(b"idx1", b"".join(
            struct.pack("<4I", 0x10, 0, frame_bytes, 0) for _ in range(frames)))
    size = declared_riff_size if declared_riff_size is not None else len(out) - 8
    struct.pack_into("<I", out, 4, size)
    return bytes(out)


def avi_without_frames() -> bytes:
    """A header list that fills the file; the frames it describes are not here."""
    return build_avi(include_frames=False, with_index=False)


def avi_index_without_frames() -> bytes:
    """An idx1 index that lists frames the file does not carry, as a cut movie list looks."""
    return build_avi(include_frames=False)


def avi_cut_riff_size(*, declared_frames: int = 400_000) -> bytes:
    """A complete header list whose RIFF size reaches past anything the scan can reach."""
    return build_avi(declared_riff_size=declared_frames * 4096)


def avi_oversized_chunk(*, declared_list: int = 1 << 30) -> bytes:
    """A movie list whose chunk size is bigger than any file the format allows."""
    body = bytearray(build_avi(frames=2))
    struct.pack_into("<I", body, _avi_chunk_offset(bytes(body), b"movi") + 4, declared_list)
    return bytes(body)


def _avi_chunk_offset(data: bytes, form: bytes) -> int:
    """The offset of the size field of the top-level LIST carrying `form`."""
    pos = 12
    while pos + 8 <= len(data):
        size = struct.unpack_from("<I", data, pos + 4)[0]
        if data[pos:pos + 4] == b"LIST" and data[pos + 8:pos + 12] == form:
            return pos
        step = 8 + size
        pos += step + (step % 2)
    raise ValueError(f"no top-level LIST {form!r}")


_MP3_BITRATES = {
    1: ([0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
        [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224]),
    2: ([0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]),
    3: ([0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]),
}

_MP3_SAMPLE_RATES = {
    0: [11025, 12000, 8000],
    2: [22050, 24000, 16000],
    3: [44100, 48000, 32000],
}


def _mp3_frame(version: int, layer: int, bitrate_index: int, rate_index: int,
               payload: int) -> bytes:
    """One frame with a header whose declared length is the payload, so a walk tiles the file."""
    second = 0xE0 | (version << 3) | ((4 - layer) << 1)  # protection off: no CRC to count
    third = (bitrate_index << 4) | (rate_index << 2)
    return bytes([0xFF, second, third, 0x40]) + bytes(
        ((position * 7) & 0xFF for position in range(payload)))


def build_mp3(*, frames: int = 24, version: int = 3, layer: int = 3, bitrate_index: int = 8,
              rate_index: int = 0, id3v2: bool = True, id3v1: bool = False,
              title: bytes = b"OpenRecover test recording") -> bytes:
    """MPEG audio built from the tables the validator uses, so a builder that drifts fails.

    `layer` is the numbered layer (III for an .mp3), `version` is the header's two-bit code:
    3 is MPEG 1 and 2 is MPEG 2, whose half-rate tables give half the bytes per frame.
    """
    mpeg1 = version == 3
    bitrate = _MP3_BITRATES[layer][0 if mpeg1 else 1][bitrate_index]
    sample_rate = _MP3_SAMPLE_RATES[version][rate_index]
    # A Layer I frame carries a third of the samples a Layer II or III frame carries, so the
    # constants below are the format's own: 48000 (24000) for Layer I, 144000 (72000) for the rest.
    if layer == 1:
        size = (48000 if mpeg1 else 24000) * bitrate // sample_rate
    else:
        size = (144000 if mpeg1 else 72000) * bitrate // sample_rate
    body = b"".join(_mp3_frame(version, layer, bitrate_index, rate_index, max(size - 4, 0))
                    for _ in range(frames))
    out = bytearray()
    if id3v2:
        tag_frame = (b"TIT2" + struct.pack(">I", len(title) + 1) + bytes(2) + b"\x00" + title)
        size = len(tag_frame)
        out += b"ID3\x03\x00\x00" + bytes([(size >> 21) & 0x7F, (size >> 14) & 0x7F,
                                           (size >> 7) & 0x7F, size & 0x7F])
        out += tag_frame
    out += body
    if id3v1:
        out += (b"TAG" + title[:30].ljust(30, b"\x00") + bytes(30) + bytes(30) +
                b"2026" + bytes(30) + b"\x00")
    return bytes(out)


def mp3_without_tag(*, frames: int = 20) -> bytes:
    """A recording that opens on its first frame header, as an encoder writes without metadata."""
    return build_mp3(frames=frames, id3v2=False)


def mp3_with_trailer() -> bytes:
    """A tagged recording that closes with the 128-byte ID3v1 tag some tools append."""
    return build_mp3(frames=18, id3v1=True)


def mp3_padded_tag(*, padding: int = 512) -> bytes:
    """A tag that stops where its frames do, leaving the padding it promised to the audio."""
    audio = build_mp3(frames=12, id3v2=False)
    title = b"Padded"
    tag_frame = b"TIT2" + struct.pack(">I", len(title) + 1) + bytes(2) + b"\x00" + title
    size = len(tag_frame)
    header = (b"ID3\x04\x00\x00" +
              bytes([(size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F]))
    return header + tag_frame + bytes(padding) + audio


def mp3_mpeg2_layer_ii() -> bytes:
    """MPEG 2 Layer II at 32 kbit/s, the shape an internet radio capture is saved as."""
    return build_mp3(frames=16, version=2, layer=2, bitrate_index=4, rate_index=0)


def mp3_bad_size_field() -> bytes:
    """An ID3v2 tag whose size field is not a synchsafe integer."""
    out = bytearray(build_mp3(frames=8))
    out[6] = 0x80
    return bytes(out)


def mp3_sample_rate_change() -> bytes:
    """Two frames at 44.1 kHz followed by one at 48 kHz: the stream ends, the bytes do not."""
    return (_mp3_frame(3, 3, 8, 0, 413) + _mp3_frame(3, 3, 8, 0, 413) +
            _mp3_frame(3, 3, 8, 1, 380))


def mp3_single_frame() -> bytes:
    """One frame header and nothing that chains from it; not enough to call a recording."""
    return _mp3_frame(3, 3, 8, 0, 413) + bytes(600)


_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_CFB_ENDOFCHAIN = 0xFFFFFFFE
_CFB_FREESECT = 0xFFFFFFFF
_CFB_FATSECT = 0xFFFFFFFD
_CFB_DIFSECT = 0xFFFFFFFC
_CFB_NOSTREAM = 0xFFFFFFFF
_CFB_INLINE_DIFAT = 109


def _cfb_labelled(name: str) -> bytes:
    """A directory name as the format stores it: UTF-16 with its terminator."""
    return name.encode("utf-16-le") + b"\x00\x00"


def _cfb_entry(name: str, obj_type: int, start: int, size: int, *, child: int = _CFB_NOSTREAM,
               left: int = _CFB_NOSTREAM, right: int = _CFB_NOSTREAM, color: int = 1) -> bytes:
    entry = bytearray(128)
    labelled = _cfb_labelled(name)
    entry[0:len(labelled)] = labelled
    struct.pack_into("<H", entry, 0x40, len(labelled))
    entry[0x42] = obj_type
    entry[0x43] = color
    struct.pack_into("<I", entry, 0x44, left)
    struct.pack_into("<I", entry, 0x48, right)
    struct.pack_into("<I", entry, 0x4C, child)
    struct.pack_into("<I", entry, 0x74, start)
    struct.pack_into("<Q", entry, 0x78, size)
    return bytes(entry)


def _cfb_difat_slots(fat_sectors: int, entries_per_sector: int) -> list[list[int]]:
    """The sector ids the map holds inline, then the groups each DIFAT sector carries."""
    inline = list(range(min(fat_sectors, _CFB_INLINE_DIFAT)))
    rest = list(range(_CFB_INLINE_DIFAT, fat_sectors))
    per_sector = entries_per_sector - 2
    groups = [rest[i:i + per_sector] for i in range(0, len(rest), per_sector)]
    return [inline, groups]


def build_cfb(*, streams: tuple[tuple[str, int], ...] = (("WordDocument", 8192),
                                                          ("1Table", 4096)),
              version: int = 3, sector_shift: int = 9, extra_fat_sectors: int = 0,
              root: str = "Root Entry") -> bytes:
    """A compound file whose allocation table describes exactly the sectors it holds.

    Every stream is at least the mini stream cutoff, so nothing lives in the mini stream and the
    container needs no MiniFat sector -- the layout a legacy Word document writes. Streams smaller
    than the cutoff would be chained through the mini stream instead, which this builder avoids so
    that the sector table alone decides where the file ends.
    """
    sector_size = 1 << sector_shift
    entries_per_sector = sector_size // 4

    chain_lengths = [-(-size // sector_size) for (_, size) in streams]
    dir_sectors = -(-((len(streams) + 1) * 128) // sector_size)
    data_sectors = sum(chain_lengths)

    fat_sectors = 1
    while True:
        difat_sectors = (0 if fat_sectors <= _CFB_INLINE_DIFAT else
                         -(-(fat_sectors - _CFB_INLINE_DIFAT) // (entries_per_sector - 2)))
        total = fat_sectors + dir_sectors + data_sectors + difat_sectors
        if total <= fat_sectors * entries_per_sector:
            break
        fat_sectors += 1
    fat_sectors += extra_fat_sectors
    difat_sectors = (0 if fat_sectors <= _CFB_INLINE_DIFAT else
                     -(-(fat_sectors - _CFB_INLINE_DIFAT) // (entries_per_sector - 2)))

    dir_start = fat_sectors
    difat_start = dir_start + dir_sectors
    data_start = difat_start + difat_sectors

    fat = [_CFB_FREESECT] * (fat_sectors * entries_per_sector)
    for index in range(fat_sectors):
        fat[index] = _CFB_FATSECT
    for index in range(dir_sectors):
        at = dir_start + index
        fat[at] = (dir_start + index + 1 if index + 1 < dir_sectors else _CFB_ENDOFCHAIN)
    for index in range(difat_sectors):
        # A DIFAT sector is named by the chain inside the sectors themselves, so its own table
        # entry only says what it is.
        fat[difat_start + index] = _CFB_DIFSECT
    starts = []
    cursor = data_start
    for length in chain_lengths:
        starts.append(cursor)
        for index in range(length):
            at = cursor + index
            fat[at] = (cursor + index + 1 if index + 1 < length else _CFB_ENDOFCHAIN)
        cursor += length
    total_sectors = cursor

    inline, groups = _cfb_difat_slots(fat_sectors, entries_per_sector)
    header = bytearray(512)
    header[0:8] = _CFB_MAGIC
    struct.pack_into("<HHH", header, 0x18, 0x003E, version, 0xFFFE)
    struct.pack_into("<HH", header, 0x1E, sector_shift, 6)
    struct.pack_into("<I", header, 0x28, dir_sectors if version == 4 else 0)
    struct.pack_into("<I", header, 0x2C, fat_sectors)
    struct.pack_into("<I", header, 0x30, dir_start)
    struct.pack_into("<I", header, 0x38, 0x1000)
    struct.pack_into("<I", header, 0x3C, _CFB_ENDOFCHAIN)
    struct.pack_into("<I", header, 0x44, difat_start if difat_sectors else _CFB_ENDOFCHAIN)
    struct.pack_into("<I", header, 0x48, difat_sectors)
    for index, sector in enumerate(inline):
        struct.pack_into("<I", header, 0x4C + index * 4, sector)
    for index in range(len(inline), _CFB_INLINE_DIFAT):
        struct.pack_into("<I", header, 0x4C + index * 4, _CFB_FREESECT)

    entries = [_cfb_entry(root, 5, _CFB_ENDOFCHAIN, 0, child=1 if streams else _CFB_NOSTREAM)]
    for index, (name, size) in enumerate(streams):
        entries.append(_cfb_entry(name, 2, starts[index], size,
                                  right=(index + 2 if index + 1 < len(streams) else _CFB_NOSTREAM)))
    directory = b"".join(entries) + bytes(dir_sectors * sector_size - len(entries) * 128)

    out = bytearray(header)
    for index in range(fat_sectors):
        out += struct.pack("<{}I".format(entries_per_sector),
                           *fat[index * entries_per_sector:(index + 1) * entries_per_sector])
    out += directory
    for index, group in enumerate(groups):
        sector = bytearray()
        for slot in range(entries_per_sector - 2):
            sector += struct.pack("<I", group[slot] if slot < len(group) else _CFB_FREESECT)
        sector += struct.pack("<II", _CFB_ENDOFCHAIN if index + 1 == len(groups) else
                              difat_start + index + 1, difat_sectors)
        out += sector
    cursor = data_start
    for (name, size), length in zip(streams, chain_lengths):
        seed = 3 + len(name)
        payload = bytes(((position * seed) & 0xFF for position in range(size)))
        out += payload + bytes(length * sector_size - size)
        cursor += length
    assert len(out) == 512 + total_sectors * sector_size, "the table and the file disagree"
    return bytes(out)


def _cfb_entry_at(data: bytes, name: str) -> int:
    """The offset of a directory entry, which starts with its own name."""
    at = data.find(_cfb_labelled(name))
    assert at != -1, name
    return at


def _cfb_first_dir_sector(data: bytes) -> int:
    return struct.unpack_from("<I", data, 0x30)[0]


def cfb_word() -> bytes:
    return build_cfb()


def cfb_excel() -> bytes:
    return build_cfb(streams=(("Workbook", 6000), ("_rels", 4096)))


def cfb_powerpoint() -> bytes:
    return build_cfb(streams=(("PowerPoint Document", 9000), ("Current User", 4096)))


def cfb_large_sectors() -> bytes:
    """Version 4 stores four kibibyte sectors, which changes every offset the table describes."""
    return build_cfb(version=4, sector_shift=12)


def cfb_long_table() -> bytes:
    """Enough allocation sectors that the map in the header runs out and a DIFAT chain takes over."""
    return build_cfb(streams=(("WordDocument", 4096),), extra_fat_sectors=110)


def cfb_generic_container() -> bytes:
    """A compound file holding no application stream: a real container, but not an Office document."""
    return build_cfb(streams=(("\x01CompObj", 4096), ("\x05DocumentSummaryInformation", 4096)))


def cfb_without_streams() -> bytes:
    """A header, a table and a root entry; there is no stream in it to recover."""
    return build_cfb(streams=())


def cfb_foreign_byte_order() -> bytes:
    data = bytearray(build_cfb())
    struct.pack_into("<H", data, 0x1C, 0x00FE)
    return bytes(data)


def cfb_bad_sector_shift() -> bytes:
    data = bytearray(build_cfb())
    struct.pack_into("<H", data, 0x1E, 10)
    return bytes(data)


def cfb_entry_points_past_the_end() -> bytes:
    at = _cfb_entry_at(bytes(build_cfb()), "WordDocument")
    data = bytearray(build_cfb())
    struct.pack_into("<I", data, at + 0x74, 0x00FF0000)
    return bytes(data)


def cfb_stream_larger_than_the_file() -> bytes:
    data = bytearray(build_cfb())
    at = _cfb_entry_at(bytes(data), "1Table")
    struct.pack_into("<I", data, at + 0x78, 1 << 31)
    return bytes(data)


def cfb_directory_cycle() -> bytes:
    """The directory sector chains to itself, so a walk over it never ends."""
    data = bytearray(build_cfb())
    directory = _cfb_first_dir_sector(bytes(data))
    struct.pack_into("<I", data, 512 + 4 * directory, directory)
    return bytes(data)


def cfb_table_past_the_end() -> bytes:
    """The map names an allocation sector the table itself cannot reach."""
    data = bytearray(build_cfb())
    struct.pack_into("<I", data, 0x4C, 0x00FF0000)
    return bytes(data)


def _pdf_header(version: str) -> bytes:
    # The binary comment exercises the validator's binary_comment note.
    return f"%PDF-{version}\n".encode("ascii") + b"%\xE2\xE3\xCF\xD3\n"


def _pdf_xref_entry(offset: int, generation: int, in_use: bool) -> bytes:
    line = f"{offset:010d} {generation:05d} {'n' if in_use else 'f'} \n"
    assert len(line) == 20
    return line.encode("ascii")


def build_pdf_classic() -> bytes:
    body = bytearray(_pdf_header("1.7"))
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n",
    ]
    offsets = []
    for obj in objects:
        offsets.append(len(body))
        body += obj
    xref_offset = len(body)
    body += b"xref\n0 4\n"
    body += _pdf_xref_entry(0, 65535, False)
    for offset in offsets:
        body += _pdf_xref_entry(offset, 0, True)
    body += b"trailer\n<< /Size 4 /Root 1 0 R >>\n"
    body += b"startxref\n" + str(xref_offset).encode("ascii") + b"\n%%EOF\n"
    return bytes(body)


def build_pdf_xref_stream() -> bytes:
    body = bytearray(_pdf_header("1.5"))
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n",
    ]
    for obj in objects:
        body += obj
    xref_offset = len(body)
    body += (
        b"3 0 obj\n"
        b"<< /Type /XRef /Size 4 /Root 1 0 R /W [1 2 1] /Length 4 >>\n"
        b"stream\n\x00\x00\x00\x00\nendstream\nendobj\n"
    )
    body += b"startxref\n" + str(xref_offset).encode("ascii") + b"\n%%EOF\n"
    return bytes(body)


def build_pdf_incremental() -> bytes:
    body = bytearray(_pdf_header("1.4"))
    first_object = len(body)
    body += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    second_object = len(body)
    body += b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    xref_one = len(body)
    body += b"xref\n0 3\n"
    body += _pdf_xref_entry(0, 65535, False)
    body += _pdf_xref_entry(first_object, 0, True)
    body += _pdf_xref_entry(second_object, 0, True)
    body += b"trailer\n<< /Size 3 /Root 1 0 R >>\n"
    body += b"startxref\n" + str(xref_one).encode("ascii") + b"\n%%EOF\n"

    updated_object = len(body)
    body += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Lang (en) >>\nendobj\n"
    xref_two = len(body)
    body += b"xref\n0 2\n"
    body += _pdf_xref_entry(0, 65535, False)
    body += _pdf_xref_entry(updated_object, 0, True)
    body += b"trailer\n<< /Size 3 /Root 1 0 R /Prev " + str(xref_one).encode("ascii") + b" >>\n"
    body += b"startxref\n" + str(xref_two).encode("ascii") + b"\n%%EOF\n"
    return bytes(body)


def build_zip(entries: list[tuple[str, bytes]]) -> bytes:
    """A complete archive with one stored entry per (name, payload) pair."""
    out = bytearray()
    central_entries = []
    for name, payload in entries:
        encoded = name.encode("utf-8")
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        local_offset = len(out)
        out += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, crc,
            len(payload), len(payload), len(encoded), 0,
        )
        out += encoded + payload
        central_entries.append((encoded, crc, len(payload), local_offset))

    central_offset = len(out)
    for encoded, crc, size, local_offset in central_entries:
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0, crc,
            size, size, len(encoded), 0, 0, 0, 0, 0, local_offset,
        )
        out += encoded
    central_size = len(out) - central_offset
    out += struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(central_entries), len(central_entries),
        central_size, central_offset, 0,
    )
    return bytes(out)


def zip_payload_offset(archive: bytes) -> int:
    """Payload offset of the first stored entry."""
    name_length = struct.unpack("<H", archive[26:28])[0]
    extra_length = struct.unpack("<H", archive[28:30])[0]
    return 30 + name_length + extra_length


def find_magic_offsets(data: bytes, magic: bytes) -> list[int]:
    offsets = []
    pos = data.find(magic)
    while pos >= 0:
        offsets.append(pos)
        pos = data.find(magic, pos + 1)
    return offsets
