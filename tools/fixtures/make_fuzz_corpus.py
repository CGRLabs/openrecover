#!/usr/bin/env python3
"""Writes the seed corpora consumed by the libFuzzer targets in fuzz/.

Seeds are small, deterministic and committed under tests/fixtures/fuzz/. Re-run this
script after changing a parser or a fixture builder, but keep the committed
`sig_png/palette.png`: like the `carve_mixed*` images, its compressed bytes depend on the
zlib build and a rewrite churns a seed that did not change.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import file_builders as fb
import lznt1
import make_ext4_fixtures as ext4
import make_ntfs_fixtures as ntfs
import make_vhd_fixtures as vhd
import make_vhdx_fixtures as vhdx

SWEEP_ALPHABET = 13


def sweep_volume(size: int) -> bytes:
    """A 13-valued pattern, so a byte a parser invented stands out from the container's own.

    The C++ VHD tests rebuild this exact volume, which keeps the Python builders and the
    hand-written C++ fixtures honest about the same container layout.
    """
    return bytes((i * 31 + 7) % SWEEP_ALPHABET + 1 for i in range(size))


def hole_in(volume: bytes, start: int, end: int) -> bytes:
    out = bytearray(volume)
    out[start:end] = bytes(end - start)
    return bytes(out)


def fat_checksum(name: bytes) -> int:
    value = 0
    for byte in name:
        value = (((value & 1) << 7) + (value >> 1) + byte) & 0xFF
    return value


def fat_short_entry(name: str, *, deleted: bool = False, size: int = 6,
                    cluster: int = 2) -> bytes:
    raw_name = name.encode("ascii")
    assert len(raw_name) == 11
    out = bytearray(32)
    out[0:11] = raw_name
    if deleted:
        out[0] = 0xE5
    out[11] = 0x20  # archive
    out[26] = cluster & 0xFF
    out[27] = (cluster >> 8) & 0xFF
    out[28:32] = struct.pack("<I", size)
    return bytes(out)


def fat_lfn_entry(ordinal: int, checksum: int, units: str) -> bytes:
    out = bytearray(32)
    out[0] = ordinal
    encoded = units.encode("utf-16-le")[:26].ljust(26, b"\x00")
    out[1:27] = encoded
    out[11] = 0x0F
    out[13] = checksum
    return bytes(out)


def make_fat32_boot() -> dict[str, bytes]:
    total_sectors = 65536
    sector = bytearray(512)
    sector[0:3] = b"\xEB\x58\x90"
    sector[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", sector, 0x0B, 512)
    sector[0x0D] = 1
    struct.pack_into("<H", sector, 0x0E, 32)
    sector[0x10] = 2
    struct.pack_into("<I", sector, 0x20, total_sectors)
    struct.pack_into("<I", sector, 0x24, 512)
    struct.pack_into("<I", sector, 0x2C, 2)
    struct.pack_into("<H", sector, 0x30, 1)
    struct.pack_into("<H", sector, 0x1FE, 0xAA55)
    corrupt = bytearray(sector)
    struct.pack_into("<H", corrupt, 0x1FE, 0x0000)
    return {
        "fat32_valid_bpb.bin": bytes(sector),
        "fat32_bad_signature.bin": bytes(corrupt),
    }


def make_fat32_dir() -> dict[str, bytes]:
    short = fat_short_entry("LONGFI~1TXT")
    checksum = fat_checksum(short[0:11])
    lfn = fat_lfn_entry(0x41, checksum, "long file.txt")
    deleted_short = fat_short_entry("DELETED TXT", deleted=True, size=321)
    deleted_checksum = fat_checksum(b"\xE5" + deleted_short[1:11])
    deleted_lfn = fat_lfn_entry(0x41, deleted_checksum, "deleted name.txt")
    plain = fat_short_entry("PLAIN   TXT")
    return {
        "lfn_and_short.bin": lfn + short,
        "deleted_lfn.bin": deleted_lfn + deleted_short,
        "plain_short.bin": plain,
    }


def make_ntfs_runlist() -> dict[str, bytes]:
    header = struct.pack("<QQ", 4096, 0)
    return {
        "contiguous.bin": header + b"\x21\x08\x01\x00",
        "two_runs.bin": header + b"\x21\x04\x01\x11\x04\x20\x00",
        "sparse.bin": header + b"\x21\x04\x01\x01\x04\x00",
    }


def make_lznt1() -> dict[str, bytes]:
    """[MS-XCA]'s own worked example, plus the unit shapes the NTFS fixture writes."""
    msxca = bytes.fromhex(
        "38b08846232000204720410010a24701a045204400084501"
        "507900c045200524138805b4024a44ef0358028c09160148"
        "4500be009e000401189000"
    )
    raw = b"hello world abcde"
    units = lznt1.classify_units(
        ntfs.mixed_compressed_bytes(),
        cluster_size=ntfs.BYTES_PER_CLUSTER,
        unit_clusters=ntfs.UNIT_CLUSTERS,
    )
    shapes = b"".join(payload for kind, payload in units if kind == "compressed")
    return {
        "msxca_example.bin": msxca,
        "raw_chunk.bin": struct.pack("<H", len(raw) - 1) + raw,
        "compressed_units.bin": shapes,
        "compressed_units_half.bin": shapes[: len(shapes) // 2],
        "compressed_units_cut_header.bin": shapes[:-3],
    }


def make_recycle_info() -> dict[str, bytes]:
    """The $I shapes the recycle-bin fixture writes, and the ways such a record breaks."""
    # The record builders take Unix seconds and write the FILETIME themselves.
    deleted = ntfs.DELETED_AT
    versioned = bytearray(ntfs.recycle_info_v2(r"C:\Users\bob\Documents\notes.txt", 5000, deleted))
    versioned[0] = 3
    return {
        "version2_path.bin": bytes(
            ntfs.recycle_info_v2(r"C:\Users\bob\Documents\notes.txt", 5000, deleted)),
        "version1_padded.bin": bytes(
            ntfs.recycle_info_v1(r"C:\Users\bob\Pictures\photo.jpg", 300, deleted)),
        "version2_relative.bin": bytes(
            ntfs.recycle_info_v2(r"..\..\Windows\System32\evil.dll", 512, deleted)),
        "version2_unicode.bin": bytes(
            ntfs.recycle_info_v2("C:\\Users\\bob\\Docs\\настройки.cfg", 42, deleted)),
        "version2_undated.bin": bytes(ntfs.recycle_info_v2(r"C:\dir\a.txt", 10, 0)),
        "header_only.bin": bytes(ntfs.recycle_info_v2(r"C:\dir\a.txt", 10, deleted))[:24],
        "path_without_terminator.bin": bytes(
            ntfs.recycle_info_v2(r"C:\dir\a.txt", 10, deleted))[:-2],
        "path_runs_off.bin": bytes(ntfs.recycle_info_unreadable(r"C:\dir\b.txt", 10, deleted)),
        "unknown_version.bin": bytes(versioned),
    }


def _chained_jpeg() -> bytes:
    """A JPEG whose scan is interrupted twice, so the walk has to resume past each cut."""
    jpeg = bytearray(fb.build_jpeg(entropy_size=1024))
    scan = fb.jpeg_scan_start(bytes(jpeg))
    for offset, cut in ((scan + 700, b"\xFF\x02"), (scan + 1000, b"\xFF\xDA\x00\x02")):
        jpeg[offset:offset] = cut
    return bytes(jpeg)


def _split_png(*, tail: bool) -> bytes:
    """A PNG cut inside an IDAT chunk's data, followed by junk.

    With `tail` the surviving chunk run from the next boundary is appended, so replay reaches
    a complete continuation; without it the walk has to refuse the junk on its own. The junk
    runs past where the cut chunk says it ends, or the validator would see a live chunk
    boundary there and reject the file whole instead of reporting a cut.
    """
    png = fb.build_png_rgb()
    chunks = fb.png_chunks(png)
    idat = next(chunk for chunk in chunks if chunk["type"] == "IDAT")
    cut = idat["data_offset"] + idat["data_length"] // 2
    following = next(chunk["offset"] for chunk in chunks if chunk["offset"] > cut)
    out = bytearray(png[:cut]) + bytes([0x5A]) * 1024
    if tail:
        out += png[following:]
    return bytes(out)


def _split_gif(*, tail: bool) -> bytes:
    """A GIF cut on the block boundary before a frame, followed by junk.

    With `tail` the surviving frames from the cut are appended after the junk, so replay
    reaches a complete continuation; without it the walk has to refuse the junk on its own.
    The 0x5A fill cannot open a block, so the validator stops at the cut and reports the
    head as the file's surviving prefix.
    """
    gif = fb.build_gif(frames=3, width=64, height=64, noise=True)
    cut = fb.gif_blocks(gif)[2]["offset"]
    out = bytearray(gif[:cut]) + bytes([0x5A]) * 1024
    if tail:
        out += gif[cut:]
    return bytes(out)


def make_signatures() -> dict[str, dict[str, bytes]]:
    return {
        "sig_jpeg": {
            "baseline.jpg": fb.build_jpeg(),
            "progressive.jpg": fb.build_jpeg(progressive=True),
            "exif.jpg": fb.build_jpeg(exif=True),
            # Cut inside the scan, so replay reaches the continuation hook as well as validate.
            "truncated.jpg": fb.build_jpeg(entropy_size=1024)[:-200],
            # Two cuts inside one scan, so replay walks from one continuation to the next.
            "chained.jpg": _chained_jpeg(),
        },
        "sig_png": {
            "rgba.png": fb.build_png("rgba"),
            "palette.png": fb.build_png("palette"),
            "gray.png": fb.build_png("gray"),
            "bad_idat_crc.png": fb.png_with_bad_idat_crc(),
            # Cut inside an IDAT, so replay reaches the continuation hook as well as validate.
            "split_idat.png": _split_png(tail=True),
            "orphan_idat.png": _split_png(tail=False),
        },
        "sig_pdf": {
            "classic.pdf": fb.build_pdf_classic(),
            "xref_stream.pdf": fb.build_pdf_xref_stream(),
            "incremental.pdf": fb.build_pdf_incremental(),
        },
        "sig_zip": {
            "stored.zip": fb.build_zip([("hello.txt", b"hello world\n")]),
            "two_entries.zip": fb.build_zip(
                [("a.bin", bytes(range(64))), ("dir/b.bin", b"second")]
            ),
        },
        "sig_gif": {
            "two_frames.gif": fb.build_gif(),
            "single_frame.gif": fb.build_gif(frames=1),
            "no_trailer.gif": fb.gif_without_trailer(),
            # Cut on a block boundary, so replay reaches the continuation hook as well.
            "cut_frame.gif": _split_gif(tail=False),
            "split_frames.gif": _split_gif(tail=True),
        },
        "sig_bmp": {
            "rgb24.bmp": fb.build_bmp(),
            "large_8x8.bmp": fb.build_bmp(width=8, height=8),
            "bad_header.bmp": fb.bmp_with_bad_header(),
        },
        "sig_tiff": {
            "little.tif": fb.build_tiff(),
            "big.tif": fb.build_tiff(little=False),
            "with_slack.tif": fb.build_tiff(slack=4096),
            "invalid_bad_entry_type.tif": fb.tiff_with_bad_entry_type(),
        },
        "sig_wav": {
            "pcm8.wav": fb.build_wav(),
            "info_before_fmt.wav": fb.build_wav(info_chunk=True),
            "truncated.wav": fb.build_wav(samples=4096, declared_riff_size=1 << 20),
            "invalid_no_data.wav": fb.wav_without_data(),
        },
        "sig_mp4": {
            "isom_video.mp4": fb.build_mp4(),
            "camera_moov_last.mp4": fb.build_mp4(moov_last=True, free_bytes=16),
            "quicktime.mov": fb.build_mov(),
            "aac_audio.m4a": fb.build_m4a(),
            "mobile_3gp.3gp": fb.build_3gp(),
            "heif_image.heic": fb.build_heic(),
            "truncated_mdat.mp4": fb.mp4_truncated_mdat(),
            "invalid_unknown_brand.mp4": fb.mp4_unknown_brand(),
            "invalid_header_only.mp4": fb.mp4_without_media(),
            "invalid_ftyp_overrun.mp4": fb.mp4_ftyp_overrun(),
        },
        "sig_avi": {
            "frames_and_index.avi": fb.build_avi(),
            "rec_lists.avi": fb.build_avi(frames=6, rec_lists=True),
            "no_index.avi": fb.build_avi(with_index=False),
            "header_only.avi": fb.avi_without_frames(),
            "index_without_frames.avi": fb.avi_index_without_frames(),
            "cut_riff_size.avi": fb.avi_cut_riff_size(),
            "invalid_wave_form.wav": fb.build_wav(),
            "invalid_oversized_list.avi": fb.avi_oversized_chunk(),
            "invalid_empty_riff.avi": b"RIFF" + struct.pack("<I", 4) + b"AVI ",
        },
        "sig_mp3": {
            "tagged.mp3": fb.build_mp3(),
            "untagged.mp3": fb.mp3_without_tag(),
            "with_trailer.mp3": fb.mp3_with_trailer(),
            "padded_tag.mp3": fb.mp3_padded_tag(),
            "mpeg2_layer_ii.mp3": fb.mp3_mpeg2_layer_ii(),
            "invalid_bad_tag_size.mp3": fb.mp3_bad_size_field(),
            "invalid_sample_rate_change.mp3": fb.mp3_sample_rate_change(),
            "invalid_single_frame.mp3": fb.mp3_single_frame(),
        },
        "sig_cfb": {
            "word.cfb": fb.cfb_word(),
            "excel.cfb": fb.cfb_excel(),
            "powerpoint.cfb": fb.cfb_powerpoint(),
            "large_sectors.cfb": fb.cfb_large_sectors(),
            "long_table.cfb": fb.cfb_long_table(),
            "generic_container.cfb": fb.cfb_generic_container(),
            "invalid_without_streams.cfb": fb.cfb_without_streams(),
            "invalid_foreign_byte_order.cfb": fb.cfb_foreign_byte_order(),
            "invalid_bad_sector_shift.cfb": fb.cfb_bad_sector_shift(),
            "invalid_entry_past_end.cfb": fb.cfb_entry_points_past_the_end(),
            "invalid_stream_too_large.cfb": fb.cfb_stream_larger_than_the_file(),
            "invalid_directory_cycle.cfb": fb.cfb_directory_cycle(),
            "invalid_table_past_end.cfb": fb.cfb_table_past_the_end(),
            "invalid_empty_header.cfb": fb._CFB_MAGIC + bytes(504),
        },
        "sig_sqlite": {
            "pages2_4k.db": fb.build_sqlite(),
            "page512_4.db": fb.build_sqlite(page_size=512, pages=4),
            "page64k_1.db": fb.build_sqlite(page_size=65536, pages=1),
            "stale_page_count.db": fb.sqlite_with_stale_page_count(),
            "invalid_short_header.db": fb.sqlite_short_header(),
        },
    }


def make_vhd() -> dict[str, bytes]:
    """Small VHD containers around one volume the C++ sweep tests rebuild byte for byte.

    The shared volume has a 1 KiB run of zeros, so every seed also exercises the sparse read
    path; the seeds differ only in how that volume is laid out in the container.
    """
    volume = hole_in(sweep_volume(4096), 1024, 2048)
    differencing = bytearray(volume)
    differencing += vhd.footer(vhd.TYPE_DIFFERENCING, len(volume), 0xFFFFFFFFFFFFFFFF)

    broken = bytearray(vhd.build_fixed(volume))
    broken[-300] ^= 0xFF  # reserved area, mutated after the checksum was computed

    return {
        "fixed_basic.vhd": vhd.build_fixed(volume),
        "dynamic_blocks_512.vhd": vhd.build_dynamic(volume, 512),
        "dynamic_blocks_1k.vhd": vhd.build_dynamic(volume, 1024),
        "dynamic_blocks_4k.vhd": vhd.build_dynamic(volume, 4096),
        "invalid_differencing.vhd": bytes(differencing),
        "invalid_no_footer.vhd": bytes(sweep_volume(2048)),
        "invalid_broken_checksum.vhd": bytes(broken),
    }


def make_vhdx() -> dict[str, bytes]:
    """Minimal VHDX containers: one per block state plus a parent and a truncated copy."""
    return vhdx.build_fuzz_seeds()


def make_gpt() -> dict[str, bytes]:
    sector_size = 512
    total_sectors = 64
    entry_lba = 2
    entry_count = 4
    entry_size = 128
    entries = bytearray(entry_count * entry_size)
    # Linux filesystem type GUID, nonzero unique GUID, LBA 40..50, name "seed".
    type_guid = bytes.fromhex("0fc63daf848347728e793d69d8477de4")
    unique_guid = bytes(range(16))
    entries[0:16] = type_guid
    entries[16:32] = unique_guid
    struct.pack_into("<QQ", entries, 32, 40, 50)
    entries[56:64] = "seed".encode("utf-16-le")
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF

    header = bytearray(sector_size)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<QQQQ", header, 24, 1, total_sectors - 1, 34, total_sectors - 34)
    struct.pack_into("<Q", header, 72, entry_lba)
    struct.pack_into("<III", header, 80, entry_count, entry_size, entries_crc)
    header_crc = zlib.crc32(bytes(header[:92])) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, header_crc)

    image = bytearray(total_sectors * sector_size)
    image[0x1BE] = 0x00
    image[0x1BE + 4] = 0xEE
    struct.pack_into("<II", image, 0x1BE + 8, 1, total_sectors - 1)
    struct.pack_into("<H", image, 0x1FE, 0xAA55)
    image[sector_size:sector_size * 2] = header
    image[entry_lba * sector_size:entry_lba * sector_size + len(entries)] = entries
    backup = bytearray(header)
    struct.pack_into("<Q", backup, 24, total_sectors - 1)
    struct.pack_into("<Q", backup, 32, 1)
    struct.pack_into("<I", backup, 16, 0)
    struct.pack_into("<I", backup, 16, zlib.crc32(bytes(backup[:92])) & 0xFFFFFFFF)
    image[(total_sectors - 1) * sector_size:
          total_sectors * sector_size] = backup

    broken = bytearray(image)
    broken[sector_size] = 0x00
    return {
        "valid_gpt.bin": bytes(image),
        "backup_only.bin": bytes(broken),
    }


def make_ext4_super() -> dict[str, bytes]:
    """A 16 KiB volume, the smallest geometry read_superblock accepts, and the ways it
    breaks. The committed 256 KiB fixture is larger than libFuzzer's max_len, so the
    superblock corpus is built here instead of sliced out of it."""
    block = 1024
    image = bytearray(16 * block)
    s = bytearray(block)  # the superblock copy at 1024, spliced in once it is filled

    def put16(off: int, value: int) -> None:
        struct.pack_into("<H", s, off, value)

    def put32(off: int, value: int) -> None:
        struct.pack_into("<I", s, off, value)

    put32(0, 16)          # s_inodes_count
    put32(4, 16)          # s_blocks_count_lo
    put32(20, 0)          # s_first_data_block, 0 for 1 KiB blocks
    put32(24, 0)          # s_log_block_size
    put32(32, 8)          # s_blocks_per_group
    put32(40, 16)         # s_inodes_per_group
    put16(56, 0xEF53)     # s_magic
    put16(58, 1)          # s_state
    put32(72, 0)          # s_creator_os, Linux
    put32(76, 1)          # s_rev_level
    put32(84, 11)         # s_first_ino
    put16(88, 256)        # s_inode_size
    put32(96, 0x0042)     # s_feature_incompat: FILETYPE | EXTENTS
    put32(100, 0x0001)    # s_feature_ro_compat: SPARSE_SUPER
    put16(254, 32)        # s_desc_size
    image[block:2 * block] = s

    valid = bytes(image)
    bad_magic = bytearray(valid)
    struct.pack_into("<H", bad_magic, block + 56, 0)
    bad_geometry = bytearray(valid)
    struct.pack_into("<I", bad_geometry, block + 32, 2)      # below any mkfs minimum
    short_volume = valid[:8 * block]
    return {
        "valid_small.img": valid,
        "bad_magic.img": bytes(bad_magic),
        "bad_geometry.img": bytes(bad_geometry),
        "short_volume.img": short_volume,
    }


def make_ext4_dir() -> dict[str, bytes]:
    """Directory blocks from the ext4 fixture, where a deleted name survives in the slack
    of a live record, two deletions share a second, and the checksum pseudo-entry sits at
    the head of a block."""
    image = bytes(ext4.Volume().buf)

    def block(blk: int) -> bytes:
        return image[blk * ext4.BLOCK:(blk + 1) * ext4.BLOCK]

    pseudo = bytearray(block(ext4.ROOT_BLOCK))
    # A metadata_csum directory opens with a nameless 0xDE record the walk has to skip.
    struct.pack_into("<IHBB", pseudo, 0, 0xFFFFFFFE, 12, 0, 0xDE)
    return {
        "root_with_slack.bin": block(ext4.ROOT_BLOCK),
        "subdir_photo.bin": block(ext4.SUB_BLOCK),
        "two_deleted.bin": block(ext4.MISC_BLOCK),
        "csum_pseudo_entry.bin": bytes(pseudo),
        "short_tail.bin": block(ext4.ROOT_BLOCK)[:1000],
    }


def make_ext4_inode() -> dict[str, bytes]:
    """Inode records from the fixture: a leaf extent tree, inline data, the pre-extents
    direct-and-index layout, and the two flags the scanner refuses to read through."""
    image = bytes(ext4.Volume().buf)

    def inode(ino: int) -> bytes:
        start = ext4.inode_byte(ino)
        return image[start:start + ext4.INODE_SIZE]

    return {
        "extent_leaf.bin": inode(ext4.SECRET_INO),
        "inline_data.bin": inode(ext4.INLINE_INO),
        "indirect.bin": inode(ext4.INDIRECT_INO),
        "encrypted.bin": inode(ext4.ENCRYPTED_INO),
        "unwritten.bin": inode(ext4.UNWRITTEN_INO),
    }


def write_corpus(root: Path) -> None:
    corpora: dict[str, dict[str, bytes]] = {
        "fat32_boot": make_fat32_boot(),
        "fat32_dir": make_fat32_dir(),
        "ext4_super": make_ext4_super(),
        "ext4_dir": make_ext4_dir(),
        "ext4_inode": make_ext4_inode(),
        "ntfs_runlist": make_ntfs_runlist(),
        "lznt1": make_lznt1(),
        "recycle_info": make_recycle_info(),
        "gpt": make_gpt(),
        "vhd": make_vhd(),
        "vhdx": make_vhdx(),
    }
    corpora.update(make_signatures())
    for name, files in corpora.items():
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        for filename, content in files.items():
            (directory / filename).write_bytes(content)
        print(f"{name}: {len(files)} seeds")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "fuzz")
    args = parser.parse_args()
    write_corpus(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
