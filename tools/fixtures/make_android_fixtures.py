#!/usr/bin/env python3
"""Generate the deterministic fake /sdcard tree used by the Android bridge tests.

The tree is committed; rerunning this script must reproduce it byte-for-byte.
File mtimes are intentionally not pinned: the fake transport reads the real
filesystem mtime and the tests compare the pulled copy against that value.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from file_builders import (  # noqa: E402
    bmp_with_bad_header,
    build_bmp,
    build_gif,
    build_jpeg,
    build_pdf_classic,
    build_png,
    build_zip,
    gif_without_trailer,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "android" / "fake_sdcard"


def write(relative: str, data: bytes) -> None:
    path = FIXTURE / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    valid_jpeg = build_jpeg(entropy_size=300)
    exif_jpeg = build_jpeg(exif=True, entropy_size=256)
    progressive_jpeg = build_jpeg(progressive=True, entropy_size=288)
    valid_png = build_png("rgba")
    valid_pdf = build_pdf_classic()
    valid_zip = build_zip([("readme.txt", b"openrecover android fixture\n")])

    write("DCIM/.thumbnails/thumb_valid.jpg", valid_jpeg)
    write("DCIM/.thumbnails/thumb_corrupt.jpg", b"\xff\xd8not-a-jpeg-payload" * 8)
    write("DCIM/.thumbnails/thumb_truncated.jpg", valid_jpeg[:-2])
    write("DCIM/.thumbnails/notes.txt", b"")

    write("Pictures/.thumbnails/uni_pic.jpg", exif_jpeg)

    write("DCIM/IMG_0001.jpg", valid_jpeg)
    write("DCIM/.trashed-1735689600-IMG_1.jpg", progressive_jpeg)
    write("DCIM/.trashed-1735689600-IMG_2.JPG", exif_jpeg)

    write("Android/data/com.x/cache/a.png", valid_png)
    write("Android/data/com.x/cache/zero.txt", b"")
    write("Android/data/com.x/files/not_cache.jpg", valid_jpeg)
    write("Android/data/com.denied/cache/secret.jpg", valid_jpeg)

    write("Download/report.pdf", valid_pdf)
    write("Download/archive.zip", valid_zip)
    write("Download/anim.gif", build_gif())
    write("Download/picture.bmp", build_bmp())
    write("Download/broken.gif", gif_without_trailer())
    write("Download/broken.bmp", bmp_with_bad_header())

    print(f"android fixtures written under {FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
