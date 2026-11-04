#!/usr/bin/env python3
"""Decompress every *.img.gz fixture into the build tree at configure time."""

from __future__ import annotations

import gzip
import shutil
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: decompress_gz.py SRC_DIR DST_DIR", file=sys.stderr)
        return 2
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    if not source.is_dir():
        print(f"fixture source directory not found: {source}", file=sys.stderr)
        return 1
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    for archive in sorted(source.glob("*.img.gz")):
        target = destination / archive.name[: -len(".gz")]
        with gzip.open(archive, "rb") as compressed, target.open("wb") as raw:
            shutil.copyfileobj(compressed, raw)
        count += 1
    if count == 0:
        print(f"no *.img.gz fixtures found in {source}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
