#!/usr/bin/env python3
"""M5 large/sparse stress test (spec section 9, M5 test 4).

Creates a 2 GiB sparse image with valid signatures near the beginning and the end,
runs `openrecover carve --scope all`, and checks the 120 s budget and a peak RSS
below 512 MiB. The 64 GiB variant is run separately under the M5-nightly label.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

IMAGE_SIZE = 2 * 1024**3
TIME_BUDGET_SECONDS = 120.0
MEMORY_BUDGET_BYTES = 512 * 1024 * 1024


def memory_usage(pid: int) -> int:
    if sys.platform.startswith("linux"):
        try:
            for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            return 0
        return 0
    if os.name == "nt":
        import ctypes
        import ctypes.wintypes as wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        process = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not process:
            return 0
        try:
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
                return int(counters.PeakWorkingSetSize)
            return 0
        finally:
            ctypes.windll.kernel32.CloseHandle(process)
    return 0


def run_measured(command: list[str]) -> tuple[int, float, int, str]:
    start = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peak = 0
    while process.poll() is None:
        peak = max(peak, memory_usage(process.pid))
        time.sleep(0.05)
    stdout, stderr = process.communicate()
    elapsed = time.monotonic() - start
    peak = max(peak, memory_usage(process.pid))
    return process.returncode, elapsed, peak, stdout + stderr


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--size-gib", type=int, default=2)
    parser.add_argument("--nightly", action="store_true", help="use the 64 GiB image")
    args = parser.parse_args(argv)

    size = (64 if args.nightly else args.size_gib) * 1024**3
    work = args.work
    work.mkdir(parents=True, exist_ok=True)
    image = work / f"sparse_{size // 1024**3}GiB.img"
    out_dir = work / "out"
    for stale in (image,):
        if stale.exists():
            stale.unlink()
    fixture_bytes = args.fixture.read_bytes()
    with image.open("wb") as stream:
        stream.truncate(size)
        stream.seek(0)
        stream.write(fixture_bytes)
        stream.seek(size - len(fixture_bytes))
        stream.write(fixture_bytes)

    command = [
        str(args.exe), "carve", "--source", str(image), "--out", str(out_dir),
        "--scope", "all", "--no-progress",
    ]
    code, elapsed, peak, output = run_measured(command)
    if code != 0:
        print(f"stress carve failed with exit code {code}:\n{output[-4000:]}", file=sys.stderr)
        return 1
    print(f"carve {size // 1024**3} GiB in {elapsed:.1f}s (budget {TIME_BUDGET_SECONDS:.0f}s), "
          f"peak RSS {peak / 1024**2:.1f} MiB")
    failures = []
    if elapsed > TIME_BUDGET_SECONDS * (1 if not args.nightly else 16):
        failures.append(f"elapsed {elapsed:.1f}s exceeds the time budget")
    if peak and peak > MEMORY_BUDGET_BYTES:
        failures.append(f"peak RSS {peak / 1024**2:.1f} MiB exceeds 512 MiB")
    report = out_dir / "report.json"
    if not report.is_file():
        failures.append("report.json was not written")
    else:
        import json

        data = json.loads(report.read_text(encoding="utf-8"))
        hits = data["statistics"]["carve_hits"]
        if hits < 12:
            failures.append(f"expected at least 12 carve hits, found {hits}")
        if not any(entry["offset"] >= size * 3 // 4 for entry in data["carved"]):
            failures.append("no signature was found in the last quarter of the image")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    if image.exists():
        image.unlink()
    print("cli_stress_sparse: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
