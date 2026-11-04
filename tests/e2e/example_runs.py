import json
import pathlib
import shutil
import subprocess
import sys

exe = pathlib.Path(sys.argv[1])
images = pathlib.Path(sys.argv[2])
work = pathlib.Path(sys.argv[3])
work.mkdir(parents=True, exist_ok=True)

# name -> (expected filesystem in the partition list, minimum exported carved files)
CASES = {
    "fat32_in_mbr": ("fat32", 0),
    "fat32_basic": ("fat32", 0),
    "fat32_reused": ("fat32", 0),
    "fat32_vhd_fixed": ("fat32", 0),
    "fat32_vhd_dynamic": ("fat32", 0),
    "ntfs_basic": ("ntfs", 0),
    "ntfs_4k_sector": ("ntfs", 0),
    "exfat_basic": ("exfat", 0),
    "carve_mixed": (None, 10),
    "carve_mixed_unaligned": (None, 10),
}


def run(image, out):
    if out.exists():
        shutil.rmtree(out)
    proc = subprocess.run([str(exe), str(image), str(out)], capture_output=True)
    if proc.returncode != 0:
        raise AssertionError(f"exit {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[:400]}")
    return json.loads(proc.stdout.decode("utf-8")), out


failures = []
for name, (want_fs, min_carved) in CASES.items():
    image = images / (name + ".img")
    out = work / name
    try:
        doc, out = run(image, out)
    except AssertionError as exc:
        failures.append(f"{name}: {exc}")
        continue
    stats = doc["statistics"]
    written = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    files_dir = out / "files"
    exported_files = sorted(p.relative_to(out).as_posix() for p in files_dir.rglob("*") if p.is_file()) \
        if files_dir.exists() else []
    carved_dir = out / "carved"
    carved_files = sorted(p.relative_to(carved_dir).as_posix() for p in carved_dir.rglob("*") if p.is_file()) \
        if carved_dir.exists() else []

    # Every file the metadata named is reported, but only the ones that passed the filter are written;
    # `exported` counts both phases, so it has to equal what is actually on disk.
    named = [entry for entry in doc["files"] if entry["exported_to"]]
    if len(doc["files"]) != stats["deleted_entries_found"]:
        failures.append(f"{name}: {len(doc['files'])} entries for {stats['deleted_entries_found']} "
                        "deleted entries found")
    if len(named) != len(exported_files):
        failures.append(f"{name}: {len(named)} reported metadata exports for {len(exported_files)} "
                        "files written under files/")
    if stats["exported"] != len(exported_files) + len(carved_files):
        failures.append(f"{name}: exported {stats['exported']} != {len(exported_files)} metadata + "
                        f"{len(carved_files)} carved")
    for entry in named:
        if entry["exported_to"] not in exported_files:
            failures.append(f"{name}: {entry['path']} not written at {entry['exported_to']}")
        if not entry["sha256"]:
            failures.append(f"{name}: {entry['path']} exported without a sha256")
    for entry in doc["carved"]:
        target = entry.get("exported_to")
        if not entry["sha256"]:
            failures.append(f"{name}: carved entry at {entry['offset']} has no sha256")
        if target and target not in written:
            failures.append(f"{name}: carved {target} missing from disk")
    if not doc["generated_at"]:
        failures.append(f"{name}: generated_at unset")
    if len(carved_files) != stats["carve_hits"] - stats["duplicates_skipped"]:
        failures.append(f"{name}: {len(carved_files)} carved files for {stats['carve_hits']} hits and "
                        f"{stats['duplicates_skipped']} duplicates")
    found_fs = [p["fs"] for p in doc["partitions"] if p["fs"]]
    if want_fs is None:
        if doc["partitions"]:
            failures.append(f"{name}: expected no partitions, got {doc['partitions']}")
        if not any("partition table" in w or "filesystem" in w for w in doc["warnings"]):
            failures.append(f"{name}: expected a warning for the raw image, got {doc['warnings']}")
    else:
        if found_fs != [want_fs]:
            failures.append(f"{name}: expected fs {want_fs}, report says {found_fs}")
        if not doc["partitions"]:
            failures.append(f"{name}: no partition summaries")
    if len(carved_files) < min_carved:
        failures.append(f"{name}: expected >= {min_carved} carved files, got {len(carved_files)}")
    if not (out / "report.json").exists() or not (out / "manifest.csv").exists():
        failures.append(f"{name}: report.json or manifest.csv missing")
    print(f"{name:24s} exit=0 fs={found_fs} files={stats['exported']} carve={stats['carve_hits']} "
          f"dups={stats['duplicates_skipped']} carved_files={len(carved_files)} warn={doc['warnings']}")

if failures:
    print()
    print("\n".join(failures))
    sys.exit(1)
print("all example runs verified")
