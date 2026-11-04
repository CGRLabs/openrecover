#!/usr/bin/env python3
"""M5 end-to-end CLI tests (spec section 9, M5 tests 1-3, 5, and the Android CLI).

Runs the real `openrecover` binary against the committed disk images and checks:
  * report.json against goldens (generated_at masked),
  * `openrecover verify` on every exported file,
  * exit codes 1/2/3/5/6/7,
  * determinism of report.json and manifest.csv,
  * source images are byte-identical before/after and, on Linux, strace shows no
    write access to the source,
  * the Android scan/pull CLI against fake_adb.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "fixtures"))

import file_builders as media  # noqa: E402  (path is set up above)

EXE: Path
FIXTURES: Path
GOLDEN: Path
WORK: Path
FAKE_ADB: Path
ANDROID_FIXTURE: Path
PROFILES: Path
UPDATE = False


class Failure(Exception):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def cli(args: list[str], expect_code: int = 0, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    command = [str(EXE), *args]
    process = subprocess.run(command, capture_output=True, text=True, env=env)
    if process.returncode != expect_code:
        raise Failure(
            f"{' '.join(command)} exited {process.returncode}, expected {expect_code}\n"
            f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}"
        )
    return process


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_masked_report(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    report.pop("generated_at", None)
    return report


def compare_golden(name: str, report_path: Path) -> None:
    actual = load_masked_report(report_path)
    golden_path = GOLDEN / f"{name}.report.json"
    if UPDATE:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(json.dumps(actual, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    golden.pop("generated_at", None)
    if actual != golden:
        diff = "\n".join(
            difflib.unified_diff(
                json.dumps(golden, indent=2, ensure_ascii=False).splitlines(),
                json.dumps(actual, indent=2, ensure_ascii=False).splitlines(),
                fromfile=f"golden/{name}.report.json",
                tofile=str(report_path),
                lineterm="",
            )
        )
        raise Failure(f"report mismatch for {name}:\n{diff[:8000]}")


def resolve_executable(name: str) -> str | None:
    return shutil.which(name)


def strace_readonly_proof(image: Path, out_dir: Path) -> None:
    """On Linux, prove the source is only ever opened read-only and never written."""
    if not sys.platform.startswith("linux"):
        return
    if resolve_executable("strace") is None:
        return
    trace = WORK / f"trace_{image.stem}.txt"
    command = [
        "strace", "-f", "-s", "4096",
        "-e", "trace=open,openat,openat2,creat,write,pwrite64,pwritev,pwritev2,writev,"
              "ftruncate,truncate,fallocate,unlink,unlinkat,rename,renameat,renameat2",
        "-o", str(trace), str(EXE),
        "recover", "--source", str(image), "--out", str(out_dir), "--mode", "both", "--no-progress",
    ]
    process = subprocess.run(command, capture_output=True, text=True)
    expect(process.returncode == 0, f"strace recover failed: {process.stderr}")
    text = trace.read_text(encoding="utf-8", errors="replace")
    resolved = image.resolve()
    open_re = re.compile(r"\b(open|openat|openat2)\((?:[^,]*, )?\"([^\"]*)\", ([A-Z_|0-9x]+)[^=]*= (-?\d+)")
    creat_re = re.compile(r"\bcreat\(\"([^\"]*)\"")
    write_re = re.compile(r"\b(write|pwrite64|pwritev|pwritev2|writev|ftruncate|truncate|fallocate)\((\d+)\b")
    source_fds: set[int] = set()
    problems: list[str] = []
    for line in text.splitlines():
        match = open_re.search(line)
        if match:
            try:
                same = Path(match.group(2)).resolve() == resolved
            except OSError:
                same = False
            if same:
                flags = match.group(3)
                if any(flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")):
                    problems.append(line)
                descriptor = int(match.group(4))
                if descriptor >= 0:
                    source_fds.add(descriptor)
            continue
        match = creat_re.search(line)
        if match:
            try:
                if Path(match.group(1)).resolve() == resolved:
                    problems.append(line)
            except OSError:
                pass
    for line in text.splitlines():
        match = write_re.search(line)
        if match and int(match.group(2)) in source_fds:
            problems.append(line)
    if problems:
        raise Failure("writes to the source image observed under strace:\n" + "\n".join(problems[:20]))


def test_partitions_and_scan() -> None:
    image = FIXTURES / "fat32_basic.img"
    result = cli(["partitions", "--source", str(image), "--json", "--no-progress"])
    data = json.loads(result.stdout)
    expect(len(data["partitions"]) == 1, "fat32_basic must have one partition entry")
    expect(data["partitions"][0]["fs"] == "fat32", "fat32_basic must be detected as FAT32")

    result = cli(["scan", "--source", str(image), "--json", "--no-progress"])
    data = json.loads(result.stdout)
    expect(data["statistics"]["deleted_entries_found"] == 9, "fat32_basic must report 9 deleted entries")
    expect(len(data["files"]) == 9, "fat32_basic scan must list 9 files")
    expect(all(not entry.get("exported_to") for entry in data["files"]), "scan must not export files")


def test_exfat_scan() -> None:
    image = FIXTURES / "exfat_basic.img"
    result = cli(["partitions", "--source", str(image), "--json", "--no-progress"])
    data = json.loads(result.stdout)
    expect(len(data["partitions"]) == 1, "exfat_basic must have one partition entry")
    expect(data["partitions"][0]["fs"] == "exfat", "exfat_basic must be detected as exFAT")

    result = cli(["scan", "--source", str(image), "--json", "--no-progress"])
    data = json.loads(result.stdout)
    expect(data["statistics"]["deleted_entries_found"] == 10,
           "exfat_basic must report 10 deleted entries")
    expect(len(data["files"]) == 10, "exfat_basic scan must list 10 files")
    expect(any(entry["path"] == "Old Stuff/inner one.bin" for entry in data["files"]),
           "deleted exFAT directories must be traversed")


def test_ext4_scan() -> None:
    image = FIXTURES / "ext4_basic.img"
    result = cli(["partitions", "--source", str(image), "--json", "--no-progress"])
    data = json.loads(result.stdout)
    expect(len(data["partitions"]) == 1, "ext4_basic must be listed as one partition entry")
    expect(data["partitions"][0]["scheme"] == "superfloppy",
           "a bare ext4 volume has no partition table and must be a superfloppy")
    expect(data["partitions"][0]["fs"] == "ext4", "ext4_basic must be detected as ext4")

    result = cli(["scan", "--source", str(image), "--json", "--no-progress"])
    data = json.loads(result.stdout)
    expect(data["statistics"]["deleted_entries_found"] == 11,
           "ext4_basic must report 11 deleted entries")
    expect(len(data["files"]) == 11, "ext4_basic scan must list 11 files")
    by_path = {entry["path"]: entry for entry in data["files"]}
    expect(by_path["subdir/photo.jpg"]["confidence"] == "high",
           "a deleted directory entry must name its file with high confidence")
    expect("ClustersReallocated" in by_path["inode-20"]["flags"],
           "a reused block must keep the deleted inode at low confidence")
    expect("Unsupported" in by_path["inode-25"]["flags"],
           "an encrypted inode must be reported as unsupported")


def test_recover_goldens() -> None:
    cases = [
        ("cli_fat32_basic", "fat32_basic.img", ["recover", "--mode", "both"]),
        ("cli_exfat_basic", "exfat_basic.img", ["recover", "--mode", "metadata"]),
        ("cli_ext4_basic", "ext4_basic.img", ["recover", "--mode", "metadata"]),
        ("cli_vhdx", "fat32_vhdx_full.img", ["recover", "--mode", "metadata"]),
        ("cli_ntfs_basic", "ntfs_basic.img", ["recover", "--mode", "metadata"]),
        ("cli_ntfs_recyclebin", "ntfs_recyclebin.img", ["recover", "--mode", "metadata"]),
        ("cli_carve_mixed", "carve_mixed.img", ["carve", "--scope", "all"]),
        ("cli_carve_fragmented", "carve_fragmented.img", ["carve", "--scope", "all"]),
        ("cli_carve_fragmented_png", "carve_fragmented_png.img",
         ["carve", "--scope", "all"]),
        ("cli_carve_fragmented_gif", "carve_fragmented_gif.img",
         ["carve", "--scope", "all"]),
    ]
    for name, image_name, verb in cases:
        image = FIXTURES / image_name
        before = sha256_file(image)
        out_dir = WORK / name
        cli([*verb, "--source", str(image), "--out", str(out_dir), "--no-progress"])
        expect(sha256_file(image) == before, f"{image_name} changed during {verb[0]}")
        compare_golden(name, out_dir / "report.json")
        cli(["verify", "--report", str(out_dir / "report.json")], expect_code=0)
        strace_readonly_proof(image, WORK / f"{name}_strace")


def test_carve_reassemble_flag() -> None:
    """`--no-reassemble` must hand back the truncated head the joined run hides."""

    image = FIXTURES / "carve_fragmented.img"
    golden = json.loads((GOLDEN / "carve_fragmented.golden.json").read_text(encoding="utf-8"))
    fragmented = golden["fragmented"]
    chained = golden["chained"]
    before = sha256_file(image)

    joined = WORK / "carve_fragmented_joined"
    cli(["carve", "--source", str(image), "--out", str(joined), "--scope", "all",
         "--no-progress"])
    report = load_masked_report(joined / "report.json")
    hits = {entry["offset"]: entry for entry in report["carved"]}
    head = hits[fragmented["offset"]]
    expect(head["length"] == fragmented["length"], "the joined hit must be the whole file")
    expect(head["fragments"] == 2, "the joined hit must report two extents")
    expect([e["offset"] for e in head["extents"]] ==
           [fragmented["offset"], fragmented["tail_offset"]],
           "the joined hit must map each extent on the device")
    expect([e["length"] for e in head["extents"]] ==
           [fragmented["prefix_length"], fragmented["tail_length"]],
           "the joined extents must add up in file order")
    expect(head["confidence"] == "low", "a joined hit must stay low confidence")
    expect(head["sha256"] == fragmented["sha256"], "the joined hash must be the original file's")
    chain = hits[chained["offset"]]
    expect(chain["length"] == chained["length"], "the chained hit must be the whole file")
    expect(chain["fragments"] == chained["fragments"], "the chained hit must report every extent")
    expect([e["offset"] for e in chain["extents"]] ==
           [piece["offset"] for piece in chained["pieces"]],
           "the chained hit must map every extent on the device")
    expect(chain["sha256"] == chained["sha256"], "the chained hash must be the original file's")
    expect("extents" not in hits[golden["orphan"]["offset"]],
           "a contiguous hit must not carry an extents key")
    expect(len(hits) == 3, f"expected both joined heads and the orphan, got {sorted(hits)}")
    cli(["verify", "--report", str(joined / "report.json")], expect_code=0)

    split = WORK / "carve_fragmented_split"
    cli(["carve", "--source", str(image), "--out", str(split), "--scope", "all",
         "--no-reassemble", "--no-progress"])
    report = load_masked_report(split / "report.json")
    hits = {entry["offset"]: entry for entry in report["carved"]}
    head = hits[fragmented["offset"]]
    expect(head["length"] == fragmented["prefix_length"], "--no-reassemble must keep the prefix")
    expect("fragments" not in head, "an unjoined hit must not carry a fragments key")
    expect("extents" not in head, "an unjoined hit must not carry an extents key")
    expect(head["sha256"] != fragmented["sha256"], "an unjoined hit cannot hash as the original")
    chain = hits[chained["offset"]]
    expect(chain["length"] == chained["pieces"][0]["length"],
           "--no-reassemble must keep only the first piece of a chain")
    expect(sha256_file(image) == before, "the fixture image changed during carving")

    # `recover --mode carve` follows the same switch, because it shares the pipeline.
    recover_dir = WORK / "carve_fragmented_recover"
    cli(["recover", "--source", str(image), "--out", str(recover_dir), "--mode", "carve",
         "--no-reassemble", "--no-progress"])
    report = load_masked_report(recover_dir / "report.json")
    expect(any(entry["offset"] == fragmented["offset"] and
               entry["length"] == fragmented["prefix_length"] for entry in report["carved"]),
           "recover --mode carve must honour --no-reassemble")


def test_carve_png_reassemble_flag() -> None:
    """A PNG cut inside its image data must rejoin on chunk boundaries that still verify."""

    image = FIXTURES / "carve_fragmented_png.img"
    golden = json.loads((GOLDEN / "carve_fragmented_png.golden.json").read_text(encoding="utf-8"))
    joined_expected = golden["joined"]
    chained = golden["chained"]
    orphan = golden["orphan"]
    before = sha256_file(image)

    joined_dir = WORK / "carve_fragmented_png_joined"
    cli(["carve", "--source", str(image), "--out", str(joined_dir), "--scope", "all",
         "--no-progress"])
    report = load_masked_report(joined_dir / "report.json")
    hits = {entry["offset"]: entry for entry in report["carved"]}
    expect(len(hits) == 3, f"expected two joined heads and the orphan, got {sorted(hits)}")
    head = hits[joined_expected["offset"]]
    expect(head["type"] == "png", "the joined hit must be a PNG")
    expect(head["length"] == joined_expected["length"], "the joined hit must be the whole file")
    expect(head["fragments"] == 2, "the joined hit must report two extents")
    expect([e["offset"] for e in head["extents"]] ==
           [joined_expected["offset"], joined_expected["tail_offset"]],
           "the joined hit must map each extent on the device")
    expect([e["length"] for e in head["extents"]] ==
           [joined_expected["prefix_length"], joined_expected["tail_length"]],
           "the joined extents must add up in file order")
    expect(head["confidence"] == "low", "a joined hit must stay low confidence")
    expect(head["sha256"] == joined_expected["sha256"],
           "the joined hash must match the lost file's chunks")
    chain = hits[chained["offset"]]
    expect(chain["length"] == chained["length"], "the chained hit must be the whole file")
    expect(chain["fragments"] == chained["fragments"],
           "the chained hit must report every extent")
    expect([e["offset"] for e in chain["extents"]] ==
           [piece["offset"] for piece in chained["pieces"]],
           "the chained hit must map every extent on the device")
    expect([e["length"] for e in chain["extents"]] ==
           [piece["length"] for piece in chained["pieces"]],
           "the chained extents must add up in file order")
    expect(chain["sha256"] == chained["sha256"], "the chained hash must match the lost chunks")
    stray = hits[orphan["offset"]]
    expect(stray["length"] == orphan["length"],
           "a head whose tail is another image must stop at its first broken chunk")
    expect("fragments" not in stray and "extents" not in stray,
           "an unjoined PNG hit must not carry an extents key")
    cli(["verify", "--report", str(joined_dir / "report.json")], expect_code=0)

    split_dir = WORK / "carve_fragmented_png_split"
    cli(["carve", "--source", str(image), "--out", str(split_dir), "--scope", "all",
         "--no-reassemble", "--no-progress"])
    report = load_masked_report(split_dir / "report.json")
    hits = {entry["offset"]: entry for entry in report["carved"]}
    head = hits[joined_expected["offset"]]
    expect(head["length"] == joined_expected["prefix_length"],
           "--no-reassemble must keep the bytes before the broken chunk")
    expect("fragments" not in head and "extents" not in head,
           "an unjoined PNG hit must not carry a fragments key")
    expect(head["sha256"] != joined_expected["sha256"],
           "an unjoined hit cannot hash as the lost file")
    chain = hits[chained["offset"]]
    expect(chain["length"] == chained["pieces"][0]["length"],
           "--no-reassemble must keep only the first piece of a chain")
    expect(sha256_file(image) == before, "the fixture image changed during carving")


def test_carve_gif_reassemble_flag() -> None:
    """A GIF cut on a block boundary must rejoin on a tail whose blocks prove themselves."""

    image = FIXTURES / "carve_fragmented_gif.img"
    golden = json.loads((GOLDEN / "carve_fragmented_gif.golden.json").read_text(encoding="utf-8"))
    joined_expected = golden["joined"]
    chained = golden["chained"]
    orphan = golden["orphan"]
    before = sha256_file(image)

    joined_dir = WORK / "carve_fragmented_gif_joined"
    cli(["carve", "--source", str(image), "--out", str(joined_dir), "--scope", "all",
         "--no-progress"])
    report = load_masked_report(joined_dir / "report.json")
    hits = {entry["offset"]: entry for entry in report["carved"]}
    expect(len(hits) == 3, f"expected two joined heads and the orphan, got {sorted(hits)}")
    head = hits[joined_expected["offset"]]
    expect(head["type"] == "gif", "the joined hit must be a GIF")
    expect(head["length"] == joined_expected["length"], "the joined hit must be the whole file")
    expect(head["fragments"] == 2, "the joined hit must report two extents")
    expect([e["offset"] for e in head["extents"]] ==
           [joined_expected["offset"], joined_expected["tail_offset"]],
           "the joined hit must map each extent on the device")
    expect([e["length"] for e in head["extents"]] ==
           [joined_expected["prefix_length"], joined_expected["tail_length"]],
           "the joined extents must add up in file order")
    expect(head["confidence"] == "low", "a joined hit must stay low confidence")
    expect(head["sha256"] == joined_expected["sha256"],
           "the joined hash must match the lost file's blocks")
    chain = hits[chained["offset"]]
    expect(chain["length"] == chained["length"], "the chained hit must be the whole file")
    expect(chain["fragments"] == chained["fragments"],
           "the chained hit must report every extent")
    expect([e["offset"] for e in chain["extents"]] ==
           [piece["offset"] for piece in chained["pieces"]],
           "the chained hit must map every extent on the device")
    expect([e["length"] for e in chain["extents"]] ==
           [piece["length"] for piece in chained["pieces"]],
           "the chained extents must add up in file order")
    expect(chain["sha256"] == chained["sha256"], "the chained hash must match the lost blocks")
    stray = hits[orphan["offset"]]
    expect(stray["length"] == orphan["length"],
           "a head whose tail is another image must stop at its cut")
    expect("fragments" not in stray and "extents" not in stray,
           "an unjoined GIF hit must not carry an extents key")
    cli(["verify", "--report", str(joined_dir / "report.json")], expect_code=0)

    split_dir = WORK / "carve_fragmented_gif_split"
    cli(["carve", "--source", str(image), "--out", str(split_dir), "--scope", "all",
         "--no-reassemble", "--no-progress"])
    report = load_masked_report(split_dir / "report.json")
    hits = {entry["offset"]: entry for entry in report["carved"]}
    head = hits[joined_expected["offset"]]
    expect(head["length"] == joined_expected["prefix_length"],
           "--no-reassemble must keep the bytes before the cut")
    expect("fragments" not in head and "extents" not in head,
           "an unjoined GIF hit must not carry a fragments key")
    expect(head["sha256"] != joined_expected["sha256"],
           "an unjoined hit cannot hash as the lost file")
    chain = hits[chained["offset"]]
    expect(chain["length"] == chained["pieces"][0]["length"],
           "--no-reassemble must keep only the first piece of a chain")
    expect(sha256_file(image) == before, "the fixture image changed during carving")


def test_vhd_containers() -> None:
    """A VHD must recover exactly like the flat image it carries."""

    def recover_run(image: Path, tag: str) -> tuple[Path, dict]:
        before = sha256_file(image)
        out_dir = WORK / f"vhd_{tag}"
        cli(["recover", "--mode", "metadata", "--source", str(image), "--out", str(out_dir),
             "--no-progress"])
        expect(sha256_file(image) == before, f"{image.name} changed during recover")
        return out_dir, load_masked_report(out_dir / "report.json")

    def comparable(report: dict) -> dict:
        return {key: value for key, value in report.items() if key != "source"}

    def exported_digests(out_dir: Path, report: dict) -> dict[str, str]:
        return {entry["path"]: sha256_file(out_dir / entry["exported_to"])
                for entry in report["files"] if entry.get("exported_to")}

    flat_dir, flat = recover_run(FIXTURES / "fat32_basic.img", "flat")
    flat_digests = exported_digests(flat_dir, flat)
    expect(len(flat_digests) == 9, "the flat run must export 9 files")
    expect(flat["source"]["container"] == "", "a flat image must report no container")

    for image_name, flavour in (("fat32_vhd_fixed.img", "vhd fixed"),
                                ("fat32_vhd_dynamic.img", "vhd dynamic"),
                                ("fat32_vhdx_full.img", "vhdx"),
                                ("fat32_vhdx_sparse.img", "vhdx")):
        image = FIXTURES / image_name
        out_dir, report = recover_run(image, image_name[: -len(".img")])
        expect(report["source"]["container"] == flavour,
               f"{image_name} must be reported as a {flavour} device, got "
               f"{report['source']['container']!r}")
        expect(report["source"]["size_bytes"] == 8388608,
               f"{image_name} must expose the virtual 8 MiB volume")

        parts = json.loads(cli(["partitions", "--source", str(image), "--json", "--no-progress"]).stdout)
        expect(parts["partitions"][0]["fs"] == "fat32", f"{image_name} must be detected as FAT32")

        scan = json.loads(cli(["scan", "--source", str(image), "--json", "--no-progress"]).stdout)
        expect(scan["statistics"]["deleted_entries_found"] == 9,
               f"{image_name} must report 9 deleted entries")

        expect(comparable(report) == comparable(flat),
               f"{image_name} produced a different report from the flat image")
        digests = exported_digests(out_dir, report)
        expect(digests == flat_digests, f"{image_name} exported different bytes than the flat image")

        cli(["verify", "--report", str(out_dir / "report.json")])


def test_carve_gif_bmp() -> None:
    gif = media.build_gif()
    bmp = media.build_bmp()
    gif_offset = 0x8000
    bmp_offset = 0x10000
    image = bytearray(0x20000)
    image[gif_offset : gif_offset + len(gif)] = gif
    image[bmp_offset : bmp_offset + len(bmp)] = bmp
    image_path = WORK / "carve_gif_bmp.img"
    image_path.write_bytes(bytes(image))

    out_dir = WORK / "carve_gif_bmp"
    cli(["carve", "--source", str(image_path), "--out", str(out_dir),
         "--scope", "all", "--types", "gif,bmp", "--no-progress"])
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    carved = {entry["type"]: entry for entry in report["carved"]}
    expect(set(carved) == {"gif", "bmp"}, f"expected one gif and one bmp hit, got {sorted(carved)}")

    expect(carved["gif"]["offset"] == gif_offset, "gif hit offset mismatch")
    expect(carved["gif"]["length"] == len(gif), "gif hit length mismatch")
    expect(carved["gif"]["subtype"] == "gif89a", "gif subtype must be reported")
    expect(carved["gif"]["confidence"] == "medium", "shallow gif validation must be medium")
    expect((out_dir / carved["gif"]["exported_to"]).read_bytes() == gif,
           "exported gif must match the source bytes")

    expect(carved["bmp"]["offset"] == bmp_offset, "bmp hit offset mismatch")
    expect(carved["bmp"]["length"] == len(bmp), "bmp hit length mismatch")
    expect(carved["bmp"]["subtype"] == "bmp", "bmp subtype must be reported")
    expect(carved["bmp"]["confidence"] == "medium", "shallow bmp validation must be medium")
    expect((out_dir / carved["bmp"]["exported_to"]).read_bytes() == bmp,
           "exported bmp must match the source bytes")
    cli(["verify", "--report", str(out_dir / "report.json")], expect_code=0)

    deep_dir = WORK / "carve_gif_bmp_deep"
    cli(["carve", "--source", str(image_path), "--out", str(deep_dir),
         "--scope", "all", "--types", "gif,bmp", "--deep", "--no-progress"])
    deep = json.loads((deep_dir / "report.json").read_text(encoding="utf-8"))
    expect(all(entry["confidence"] == "high" for entry in deep["carved"]),
           "deep validation must raise both hits to high confidence")


def test_determinism() -> None:
    image = FIXTURES / "fat32_basic.img"
    outputs = []
    for index in (1, 2):
        out_dir = WORK / f"determinism_{index}"
        cli(["recover", "--source", str(image), "--out", str(out_dir), "--mode", "both", "--no-progress"])
        outputs.append(out_dir)
    first = load_masked_report(outputs[0] / "report.json")
    second = load_masked_report(outputs[1] / "report.json")
    expect(first == second, "two identical runs produced different report.json contents")
    expect(
        (outputs[0] / "manifest.csv").read_bytes() == (outputs[1] / "manifest.csv").read_bytes(),
        "two identical runs produced different manifest.csv contents",
    )


def test_verify_detects_tampering() -> None:
    source = WORK / "cli_ntfs_basic"
    tampered = WORK / "tampered"
    shutil.copytree(source, tampered)
    report = json.loads((tampered / "report.json").read_text(encoding="utf-8"))
    exported = next((entry["exported_to"] for entry in report["files"] if entry.get("exported_to")), None)
    expect(exported is not None, "tamper test needs at least one exported file")
    file_path = tampered / exported
    data = bytearray(file_path.read_bytes())
    expect(len(data) > 0, "tamper test needs a non-empty exported file")
    data[0] ^= 0xFF
    file_path.write_bytes(bytes(data))
    result = cli(["verify", "--report", str(tampered / "report.json")], expect_code=1)
    expect("sha256 mismatch" in result.stdout, "verify must report a sha256 mismatch")


def test_exit_codes() -> None:
    missing = FIXTURES / "does-not-exist.img"
    cli(["scan", "--source", str(missing), "--no-progress"], expect_code=1)

    # A name the parser does not know is a usage error; a known filesystem that is not on the
    # volume is reported as "no such filesystem" once the volume has been read.
    cli(["scan", "--source", str(FIXTURES / "fat32_basic.img"), "--fs", "bfs", "--no-progress"],
        expect_code=2)
    cli(["scan", "--source", str(FIXTURES / "fat32_basic.img"), "--fs", "ext4", "--no-progress"],
        expect_code=5)

    unsupported = WORK / "unsupported.img"
    with unsupported.open("wb") as stream:
        stream.truncate(2 * 1024 * 1024)
    cli(["scan", "--source", str(unsupported), "--no-progress"], expect_code=5)

    on_source = WORK / "on-source"
    on_source.mkdir(parents=True, exist_ok=True)
    copied = on_source / "fat32_basic.img"
    shutil.copyfile(FIXTURES / "fat32_basic.img", copied)
    cli(["recover", "--source", str(copied), "--out", str(on_source), "--no-progress"], expect_code=6)
    expect(not (on_source / "report.json").exists(), "output-on-source refusal must not create a report")

    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        unreadable = WORK / "unreadable.img"
        shutil.copyfile(FIXTURES / "fat32_basic.img", unreadable)
        unreadable.chmod(0o000)
        try:
            cli(["scan", "--source", str(unreadable), "--no-progress"], expect_code=3)
        finally:
            unreadable.chmod(0o644)


def android_environment(device_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["FAKE_ADB_ROOT"] = str(device_root)
    return env


def test_android_cli() -> None:
    if not FAKE_ADB.is_file():
        raise Failure(f"fake adb executable missing: {FAKE_ADB}")
    device_root = WORK / "android-device"
    sdcard = device_root / "sdcard"
    shutil.copytree(ANDROID_FIXTURE, sdcard)
    env = android_environment(device_root)
    profile = PROFILES / "default.json"
    out_dir = WORK / "android-scan"

    result = cli(
        ["android", "scan", "--serial", "FAKE123", "--out", str(out_dir), "--profile", str(profile),
         "--adb-path", str(FAKE_ADB), "--no-progress", "--json"],
        env=env,
    )
    report = json.loads(result.stdout)
    expect(report["android"]["device"]["serial"] == "FAKE123", "Android report must identify the device")
    expect(len(report["files"]) == 8, f"expected 8 Android candidates, got {len(report['files'])}")
    expect(not any(entry.get("exported_to") for entry in report["files"]), "Android scan must not pull files")

    pull_dir = WORK / "android-pull"
    cli(
        ["android", "pull", "--serial", "FAKE123", "--out", str(pull_dir), "--profile", str(profile),
         "--adb-path", str(FAKE_ADB), "--no-progress"],
        env=env,
    )
    cli(["verify", "--report", str(pull_dir / "report.json")], expect_code=0)

    unauthorized = dict(env)
    unauthorized["FAKE_ADB_STATE"] = "unauthorized"
    cli(
        ["android", "scan", "--serial", "FAKE123", "--out", str(WORK / "android-unauthorized"),
         "--profile", str(profile), "--adb-path", str(FAKE_ADB), "--no-progress"],
        expect_code=7,
        env=unauthorized,
    )


def main(argv: list[str]) -> int:
    global EXE, FIXTURES, GOLDEN, WORK, FAKE_ADB, ANDROID_FIXTURE, PROFILES, UPDATE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--golden", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--fake-adb", type=Path, required=True)
    parser.add_argument("--android-fixture", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--update-goldens", action="store_true")
    args = parser.parse_args(argv)
    EXE, FIXTURES, GOLDEN, WORK = args.exe, args.fixtures, args.golden, args.work
    FAKE_ADB, ANDROID_FIXTURE, PROFILES = args.fake_adb, args.android_fixture, args.profiles
    UPDATE = args.update_goldens

    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)

    tests = [
        test_partitions_and_scan,
        test_exfat_scan,
        test_ext4_scan,
        test_recover_goldens,
        test_carve_reassemble_flag,
        test_carve_png_reassemble_flag,
        test_carve_gif_reassemble_flag,
        test_vhd_containers,
        test_carve_gif_bmp,
        test_determinism,
        test_verify_detects_tampering,
        test_exit_codes,
        test_android_cli,
    ]
    for test in tests:
        try:
            test()
        except Failure as failure:
            print(f"FAIL: {test.__name__}: {failure}", file=sys.stderr)
            return 1
        except Exception as error:  # noqa: BLE001 - surface unexpected errors as test failures
            print(f"ERROR: {test.__name__}: {type(error).__name__}: {error}", file=sys.stderr)
            return 1
        print(f"ok: {test.__name__}")
    print("cli_e2e: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
