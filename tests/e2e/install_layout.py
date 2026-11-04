"""Check the installed OpenRecover package without a compiler.

Verifies the layout a `find_package(OpenRecover)` consumer depends on, that the exported CMake
files reference only files that were actually installed, that no build-tree path leaked into the
package, and that every quoted include in the installed public headers resolves inside the
package. The header closure check is what catches a header that was forgotten by the install rules.
"""

import argparse
import pathlib
import re
import shutil
import subprocess
import sys

INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.MULTILINE)
TARGET_FILE_RE = re.compile(r'_IMPORT_PREFIX\}/([^"]+\.(?:lib|a))')


def fail(messages, text):
    messages.append(text)


def install(cmake, build_dir, prefix):
    if prefix.exists():
        shutil.rmtree(prefix)
    proc = subprocess.run([cmake, "--install", str(build_dir), "--prefix", str(prefix)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"cmake --install failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def check_layout(prefix, problems):
    exe = "bin/openrecover.exe" if sys.platform == "win32" else "bin/openrecover"
    required = [
        "include/openrecover/openrecover.hpp",
        "include/tl/expected.hpp",
        "lib/cmake/OpenRecover/OpenRecoverConfig.cmake",
        "lib/cmake/OpenRecover/OpenRecoverConfigVersion.cmake",
        "lib/cmake/OpenRecover/OpenRecoverTargets.cmake",
        exe,
        "share/doc/openrecover/README.md",
        "share/doc/openrecover/READONLY_POLICY.md",
    ]
    for rel in required:
        if not (prefix / rel).is_file():
            fail(problems, f"missing from the package: {rel}")
    archives = sorted(p.name for p in (prefix / "lib").glob("*.lib")) + sorted(p.name for p in (prefix / "lib").glob("*.a"))
    if len(archives) < 2:
        fail(problems, f"expected the core and miniz archives in lib/, found {archives}")
    profiles = prefix / "share" / "openrecover" / "profiles"
    if not any(profiles.glob("*.json")):
        fail(problems, f"the installed CLI looks for profiles in {profiles}; none are there")
    sidecar = prefix / "bin" / "tools" / "adb_sidecar"
    for name in ("sidecar.py", "policy.json"):
        if not (sidecar / name).is_file():
            fail(problems, f"missing sidecar payload: bin/tools/adb_sidecar/{name}")
    return archives


def check_export(cmake_dir, prefix, archives, problems):
    targets = (cmake_dir / "OpenRecoverTargets.cmake").read_text(encoding="utf-8")
    per_config = "\n".join(p.read_text(encoding="utf-8") for p in cmake_dir.glob("OpenRecoverTargets-*.cmake"))
    expected = re.findall(r"_cmake_expected_target IN ITEMS ([^)]+)", targets)
    listed = expected[0].split() if expected else []
    if "OpenRecover::core" not in listed:
        fail(problems, f"the package does not export OpenRecover::core, only {listed}")
    for name in re.findall(r"add_library\((\S+) STATIC IMPORTED\)", targets):
        if not name.startswith("OpenRecover::"):
            fail(problems, f"exported target {name} is not namespaced")
    for rel in dict.fromkeys(TARGET_FILE_RE.findall(per_config)):
        if not (prefix / rel).is_file():
            fail(problems, f"the export set imports {rel}, which is not installed")
    for name in archives:
        if name not in per_config:
            fail(problems, f"{name} is installed but not referenced by the export set")
    for text, where in ((targets, "OpenRecoverTargets.cmake"), (per_config, "the per-config targets file"),
                        ((cmake_dir / "OpenRecoverConfig.cmake").read_text(encoding="utf-8"), "OpenRecoverConfig.cmake")):
        for line in text.splitlines():
            if re.search(r"[A-Za-z]:[\\\\/]|/home/|/Users/|_deps/|build/", line) and "_IMPORT_PREFIX" not in line:
                fail(problems, f"{where} hardcodes a build-tree path: {line.strip()}")


def check_header_closure(include_dir, problems):
    root = include_dir
    pending = sorted(root.rglob("*.hpp")) + sorted(root.rglob("*.h"))
    seen = set()
    for header in pending:
        if header in seen:
            continue
        seen.add(header)
        text = header.read_text(encoding="utf-8", errors="replace")
        for name in INCLUDE_RE.findall(text):
            if name.startswith("openrecover/") or name.startswith("tl/"):
                if not (root / name).is_file():
                    fail(problems, f"{header.relative_to(root)}: quoted include {name} is not in the package")
            else:
                # Relative to the including header, the way the compiler resolves it.
                if not (header.parent / name).is_file() and not (root / name).is_file():
                    fail(problems, f"{header.relative_to(root)}: quoted include {name} does not resolve")


def check_umbrella(include_dir, problems):
    umbrella = include_dir / "openrecover" / "openrecover.hpp"
    if not umbrella.is_file():
        return
    text = umbrella.read_text(encoding="utf-8")
    headers = [m for m in INCLUDE_RE.findall(text) if m.startswith("openrecover/")]
    if len(headers) < 10:
        fail(problems, f"the umbrella header pulls in only {len(headers)} headers")
    # Every subsystem the public API exposes must be reachable from the umbrella.
    for needed in ("openrecover/io/block_device.hpp", "openrecover/io/output_sink.hpp",
                   "openrecover/fs/filesystem.hpp", "openrecover/carve/carve_engine.hpp",
                   "openrecover/report/report.hpp", "openrecover/partition/partition_scanner.hpp"):
        if needed not in headers:
            fail(problems, f"umbrella header is missing {needed}")
    for stray in ("fat32.hpp", "ntfs.hpp", "exfat_scanner.hpp"):
        for header in headers:
            if header.endswith(stray):
                fail(problems, f"umbrella header exposes the internal scanner {header}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmake", default="cmake")
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--skip-install", action="store_true", help="audit an already installed prefix")
    args = ap.parse_args()

    build_dir = pathlib.Path(args.build_dir).resolve()
    prefix = pathlib.Path(args.prefix).resolve()
    if not args.skip_install:
        install(args.cmake, build_dir, prefix)

    problems = []
    archives = check_layout(prefix, problems)
    check_export(prefix / "lib" / "cmake" / "OpenRecover", prefix, archives, problems)
    check_header_closure(prefix / "include", problems)
    check_umbrella(prefix / "include", problems)

    installed_headers = len(list((prefix / "include").rglob("*.hpp")))
    print(f"installed {installed_headers} public headers, {archives} archives under {prefix}")
    if problems:
        print("\n".join(problems))
        return 1
    print("package layout is consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
