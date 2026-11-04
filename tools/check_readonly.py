#!/usr/bin/env python3
"""Static read-only policy gate for OpenRecover (spec section 3.6)."""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

SCAN_DIRS = ("libopenrecover", "cli")
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".ipp"}

OUTPUT_SINK = "libopenrecover/src/io/output_sink.cpp"
WIN32_REAL = "libopenrecover/src/io/win/win32_api_real.cpp"
LINUX_IO = "libopenrecover/src/io/linux/*.cpp"
ADB_POLICY = "libopenrecover/src/android/adb_command_policy.cpp"
# The transport parses the device state named "sideload" from `adb devices -l`; it
# never invokes that (or any other) mutating verb.
ADB_TRANSPORT = "libopenrecover/src/android/adb_transport.cpp"
# Only child-process stdio pipes are written here (sidecar JSON Lines); no file or
# device handle is ever obtained in this file.
CHILD_PROCESS = "libopenrecover/src/android/child_process.cpp"


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    allowed: tuple[str, ...]


def _r(name: str, regex: str, *allowed: str) -> Rule:
    return Rule(name, re.compile(regex), tuple(allowed))


RULES: tuple[Rule, ...] = (
    # Win32 mutation APIs
    _r("win32-write", r"\bWriteFile(Ex)?\b", OUTPUT_SINK, CHILD_PROCESS),
    _r("win32-write", r"\bSetEndOfFile\b", OUTPUT_SINK),
    _r("win32-write", r"\bSetFileInformationByHandle\b", OUTPUT_SINK),
    _r("win32-write", r"\bDeleteFile", OUTPUT_SINK),
    _r("win32-write", r"\bMoveFile", OUTPUT_SINK),
    _r("win32-write", r"\bFlushFileBuffers\b", OUTPUT_SINK),
    _r("win32-create", r"\b(CREATE_ALWAYS|CREATE_NEW|OPEN_ALWAYS|TRUNCATE_EXISTING)\b", OUTPUT_SINK),
    # POSIX / C / C++ mutation APIs
    _r("posix-write", r"\bpwrite(64)?\b", OUTPUT_SINK),
    _r("posix-write", r"\bwrite\s*\(", OUTPUT_SINK, CHILD_PROCESS),
    _r("posix-write", r"\bftruncate\b", OUTPUT_SINK),
    _r("posix-write", r"\bfsync\b", OUTPUT_SINK),
    _r("posix-write", r"\bfwrite\b", OUTPUT_SINK),
    _r("posix-write", r"\b_?w?fopen\b", OUTPUT_SINK),
    _r("posix-write", r"std::(basic_)?ofstream", OUTPUT_SINK),
    _r("posix-write", r"std::(basic_)?fstream", OUTPUT_SINK),
    _r("posix-write", r"\bO_WRONLY\b", OUTPUT_SINK),
    _r("posix-write", r"\bO_RDWR\b", OUTPUT_SINK),
    _r("posix-write", r"\bO_CREAT\b", OUTPUT_SINK),
    _r("posix-write", r"\bO_TRUNC\b", OUTPUT_SINK),
    # Destructive control codes: nowhere
    _r("destructive-ioctl", r"FSCTL_(LOCK|DISMOUNT|SET_|DELETE)"),
    _r("destructive-ioctl", r"IOCTL_DISK_(SET|FORMAT|GROW|DELETE)"),
    _r("destructive-ioctl", r"IOCTL_STORAGE_EJECT"),
    # Write access rights: nowhere
    _r("write-access", r"\bGENERIC_WRITE\b"),
    _r("write-access", r"\bGENERIC_ALL\b"),
    _r("write-access", r"\bFILE_WRITE_DATA\b"),
    _r("write-access", r"\bFILE_APPEND_DATA\b"),
    # Raw control-code entry points
    _r("raw-ioctl", r"\bDeviceIoControl\b", WIN32_REAL),
    _r("raw-ioctl", r"\bioctl\s*\(", LINUX_IO),
    # Driver installation / device state changes: nowhere
    _r("driver-install", r"\bDIF_[A-Z_]+\b"),
    _r("driver-install", r"\bSetupDiCallClassInstaller\b"),
    _r("driver-install", r"\bSetupDiSetClassInstallParams\w*\b"),
    _r("driver-install", r"\bSetupDiInstallDevice\b"),
    _r("driver-install", r"\bSetupDiRemoveDevice\b"),
    _r("driver-install", r"\bUpdateDriverForPlugAndPlayDevices\w*\b"),
    _r("driver-install", r"\bDiInstallDr\w*\b"),
    # Mutating adb verbs as string literals. The full deny-list may only be declared
    # in the policy file; "sideload" is also a device state parsed by the transport.
    _r("adb-verb",
       r"\"(push|install|uninstall|rm|mv|cp|su|root|unroot|remount|reboot|"
       r"disable-verity|enable-verity|settings|pm|am|dd|mkfs|format|wipe|restorecon|"
       r"chmod|chown|ln|touch|mkdir|rmdir|setprop|svc|input|stop|start|kill|fastboot|"
       r"shell-with-su)\"",
       ADB_POLICY),
    _r("adb-verb", r"\"sideload\"", ADB_POLICY, ADB_TRANSPORT),
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    text: str
    allowed: tuple[str, ...]

    def __str__(self) -> str:
        where = ", ".join(self.allowed) if self.allowed else "nowhere"
        return f"{self.path}:{self.line}: [{self.rule}] '{self.text}' (allowed in: {where})"


def _is_allowed(rel: str, allowed: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(rel, pat) for pat in allowed)


def iter_sources(root: Path):
    for d in SCAN_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES:
                yield p


def scan(root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in iter_sources(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                for m in rule.pattern.finditer(line):
                    if not _is_allowed(rel, rule.allowed):
                        violations.append(Violation(rel, lineno, rule.name, m.group(0), rule.allowed))
    return violations


def selftest() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="or_readonly_selftest_") as tmp:
        root = Path(tmp)
        src = root / "libopenrecover" / "src"
        (src / "io" / "linux").mkdir(parents=True)
        (src / "io" / "win").mkdir(parents=True)
        (root / "cli" / "src").mkdir(parents=True)

        clean = src / "clean.cpp"
        clean.write_text("int f(int ioctl_like) { return ioctl_like; }\n", encoding="utf-8")
        if scan(root):
            failures.append("clean tree reported violations")

        planted = src / "planted.cpp"
        planted.write_text("void g(void* h) { WriteFile(h, 0, 0, 0, 0); }\n", encoding="utf-8")
        v = scan(root)
        if not any(x.path.endswith("planted.cpp") and "WriteFile" in x.text for x in v):
            failures.append("planted WriteFile( was not detected")
        planted.unlink()

        sink = src / "io" / "output_sink.cpp"
        sink.write_text("void s(void* h) { WriteFile(h, 0, 0, 0, 0); }\n", encoding="utf-8")
        if scan(root):
            failures.append("WriteFile in output_sink.cpp was wrongly rejected")

        lin = src / "io" / "linux" / "dev.cpp"
        lin.write_text("int q(int fd) { return ioctl(fd, 0); }\n", encoding="utf-8")
        if scan(root):
            failures.append("ioctl( in src/io/linux was wrongly rejected")

        cases = {
            "cli/src/a.cpp": "auto f = O_RDWR;\n",
            "libopenrecover/src/b.cpp": "unsigned c = FSCTL_LOCK_VOLUME;\n",
            "libopenrecover/src/c.cpp": "unsigned a = GENERIC_WRITE;\n",
            "libopenrecover/src/d.cpp": "const char* v = \"push\";\n",
            "libopenrecover/src/d2.cpp": "const char* v = \"remount\";\n",
            "libopenrecover/src/e.cpp": "x = DeviceIoControl(h);\n",
            "libopenrecover/src/f.cpp": "std::ofstream o(p);\n",
            "libopenrecover/src/g.cpp": "SetupDiCallClassInstaller(DIF_REMOVE, s, d);\n",
            "libopenrecover/src/io/output_sink.cpp": "unsigned c = IOCTL_DISK_SET_DRIVE_LAYOUT_EX;\n",
        }
        for rel, body in cases.items():
            p = root / rel
            p.write_text(body, encoding="utf-8")
            if not any(x.path == rel for x in scan(root)):
                failures.append(f"planted token in {rel} not detected: {body.strip()}")
            p.unlink()

    if failures:
        for f in failures:
            print(f"SELFTEST FAIL: {f}", file=sys.stderr)
        return 1
    print("check_readonly selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                    help="repository root (default: parent of tools/)")
    ap.add_argument("--selftest", action="store_true", help="verify the checker detects planted tokens")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    root = args.root.resolve()
    if not (root / "libopenrecover").is_dir():
        print(f"error: {root} does not contain libopenrecover/", file=sys.stderr)
        return 2
    violations = scan(root)
    for v in violations:
        print(v, file=sys.stderr)
    if violations:
        print(f"check_readonly: {len(violations)} violation(s)", file=sys.stderr)
        return 1
    print(f"check_readonly: OK ({sum(1 for _ in iter_sources(root))} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
