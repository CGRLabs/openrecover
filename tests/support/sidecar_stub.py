#!/usr/bin/env python3
"""Protocol stub for PySidecarAdbTransport tests (no ppadb, no device).

Emulates the sidecar JSON Lines protocol against a fake shared-storage tree.
Environment:
  SIDECAR_STUB_ROOT   root containing sdcard/ (and storage/<mount>/) directories
  SIDECAR_STUB_MODE   ok | malformed | crash | hang | no-hello | bad-proto
  SIDECAR_STUB_DENY   remote path prefix that produces AccessDenied
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any


def send(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def fail(request_id: Any, code: str, message: str) -> None:
    send({"id": request_id, "ok": False, "error": {"code": code, "message": message}})


def to_local(root: Path, remote: str) -> Path | None:
    if remote in ("/sdcard", "/storage/emulated/0"):
        return root / "sdcard"
    if remote.startswith("/sdcard/"):
        return root / "sdcard" / remote[len("/sdcard/"):]
    if remote.startswith("/storage/emulated/0/"):
        return root / "sdcard" / remote[len("/storage/emulated/0/"):]
    if remote.startswith("/storage/") and len(remote) >= 18 and remote[18] == "/":
        mount = remote[9:18]
        return root / "storage" / mount / remote[19:]
    return None


def to_remote(root: Path, local: Path) -> str:
    sdcard = root / "sdcard"
    try:
        return "/sdcard/" + local.relative_to(sdcard).as_posix()
    except ValueError:
        pass
    storage = root / "storage"
    try:
        relative = local.relative_to(storage)
        parts = relative.parts
        return "/storage/" + parts[0] + "/" + "/".join(parts[1:])
    except (ValueError, IndexError):
        return local.as_posix()


def property_value(key: str) -> str:
    values = {
        "ro.product.model": os.environ.get("SIDECAR_STUB_MODEL", "Pixel_7"),
        "ro.product.manufacturer": "Google",
        "ro.build.version.release": "14",
        "ro.build.version.sdk": "34",
        "ro.crypto.state": "encrypted",
    }
    return values.get(key, "")


def denied(remote: str) -> bool:
    rule = os.environ.get("SIDECAR_STUB_DENY", "")
    return bool(rule) and (remote == rule or remote.startswith(rule + "/"))


def handle_shell(root: Path, request: dict[str, Any]) -> tuple[bool, Any]:
    cmd = request.get("cmd")
    if not isinstance(cmd, dict):
        return False, ("PolicyViolation", "cmd must be an object")
    kind = cmd.get("kind")
    if kind == "GetProp":
        return True, property_value(str(cmd.get("key")))
    if kind == "ListFiles":
        directory = str(cmd.get("dir"))
        if denied(directory):
            return False, ("AccessDenied", "find: Permission denied")
        local = to_local(root, directory)
        if local is None or not local.is_dir():
            return False, ("NotFound", "find: No such file or directory")
        files = sorted(
            to_remote(root, Path(dirpath) / name)
            for dirpath, _dirs, names in os.walk(local)
            for name in names
            if (Path(dirpath) / name).is_file()
        )
        return True, "".join(file + "\n" for file in files)
    if kind == "StatBatch":
        lines = []
        for remote in cmd.get("files", []):
            remote = str(remote)
            if denied(remote):
                continue
            local = to_local(root, remote)
            if local is None:
                continue
            try:
                stat = local.stat()
            except OSError:
                continue
            if local.is_file():
                lines.append(f"{stat.st_size}|{int(stat.st_mtime)}|{remote}")
        return True, "".join(line + "\n" for line in lines)
    if kind == "TestDir":
        directory = str(cmd.get("dir"))
        if denied(directory):
            return False, ("AccessDenied", "test: Permission denied")
        local = to_local(root, directory)
        return True, "1" if local is not None and local.is_dir() else "0"
    return False, ("PolicyViolation", "unknown shell kind")


def handle_pull(root: Path, request: dict[str, Any]) -> tuple[bool, Any]:
    remote = str(request.get("remote"))
    if denied(remote):
        return False, ("AccessDenied", "adb: failed to stat remote object: Permission denied")
    local = to_local(root, remote)
    if local is None or not local.is_file():
        return False, ("NotFound", f"adb: failed to stat remote object '{remote}'")
    destination = Path(str(request.get("local")))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(local, destination)
    return True, None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="OpenRecover sidecar test stub")
    parser.add_argument("--policy", required=True)
    parser.parse_args(argv)

    sys.stdin.reconfigure(encoding="utf-8", errors="strict", newline="\n")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")

    mode = os.environ.get("SIDECAR_STUB_MODE", "ok")
    root = Path(os.environ.get("SIDECAR_STUB_ROOT", ""))
    if mode == "hang":
        time.sleep(60)
        return 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            send({"ok": False, "error": {"code": "ProtocolError", "message": "bad request"}})
            continue
        if not isinstance(request, dict):
            send({"ok": False, "error": {"code": "ProtocolError", "message": "bad request"}})
            continue
        if request.get("op") == "hello":
            if mode == "no-hello":
                continue
            if mode == "bad-proto":
                send({"ok": True, "data": {"proto": 99, "ppadb": "stub-1"}})
                return 0
            send({"ok": True, "data": {"proto": 1, "ppadb": "stub-1"}})
            if mode == "crash":
                return 3
            continue
        if mode == "malformed":
            sys.stdout.write("this is not json {\n")
            sys.stdout.flush()
            continue
        request_id = request.get("id")
        try:
            op = request.get("op")
            if op == "list_devices":
                ok, data = True, [
                    {
                        "serial": "FAKE123",
                        "state": "device",
                        "state_raw": "device",
                        "model": "Pixel_7",
                        "product": "panther",
                        "transport_id": "1",
                    }
                ]
            elif op == "shell":
                ok, data = handle_shell(root, request)
            elif op == "pull":
                ok, data = handle_pull(root, request)
            else:
                ok, data = False, ("PolicyViolation", "operation is not allowlisted")
        except Exception as exc:  # stub robustness
            ok, data = False, ("IoError", str(exc))
        if ok:
            send({"id": request_id, "ok": True, "data": data})
        else:
            fail(request_id, data[0], data[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
