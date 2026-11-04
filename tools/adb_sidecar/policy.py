#!/usr/bin/env python3
"""Read-only ADB policy shared by the Python sidecar and the C++ bridge.

The constants live in ``policy.json``, which is generated from the C++ policy at build
time (``adb_policy_dump``). Both implementations are checked against the same malicious
inputs by ``test_android_sidecar``.

This module never talks to a device and contains no command execution.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

PROTO = 1

REQUIRED_KEYS = (
    "schema",
    "proto",
    "max_remote_path_bytes",
    "max_prop_key_bytes",
    "max_serial_bytes",
    "max_stat_files",
    "sd_card_regex",
    "forbidden_remote_path_chars",
    "stat_format",
    "testdir_probe_yes",
    "testdir_probe_no",
    "denied_verbs",
    "allowed_ops",
    "shell_kinds",
    "malicious_remote_paths",
    "accepted_remote_path_samples",
)


class PolicyError(ValueError):
    """A device argument was rejected by the read-only policy."""


def load_policy(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict):
        raise PolicyError("policy.json must contain a JSON object")
    missing = [key for key in REQUIRED_KEYS if key not in policy]
    if missing:
        raise PolicyError("policy.json is missing: " + ", ".join(missing))
    if policy["proto"] != PROTO:
        raise PolicyError(f"unsupported sidecar protocol {policy['proto']!r}")
    return policy


def _short(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _utf8_length(text: str) -> int:
    try:
        return len(text.encode("utf-8", "strict"))
    except UnicodeEncodeError as exc:
        raise PolicyError("remote path is not valid UTF-8") from exc


def _shared_storage_prefix(path: str, policy: dict[str, Any]) -> bool:
    if path == "/sdcard" or path.startswith("/sdcard/"):
        return True
    if path == "/storage/emulated/0" or path.startswith("/storage/emulated/0/"):
        return True
    return re.match(policy["sd_card_regex"], path) is not None


def validate_remote_path(path: Any, policy: dict[str, Any]) -> None:
    if not isinstance(path, str):
        raise PolicyError("remote path must be a string")
    if not path:
        raise PolicyError("remote path is empty")
    if _utf8_length(path) > policy["max_remote_path_bytes"]:
        raise PolicyError("remote path exceeds the maximum byte length")
    forbidden = policy["forbidden_remote_path_chars"]
    for char in path:
        if ord(char) < 0x20 or ord(char) == 0x7F or char == "\\" or char in forbidden:
            raise PolicyError(
                "remote path contains a control character or shell metacharacter: " + _short(path)
            )
    if path.endswith("/"):
        raise PolicyError("remote path has a trailing slash: " + _short(path))
    if not _shared_storage_prefix(path, policy):
        raise PolicyError("remote path is outside shared storage: " + _short(path))
    for component in path[1:].split("/"):
        if not component:
            raise PolicyError("remote path has an empty component: " + _short(path))
        if component in (".", ".."):
            raise PolicyError("remote path contains a relative component: " + _short(path))


def validate_prop_key(key: Any, policy: dict[str, Any]) -> None:
    if not isinstance(key, str) or not re.fullmatch(
        rf"[A-Za-z0-9._-]{{1,{int(policy['max_prop_key_bytes'])}}}", key
    ):
        raise PolicyError("invalid property key")


def validate_serial(serial: Any, policy: dict[str, Any]) -> None:
    if not isinstance(serial, str) or not re.fullmatch(
        rf"[A-Za-z0-9._:-]{{1,{int(policy['max_serial_bytes'])}}}", serial
    ):
        raise PolicyError("invalid adb serial")


def shell_quote(arg: str) -> str:
    return "'" + arg.replace("'", "'\\''") + "'"


def build_shell_command(cmd: Any, policy: dict[str, Any]) -> str:
    if not isinstance(cmd, dict):
        raise PolicyError("cmd must be a JSON object")
    kind = cmd.get("kind")
    if kind == "GetProp":
        key = cmd.get("key")
        validate_prop_key(key, policy)
        return "getprop " + shell_quote(key)
    if kind == "ListFiles":
        directory = cmd.get("dir")
        validate_remote_path(directory, policy)
        return "find " + shell_quote(directory) + " -type f"
    if kind == "StatBatch":
        files = cmd.get("files")
        if not isinstance(files, list):
            raise PolicyError("stat files must be a list")
        if not 1 <= len(files) <= int(policy["max_stat_files"]):
            raise PolicyError("stat accepts 1..64 files")
        for path in files:
            validate_remote_path(path, policy)
        return (
            "stat -c "
            + shell_quote(policy["stat_format"])
            + "".join(" " + shell_quote(path) for path in files)
        )
    if kind == "TestDir":
        directory = cmd.get("dir")
        validate_remote_path(directory, policy)
        return "test -d " + shell_quote(directory)
    raise PolicyError("device command is not allowlisted")


def testdir_probe_command(cmd: dict[str, Any], policy: dict[str, Any]) -> str:
    """`test -d` wrapper for backends that expose stdout but not the exit status."""
    return (
        build_shell_command(cmd, policy)
        + " && echo "
        + policy["testdir_probe_yes"]
        + " || echo "
        + policy["testdir_probe_no"]
    )


def evaluate(requests: Iterable[Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for request in requests:
        try:
            if not isinstance(request, dict):
                raise PolicyError("request must be an object")
            op = request.get("op")
            value: Any = None
            if op == "validate_path":
                validate_remote_path(request.get("path"), policy)
            elif op == "validate_prop_key":
                validate_prop_key(request.get("key"), policy)
            elif op == "validate_serial":
                validate_serial(request.get("serial"), policy)
            elif op == "shell_command":
                value = build_shell_command(request.get("cmd"), policy)
            else:
                raise PolicyError("unknown policy operation")
            results.append({"ok": True, "value": value})
        except (PolicyError, KeyError, TypeError, ValueError) as exc:
            results.append({"ok": False, "error": str(exc)})
    return results


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path, help="generated policy.json")
    parser.add_argument(
        "--evaluate",
        type=Path,
        help="JSON array of policy requests; results are written to stdout as a JSON array",
    )
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")

    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError) as exc:
        print(f"policy: {exc}", file=sys.stderr)
        return 2
    if args.evaluate is None:
        print("policy: OK (use --evaluate <file> to run requests)", file=sys.stderr)
        return 0
    try:
        with open(args.evaluate, "r", encoding="utf-8") as handle:
            requests = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"policy: cannot read requests: {exc}", file=sys.stderr)
        return 2
    if not isinstance(requests, list):
        print("policy: requests must be a JSON array", file=sys.stderr)
        return 2
    json.dump(evaluate(requests, policy), sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
