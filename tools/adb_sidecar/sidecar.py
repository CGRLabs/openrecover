#!/usr/bin/env python3
"""JSON Lines supervisor for the optional pure-python-adb backend.

The sidecar exposes exactly three operations (list_devices, shell, pull) and only the
four allowlisted shell kinds from the shared policy. It has no pass-through shell and
no operation that can modify the device; every device argument is validated with
``policy.py`` before a command string is constructed.

Requests on stdin, one JSON object per line. Responses on stdout, one JSON object per
line. stderr is reserved for logs. See docs/SPEC.md section 6.2.3.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import policy as adb_policy  # noqa: E402

PROTO = 1


def send(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def error_payload(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message}}


def classify(exc: BaseException) -> tuple[str, str]:
    text = str(exc).strip() or exc.__class__.__name__
    lowered = text.lower()
    if "unauthorized" in lowered:
        return "DeviceUnauthorized", text
    if "offline" in lowered:
        return "DeviceOffline", text
    if "permission denied" in lowered or "operation not permitted" in lowered:
        return "AccessDenied", text
    if "timed out" in lowered or "timeout" in lowered:
        return "Timeout", text
    if "not found" in lowered or "no such" in lowered or "does not exist" in lowered:
        return "NotFound", text
    return "IoError", text


def load_ppadb() -> tuple[Any, str]:
    """Imports ppadb and returns (Client class, version). Raises ImportError."""
    from ppadb.client import Client  # type: ignore[import-not-found]

    version = "unknown"
    try:
        from importlib.metadata import version as package_version

        version = package_version("pure-python-adb")
    except Exception:
        pass
    return Client, version


def raw_host_devices(client: Any) -> dict[str, str] | None:
    """Best-effort serial -> state map, including unauthorized/offline devices."""
    for name in ("host_devices", "list_devices"):
        method = getattr(client, name, None)
        if not callable(method):
            continue
        try:
            raw = method()
        except Exception:
            continue
        if isinstance(raw, dict):
            return {str(serial): str(state) for serial, state in raw.items()}
        if isinstance(raw, list):
            pairs: dict[str, str] = {}
            for item in raw:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    pairs[str(item[0])] = str(item[1])
            if pairs:
                return pairs
    return None


def list_devices(client: Any) -> list[dict[str, str]]:
    raw = raw_host_devices(client)
    if raw is not None:
        return [
            {
                "serial": serial,
                "state": state,
                "state_raw": state,
                "model": "",
                "product": "",
                "transport_id": "",
            }
            for serial, state in raw.items()
        ]
    devices = []
    for device in client.devices():
        state = "device"
        try:
            get_state = getattr(device, "get_state", None)
            if callable(get_state):
                state = str(get_state())
        except Exception:
            state = "device"
        devices.append(
            {
                "serial": str(device.serial),
                "state": state,
                "state_raw": state,
                "model": "",
                "product": "",
                "transport_id": "",
            }
        )
    return devices


def require_device(client: Any, serial: str) -> Any:
    raw = raw_host_devices(client)
    if raw is not None and serial in raw:
        state = raw[serial]
        if state != "device":
            raise PermissionError(f"device {serial} is {state}; accept the USB debugging prompt")
    for device in client.devices():
        if str(device.serial) == serial:
            return device
    raise LookupError(f"device not found: {serial}")


def handle_shell(client: Any, request: dict[str, Any], policy: dict[str, Any]) -> str:
    serial = request.get("serial")
    adb_policy.validate_serial(serial, policy)
    cmd = request.get("cmd")
    if not isinstance(cmd, dict):
        raise adb_policy.PolicyError("cmd must be a JSON object")
    command = adb_policy.build_shell_command(cmd, policy)
    device = require_device(client, serial)

    if cmd.get("kind") == "TestDir":
        probe = adb_policy.testdir_probe_command(cmd, policy)
        output = device.shell(probe) or ""
        if policy["testdir_probe_yes"] in output:
            return "1"
        if policy["testdir_probe_no"] in output:
            return "0"
        raise RuntimeError("test -d returned neither the present nor the absent marker")

    output = device.shell(command)
    return "" if output is None else str(output)


def handle_pull(client: Any, request: dict[str, Any], policy: dict[str, Any]) -> None:
    serial = request.get("serial")
    adb_policy.validate_serial(serial, policy)
    remote = request.get("remote")
    adb_policy.validate_remote_path(remote, policy)
    local = request.get("local")
    if not isinstance(local, str) or not local:
        raise adb_policy.PolicyError("local pull destination is missing")
    if "\x00" in local:
        raise adb_policy.PolicyError("local pull destination contains NUL")
    device = require_device(client, serial)
    pulled = device.pull(remote, local)
    if pulled is False:
        raise RuntimeError(f"adb pull failed for {remote}")


def handle_request(
    client: Any, request: dict[str, Any], policy: dict[str, Any]
) -> tuple[bool, Any]:
    if client is None:
        raise RuntimeError("sidecar is not connected to the ADB server")
    op = request.get("op")
    if op == "list_devices":
        return True, list_devices(client)
    if op == "shell":
        return True, handle_shell(client, request, policy)
    if op == "pull":
        handle_pull(client, request, policy)
        return True, None
    raise adb_policy.PolicyError("operation is not allowlisted")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="OpenRecover read-only adb sidecar")
    parser.add_argument("--policy", required=True, type=Path, help="generated policy.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5037)
    args = parser.parse_args(argv)

    sys.stdin.reconfigure(encoding="utf-8", errors="strict", newline="\n")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")

    try:
        policy = adb_policy.load_policy(args.policy)
    except Exception as exc:
        send(error_payload("ProtocolError", f"cannot load the shared policy: {exc}"))
        return 2

    client = None
    ppadb_version = "unknown"
    connect_error: BaseException | None = None
    try:
        client_class, ppadb_version = load_ppadb()
        client = client_class(host=args.host, port=args.port)
    except BaseException as exc:  # ImportError or a connection failure
        connect_error = exc

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            send(error_payload("ProtocolError", f"malformed request line: {exc}"))
            continue
        if not isinstance(request, dict):
            send(error_payload("ProtocolError", "request must be a JSON object"))
            continue

        if request.get("op") == "hello":
            if connect_error is not None:
                if isinstance(connect_error, ImportError):
                    send(
                        error_payload(
                            "Unsupported",
                            "pure-python-adb is not installed; run: pip install -r "
                            "tools/adb_sidecar/requirements.txt",
                        )
                    )
                else:
                    code, message = classify(connect_error)
                    send(error_payload(code, f"cannot reach the ADB server: {message}"))
                continue
            send({"ok": True, "data": {"proto": PROTO, "ppadb": ppadb_version}})
            continue

        request_id = request.get("id")
        if isinstance(request_id, bool) or not isinstance(request_id, int) or request_id < 0:
            send(error_payload("ProtocolError", "request id is required"))
            continue

        try:
            ok, data = handle_request(client, request, policy)
            send({"id": request_id, "ok": ok, "data": data})
        except adb_policy.PolicyError as exc:
            send({"id": request_id, "ok": False,
                  "error": {"code": "PolicyViolation", "message": str(exc)}})
        except Exception as exc:
            code, message = classify(exc)
            send({"id": request_id, "ok": False,
                  "error": {"code": code, "message": message}})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
