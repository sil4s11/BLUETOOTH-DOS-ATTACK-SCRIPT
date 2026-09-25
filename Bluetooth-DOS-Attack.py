#!/usr/bin/env python3
"""Safety-first Bluetooth L2CAP diagnostic helper.

The original script launched unbounded flood commands. This version keeps the
interactive workflow, but defaults to dry-run mode and only runs bounded
diagnostic pings after explicit authorization.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Iterable


DEFAULT_INTERFACE = "hci0"
DEFAULT_PACKAGE_SIZE = 44
DEFAULT_THREADS = 1
DEFAULT_PACKET_COUNT = 4
DEFAULT_TIMEOUT = 5
DEFAULT_DELAY = 1

MAX_PACKAGE_SIZE = 600
MAX_THREADS = 16
MAX_PACKET_COUNT = 20
MAX_TIMEOUT = 30
MAX_DELAY = 10

VERSION = "2.0.0"

MAC_ADDRESS_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
INTERFACE_RE = re.compile(r"^hci[0-9]{1,3}$")


class ValidationError(ValueError):
    """Raised when user supplied input is not safe to run."""


def print_logo() -> None:
    print("Bluetooth L2CAP Diagnostic Helper")


def is_valid_mac(value: str) -> bool:
    return bool(MAC_ADDRESS_RE.fullmatch(value.strip()))


def normalize_mac(value: str) -> str:
    mac = value.strip().upper()
    if not is_valid_mac(mac):
        raise ValidationError(f"Invalid Bluetooth MAC address: {value!r}")
    return mac


def validate_interface(value: str) -> str:
    interface = value.strip()
    if not interface:
        raise ValidationError("Bluetooth interface must not be empty.")
    if not INTERFACE_RE.fullmatch(interface):
        raise ValidationError(f"Invalid Bluetooth interface: {value!r}")
    return interface


def validate_int_range(name: str, value: int, minimum: int, maximum: int) -> int:
    if value < minimum or value > maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}")
    return value


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool is not installed or not on PATH: {name}")


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
BLUETOOTHCTL_DEVICE_RE = re.compile(r"^\[NEW\]\s+Device\s+([0-9A-Fa-f:]{17})(?:\s+(.*))?$")

BLUETOOTH_SYSFS = "/sys/class/bluetooth"
DEFAULT_SCAN_SECONDS = 8
DEFAULT_SCAN_TIMEOUT = 30


def parse_scan_output(output: str) -> list[tuple[str, str]]:
    """Parse `bluetoothctl scan on` output into (mac, name) pairs.

    hcitool was removed from BlueZ 5.87, so discovery goes over D-Bus instead.
    Only "[NEW] Device" lines carry an address and name. Two other line shapes
    are deliberately skipped: the LE/BREDR object lines, which repeat a device
    once per transport, and "[CHG] Device" lines, which report RSSI
    ("[CHG] Device 74:E9:.. RSSI: 0xffffffb8 (-72)") and would otherwise be
    mistaken for its name.
    """
    devices: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = ANSI_ESCAPE_RE.sub("", raw_line).strip()
        if not line:
            continue

        match = BLUETOOTHCTL_DEVICE_RE.match(line)
        if not match:
            continue

        mac = normalize_mac(match.group(1))
        name = (match.group(2) or "").strip()
        if not name:
            name = "Unknown"
        devices.setdefault(mac, name)

    return list(devices.items())



def scan_devices(interface: str = DEFAULT_INTERFACE) -> list[tuple[str, str]]:
    """Discover nearby devices over D-Bus.

    hcitool was removed from BlueZ 5.87, so scanning goes through bluetoothctl,
    which talks to bluetoothd over D-Bus and needs no raw HCI socket.

    `scan on` runs on bluetoothctl's default controller, so no `select` is
    issued: bluetoothctl addresses controllers by BD_ADDR or alias rather than
    by the hciN kernel name, and passing `select` together with `scan` in one
    argv also keeps the client alive past --timeout.
    """
    require_tool("bluetoothctl")
    safe_interface = validate_interface(interface)
    require_adapter(safe_interface)

    result = subprocess.run(
        ["bluetoothctl", "--timeout", str(DEFAULT_SCAN_SECONDS), "scan", "on"],
        check=True,
        capture_output=True,
        text=True,
        timeout=DEFAULT_SCAN_TIMEOUT,
    )
    return parse_scan_output(result.stdout)


def require_adapter(interface: str) -> None:
    root = Path(BLUETOOTH_SYSFS)
    if (root / interface).is_dir():
        return

    available = sorted(entry.name for entry in root.iterdir() if entry.name.startswith("hci")) if root.is_dir() else []
    raise RuntimeError(
        f"Bluetooth adapter {interface!r} not found. "
        f"Available: {', '.join(available) if available else 'none'}"
    )


def build_l2ping_command(
    target_addr: str,
    package_size: int,
    packet_count: int,
    interface: str = DEFAULT_INTERFACE,
    timeout: int = DEFAULT_TIMEOUT,
    delay: int = DEFAULT_DELAY,
) -> list[str]:
    target = normalize_mac(target_addr)
    safe_interface = validate_interface(interface)
    size = validate_int_range("Package size", package_size, 1, MAX_PACKAGE_SIZE)
    count = validate_int_range("Packet count", packet_count, 1, MAX_PACKET_COUNT)
    timeout_value = validate_int_range("Timeout", timeout, 1, MAX_TIMEOUT)
    delay_value = validate_int_range("Delay", delay, 0, MAX_DELAY)

    return [
        "l2ping",
        "-i",
        safe_interface,
        "-s",
        str(size),
        "-c",
        str(count),
        "-t",
        str(timeout_value),
        "-d",
        str(delay_value),
        target,
    ]


def print_devices(devices: Iterable[tuple[str, str]], json_output: bool = False) -> None:
    device_list = list(devices)
    if json_output:
        print(json.dumps([{"id": index, "mac": mac, "name": name} for index, (mac, name) in enumerate(device_list)]))
        return

    print("| id | mac address       | device name |")
    print("|----|-------------------|-------------|")
    for index, (mac, name) in enumerate(device_list):
        print(f"| {index:<2} | {mac:<17} | {name} |")


def resolve_target(value: str, devices: list[tuple[str, str]]) -> str:
    candidate = value.strip()
    if candidate.isdigit():
        index = int(candidate)
        try:
            return devices[index][0]
        except IndexError as exc:
            raise ValidationError(f"Device id is out of range: {candidate}") from exc

    return normalize_mac(candidate)


def prompt_int(prompt: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = input(f"{prompt} [{default}] > ").strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValidationError(f"{prompt} must be an integer") from exc
    return validate_int_range(prompt, value, minimum, maximum)


def run_worker(command: list[str]) -> None:
    subprocess.run(command, check=False)


def run_l2ping_workers(command: list[str], threads_count: int) -> None:
    require_tool("l2ping")
    threads = []
    for _ in range(threads_count):
        thread = threading.Thread(target=run_worker, args=(command,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def print_dry_run(command: list[str], threads_count: int, json_output: bool = False) -> None:
    if json_output:
        print(json.dumps({"dry_run": True, "threads": threads_count, "command": command}))
        return

    print("[dry-run] No packets were sent.")
    print(f"[dry-run] Workers: {threads_count}")
    print("[dry-run] Command:", " ".join(command))


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Bluetooth L2CAP diagnostic helper. Dry-run is the default; "
            "execution requires --execute and --confirm-authorized."
        )
    )
    parser.add_argument("--scan", action="store_true", help="Scan nearby Bluetooth devices and exit.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON for scan and dry-run output.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--target", help="Bluetooth MAC address to check.")
    parser.add_argument("--interface", default=DEFAULT_INTERFACE, help="Bluetooth interface to use.")
    parser.add_argument(
        "--package-size",
        type=int,
        default=DEFAULT_PACKAGE_SIZE,
        help=f"L2CAP payload size, 1-{MAX_PACKAGE_SIZE} bytes.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Worker count, 1-{MAX_THREADS}.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_PACKET_COUNT,
        help=f"Packets per worker, 1-{MAX_PACKET_COUNT}.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Response timeout in seconds, 1-{MAX_TIMEOUT}.",
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=DEFAULT_DELAY,
        help=f"Delay between packets in seconds, 0-{MAX_DELAY}.",
    )
    parser.add_argument("--execute", action="store_true", help="Run the bounded diagnostic command.")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm that you own the target or have written permission to test it.",
    )
    return parser


def run_from_args(args: argparse.Namespace) -> int:
    if args.scan and not args.target:
        devices = scan_devices(args.interface)
        if devices:
            print_devices(devices, json_output=args.json)
        else:
            if args.json:
                print("[]")
            else:
                print("No Bluetooth devices found.")
        return 0

    if not args.target:
        return run_interactive(args.interface)

    threads_count = validate_int_range("Threads count", args.threads, 1, MAX_THREADS)
    command = build_l2ping_command(
        args.target,
        args.package_size,
        args.count,
        args.interface,
        timeout=args.timeout,
        delay=args.delay,
    )

    if not args.execute:
        print_dry_run(command, threads_count, json_output=args.json)
        return 0

    if not args.confirm_authorized:
        raise ValidationError("Execution requires --confirm-authorized.")

    run_l2ping_workers(command, threads_count)
    return 0


def run_interactive(interface: str = DEFAULT_INTERFACE) -> int:
    print_logo()
    print()
    print("Use this tool only on Bluetooth devices you own or are explicitly authorized to test.")
    print("Interactive mode defaults to dry-run unless you type the authorization phrase.")
    print()

    if input("Do you agree? (y/n) > ").strip().lower() != "y":
        print("Aborted.")
        return 0

    devices = scan_devices(interface)
    if not devices:
        print("No Bluetooth devices found. You can rerun with --target AA:BB:CC:DD:EE:FF.")
        return 1

    print_devices(devices)
    target = resolve_target(input("Target id or MAC > "), devices)
    package_size = prompt_int("Package size", DEFAULT_PACKAGE_SIZE, 1, MAX_PACKAGE_SIZE)
    threads_count = prompt_int("Threads count", DEFAULT_THREADS, 1, MAX_THREADS)
    packet_count = prompt_int("Packet count", DEFAULT_PACKET_COUNT, 1, MAX_PACKET_COUNT)
    timeout = prompt_int("Timeout", DEFAULT_TIMEOUT, 1, MAX_TIMEOUT)
    delay = prompt_int("Delay", DEFAULT_DELAY, 0, MAX_DELAY)
    command = build_l2ping_command(
        target,
        package_size,
        packet_count,
        interface,
        timeout=timeout,
        delay=delay,
    )

    phrase = input("Type 'authorized' to execute, or press Enter for dry-run > ").strip()
    if phrase != "authorized":
        print_dry_run(command, threads_count)
        return 0

    run_l2ping_workers(command, threads_count)
    return 0


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()
    return run_from_args(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        raise SystemExit(130)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() or (exc.stdout or "").strip()
        print(f"Error: {' '.join(exc.cmd)} exited with status {exc.returncode}.", file=sys.stderr)
        if detail:
            print(f"Output: {detail}", file=sys.stderr)
        raise SystemExit(1)
    except (RuntimeError, ValidationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
