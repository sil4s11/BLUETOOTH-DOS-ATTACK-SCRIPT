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
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


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


def parse_scan_output(output: str) -> list[tuple[str, str]]:
    devices: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("scanning"):
            continue

        parts = line.split(maxsplit=1)
        if not parts:
            continue

        mac = parts[0]
        if not is_valid_mac(mac):
            continue

        name = parts[1] if len(parts) > 1 else "Unknown"
        devices.append((normalize_mac(mac), name))

    return devices


def scan_devices() -> list[tuple[str, str]]:
    require_tool("hcitool")
    result = subprocess.run(
        ["hcitool", "scan"],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_scan_output(result.stdout)


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
        devices = scan_devices()
        if devices:
            print_devices(devices, json_output=args.json)
        else:
            if args.json:
                print("[]")
            else:
                print("No Bluetooth devices found.")
        return 0

    if not args.target:
        return run_interactive()

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


def run_interactive() -> int:
    print_logo()
    print()
    print("Use this tool only on Bluetooth devices you own or are explicitly authorized to test.")
    print("Interactive mode defaults to dry-run unless you type the authorization phrase.")
    print()

    if input("Do you agree? (y/n) > ").strip().lower() != "y":
        print("Aborted.")
        return 0

    devices = scan_devices()
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
    command = build_l2ping_command(target, package_size, packet_count, timeout=timeout, delay=delay)

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
    except (RuntimeError, ValidationError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
