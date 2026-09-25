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
MAX_TOTAL_PACKETS = 64

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


def validate_total_packets(threads_count: int, packet_count: int) -> int:
    """Bound packets across all workers, not just per worker.

    MAX_THREADS * MAX_PACKET_COUNT is 320 packets, well above the small samples
    the diagnostic baseline describes, so the product is capped as well.
    """
    total = threads_count * packet_count
    if total > MAX_TOTAL_PACKETS:
        raise ValidationError(
            f"{threads_count} workers x {packet_count} packets = {total} packets, "
            f"which exceeds the total budget of {MAX_TOTAL_PACKETS}. "
            f"Lower --threads or --count."
        )
    return total


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool is not installed or not on PATH: {name}")


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
BLUETOOTHCTL_DEVICE_RE = re.compile(r"^\[NEW\]\s+Device\s+([0-9A-Fa-f:]{17})(?:\s+(.*))?$")

BLUETOOTH_SYSFS = "/sys/class/bluetooth"
DEFAULT_SCAN_SECONDS = 8
DEFAULT_SCAN_TIMEOUT = 30
WORKER_TIMEOUT = 300


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


L2PING_REPLY_RE = re.compile(r"^(\d+) bytes from \S+ id (\d+) time ([\d.]+)ms")
L2PING_SUMMARY_RE = re.compile(r"^(\d+) sent, (\d+) received, (\d+)% loss")
L2PING_UNSUPPORTED_MARKER = "Peer doesn't support Echo packets"
L2PING_FAILURE_MARKER = "Can't create socket"


def parse_l2ping_output(output: str) -> dict[str, object]:
    """Summarise l2ping stdout.

    Line shapes come from the format strings in the l2ping binary:
      "Ping: %s from %s (data size %d) ..."
      "%d bytes from %s id %d time %.2fms"
      "no response from %s: id %d"
      "%d sent, %d received, %d%% loss"
    A peer with no L2CAP echo channel reports "Peer doesn't support Echo
    packets". "Can't create socket" means l2ping never sent anything, which
    is a permissions failure rather than a measurement.
    """
    times: list[float] = []
    sent = received = loss = None
    unsupported = False
    failed = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if L2PING_UNSUPPORTED_MARKER in line:
            unsupported = True
            continue
        if L2PING_FAILURE_MARKER in line:
            failed = True
            continue

        reply = L2PING_REPLY_RE.match(line)
        if reply:
            times.append(float(reply.group(3)))
            continue

        summary = L2PING_SUMMARY_RE.match(line)
        if summary:
            sent, received, loss = (int(summary.group(index)) for index in (1, 2, 3))

    result: dict[str, object] = {
        "sent": sent,
        "received": len(times) if received is None else received,
        "loss_percent": loss,
        "unsupported_echo": unsupported,
        "failed_to_start": failed,
    }
    if times:
        result["rtt_ms_min"] = round(min(times), 2)
        result["rtt_ms_avg"] = round(sum(times) / len(times), 2)
        result["rtt_ms_max"] = round(max(times), 2)
    return result


def format_summary(summary: dict[str, object]) -> str:
    if summary["failed_to_start"]:
        return (
            "l2ping could not open the Bluetooth socket; nothing was sent. "
            "Run as root or grant CAP_NET_RAW/CAP_NET_ADMIN."
        )
    if summary["unsupported_echo"]:
        return "Peer does not support L2CAP echo packets; no diagnostics possible."

    if not summary.get("rtt_ms_avg"):
        return "No replies received."

    return (
        f"Replies: {summary['received']}/{summary['sent']} "
        f"({summary['loss_percent']}% loss) | "
        f"RTT min {summary['rtt_ms_min']} ms, "
        f"avg {summary['rtt_ms_avg']} ms, "
        f"max {summary['rtt_ms_max']} ms"
    )


def run_worker(command: list[str], results: list[str], lock: threading.Lock) -> None:
    """Run one l2ping worker and collect its output.

    l2ping exits 0 even when every packet is lost, so the return code is not a
    usable signal; the output has to be parsed instead.
    """
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=WORKER_TIMEOUT,
    )
    output = f"{completed.stdout}{completed.stderr}"
    with lock:
        results.append(output)


def run_l2ping_workers(command: list[str], threads_count: int) -> dict[str, object]:
    """Run bounded l2ping workers and return an aggregated summary."""
    require_tool("l2ping")
    results: list[str] = []
    lock = threading.Lock()

    threads = [
        threading.Thread(target=run_worker, args=(command, results, lock))
        for _ in range(threads_count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    return merge_summaries([parse_l2ping_output(output) for output in results])


def merge_summaries(summaries: list[dict[str, object]]) -> dict[str, object]:
    """Combine per-worker summaries into one."""
    merged: dict[str, object] = {
        "sent": 0,
        "received": 0,
        "loss_percent": None,
        "unsupported_echo": any(item["unsupported_echo"] for item in summaries),
        "failed_to_start": bool(summaries) and all(item["failed_to_start"] for item in summaries),
        "workers": len(summaries),
    }

    rtt_values: list[float] = []
    averages: list[float] = []
    for item in summaries:
        if item["sent"] is not None:
            merged["sent"] = int(merged["sent"]) + int(item["sent"])
        merged["received"] = int(merged["received"]) + int(item["received"])
        for key in ("rtt_ms_min", "rtt_ms_max"):
            if key in item:
                rtt_values.append(float(item[key]))
        if "rtt_ms_avg" in item:
            averages.append(float(item["rtt_ms_avg"]))

    if rtt_values:
        merged["rtt_ms_min"] = round(min(rtt_values), 2)
        merged["rtt_ms_max"] = round(max(rtt_values), 2)
        merged["rtt_ms_avg"] = round(sum(averages) / len(averages), 2)

    sent = int(merged["sent"])
    if sent:
        merged["loss_percent"] = round(
            100 * (sent - int(merged["received"])) / sent
        )
    return merged

def print_result(summary: dict[str, object], json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(summary))
        return
    print("[result]", format_summary(summary))



def print_dry_run(
    command: list[str],
    threads_count: int,
    total_packets: int,
    json_output: bool = False,
) -> None:
    if json_output:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "threads": threads_count,
                    "total_packets": total_packets,
                    "command": command,
                }
            )
        )
        return

    print("[dry-run] No packets were sent.")
    print(f"[dry-run] Workers: {threads_count}")
    print(f"[dry-run] Total packets if executed: {total_packets} (budget {MAX_TOTAL_PACKETS})")
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

    total_packets = validate_total_packets(threads_count, args.count)

    if not args.execute:
        print_dry_run(command, threads_count, total_packets, json_output=args.json)
        return 0

    if not args.confirm_authorized:
        raise ValidationError("Execution requires --confirm-authorized.")

    summary = run_l2ping_workers(command, threads_count)
    print_result(summary, json_output=args.json)
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

    total_packets = validate_total_packets(threads_count, packet_count)

    phrase = input("Type 'authorized' to execute, or press Enter for dry-run > ").strip()
    if phrase != "authorized":
        print_dry_run(command, threads_count, total_packets)
        return 0

    summary = run_l2ping_workers(command, threads_count)
    print_result(summary)
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
