# Bluetooth L2CAP Diagnostic Helper

Small Linux CLI for authorized Bluetooth L2CAP echo diagnostics. It can scan nearby devices, build bounded `l2ping` checks, and print dry-run commands before anything is sent.

This project is intended for devices you own or have written permission to test.

## What changed

- Dry-run is the default behavior.
- Live execution requires both `--execute` and `--confirm-authorized`.
- `l2ping` runs are bounded with `--count`; flood mode is not used.
- Bluetooth MAC addresses, adapter names, sizes, counts, timeouts, delays, and worker counts are validated.
- Scanning is bounded by a fixed discovery window and a subprocess timeout.
- `--interface` accepts only real BlueZ adapter names (`hciN`).
- Failed subprocesses report the real stderr instead of only an exit status.
- Shell command strings were replaced with argument lists passed to `subprocess.run`.
- `--scan`, `--json`, `--timeout`, `--delay`, and `--version` were added.
- Unit tests cover parsing, validation, command building, and dry-run output.

## Requirements

- Linux with BlueZ tools installed.
- `bluetoothctl` (from BlueZ) for scanning. It uses D-Bus, so scanning works
  without root. `hcitool` was removed in BlueZ 5.87 and is no longer used.
- `l2ping` for L2CAP echo checks.
- Python 3.9 or newer.

On Debian/Kali-style systems:

```shell
sudo apt update
sudo apt install python3 bluez
```

Scanning needs the Bluetooth service running (`systemctl status bluetooth`);
`bluetoothctl` reports `Controller ... not available` if the adapter is not
registered with `bluetoothd`.

## Usage

Show CLI options:

```shell
python3 Bluetooth-DOS-Attack.py --help
```

Scan nearby devices:

```shell
python3 Bluetooth-DOS-Attack.py --scan
```

Scan with JSON output:

```shell
python3 Bluetooth-DOS-Attack.py --scan --json
```

Build a dry-run diagnostic command:

```shell
python3 Bluetooth-DOS-Attack.py --target AA:BB:CC:DD:EE:FF --package-size 64 --count 4
```

Run a bounded diagnostic check only when authorized:

```shell
python3 Bluetooth-DOS-Attack.py --target AA:BB:CC:DD:EE:FF --package-size 64 --count 4 --timeout 5 --delay 1 --execute --confirm-authorized
```

Interactive mode is still available:

```shell
python3 Bluetooth-DOS-Attack.py
```

## Manual

Target ID or MAC: ID or MAC address displayed after scanning.

Package Size: Size of the L2CAP echo payload sent to the target during a bounded diagnostic check.

Threads Count: Number of worker threads that run the diagnostic command. The default is 1, and higher values should only be used in a controlled lab with explicit authorization.

Packet Count: Number of packets each worker sends before exiting.

Timeout: Number of seconds to wait for a response.

Delay: Number of seconds to wait between packets.

## Diagnostic baseline table

Use this table for low-impact reachability and latency checks on devices you own or are authorized to test. It is not a tuning guide for disrupting devices.

| Scenario | Package size | Threads count | Packet count | Timeout, sec | Delay, sec | Purpose |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Basic reachability | 44 | 1 | 4 | 5 | 1 | Confirm the device responds to L2CAP echo. |
| Slightly larger payload | 64 | 1 | 4 | 5 | 1 | Check response behavior with a modest payload. |
| Short stability check | 64 | 1 | 10 | 5 | 1 | Confirm responses stay consistent across a small sample. |
| Slow link check | 44 | 1 | 4 | 10 | 2 | Give distant or low-power devices extra response time. |

## Safety limits

The script enforces conservative limits:

| Setting | Limit |
| --- | --- |
| Package size | 1-600 bytes |
| Workers | 1-16 |
| Packets per worker | 1-20 |
| Timeout | 1-30 seconds |
| Delay | 0-10 seconds |

## Testing

Run the unit tests:

```shell
python3 -m unittest discover
```

## Disclaimer

This software is provided as-is, without warranty. You are responsible for complying with local laws, device ownership, network policies, and test authorization.
