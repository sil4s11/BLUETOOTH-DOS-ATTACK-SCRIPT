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
- `l2ping` output is parsed and summarised: replies, packet loss, and RTT
  min/avg/max, with `--json` for machine-readable results.
- Shell command strings were replaced with argument lists passed to `subprocess.run`.
- Total packets per run are capped across all workers, not only per worker.
- `--scan`, `--json`, `--timeout`, `--delay`, and `--version` were added.
- `--recovery` measures post-load fatigue: baseline probe, bounded check, then
  single-packet probes until RTT returns to baseline.
- Unit tests cover parsing, validation, command building, packet budget, and
  dry-run output.

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

Results are summarised instead of being printed raw:

```text
[result] Replies: 2/3 (33% loss) | RTT min 3.12 ms, avg 4.3 ms, max 5.48 ms
```

Add `--json` to get the same summary as machine-readable output.

`l2ping` needs a raw HCI socket, so running a check needs root or
`CAP_NET_RAW`/`CAP_NET_ADMIN`. Scanning does not. A peer without an L2CAP
echo channel is reported as unsupported rather than as packet loss, and a
socket failure is reported as a failure rather than as a measurement.

### Measuring fatigue and recovery

`--recovery` measures how a device settles after the load phase. It takes a
baseline probe first, runs the bounded check, then re-probes at a fixed
interval and reports when RTT returns to baseline (within
`RECOVERY_RTT_FACTOR`, 1.5x):

```shell
python3 Bluetooth-DOS-Attack.py --target AA:BB:CC:DD:EE:FF --count 4 --recovery --recovery-samples 5 --recovery-interval 2 --execute --confirm-authorized
```

```text
[baseline] RTT: 3.9
[result] No replies received.
[recovery] post-load probes:
  sample 1: no reply (degraded)
  sample 2: 61.0 ms (degraded)
  sample 3: 22.0 ms (degraded)
  sample 4: 4.1 ms (ok)
[recovery] target healthy again at sample 4.
```

Each post-load probe is a single bounded packet, so observing recovery does
not add load. If a device does not return to a healthy RTT within the sample
window, that is reported explicitly.

Note: over the air, a busy 2.4 GHz band means a "no reply" may be interference
rather than the device itself. `btmon` needs root and captures the raw HCI
traffic if you need to attribute a failure.

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
| Total packets (workers x count) | 1-64 |

The per-worker limits would otherwise allow 16 x 20 = 320 packets in a
single run, well above the samples in the table above. `--dry-run` output and
`--json` both report the total so it is visible before anything is sent.

## Testing

Run the unit tests:

```shell
python3 -m unittest discover
```

## Disclaimer

This software is provided as-is, without warranty. You are responsible for complying with local laws, device ownership, network policies, and test authorization.
