import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "Bluetooth-DOS-Attack.py"
SPEC = importlib.util.spec_from_file_location("bt_l2cap_helper", SCRIPT_PATH)
bt = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bt
SPEC.loader.exec_module(bt)


class BluetoothL2capHelperTests(unittest.TestCase):
    def test_mac_validation_accepts_standard_address(self):
        self.assertTrue(bt.is_valid_mac("aa:bb:cc:dd:ee:ff"))
        self.assertEqual(bt.normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")

    def test_mac_validation_rejects_shell_input(self):
        with self.assertRaises(bt.ValidationError):
            bt.normalize_mac("AA:BB:CC:DD:EE:FF; reboot")

    def test_parse_scan_output_reads_bluetoothctl_devices(self):
        output = (
            "SetDiscoveryFilter success\n"
            "AdvertisementMonitor path registered\n"
            "Discovery started\n"
            "[\x1b[0;93mCHG\x1b[0m] Controller 88:F4:DA:99:89:AE Discovering: yes\n"
            "[\x1b[0;92mNEW\x1b[0m] Device 0c:ec:84:10:24:18 View3 Pro\n"
            "[\x1b[0;92mNEW\x1b[0m] LE /org/bluez/hci0/dev_0C_EC_84_10_24_18\n"
            "[\x1b[0;92mNEW\x1b[0m] Device 04:39:26:B6:02:97\n"
        )

        self.assertEqual(
            bt.parse_scan_output(output),
            [
                ("0C:EC:84:10:24:18", "View3 Pro"),
                ("04:39:26:B6:02:97", "Unknown"),
            ],
        )

    def test_parse_scan_output_ignores_transport_lines(self):
        # A single dual-mode device emits one "Device" line plus one object
        # line per transport. Only the Device line carries the name.
        output = (
            "[NEW] Device 50:e3:da:1f:0d:82 ALEJOHACKTOOL\n"
            "[NEW] LE /org/bluez/hci0/dev_50_E3_DA_1F_0D_82\n"
            "[NEW] BREDR /org/bluez/hci0/dev_50_E3_DA_1F_0D_82\n"
        )

        self.assertEqual(
            bt.parse_scan_output(output),
            [("50:E3:DA:1F:0D:82", "ALEJOHACKTOOL")],
        )

    def test_parse_scan_output_dedupes_repeated_advertisements(self):
        output = (
            "[NEW] Device 74:e9:d8:33:f7:a5 SSL_0EXcXKGF5CDZWOA==\n"
            "[NEW] Device 74:E9:D8:33:F7:A5 SSL_0EXcXKGF5CDZWOA==\n"
        )

        self.assertEqual(
            bt.parse_scan_output(output),
            [("74:E9:D8:33:F7:A5", "SSL_0EXcXKGF5CDZWOA==")],
        )

    def test_parse_scan_output_ignores_non_device_lines(self):
        output = (
            "Discovery started\n"
            "[CHG] Controller 88:F4:DA:99:89:AE Discovering: no\n"
            "  aa:bb:cc:dd:ee:ff    Old hcitool row\n"
            "not-a-mac ignored\n"
        )

        self.assertEqual(bt.parse_scan_output(output), [])

    def test_parse_scan_output_ignores_chg_rssi_lines(self):
        # [CHG] Device lines carry RSSI, never a name. Treating one as a name
        # produced devices listed as "RSSI: 0xffffffb8 (-72)".
        output = (
            "[NEW] Device 74:E9:D8:33:F7:A5 SSL_0EXcXKGF5CDZWOA==\n"
            "[CHG] Device 74:E9:D8:33:F7:A5 RSSI: 0xffffffb8 (-72)\n"
            "[CHG] Device 04:39:26:B6:02:97 RSSI: 0xffffffae (-82)\n"
        )

        self.assertEqual(
            bt.parse_scan_output(output),
            [("74:E9:D8:33:F7:A5", "SSL_0EXcXKGF5CDZWOA==")],
        )

    def test_build_l2ping_command_is_bounded(self):
        command = bt.build_l2ping_command(
            "AA:BB:CC:DD:EE:FF",
            package_size=64,
            packet_count=3,
            interface="hci0",
            timeout=7,
            delay=2,
        )

        self.assertEqual(
            command,
            [
                "l2ping",
                "-i",
                "hci0",
                "-s",
                "64",
                "-c",
                "3",
                "-t",
                "7",
                "-d",
                "2",
                "AA:BB:CC:DD:EE:FF",
            ],
        )
        self.assertNotIn("-f", command)

    def test_validate_interface_rejects_flag_like_values(self):
        # getopt consumes the next argv as the -i value even when it starts with
        # "-", so these must never reach l2ping as a device name.
        for value in ("-f", "-i", "-r", "--help", "..", "hci0 -f", "eth0", "hci", ""):
            with self.subTest(value=value):
                with self.assertRaises(bt.ValidationError):
                    bt.validate_interface(value)

    def test_validate_interface_accepts_bluez_device_names(self):
        for value in ("hci0", "hci1", "hci10", " hci2 "):
            with self.subTest(value=value):
                self.assertEqual(bt.validate_interface(value), value.strip())

    def test_build_l2ping_command_rejects_flag_like_interface(self):
        with self.assertRaises(bt.ValidationError):
            bt.build_l2ping_command("AA:BB:CC:DD:EE:FF", 44, 1, interface="-f")

    def test_limits_reject_unbounded_values(self):
        with self.assertRaises(bt.ValidationError):
            bt.validate_int_range("Threads count", bt.MAX_THREADS + 1, 1, bt.MAX_THREADS)
        with self.assertRaises(bt.ValidationError):
            bt.build_l2ping_command("AA:BB:CC:DD:EE:FF", bt.MAX_PACKAGE_SIZE + 1, 1)

    def test_dry_run_json_output(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            bt.print_dry_run(
                ["l2ping", "-c", "1", "AA:BB:CC:DD:EE:FF"],
                1,
                1,
                json_output=True,
            )

        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["threads"], 1)
        self.assertEqual(payload["total_packets"], 1)
        self.assertEqual(payload["command"][0], "l2ping")

    def test_total_packet_budget_rejects_multiplied_sends(self):
        # Per-worker limits alone allow 16 * 20 = 320 packets.
        self.assertEqual(bt.validate_total_packets(1, 20), 20)
        self.assertEqual(bt.validate_total_packets(4, 16), 64)
        with self.assertRaises(bt.ValidationError):
            bt.validate_total_packets(bt.MAX_THREADS, bt.MAX_PACKET_COUNT)
        with self.assertRaises(bt.ValidationError):
            bt.validate_total_packets(16, 5)

    def test_total_packet_budget_error_names_the_product(self):
        with self.assertRaises(bt.ValidationError) as caught:
            bt.validate_total_packets(bt.MAX_THREADS, bt.MAX_PACKET_COUNT)

        message = str(caught.exception)
        self.assertIn("320", message)
        self.assertIn(str(bt.MAX_TOTAL_PACKETS), message)

    def test_dry_run_reports_total_packet_budget(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            bt.print_dry_run(["l2ping", "-c", "4", "AA:BB:CC:DD:EE:FF"], 2, 8)

        self.assertIn("8", stdout.getvalue())
        self.assertIn(str(bt.MAX_TOTAL_PACKETS), stdout.getvalue())

    def test_parse_l2ping_output_reads_replies_and_summary(self):
        output = (
            "Ping: 88:F4:DA:99:89:AE from hci0 (data size 44) ...\n"
            "44 bytes from 88:F4:DA:99:89:AE id 0 time 3.12ms\n"
            "no response from 88:F4:DA:99:89:AE: id 1\n"
            "44 bytes from 88:F4:DA:99:89:AE id 2 time 5.48ms\n"
            "3 sent, 2 received, 33% loss\n"
        )

        summary = bt.parse_l2ping_output(output)

        self.assertEqual(summary["sent"], 3)
        self.assertEqual(summary["received"], 2)
        self.assertEqual(summary["loss_percent"], 33)
        self.assertEqual(summary["rtt_ms_min"], 3.12)
        self.assertEqual(summary["rtt_ms_max"], 5.48)
        self.assertEqual(summary["rtt_ms_avg"], 4.3)
        self.assertFalse(summary["unsupported_echo"])

    def test_parse_l2ping_output_flags_peer_without_echo_support(self):
        summary = bt.parse_l2ping_output("Peer doesn't support Echo packets\n")

        self.assertTrue(summary["unsupported_echo"])
        self.assertIn("does not support", bt.format_summary(summary))

    def test_parse_l2ping_output_reports_total_loss(self):
        output = (
            "no response from 88:F4:DA:99:89:AE: id 0\n"
            "no response from 88:F4:DA:99:89:AE: id 1\n"
            "2 sent, 0 received, 100% loss\n"
        )

        summary = bt.parse_l2ping_output(output)

        self.assertEqual(summary["sent"], 2)
        self.assertEqual(summary["received"], 0)
        self.assertEqual(summary["loss_percent"], 100)
        self.assertNotIn("rtt_ms_avg", summary)
        self.assertEqual(bt.format_summary(summary), "No replies received.")

    def test_parse_l2ping_output_distinguishes_socket_failure_from_loss(self):
        # l2ping exits 0 even when it cannot open the HCI socket, so nothing was
        # measured. That must not be reported as 100% packet loss.
        summary = bt.parse_l2ping_output("Can't create socket: Operation not permitted\n")

        self.assertTrue(summary["failed_to_start"])
        self.assertEqual(summary["received"], 0)
        self.assertIn("nothing was sent", bt.format_summary(summary))

    def test_merge_summaries_keeps_loss_when_only_some_workers_failed(self):
        merged = bt.merge_summaries(
            [
                bt.parse_l2ping_output("Can't create socket: Operation not permitted\n"),
                bt.parse_l2ping_output(
                    "44 bytes from AA:BB:CC:DD:EE:FF id 0 time 4.00ms\n"
                    "1 sent, 1 received, 0% loss\n"
                ),
            ]
        )

        self.assertFalse(merged["failed_to_start"])
        self.assertEqual(merged["received"], 1)

    def test_merge_summaries_aggregates_workers(self):
        workers = [
            bt.parse_l2ping_output(
                "44 bytes from AA:BB:CC:DD:EE:FF id 0 time 3.00ms\n"
                "1 sent, 1 received, 0% loss\n"
            ),
            bt.parse_l2ping_output(
                "44 bytes from AA:BB:CC:DD:EE:FF id 0 time 9.00ms\n"
                "no response from AA:BB:CC:DD:EE:FF: id 1\n"
                "2 sent, 1 received, 50% loss\n"
            ),
        ]

        merged = bt.merge_summaries(workers)

        self.assertEqual(merged["workers"], 2)
        self.assertEqual(merged["sent"], 3)
        self.assertEqual(merged["received"], 2)
        self.assertEqual(merged["loss_percent"], 33)
        self.assertEqual(merged["rtt_ms_min"], 3.0)
        self.assertEqual(merged["rtt_ms_max"], 9.0)

    def test_merge_summaries_propagates_unsupported_peer(self):
        merged = bt.merge_summaries(
            [
                bt.parse_l2ping_output("44 bytes from AA:BB:CC:DD:EE:FF id 0 time 3.00ms\n"),
                bt.parse_l2ping_output("Peer doesn't support Echo packets\n"),
            ]
        )

        self.assertTrue(merged["unsupported_echo"])
        self.assertIn("does not support", bt.format_summary(merged))

    def test_dry_run_does_not_fall_through_to_authorization_check(self):
        # A dry-run must be terminal: it prints and returns 0 without ever
        # demanding --confirm-authorized or touching the radio.
        args = bt.create_parser().parse_args(
            ["--target", "AA:BB:CC:DD:EE:FF", "--threads", "2", "--count", "4"]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(bt.run_from_args(args), 0)

        self.assertIn("[dry-run]", stdout.getvalue())
        self.assertNotIn("--confirm-authorized", stdout.getvalue())

    def test_execute_without_authorization_is_rejected(self):
        args = bt.create_parser().parse_args(
            ["--target", "AA:BB:CC:DD:EE:FF", "--count", "2", "--execute"]
        )
        with self.assertRaises(bt.ValidationError):
            bt.run_from_args(args)

    def test_over_budget_request_is_rejected_before_dry_run(self):
        args = bt.create_parser().parse_args(
            ["--target", "AA:BB:CC:DD:EE:FF", "--threads", "16", "--count", "20"]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(bt.ValidationError):
                bt.run_from_args(args)

        self.assertEqual(stdout.getvalue(), "")

    def test_health_requires_a_reply(self):
        self.assertFalse(bt.is_healthy(None, 3.0))

    def test_health_compares_against_baseline_factor(self):
        factor = bt.RECOVERY_RTT_FACTOR
        self.assertTrue(bt.is_healthy(3.0 * factor, 3.0))
        self.assertTrue(bt.is_healthy(3.0 * factor - 0.01, 3.0))
        self.assertFalse(bt.is_healthy(3.0 * factor + 0.01, 3.0))

    def test_health_without_baseline_only_requires_a_reply(self):
        self.assertTrue(bt.is_healthy(500.0, None))
        self.assertFalse(bt.is_healthy(None, None))

    def test_format_recovery_reports_first_healthy_sample(self):
        observations = [
            {"sample": 1, "rtt_ms_avg": None, "received": 0, "healthy": False},
            {"sample": 2, "rtt_ms_avg": 40.0, "received": 1, "healthy": False},
            {"sample": 3, "rtt_ms_avg": 4.1, "received": 1, "healthy": True},
        ]

        text = bt.format_recovery(observations)

        self.assertIn("no reply", text)
        self.assertIn("40.0 ms (degraded)", text)
        self.assertIn("healthy again at sample 3", text)

    def test_format_recovery_reports_target_that_never_recovers(self):
        observations = [
            {"sample": 1, "rtt_ms_avg": None, "received": 0, "healthy": False},
            {"sample": 2, "rtt_ms_avg": 90.0, "received": 1, "healthy": False},
        ]

        self.assertIn("did not return", bt.format_recovery(observations))

    def test_recovery_limits_are_validated(self):
        args = bt.create_parser().parse_args(
            [
                "--target", "AA:BB:CC:DD:EE:FF",
                "--recovery",
                "--recovery-samples", str(bt.MAX_RECOVERY_SAMPLES + 1),
            ]
        )
        with self.assertRaises(bt.ValidationError):
            bt.validate_int_range(
                "Recovery samples", args.recovery_samples, 1, bt.MAX_RECOVERY_SAMPLES
            )

    def test_recovery_probe_uses_a_single_packet(self):
        # Probing must not re-add load: each post-load probe is one packet.
        command = bt.build_l2ping_command("AA:BB:CC:DD:EE:FF", 44, 1, "hci0")

        self.assertEqual(command[command.index("-c") + 1], "1")

    def test_measure_recovery_probes_and_classifies_each_sample(self):
        # Exercises measure_recovery end to end so the probe loop, the sleep,
        # and the health classification all run. A stubbed l2ping keeps this off
        # the radio.
        original_which = bt.shutil.which
        original_run = bt.run_l2ping_workers
        self.addCleanup(setattr, bt.shutil, "which", original_which)
        self.addCleanup(setattr, bt, "run_l2ping_workers", original_run)
        bt.shutil.which = lambda name: "/usr/bin/l2ping"

        replies = iter([3.0, None, 4.0])

        def fake_run(command, threads):
            rtt = next(replies)
            return {"rtt_ms_avg": rtt, "received": 0 if rtt is None else 1}

        bt.run_l2ping_workers = fake_run

        observations = bt.measure_recovery(
            ["l2ping", "-c", "1", "AA:BB:CC:DD:EE:FF"],
            1,
            3.0,
            samples=3,
            interval=1,
        )

        self.assertEqual([item["sample"] for item in observations], [1, 2, 3])
        self.assertEqual(
            [item["healthy"] for item in observations], [True, False, True]
        )
        self.assertEqual(observations[1]["rtt_ms_avg"], None)


if __name__ == "__main__":
    unittest.main()
