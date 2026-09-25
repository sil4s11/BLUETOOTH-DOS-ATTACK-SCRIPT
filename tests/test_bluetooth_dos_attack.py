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

    def test_parse_scan_output_keeps_valid_devices(self):
        output = """
Scanning ...
        aa:bb:cc:dd:ee:ff    Speaker One
        not-a-mac            ignored
        11:22:33:44:55:66
"""
        self.assertEqual(
            bt.parse_scan_output(output),
            [
                ("AA:BB:CC:DD:EE:FF", "Speaker One"),
                ("11:22:33:44:55:66", "Unknown"),
            ],
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
            bt.print_dry_run(["l2ping", "-c", "1", "AA:BB:CC:DD:EE:FF"], 1, json_output=True)

        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["threads"], 1)
        self.assertEqual(payload["command"][0], "l2ping")


if __name__ == "__main__":
    unittest.main()
