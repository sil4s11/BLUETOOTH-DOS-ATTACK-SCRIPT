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
            bt.print_dry_run(["l2ping", "-c", "1", "AA:BB:CC:DD:EE:FF"], 1, json_output=True)

        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["threads"], 1)
        self.assertEqual(payload["command"][0], "l2ping")


if __name__ == "__main__":
    unittest.main()
