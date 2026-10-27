"""Synthetic, offline tests for snapshot validation and drift reporting."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import inventory_diff
import network_scanner


SUBNET = "192.0.2.0/24"  # RFC 5737 documentation-only addresses


def snapshot(devices, subnet=SUBNET):
    return {"schema_version": 1, "subnet": subnet, "devices": devices}


def device(ip, mac="02:00:00:00:00:01"):
    return {"ip": ip, "mac": mac}


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def write(self, name, data):
        path = self.folder / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_accepts_and_normalizes_mac(self):
        path = self.write("before.json", snapshot([device("192.0.2.10", "AA:BB:CC:DD:EE:FF")]))
        result = inventory_diff.load_snapshot(path)
        self.assertEqual(result.devices, {"192.0.2.10": "aa:bb:cc:dd:ee:ff"})

    def test_empty_snapshot(self):
        result = inventory_diff.load_snapshot(self.write("empty.json", snapshot([])))
        self.assertEqual(result.devices, {})

    def test_rejects_bad_schema_and_bool_version(self):
        for data in [snapshot([]) | {"schema_version": True}, snapshot([]) | {"schema_version": 2}, {"subnet": SUBNET, "devices": []}, []]:
            with self.subTest(data=data), self.assertRaises(inventory_diff.InventoryError):
                inventory_diff.load_snapshot(self.write("invalid.json", data))

    def test_rejects_malformed_json_and_invalid_utf8(self):
        path = self.folder / "bad.json"
        for content in [b"{broken", b"\xff"]:
            path.write_bytes(content)
            with self.subTest(content=content), self.assertRaises(inventory_diff.InventoryError):
                inventory_diff.load_snapshot(path)

    def test_rejects_large_file(self):
        path = self.folder / "huge.json"
        path.write_bytes(b"x" * (inventory_diff.MAX_SNAPSHOT_BYTES + 1))
        with self.assertRaisesRegex(inventory_diff.InventoryError, "exceeds"):
            inventory_diff.load_snapshot(path)

    def test_rejects_noncanonical_and_ipv6_subnets(self):
        for value in ["192.0.2.10/24", "2001:db8::/64", "192.0.2.0", "nonsense"]:
            with self.subTest(value=value), self.assertRaises(inventory_diff.InventoryError):
                inventory_diff.load_snapshot(self.write("bad.json", snapshot([], subnet=value)))

    def test_rejects_out_of_subnet_invalid_and_noncanonical_ips(self):
        for value in ["198.51.100.3", "2001:db8::1", "192.0.2.003", "not-ip"]:
            with self.subTest(value=value), self.assertRaises(inventory_diff.InventoryError):
                inventory_diff.load_snapshot(self.write("bad.json", snapshot([device(value)])))

    def test_rejects_bad_mac(self):
        for mac in ["aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:gg", "aabbccddeeff", "aa:bb:cc:dd:ee:ff\n"]:
            with self.subTest(mac=mac), self.assertRaises(inventory_diff.InventoryError):
                inventory_diff.load_snapshot(self.write("bad.json", snapshot([device("192.0.2.10", mac)])))

    def test_rejects_duplicate_ip(self):
        path = self.write("dup.json", snapshot([device("192.0.2.2"), device("192.0.2.2", "02:00:00:00:00:02")]))
        with self.assertRaisesRegex(inventory_diff.InventoryError, "duplicate IP"):
            inventory_diff.load_snapshot(path)

    def test_rejects_unknown_device_fields(self):
        row = device("192.0.2.2") | {"username": "not allowed"}
        with self.assertRaises(inventory_diff.InventoryError):
            inventory_diff.load_snapshot(self.write("bad.json", snapshot([row])))

    def test_rejects_nonlist_and_oversized_device_list(self):
        for rows in [{}, [None]]:
            with self.subTest(rows=rows), self.assertRaises(inventory_diff.InventoryError):
                inventory_diff.load_snapshot(self.write("bad.json", snapshot(rows)))
        with mock.patch.object(inventory_diff, "MAX_DEVICES", 1):
            with self.assertRaisesRegex(inventory_diff.InventoryError, "at most"):
                inventory_diff.load_snapshot(self.write("bad.json", snapshot([device("192.0.2.1"), device("192.0.2.2")])))

    def test_reports_sorted_additions_removals_and_mac_changes(self):
        before = inventory_diff.load_snapshot(self.write("old.json", snapshot([
            device("192.0.2.20", "02:00:00:00:00:20"),
            device("192.0.2.3", "02:00:00:00:00:03"),
            device("192.0.2.10", "02:00:00:00:00:10"),
        ])))
        after = inventory_diff.load_snapshot(self.write("new.json", snapshot([
            device("192.0.2.20", "02:00:00:00:00:21"),
            device("192.0.2.2", "02:00:00:00:00:02"),
            device("192.0.2.11", "02:00:00:00:00:11"),
        ])))
        report = inventory_diff.compare(before, after)
        self.assertEqual([d["ip"] for d in report["added"]], ["192.0.2.2", "192.0.2.11"])
        self.assertEqual([d["ip"] for d in report["removed"]], ["192.0.2.3", "192.0.2.10"])
        self.assertEqual(report["mac_changed"], [{"ip": "192.0.2.20", "before_mac": "02:00:00:00:00:20", "after_mac": "02:00:00:00:00:21"}])
        self.assertIn("Added: 2 | Removed: 2 | MAC changed: 1", inventory_diff.format_text(report))

    def test_same_inventory_no_drift(self):
        a = inventory_diff.load_snapshot(self.write("a.json", snapshot([device("192.0.2.1")])) )
        self.assertFalse(any(inventory_diff.compare(a, a)[k] for k in ("added", "removed", "mac_changed")))

    def test_rejects_mismatched_subnets(self):
        a = inventory_diff.load_snapshot(self.write("a.json", snapshot([])))
        b = inventory_diff.load_snapshot(self.write("b.json", snapshot([], "198.51.100.0/24")))
        with self.assertRaisesRegex(inventory_diff.InventoryError, "different subnets"):
            inventory_diff.compare(a, b)

    def test_cli_exit_codes_and_json_report(self):
        before = self.write("before.json", snapshot([device("192.0.2.1")]))
        after = self.write("after.json", snapshot([device("192.0.2.2")]))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = inventory_diff.main(["--before", str(before), "--after", str(after), "--format", "json", "--fail-on-change"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["added"][0]["ip"], "192.0.2.2")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(inventory_diff.main(["--before", str(before), "--after", str(after)]), 0)

    def test_cli_bad_input_returns_two(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = inventory_diff.main(["--before", "missing.json", "--after", "missing2.json"])
        self.assertEqual(code, 2)
        self.assertIn("Inventory error", err.getvalue())

    def test_scanner_json_output_round_trips_into_inventory(self):
        out = io.StringIO()
        scan = mock.Mock(return_value=[device("192.0.2.10", "AA:BB:CC:DD:EE:FF")])
        with contextlib.redirect_stdout(out):
            result = network_scanner.main(["--subnet", "192.0.2.10/24", "--format", "json"], scan=scan)
        self.assertEqual(result, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["subnet"], SUBNET)
        self.assertEqual(data["schema_version"], 1)
        path = self.write("from-scanner.json", data)
        self.assertEqual(inventory_diff.load_snapshot(path).devices["192.0.2.10"], "aa:bb:cc:dd:ee:ff")
        scan.assert_called_once()

    def test_dry_run_cannot_be_mistaken_for_inventory(self):
        scan = mock.Mock()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            network_scanner.main(["--subnet", SUBNET, "--dry-run", "--format", "json"], scan=scan)
        self.assertEqual(raised.exception.code, 2)
        scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
