import argparse
import contextlib
import io
import ipaddress
import sys
import types
import unittest
from unittest import mock

import network_scanner


class ParseSubnetTests(unittest.TestCase):
    def test_accepts_and_canonicalizes_ipv4_cidr(self):
        subnet = network_scanner.parse_subnet("192.168.1.42/24")

        self.assertEqual(subnet, ipaddress.ip_network("192.168.1.0/24"))

    def test_rejects_address_without_prefix(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "CIDR notation"):
            network_scanner.parse_subnet("192.168.1.1")

    def test_rejects_invalid_subnet(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "invalid subnet"):
            network_scanner.parse_subnet("not-a-subnet/24")

    def test_rejects_ipv6(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "only IPv4"):
            network_scanner.parse_subnet("2001:db8::/64")

    def test_rejects_subnet_larger_than_16(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "maximum"):
            network_scanner.parse_subnet("10.0.0.0/15")


class CommandLineTests(unittest.TestCase):
    def test_invalid_subnet_is_rejected_before_scanner_runs(self):
        scanner = mock.Mock()
        error_output = io.StringIO()

        with contextlib.redirect_stderr(error_output):
            with self.assertRaises(SystemExit) as raised:
                network_scanner.main(
                    ["--subnet", "not-a-subnet/24"], scan=scanner
                )

        self.assertEqual(raised.exception.code, 2)
        scanner.assert_not_called()
        self.assertIn("invalid subnet", error_output.getvalue())

    def test_dry_run_never_calls_scanner(self):
        scanner = mock.Mock()
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = network_scanner.main(
                ["--subnet", "192.168.1.10/24", "--dry-run"], scan=scanner
            )

        self.assertEqual(exit_code, 0)
        scanner.assert_not_called()
        self.assertIn("would scan 192.168.1.0/24", output.getvalue())
        self.assertIn("no packets sent", output.getvalue())

    def test_scan_displays_devices_from_injected_scanner(self):
        scanner = mock.Mock(
            return_value=[
                {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:ff"},
            ]
        )
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = network_scanner.main(
                ["--subnet", "192.168.1.0/24"], scan=scanner
            )

        self.assertEqual(exit_code, 0)
        scanner.assert_called_once_with(ipaddress.ip_network("192.168.1.0/24"))
        self.assertIn("192.168.1.2", output.getvalue())
        self.assertIn("aa:bb:cc:dd:ee:ff", output.getvalue())

    def test_scan_displays_empty_result(self):
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = network_scanner.main(
                ["--subnet", "192.168.1.0/24"], scan=lambda _: []
            )

        self.assertEqual(exit_code, 0)
        self.assertIn("No devices found.", output.getvalue())


class ScapyBoundaryTests(unittest.TestCase):
    def test_scan_builds_arp_request_and_parses_mocked_answers(self):
        class FakeLayer:
            def __init__(self, name, values):
                self.name = name
                self.values = values

            def __truediv__(self, other):
                return (self, other)

        arp = mock.Mock(side_effect=lambda **values: FakeLayer("ARP", values))
        ether = mock.Mock(side_effect=lambda **values: FakeLayer("Ether", values))
        responses = [
            (
                None,
                types.SimpleNamespace(
                    psrc="192.168.1.20", hwsrc="00:00:00:00:00:20"
                ),
            ),
            (
                None,
                types.SimpleNamespace(
                    psrc="192.168.1.3", hwsrc="00:00:00:00:00:03"
                ),
            ),
        ]
        srp = mock.Mock(return_value=(responses, []))
        scapy_package = types.ModuleType("scapy")
        scapy_package.__path__ = []
        scapy_all = types.ModuleType("scapy.all")
        scapy_all.ARP = arp
        scapy_all.Ether = ether
        scapy_all.srp = srp

        with mock.patch.dict(
            sys.modules, {"scapy": scapy_package, "scapy.all": scapy_all}
        ):
            devices = network_scanner.scan_subnet(
                ipaddress.ip_network("192.168.1.0/24")
            )

        arp.assert_called_once_with(pdst="192.168.1.0/24")
        ether.assert_called_once_with(dst="ff:ff:ff:ff:ff:ff")
        srp.assert_called_once_with(mock.ANY, timeout=3, verbose=0)
        self.assertEqual(
            devices,
            [
                {"ip": "192.168.1.3", "mac": "00:00:00:00:00:03"},
                {"ip": "192.168.1.20", "mac": "00:00:00:00:00:20"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
