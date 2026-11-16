import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import network_capture


class FakeCaptureProcess:
    def __init__(self, command, **_kwargs):
        self.command = command
        self.returncode = 0
        capture_path = Path(command[command.index("-w") + 1])
        capture_path.write_bytes(b"pcap-test-evidence")

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        return "", "1 packet captured"


class NetworkCaptureTests(unittest.TestCase):
    def setUp(self):
        self.interfaces = [(1, "lo"), (2, "eth0")]

    def test_interface_listing_does_not_expose_addresses_or_macs(self):
        with patch.object(network_capture.socket, "if_nameindex", return_value=self.interfaces):
            result = network_capture.list_capture_interfaces()
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["interfaces"][1]["name"], "eth0")
        self.assertNotIn("address", repr(result))
        self.assertNotIn("mac", repr(result).lower())

    def test_capture_requires_exact_interface_confirmation_and_authorisation(self):
        with patch.object(network_capture.socket, "if_nameindex", return_value=self.interfaces), \
             patch.object(network_capture.subprocess, "Popen") as popen:
            result = network_capture.capture_packets(
                "eth0", "lo", False, "", duration_seconds=3, packet_limit=10, filter_name="ssh"
            )
        self.assertEqual(result["status"], "error") if result.get("status") == "error" else self.assertIn("error", result)
        popen.assert_not_called()

    def test_rejects_arbitrary_capture_filter(self):
        with patch.object(network_capture.socket, "if_nameindex", return_value=self.interfaces):
            with self.assertRaises(ValueError):
                network_capture.capture_packets(
                    "eth0", "eth0", True, "lab-approval",
                    duration_seconds=3, packet_limit=10, filter_name="tcp or port 4444",
                )

    def test_capture_is_bounded_and_returns_only_metadata(self):
        packet_lines = (
            "2026-11-16 12:00:00.000000 IP 192.0.2.10.54321 > 192.0.2.20.22: Flags [S], seq 1\n"
            "2026-11-16 12:00:00.010000 IP 192.0.2.20.22 > 192.0.2.10.54321: Flags [S.], seq 2\n"
        )
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(network_capture, "CAPTURE_DIR", Path(directory)), \
             patch.object(network_capture.socket, "if_nameindex", return_value=self.interfaces), \
             patch.object(network_capture.shutil, "which", return_value="/usr/sbin/tcpdump"), \
             patch.object(network_capture.subprocess, "Popen", FakeCaptureProcess) as popen, \
             patch.object(network_capture.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=packet_lines)):
            result = network_capture.capture_packets(
                "eth0", "eth0", True, "LAB-2026-01",
                duration_seconds=3, packet_limit=20, filter_name="ssh",
            )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["ssh_packet_count"], 2)
        self.assertEqual(result["packet_count"], 2)
        self.assertFalse(result["payload_exported"])
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(result["snaplen_bytes"], 96)
        self.assertTrue(Path(result["local_file"]).is_file())
        command = popen.call_args.args[0]
        self.assertIn("tcp port 22", command)
        self.assertIn("96", command)
        self.assertNotIn("packet_lines", repr(result))

    def test_missing_tcpdump_is_reported_without_starting_process(self):
        with patch.object(network_capture.socket, "if_nameindex", return_value=self.interfaces), \
             patch.object(network_capture.shutil, "which", return_value=None), \
             patch.object(network_capture.subprocess, "Popen") as popen:
            result = network_capture.capture_packets(
                "eth0", "eth0", True, "LAB-2026-01",
                duration_seconds=3, packet_limit=10, filter_name="ssh",
            )
        self.assertEqual(result["status"], "unavailable")
        popen.assert_not_called()

    def test_rejects_packet_and_duration_limits_outside_policy(self):
        with patch.object(network_capture.socket, "if_nameindex", return_value=self.interfaces):
            with self.assertRaises(ValueError):
                network_capture.capture_packets(
                    "eth0", "eth0", True, "LAB-2026-01",
                    duration_seconds=31, packet_limit=10, filter_name="ssh",
                )
            with self.assertRaises(ValueError):
                network_capture.capture_packets(
                    "eth0", "eth0", True, "LAB-2026-01",
                    duration_seconds=3, packet_limit=2001, filter_name="ssh",
                )


if __name__ == "__main__":
    unittest.main()
