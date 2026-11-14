"""Tests for the bounded service-identification workflow."""
import unittest
from unittest.mock import patch

from service_enumeration import ALLOWED_PORTS, enumerate_services, _probe_one


class ServiceEnumerationTests(unittest.TestCase):
    def test_only_reviewed_ports_are_accepted(self):
        with self.assertRaises(ValueError):
            enumerate_services("192.0.2.10", [23])
        with self.assertRaises(ValueError):
            enumerate_services("192.0.2.10", [22, 22])

    def test_port_count_and_types_are_strict(self):
        with self.assertRaises(ValueError):
            enumerate_services("192.0.2.10", [])
        with self.assertRaises(ValueError):
            enumerate_services("192.0.2.10", sorted(ALLOWED_PORTS)[:9])
        with self.assertRaises(ValueError):
            enumerate_services("192.0.2.10", [True])

    def test_target_must_be_one_nonempty_string(self):
        for target in ("", None, ["192.0.2.10"], "x" * 254):
            with self.subTest(target=target), self.assertRaises(ValueError):
                enumerate_services(target, [22])

    def test_fixed_probe_is_called_once_per_selected_port(self):
        with patch("service_enumeration._probe_one", side_effect=[
            {"port": 22, "state": "open", "service": "ssh"},
            {"port": 80, "state": "open", "service": "http"},
        ]) as probe:
            result = enumerate_services("192.0.2.10", [22, 80])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(result["target"], "192.0.2.10")
        self.assertEqual(result["ports_checked"], [22, 80])
        self.assertEqual([row["service"] for row in result["services"]], ["ssh", "http"])
        self.assertIn("Non-authenticating", result["note"])

    def test_http_probe_sends_only_head_request(self):
        class FakeSocket:
            def __init__(self):
                self.sent = b""
                self.read = False
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def settimeout(self, timeout):
                pass
            def sendall(self, data):
                self.sent += data
            def recv(self, size):
                if self.read:
                    return b""
                self.read = True
                return b"HTTP/1.0 200 OK\r\nServer: test\r\n\r\n"
        fake = FakeSocket()
        with patch("service_enumeration.socket.create_connection", return_value=fake):
            result = _probe_one("lab.example.org", 80)
        self.assertTrue(fake.sent.startswith(b"HEAD / HTTP/1.0"))
        self.assertNotIn(b"GET ", fake.sent)
        self.assertEqual(result["state"], "open")
        self.assertIn("HTTP/1.0 200 OK", result["banner"])

    def test_no_command_execution_or_credentials_are_part_of_result(self):
        with patch("service_enumeration._probe_one", return_value={"port": 21, "state": "open", "service": "ftp", "banner": "220 ready"}):
            result = enumerate_services("lab.example.org", [21])
        self.assertNotIn("command", result)
        self.assertNotIn("credentials", result)
        self.assertEqual(result["services"][0]["banner"], "220 ready")


if __name__ == "__main__":
    unittest.main()
