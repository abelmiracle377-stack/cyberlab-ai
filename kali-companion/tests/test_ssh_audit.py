import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ssh_audit import _target


class SshAuditTargetTests(unittest.TestCase):
    def test_public_ip_is_accepted(self):
        self.assertEqual(_target("8.8.8.8"), "8.8.8.8")

    def test_private_ip_is_allowed_for_explicitly_authorised_single_host(self):
        self.assertEqual(_target("192.168.1.10"), "192.168.1.10")

    def test_loopback_is_rejected(self):
        with self.assertRaises(ValueError):
            _target("127.0.0.1")

    def test_url_is_rejected(self):
        with self.assertRaises(ValueError):
            _target("https://example.com")

    def test_hostname_is_normalised(self):
        self.assertEqual(_target("EXAMPLE.COM."), "example.com")


if __name__ == "__main__":
    unittest.main()
