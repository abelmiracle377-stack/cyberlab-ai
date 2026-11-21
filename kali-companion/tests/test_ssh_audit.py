import unittest
from ssh_audit import _target


class SshAuditTargetTests(unittest.TestCase):
    def test_public_ip_is_accepted(self):
        self.assertEqual(_target("8.8.8.8"), "8.8.8.8")

    def test_private_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            _target("192.168.1.10")

    def test_url_is_rejected(self):
        with self.assertRaises(ValueError):
            _target("https://example.com")

    def test_hostname_is_normalised(self):
        self.assertEqual(_target("EXAMPLE.COM."), "example.com")


if __name__ == "__main__":
    unittest.main()
