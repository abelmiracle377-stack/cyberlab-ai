"""Tests for the local HTTPS inspection CA and exact-host certificate issuance."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import proxy_certificates as certs


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for certificate tests")
class ProxyCertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / ".config" / "cyberlab"
        self.patches = [
            patch.object(certs, "CONFIG_ROOT", root),
            patch.object(certs, "CA_DIR", root / "proxy-ca"),
            patch.object(certs, "CA_KEY", root / "proxy-ca" / "ca-key.pem"),
            patch.object(certs, "CA_CERT", root / "proxy-ca" / "ca-cert.pem"),
            patch.object(certs, "LEAF_DIR", root / "proxy-ca" / "hosts"),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_ca_and_exact_dns_certificate_are_created_with_private_permissions(self):
        self.assertFalse(certs.ca_status()["ready"])
        status = certs.create_local_ca()
        self.assertTrue(status["ready"])
        self.assertEqual(certs.CA_KEY.stat().st_mode & 0o777, 0o600)
        self.assertEqual(certs.CA_DIR.stat().st_mode & 0o777, 0o700)

        issued = certs.issue_host_certificate("lab.example.test")
        self.assertFalse(issued["reused"])
        key = Path(issued["privateKey"])
        certificate = Path(issued["certificate"])
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertIn("DNS:lab.example.test", subprocess.check_output(
            ["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"],
            text=True,
        ))
        self.assertEqual(certs.issue_host_certificate("lab.example.test")["reused"], True)

    def test_public_certificate_export_never_contains_private_key_material(self):
        certs.create_local_ca()
        exported = certs.ca_certificate_pem()
        self.assertIn("-----BEGIN CERTIFICATE-----", exported["pem"])
        self.assertNotIn("PRIVATE KEY", exported["pem"])
        self.assertEqual(exported["filename"], "cyberlab-local-inspection-ca.pem")

    def test_ca_status_rejects_world_readable_private_key(self):
        certs.create_local_ca()
        os.chmod(certs.CA_KEY, 0o644)
        self.assertFalse(certs.ca_status()["ready"])
        self.assertEqual(certs.ca_status()["privateKeyPermissions"], "not verified")

    def test_ca_creation_refuses_to_overwrite_existing_key_material(self):
        certs.create_local_ca()
        original = certs.CA_KEY.read_bytes()
        certs.CA_CERT.unlink()
        with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
            certs.create_local_ca()
        self.assertEqual(certs.CA_KEY.read_bytes(), original)

    def test_ipv6_literals_are_normalised_for_ip_subject_alternative_names(self):
        self.assertEqual(certs._normalise_host("::1"), ("::1", "IP"))
        self.assertEqual(certs._normalise_host("[::1]"), ("::1", "IP"))

    def test_wildcard_and_url_inputs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Wildcards"):
            certs._normalise_host("*.example.test")
        with self.assertRaisesRegex(ValueError, "Wildcards"):
            certs._normalise_host("https://example.test/path")


if __name__ == "__main__":
    unittest.main()
