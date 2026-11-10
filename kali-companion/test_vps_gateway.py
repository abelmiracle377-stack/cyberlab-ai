"""Focused tests for the owner-only VPS compatibility diagnostics."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vps_gateway import app as gateway


class VPSCompatibilityTests(unittest.TestCase):
    def test_diagnostics_return_expected_checks_without_host_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(gateway, "DATA_DIR", Path(directory)):
                result = gateway.owner_diagnostics()

        self.assertIn(result["status"], {"compatible", "incompatible"})
        self.assertEqual(result["gateway"], "healthy")
        names = {item["name"] for item in result["checks"]}
        self.assertEqual(names, {"Operating system", "Python", "Available memory", "Free storage"})
        rendered = repr(result).lower()
        self.assertNotIn("hostname", rendered)
        self.assertNotIn("owner_token", rendered)
        self.assertNotIn("environment", rendered)

    def test_diagnostics_are_registered_as_owner_authenticated_route(self):
        route = next(
            item for item in gateway.app.routes
            if getattr(item, "path", None) == "/v1/owner/diagnostics"
        )
        self.assertIn("GET", route.methods)
        self.assertTrue(route.dependencies)


if __name__ == "__main__":
    unittest.main()
