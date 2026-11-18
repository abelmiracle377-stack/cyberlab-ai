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
        self.assertEqual(set(result), {"status", "checks", "gateway", "notes"})
        self.assertFalse(any("token" in key.lower() for key in result))
        self.assertFalse(any("hostname" in key.lower() or "environment" in key.lower()
                             for item in result["checks"] for key in item))

    def test_diagnostics_are_registered_as_owner_authenticated_route(self):
        route = next(
            item for item in gateway.app.routes
            if getattr(item, "path", None) == "/v1/owner/diagnostics"
        )
        self.assertIn("GET", route.methods)
        self.assertTrue(route.dependencies)

    def test_owner_token_uses_exact_bearer_value(self):
        from fastapi import HTTPException
        with mock.patch.object(gateway, "OWNER_TOKEN", "owner-secret-token"):
            self.assertTrue(gateway.owner_auth("Bearer owner-secret-token"))
            with self.assertRaises(HTTPException) as wrong:
                gateway.owner_auth("Bearer owner-secret-tokeX")
            self.assertEqual(wrong.exception.status_code, 401)
            with self.assertRaises(HTTPException) as missing:
                gateway.owner_auth(None)
            self.assertEqual(missing.exception.status_code, 401)

    def test_owner_auth_fails_closed_without_configured_token(self):
        from fastapi import HTTPException
        with mock.patch.object(gateway, "OWNER_TOKEN", ""):
            with self.assertRaises(HTTPException) as unavailable:
                gateway.owner_auth("Bearer anything")
            self.assertEqual(unavailable.exception.status_code, 503)

    def test_device_auth_rejects_short_tokens_before_database_access(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as invalid:
            gateway.device_auth("Bearer short")
        self.assertEqual(invalid.exception.status_code, 401)

    def test_pairing_acceptance_is_rate_limited(self):
        from fastapi import HTTPException
        gateway._PAIRING_ATTEMPTS.clear()
        try:
            with mock.patch.object(gateway, "PAIRING_ATTEMPT_LIMIT", 1):
                gateway.enforce_pairing_rate_limit()
                with self.assertRaises(HTTPException) as limited:
                    gateway.enforce_pairing_rate_limit()
                self.assertEqual(limited.exception.status_code, 429)
        finally:
            gateway._PAIRING_ATTEMPTS.clear()


if __name__ == "__main__":
    unittest.main()
