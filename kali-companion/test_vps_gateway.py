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


class VPSAuditTests(unittest.TestCase):
    def _temp_db(self, directory):
        return mock.patch.object(gateway, "DB_PATH", Path(directory) / "registry.sqlite3")

    def test_audit_records_and_filters_by_device(self):
        with tempfile.TemporaryDirectory() as directory, self._temp_db(directory):
            con = gateway.db()
            gateway.log_event(con, "dev-1", "device_paired", "alex")
            gateway.log_event(con, "dev-1", "file_uploaded", "photo.jpg (100 bytes)")
            gateway.log_event(con, "dev-2", "device_revoked", "")
            con.commit()
            con.close()
            everything = gateway.list_audit()
            self.assertEqual(everything["count"], 3)
            device_one = gateway.list_audit(device_id="dev-1")
            self.assertEqual(device_one["count"], 2)
            self.assertTrue(all(e["device_id"] == "dev-1" for e in device_one["events"]))
            self.assertTrue(all("token" not in e["detail"].lower() for e in everything["events"]))

    def test_audit_limit_is_bounded(self):
        from fastapi import HTTPException
        with tempfile.TemporaryDirectory() as directory, self._temp_db(directory):
            with self.assertRaises(HTTPException):
                gateway.list_audit(limit=0)
            with self.assertRaises(HTTPException):
                gateway.list_audit(limit=5000)

    def test_audit_route_is_owner_authenticated(self):
        route = next(item for item in gateway.app.routes
                     if getattr(item, "path", None) == "/v1/audit")
        self.assertIn("GET", route.methods)
        self.assertTrue(route.dependencies)

    def test_log_event_truncates_long_detail(self):
        with tempfile.TemporaryDirectory() as directory, self._temp_db(directory):
            con = gateway.db()
            gateway.log_event(con, "dev", "custom", "y" * 500)
            con.commit()
            detail = con.execute("SELECT detail FROM events").fetchone()["detail"]
            con.close()
            self.assertLessEqual(len(detail), 200)
