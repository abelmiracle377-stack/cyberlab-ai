"""Tests for the authenticated cross-machine relay queue."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fastapi import HTTPException
from vps_gateway import app as gateway


class RelayJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = mock.patch.object(gateway, "DB_PATH", Path(self.temp.name) / "relay.sqlite3")
        self.db_patch.start()
        con = gateway.db()
        con.execute(
            "INSERT INTO devices(id,name,platform,token_hash,permissions,created_at,last_seen,revoked) VALUES(?,?,?,?,?,?,?,0)",
            ("kali-1", "Kali workstation", "kali", gateway.digest("device-token"), json.dumps({"job_execution": True}), 1, 1),
        )
        con.commit()
        con.close()
        self.device = {
            "id": "kali-1",
            "permissions": json.dumps({"job_execution": True}),
            "revoked": 0,
        }

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def test_read_only_job_claim_and_result_round_trip(self):
        body = gateway.RelayJobCreate(
            device_id="kali-1", action="kali.health", payload={},
            approval_reference="ENG-2026-001", operator_approved=True,
        )
        queued = gateway.create_relay_job(body)
        self.assertEqual(queued["status"], "queued")
        claimed = gateway.claim_relay_job(self.device)
        job = claimed["job"]
        self.assertEqual(job["job_id"], queued["job_id"])
        self.assertEqual(job["action"], "kali.health")
        accepted = gateway.submit_relay_result(
            job["job_id"],
            gateway.RelayJobResult(lease_token=job["lease_token"], status="completed",
                                   result={"status": "ok"}, error=""),
            self.device,
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(len(accepted["result_sha256"]), 64)
        self.assertEqual(len(accepted["evidence_record_hash"]), 64)
        listed = gateway.list_relay_jobs(device_id="kali-1")
        self.assertTrue(listed["evidence_chain"]["verified"])
        self.assertEqual(listed["evidence_chain"]["record_count"], 1)
        self.assertEqual(listed["jobs"][0]["status"], "completed")
        self.assertEqual(listed["jobs"][0]["result"], {"status": "ok"})

    def test_evidence_hash_chain_detects_tampering(self):
        body = gateway.RelayJobCreate(
            device_id="kali-1", action="kali.health", payload={},
            approval_reference="ENG-2026-002", operator_approved=True,
        )
        queued = gateway.create_relay_job(body)
        job = gateway.claim_relay_job(self.device)["job"]
        gateway.submit_relay_result(
            job["job_id"],
            gateway.RelayJobResult(lease_token=job["lease_token"], status="completed",
                                   result={"status": "ok"}, error=""),
            self.device,
        )
        con = gateway.db()
        con.execute("UPDATE relay_evidence SET result_sha256=? WHERE job_id=?",
                    ("0" * 64, queued["job_id"]))
        con.commit()
        result = gateway.verify_relay_evidence_chain(con)
        con.close()
        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "failed")

    def test_execution_requires_explicit_operator_approval(self):
        body = gateway.RelayJobCreate(
            device_id="kali-1", action="kali.health", payload={},
            approval_reference="ENG-2026-001", operator_approved=False,
        )
        with self.assertRaises(HTTPException) as denied:
            gateway.create_relay_job(body)
        self.assertEqual(denied.exception.status_code, 403)

    def test_job_cannot_be_sent_to_wrong_device_role(self):
        con = gateway.db()
        con.execute("UPDATE devices SET platform='desktop-browser' WHERE id='kali-1'")
        con.commit()
        con.close()
        body = gateway.RelayJobCreate(
            device_id="kali-1", action="kali.health", payload={},
            approval_reference="ENG-2026-001", operator_approved=True,
        )
        with self.assertRaises(HTTPException) as denied:
            gateway.create_relay_job(body)
        self.assertEqual(denied.exception.status_code, 409)

    def test_browser_job_requires_exact_approved_https_origin(self):
        with self.assertRaises(HTTPException):
            gateway.validate_relay_payload(
                "desktop.browser.inspect",
                {"url": "http://example.com", "allowed_origins": ["http://example.com"]},
                "ENG-2026-001", True,
            )
        self.assertEqual(
            gateway.validate_relay_payload(
                "desktop.browser.inspect",
                {"url": "https://example.com/login", "allowed_origins": ["https://example.com"]},
                "ENG-2026-001", True,
            ),
            "desktop-browser",
        )

    def test_tool_job_requires_matching_approval_reference(self):
        payload = {
            "tool": "nmap", "parameters": {"target": "example.com"},
            "confirmRun": True, "authorizationReference": "OTHER-REF",
            "targetConfirmation": "example.com", "timeoutSeconds": 30,
        }
        with self.assertRaises(HTTPException) as denied:
            gateway.validate_relay_payload("kali.tool.run", payload, "ENG-2026-001", True)
        self.assertEqual(denied.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
