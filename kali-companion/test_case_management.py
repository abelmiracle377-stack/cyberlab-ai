"""Tests for unified case reports and append-only audit metadata."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import case_management


class CaseManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.ledger = root / "case-audit.jsonl"
        self.directory = root / "state"
        self.directory.mkdir()
        self.service = {"status": "completed", "target": "lab.example.org",
                        "observations": [{"port": 443, "state": "open"}],
                        "cve_reference_candidates": [{"id": "CVE-2025-1000"}],
                        "limitations": ["not a vulnerability verdict"]}
        self.artifact = {"status": "completed",
                         "observations": [{"type": "static_file_triage", "sha256": "a" * 64}],
                         "limitations": ["not a malware verdict"]}
        self.patcher = patch.multiple(case_management, LEDGER_DIR=self.directory, LEDGER_FILE=self.ledger)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def test_case_combines_sources_and_writes_hash_chained_metadata(self):
        report = case_management.build_case_report(self.service, self.artifact)
        self.assertEqual(len(report["case"]["sources"]), 2)
        self.assertEqual(report["case"]["observation_count"], 2)
        self.assertEqual(report["findings"], [])
        line = json.loads(self.ledger.read_text().strip())
        self.assertEqual(line["record_hash"], report["audit_trail"]["record_hash"])
        self.assertEqual(line["previous_record_hash"], "GENESIS")
        self.assertNotIn("lab.example.org", self.ledger.read_text())
        self.assertNotIn("CVE-2025-1000", self.ledger.read_text())

    def test_second_case_chains_to_first_record(self):
        first = case_management.build_case_report(self.service)
        second = case_management.build_case_report(artifact_report=self.artifact)
        self.assertEqual(second["audit_trail"]["previous_record_hash"], first["audit_trail"]["record_hash"])

    def artifact_report(self):
        return self.artifact

    def test_read_only_verifier_accepts_valid_hash_chain(self):
        case_management.build_case_report(self.service)
        before = self.ledger.read_bytes()
        result = case_management.verify_audit_ledger()
        self.assertTrue(result["verified"])
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_read_only_verifier_detects_content_tampering(self):
        case_management.build_case_report(self.service)
        self.ledger.write_text(self.ledger.read_text().replace('"event":"case_created"', '"event":"altered"'))
        result = case_management.verify_audit_ledger()
        self.assertFalse(result["verified"])
        self.assertTrue(any("unsupported audit event" in error or "record hash mismatch" in error for error in result["errors"]))

    def test_read_only_verifier_rejects_malformed_and_blank_lines(self):
        self.ledger.write_text('not-json\\n\\n')
        result = case_management.verify_audit_ledger()
        self.assertFalse(result["verified"])
        self.assertTrue(any("malformed JSON" in error for error in result["errors"]))
        self.assertTrue(any("blank records" in error for error in result["errors"]))

    def test_read_only_verifier_rejects_symlink_ledger(self):
        outside = self.directory / "outside.jsonl"
        outside.write_text("{}\\n")
        self.ledger.symlink_to(outside)
        result = case_management.verify_audit_ledger()
        self.assertFalse(result["verified"])
        self.assertTrue(any("symlink" in error or "regular" in error for error in result["errors"]))

    def test_read_only_verifier_reports_missing_ledger(self):
        result = case_management.verify_audit_ledger()
        self.assertFalse(result["verified"])
        self.assertIn("missing", result["errors"][0].lower())

    def test_modified_ledger_is_detected_before_append(self):
        case_management.build_case_report(self.service)
        content = self.ledger.read_text()
        self.ledger.write_text(content.replace('"event":"case_created"', '"event":"altered"'))
        with self.assertRaisesRegex(ValueError, "failed hash-chain verification"):
            case_management.build_case_report(self.artifact, None)

    def test_uncompleted_reports_are_rejected(self):
        with self.assertRaises(ValueError):
            case_management.build_case_report({"status": "running"})

    def test_payload_requires_report_and_caps_size(self):
        with self.assertRaises(ValueError):
            case_management.validate_case_payload({})
        with self.assertRaises(ValueError):
            case_management.validate_case_payload({"serviceReport": "bad"})
        with self.assertRaises(ValueError):
            case_management.validate_case_payload({"artifactReport": {"blob": "x" * 130000}})


if __name__ == "__main__":
    unittest.main()
