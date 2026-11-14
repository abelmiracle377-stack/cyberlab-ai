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
