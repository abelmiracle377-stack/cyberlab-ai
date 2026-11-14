"""Tests for deterministic case exports and private evidence archives."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import case_export


class CaseExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "exports"
        self.report = {"status": "completed", "case": {"case_id": "a" * 32,
            "created_at": "2026-11-14T00:00:00Z", "sources": [{"sha256": "b" * 64}]},
            "observations": [{"detail": "<script>alert(1)</script>"}], "findings": []}
        self.patch = patch.object(case_export, "EXPORT_ROOT", self.root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_html_escapes_untrusted_report_content(self):
        rendered = case_export.render_case_html(self.report)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("Content-Security-Policy", rendered)

    def test_archive_writes_hash_verified_files_with_restrictive_modes(self):
        result = case_export.export_case_bundle(self.report)
        folder = Path(result["archive"]["directory"])
        for name in ("case.json", "case.html", "manifest.json"):
            self.assertTrue((folder / name).is_file())
        manifest = json.loads((folder / "manifest.json").read_text())
        for name in ("case.json", "case.html"):
            data = (folder / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), manifest["files"][name]["sha256"])
        self.assertEqual((folder / "case.json").read_text(), result["json_export"])
        self.assertEqual((folder / "case.html").read_text(), result["html_export"])

    def test_existing_case_archive_is_never_overwritten(self):
        case_export.export_case_bundle(self.report)
        with self.assertRaises(FileExistsError):
            case_export.export_case_bundle(self.report)

    def test_invalid_case_and_oversized_report_rejected(self):
        invalid = dict(self.report, case={"case_id": "../bad", "sources": [{}]})
        with self.assertRaises(ValueError):
            case_export.export_case_bundle(invalid)
        oversized = dict(self.report, extra="x" * (case_export.MAX_EXPORT_BYTES + 1))
        with self.assertRaises(ValueError):
            case_export.export_case_bundle(oversized)


if __name__ == "__main__":
    unittest.main()
