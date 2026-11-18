"""Tests for bounded static artifact and recovery-manifest analysis."""
import unittest

from artifact_analysis import build_artifact_report, validate_artifact_payload


class ArtifactAnalysisTests(unittest.TestCase):
    def test_static_triage_does_not_issue_malware_verdict(self):
        triage = {"file_name": "sample.bin", "file_type": "ELF executable",
                  "size_bytes": 1024, "sha256": "a" * 64, "entropy": 7.8,
                  "indicator_groups": ["Shell execution"],
                  "matched_strings": ["/bin/sh -c example"]}
        report = build_artifact_report(triage_result=triage)
        self.assertEqual(report["risk_findings"], [])
        self.assertIn("not a malware verdict", " ".join(report["limitations"]))
        self.assertIn("static_file_triage", report["observations"][0]["type"])

    def test_manifest_summarises_hashes_and_extensions(self):
        manifest = {"schema": "cyberlab.recovery-manifest.v1", "algorithm": "SHA-256",
                    "truncated": False, "files": [
                        {"path": "jpg/0001.jpg", "size_bytes": 12, "sha256": "b" * 64},
                        {"path": "pdf/0002.pdf", "size_bytes": 30, "sha256": "c" * 64}]}
        report = build_artifact_report(recovery_manifest=manifest)
        observation = report["observations"][0]
        self.assertEqual(observation["files_hashed"], 2)
        self.assertEqual(observation["total_bytes_hashed"], 42)
        self.assertEqual(observation["extension_counts"], {"jpg": 1, "pdf": 1})

    def test_manifest_rejects_traversal_entries(self):
        manifest = {"schema": "cyberlab.recovery-manifest.v1", "algorithm": "SHA-256",
                    "files": [{"path": "../outside", "size_bytes": 1, "sha256": "d" * 64}]}
        report = build_artifact_report(recovery_manifest=manifest)
        self.assertEqual(report["observations"][0]["files"], [])

    def test_invalid_hash_and_entropy_are_rejected(self):
        base = {"size_bytes": 10, "sha256": "not-a-hash", "entropy": 2.0}
        with self.assertRaises(ValueError):
            build_artifact_report(triage_result=base)
        base["sha256"] = "e" * 64
        base["entropy"] = 9
        with self.assertRaises(ValueError):
            build_artifact_report(triage_result=base)

    def test_payload_is_bounded_and_requires_evidence(self):
        with self.assertRaises(ValueError):
            validate_artifact_payload({})
        with self.assertRaises(ValueError):
            validate_artifact_payload({"triageResult": "invalid"})
        with self.assertRaises(ValueError):
            validate_artifact_payload({"recoveryManifest": {"blob": "x" * 61000}})


if __name__ == "__main__":
    unittest.main()
