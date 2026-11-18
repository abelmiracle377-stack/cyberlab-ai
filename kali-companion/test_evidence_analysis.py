"""Tests for evidence-led service and CVE correlation."""
import unittest

from evidence_analysis import build_service_report, validate_report_payload


class EvidenceAnalysisTests(unittest.TestCase):
    def test_open_observations_are_reported_without_declaring_vulnerability(self):
        scan = {"target": "lab.example.org", "open_ports": [
            {"host": "192.0.2.8", "port": 443, "state": "open", "service": "https",
             "product": "ExampleServer", "version": "1.2.3"}]}
        calls = []
        def lookup(term, limit=10, timeout=8):
            calls.append((term, limit, timeout))
            return {"results": [{"id": "CVE-2025-1234", "description": "ExampleServer issue",
                                 "cvss": 7.5, "severity": "HIGH"}]}
        report = build_service_report(scan, lookup=lookup)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report["observations"][0]["port"], 443)
        self.assertEqual(report["cve_reference_candidates"][0]["status"], "unverified_reference_candidate")
        self.assertEqual(report["findings"], [])
        self.assertIn("not proof", " ".join(report["limitations"]))

    def test_service_name_without_product_does_not_trigger_broad_cve_search(self):
        services = {"target": "lab.example.org", "services": [
            {"port": 22, "state": "open", "service": "ssh", "banner": "SSH-2.0"}]}
        calls = []
        report = build_service_report(service_result=services,
                                      lookup=lambda *a, **k: calls.append(a) or {"results": []})
        self.assertEqual(calls, [])
        self.assertEqual(report["cve_reference_candidates"], [])
        self.assertEqual(report["observations"][0]["banner"], "SSH-2.0")

    def test_query_count_and_cve_count_are_bounded(self):
        scan = {"target": "lab.example.org", "open_ports": [
            {"port": p, "state": "open", "product": "Product" + str(p), "version": "1"}
            for p in range(20, 30)]}
        calls = []
        def lookup(term, limit=10, timeout=8):
            calls.append((term, limit))
            return {"results": [{"id": "CVE-2025-%04d" % i} for i in range(20)]}
        report = build_service_report(scan, lookup=lookup)
        self.assertLessEqual(len(calls), 3)
        self.assertTrue(all(limit == 10 for _, limit in calls))
        self.assertLessEqual(len(report["cve_reference_candidates"]), 30)

    def test_lookup_failure_is_reported_not_hidden(self):
        scan = {"target": "lab.example.org", "open_ports": [
            {"port": 443, "state": "open", "product": "ExampleServer"}]}
        report = build_service_report(scan, lookup=lambda *a, **k: (_ for _ in ()).throw(TimeoutError("offline")))
        self.assertEqual(report["cve_reference_candidates"], [])
        self.assertEqual(report["lookup_errors"][0]["query"], "ExampleServer")

    def test_payload_validation_requires_bounded_object_evidence(self):
        with self.assertRaises(ValueError):
            validate_report_payload({})
        with self.assertRaises(ValueError):
            validate_report_payload({"scanResult": "not-an-object"})
        with self.assertRaises(ValueError):
            validate_report_payload({"serviceResult": {"x": "a" * 61000}})


if __name__ == "__main__":
    unittest.main()
