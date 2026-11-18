"""Tests for the fixed passive research dispatcher."""
import unittest
from unittest.mock import patch

from research_workflows import run_research_action


class ResearchWorkflowTests(unittest.TestCase):
    def test_dns_uses_fixed_lookup(self):
        with patch("research_workflows.dns_lookup", return_value={"domain": "example.com"}) as lookup:
            result = run_research_action({"action": "dns", "value": "example.com"})
        lookup.assert_called_once_with("example.com", timeout=8)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["action"], "dns")

    def test_domain_osint_uses_fixed_lookup(self):
        with patch("research_workflows.domain_osint", return_value={"domain": "example.com"}) as lookup:
            run_research_action({"action": "domain", "value": "example.com"})
        lookup.assert_called_once_with("example.com", timeout=8)

    def test_ip_rejects_private_and_invalid_addresses(self):
        for value in ("127.0.0.1", "10.0.0.1", "not-an-ip"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                run_research_action({"action": "ip", "value": value})

    def test_ip_calls_only_public_global_lookup(self):
        with patch("research_workflows.ip_intelligence", return_value={"ip": "8.8.8.8"}) as lookup:
            run_research_action({"action": "ip", "value": "8.8.8.8"})
        lookup.assert_called_once_with("8.8.8.8", timeout=8)

    def test_cve_limit_is_strict_integer(self):
        for limit in (0, 21, True, "10"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                run_research_action({"action": "cve", "value": "OpenSSH", "limit": limit})

    def test_cve_search_uses_bounded_limit(self):
        with patch("research_workflows.cve_search", return_value={"results": []}) as lookup:
            run_research_action({"action": "cve", "value": "OpenSSH", "limit": 5})
        lookup.assert_called_once_with("OpenSSH", limit=5, timeout=8)

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            run_research_action({"action": "shell", "value": "id"})

    def test_non_object_rejected(self):
        with self.assertRaises(ValueError):
            run_research_action(["dns", "example.com"])

    def test_invalid_domain_type_and_cve_length_rejected(self):
        with self.assertRaises(ValueError):
            run_research_action({"action": "dns", "value": ["example.com"]})
        with self.assertRaises(ValueError):
            run_research_action({"action": "cve", "value": "x"})

    def test_output_size_is_bounded(self):
        with patch("research_workflows.dns_lookup", return_value={"data": "x" * 600_000}):
            with self.assertRaises(ValueError):
                run_research_action({"action": "dns", "value": "example.com"})


if __name__ == "__main__":
    unittest.main()
