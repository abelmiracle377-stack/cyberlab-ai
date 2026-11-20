"""Tests for the Shodan OSINT connector (no network — injected opener)."""
import io
import json
import unittest

import shodan_connector as sc


class FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._raw = json.dumps(payload).encode()

    def read(self):
        return self._raw


class FakeOpener:
    def __init__(self, status, payload):
        self.status, self.payload = status, payload
        self.calls = []

    def __call__(self, request, timeout=30):
        self.calls.append(request.full_url)
        return FakeResponse(self.status, self.payload)


class ShodanTests(unittest.TestCase):
    def test_host_lookup_includes_key_and_ip(self):
        opener = FakeOpener(200, {"ip_str": "8.8.8.8", "ports": [53]})
        sc.host_lookup("8.8.8.8", "KEY123", opener=opener)
        url = opener.calls[0]
        self.assertIn("/shodan/host/8.8.8.8", url)
        self.assertIn("key=KEY123", url)

    def test_search_requires_query(self):
        with self.assertRaises(ValueError):
            sc.search("", "KEY")

    def test_api_error_raises(self):
        opener = FakeOpener(401, {"error": "invalid key"})
        with self.assertRaises(RuntimeError):
            sc.api_info("BAD", opener=opener)

    def test_normalize_host(self):
        raw = {"ip_str": "1.2.3.4", "org": "ExampleOrg", "os": "Linux",
               "hostnames": ["a.example"], "vulns": ["CVE-2021-1234"],
               "data": [{"port": 443, "transport": "tcp", "product": "nginx", "data": "HTTP/1.1 200"},
                        {"port": 22, "transport": "tcp", "product": "OpenSSH"}]}
        out = sc.normalize_host(raw)
        self.assertEqual(out["ip"], "1.2.3.4")
        self.assertEqual(out["ports"], [22, 443])
        self.assertEqual(out["service_count"], 2)
        self.assertIn("CVE-2021-1234", out["vulns"])

    def test_normalize_search_limits(self):
        raw = {"total": 3, "matches": [{"ip_str": f"10.0.0.{i}", "port": 80} for i in range(3)]}
        out = sc.normalize_search(raw, limit=2)
        self.assertEqual(out["total"], 3)
        self.assertEqual(out["count"], 2)

    def test_key_required(self):
        with self.assertRaises(ValueError):
            sc.host_lookup("1.1.1.1", "")


if __name__ == "__main__":
    unittest.main()
