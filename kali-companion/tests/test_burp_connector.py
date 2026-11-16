import unittest
from unittest.mock import patch

import burp_connector


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class BurpConnectorTests(unittest.TestCase):
    def test_rejects_non_loopback_api_url(self):
        result = burp_connector.inspect_burp_status(
            api_url="http://192.0.2.10:1337",
            api_key="secret",
        )
        self.assertEqual(result["status"], "invalid_configuration")

    def test_rejects_localhost_hostname_to_avoid_dns_rebinding(self):
        result = burp_connector.inspect_burp_status(
            api_url="http://localhost:1337",
            api_key="secret",
        )
        self.assertEqual(result["status"], "invalid_configuration")

    def test_reports_missing_key_without_network_request(self):
        with patch.object(burp_connector, "_load_api_key", return_value=None), \
             patch.object(burp_connector, "urlopen") as open_url:
            result = burp_connector.inspect_burp_status()
        self.assertEqual(result["status"], "not_configured")
        open_url.assert_not_called()

    def test_reports_connection_without_leaking_key(self):
        with patch.object(burp_connector, "urlopen", return_value=FakeResponse()) as open_url, \
             patch.object(burp_connector.shutil, "which", return_value="/usr/bin/burpsuite"):
            result = burp_connector.inspect_burp_status(
                api_url="http://127.0.0.1:1337",
                api_key="never-return-this-secret",
            )
        self.assertEqual(result["status"], "connected")
        self.assertTrue(result["installed"])
        self.assertNotIn("never-return-this-secret", repr(result))
        request = open_url.call_args.args[0]
        self.assertIn("never-return-this-secret", request.full_url)

    def test_marks_scanner_as_not_implemented_until_verified(self):
        with patch.object(burp_connector, "urlopen", return_value=FakeResponse()):
            result = burp_connector.inspect_burp_status(
                api_url="http://127.0.0.1:1337",
                api_key="local-key",
            )
        self.assertEqual(result["capabilities"]["scanner"], "not_implemented")

    def test_proxy_history_requires_local_token(self):
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen") as open_url:
            token_file.read_text.side_effect = OSError("missing")
            result = burp_connector.inspect_burp_proxy_history(25)
        self.assertEqual(result["status"], "not_configured")
        open_url.assert_not_called()

    def test_proxy_history_is_bounded_and_returns_only_metadata(self):
        payload = {
            "status": "ok",
            "items": [
                {"id": 7, "timestamp": "2026-11-16T12:00:00Z", "method": "GET",
                 "url": "https://lab.example.org/", "status_code": 200, "in_scope": True,
                 "request": "must not be forwarded"}
            ]
        }
        class HistoryResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps(payload).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=HistoryResponse()) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.inspect_burp_proxy_history(999)
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["count"], 1)
        self.assertNotIn("request", result["items"][0])
        request = open_url.call_args.args[0]
        self.assertIn("limit=100", request.full_url)

    def test_site_map_excludes_out_of_scope_items(self):
        payload = {
            "status": "ok",
            "items": [
                {"method": "GET", "url": "https://lab.example.org/", "status_code": 200, "in_scope": True},
                {"method": "POST", "url": "https://other.example.net/", "status_code": 200, "in_scope": False},
            ]
        }
        class SiteMapResponse(FakeResponse):
            def read(self, _limit):
                import json
                return json.dumps(payload).encode("utf-8")
        with patch.object(burp_connector, "EXTENSION_TOKEN_FILE") as token_file, \
             patch.object(burp_connector, "urlopen", return_value=SiteMapResponse()) as open_url:
            token_file.read_text.return_value = "local-extension-token-12345678901234567890"
            result = burp_connector.inspect_burp_site_map(20)
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["count"], 1)
        self.assertTrue(result["items"][0]["in_scope"])
        self.assertNotIn("other.example.net", repr(result))
        self.assertIn("limit=20", open_url.call_args.args[0].full_url)

    def test_rejects_url_credentials(self):
        result = burp_connector.inspect_burp_status(
            api_url="http://user:pass@127.0.0.1:1337",
            api_key="secret",
        )
        self.assertEqual(result["status"], "invalid_configuration")


if __name__ == "__main__":
    unittest.main()
