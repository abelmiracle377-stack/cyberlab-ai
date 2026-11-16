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

    def test_rejects_url_credentials(self):
        result = burp_connector.inspect_burp_status(
            api_url="http://user:pass@127.0.0.1:1337",
            api_key="secret",
        )
        self.assertEqual(result["status"], "invalid_configuration")


if __name__ == "__main__":
    unittest.main()
